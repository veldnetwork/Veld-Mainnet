#pragma once
// Local validator signing safety, shared by node and standalone validator.
// Retain every (height, public key) decision across reorgs. Persist and flush
// BEFORE signing. A process owns the journal for its entire signing lifetime;
// another process must not authorize from a stale in-memory copy.
// This is local safety state, never chain-derived state or a pruning cache.

#include "../wallet/secure_channel_file.h"
#include <charconv>
#include <mutex>
#include <unordered_map>
#ifndef _WIN32
#include <sys/file.h>
#endif

class EndorseAntiEquivGuard {
  public:
    EndorseAntiEquivGuard() = default;
    EndorseAntiEquivGuard(const EndorseAntiEquivGuard&) = delete;
    EndorseAntiEquivGuard& operator=(const EndorseAntiEquivGuard&) = delete;
    ~EndorseAntiEquivGuard() {
#ifndef _WIN32
        if (fd_ >= 0)
            ::close(fd_);
        if (parent_.fd >= 0)
            ::close(parent_.fd);
#endif
    }

    bool load(const std::string& path) {
        std::lock_guard<std::mutex> lock(mu_);
        // Never reset an already loaded or failed guard to an empty history.
        if (attempted_)
            return ready_ && path == path_ && Continuous_();
        attempted_ = true;
        path_ = path;
        namespace sf = veld::channel::secure_file;
#ifdef _WIN32
        if (!owner_.Initialize(&error_) ||
            !sf::OpenParent(std::filesystem::path(path), false, owner_, parent_, &error_))
            return false;
        const auto target = parent_.canonical / parent_.leaf;
        file_ = sf::WinHandle(
            ::CreateFileW(target.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                          FILE_SHARE_READ, &owner_.attributes, OPEN_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!file_)
            return Fail_("journal is unavailable or another validator is using it");
        if (!sf::RegularSingleLink(file_.value, &identity_, &error_, "journal") ||
            !sf::HandleHasCurrentOwner(file_.value, owner_.sid(), false, &error_, "journal"))
            return false;
        if (!::FlushFileBuffers(file_.value))
            return Fail_("cannot flush journal");
#else
        if (!sf::OpenParent(std::filesystem::path(path), false, parent_, &error_))
            return false;
        struct stat parent_stat {};
        if (::fstat(parent_.fd, &parent_stat) != 0 || (parent_stat.st_mode & 0022))
            return Fail_("journal directory must not be writable by other users");
        fd_ = ::openat(parent_.fd, parent_.base.c_str(),
                       O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
        if (fd_ < 0 || ::fstat(fd_, &identity_) != 0 || !S_ISREG(identity_.st_mode) ||
            identity_.st_uid != ::geteuid() || identity_.st_nlink != 1 ||
            (identity_.st_mode & 0022))
            return Fail_("journal must be an owned regular file without writable aliases");
        if (::flock(fd_, LOCK_EX | LOCK_NB) != 0)
            return Fail_("another validator is using this journal");
        // New file name and contents both have to survive a machine restart.
        if (::fsync(fd_) != 0 || ::fsync(parent_.fd) != 0)
            return Fail_("cannot flush journal and directory");
#endif
        std::string line;
        char buffer[4096];
        for (;;) {
            size_t count = 0;
#ifdef _WIN32
            DWORD got = 0;
            if (!::ReadFile(file_.value, buffer, sizeof(buffer), &got, nullptr))
                return Fail_("cannot read journal");
            count = got;
#else
            const auto got = ::read(fd_, buffer, sizeof(buffer));
            if (got < 0) {
                if (errno == EINTR)
                    continue;
                return Fail_("cannot read journal");
            }
            count = static_cast<size_t>(got);
#endif
            if (!count)
                break;
            size_ += count;
            for (size_t i = 0; i < count; ++i) {
                if (buffer[i] == '\n') {
                    if (!line.empty() && line.back() == '\r')
                        line.pop_back();
                    const auto eq = line.find('=');
                    if (eq == std::string::npos)
                        return Fail_("malformed journal record");
                    const auto key = line.substr(0, eq), hash = line.substr(eq + 1);
                    if (!Valid_(key, hash))
                        return Fail_("malformed journal decision");
                    auto [it, inserted] = map_.emplace(key, hash);
                    if (!inserted && it->second != hash)
                        return Fail_("conflicting journal decisions; signing stopped");
                    line.clear();
                } else {
                    if (line.size() >= 8300)
                        return Fail_("oversized journal record");
                    line.push_back(buffer[i]);
                }
            }
        }
        if (!line.empty())
            return Fail_("incomplete journal record; signing stopped");
        ready_ = true;
        return Continuous_();
    }

    bool would_equivocate(const std::string& key, const std::string& hash) {
        std::lock_guard<std::mutex> lock(mu_);
        const auto it = map_.find(key);
        return it != map_.end() && it->second != hash;
    }

    bool record(const std::string& key, const std::string& hash) {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ready_ || !Valid_(key, hash) || !Continuous_())
            return false;
        const auto it = map_.find(key);
        if (it != map_.end())
            return it->second == hash;
        const std::string bytes = key + "=" + hash + "\n";
#ifdef _WIN32
        DWORD written = 0;
        if (!::WriteFile(file_.value, bytes.data(), static_cast<DWORD>(bytes.size()), &written,
                         nullptr) ||
            written != bytes.size() || !::FlushFileBuffers(file_.value))
            return Fail_("journal write/flush failed; restart and check safety state");
#else
        size_t offset = 0;
        while (offset < bytes.size()) {
            const auto written = ::write(fd_, bytes.data() + offset, bytes.size() - offset);
            if (written < 0 && errno == EINTR)
                continue;
            if (written <= 0)
                return Fail_("journal write failed; restart and check safety state");
            offset += static_cast<size_t>(written);
        }
        if (::fsync(fd_) != 0)
            return Fail_("journal flush failed; restart and check safety state");
#endif
        size_ += bytes.size();
        if (!Continuous_())
            return false;
        map_.emplace(key, hash);
        return true;
    }

    std::string error() {
        std::lock_guard<std::mutex> lock(mu_);
        return error_;
    }

    // Import an existing datadir/keyfile history into the shared identity store.
    // A conflict or unavailable source closes signing; never use last-write-wins.
    bool copy_identity_to(const std::string& public_key, EndorseAntiEquivGuard& target) {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ready_ || !Continuous_() || &target == this)
            return false;
        for (const auto& item : map_) {
            if (item.first.substr(item.first.find(':') + 1) == public_key &&
                !target.record(item.first, item.second))
                return false;
        }
        return true;
    }

  private:
    static bool Hex_(const std::string& s) {
        return !s.empty() && s.size() % 2 == 0 &&
               s.find_first_not_of("0123456789abcdef") == std::string::npos;
    }
    static bool Valid_(const std::string& key, const std::string& hash) {
        const auto colon = key.find(':');
        if (colon == std::string::npos || colon == 0 || colon > 20 ||
            (colon > 1 && key[0] == '0') || key.size() - colon - 1 > 8192 ||
            !Hex_(key.substr(colon + 1)) || hash.size() != 64 || !Hex_(hash))
            return false;
        uint64_t height = 0;
        const auto parsed = std::from_chars(key.data(), key.data() + colon, height);
        return parsed.ec == std::errc{} && parsed.ptr == key.data() + colon;
    }
    bool Fail_(const std::string& why) {
        ready_ = false;
        error_ = why;
        return false;
    }
    bool Continuous_() {
#ifdef _WIN32
        BY_HANDLE_FILE_INFORMATION now{};
        if (!::GetFileInformationByHandle(file_.value, &now) || now.nNumberOfLinks != 1 ||
            ((uint64_t(now.nFileSizeHigh) << 32) | now.nFileSizeLow) != size_)
            return Fail_("journal changed while signing; signing stopped");
#else
        struct stat now {
        }, named{};
        if (::fstat(fd_, &now) != 0 ||
            ::fstatat(parent_.fd, parent_.base.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            now.st_dev != named.st_dev || now.st_ino != named.st_ino || now.st_nlink != 1 ||
            now.st_size < 0 || uint64_t(now.st_size) != size_)
            return Fail_("journal removed, replaced or truncated; signing stopped");
#endif
        return true;
    }
    std::mutex mu_;
    std::unordered_map<std::string, std::string> map_;
    std::string path_, error_;
    uint64_t size_{0};
    bool attempted_{false}, ready_{false};
#ifdef _WIN32
    veld::channel::secure_file::WinOwnerSecurity owner_;
    veld::channel::secure_file::WinParent parent_;
    veld::channel::secure_file::WinHandle file_;
    BY_HANDLE_FILE_INFORMATION identity_{};
#else
    veld::channel::secure_file::ParentFd parent_;
    int fd_{-1};
    struct stat identity_ {};
#endif
};
