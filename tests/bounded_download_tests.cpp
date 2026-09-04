#include "../include/compat/process.h"
#include "../include/consensus/checkpoints.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <new>
#include <string>
#include <thread>
#include <vector>

namespace {
std::atomic<size_t> g_largest_allocation{0};

void RecordAllocation(size_t size) noexcept {
    size_t observed = g_largest_allocation.load(std::memory_order_relaxed);
    while (observed < size &&
           !g_largest_allocation.compare_exchange_weak(observed, size, std::memory_order_relaxed)) {
    }
}
} // namespace

void* operator new(std::size_t size) {
    if (void* value = std::malloc(size == 0 ? 1 : size)) {
        RecordAllocation(size);
        return value;
    }
    throw std::bad_alloc();
}

void* operator new[](std::size_t size) {
    return ::operator new(size);
}
void operator delete(void* value) noexcept {
    std::free(value);
}
void operator delete[](void* value) noexcept {
    std::free(value);
}
void operator delete(void* value, std::size_t) noexcept {
    std::free(value);
}
void operator delete[](void* value, std::size_t) noexcept {
    std::free(value);
}

namespace {

using veld::compat::BoundedFileResult;
using veld::compat::BoundedFileStatus;

uint64_t ParseU64(const char* text) {
    const std::string value(text ? text : "");
    size_t used = 0;
    const unsigned long long parsed = std::stoull(value, &used, 10);
    if (used != value.size())
        throw std::runtime_error("non-canonical integer");
    return static_cast<uint64_t>(parsed);
}

int EmitMode(int argc, char** argv) {
    if (argc != 5)
        return 2;
    const uint64_t bytes = ParseU64(argv[2]);
    const uint64_t delay_ms = ParseU64(argv[3]);
    const uint64_t exit_code = ParseU64(argv[4]);
    if (bytes > 64U * 1024U * 1024U || delay_ms > 60U * 1000U || exit_code > 125) {
        return 2;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    const std::string chunk(4096, 'V');
    uint64_t remaining = bytes;
    while (remaining != 0) {
        const size_t take =
            remaining < chunk.size() ? static_cast<size_t>(remaining) : chunk.size();
        std::cout.write(chunk.data(), static_cast<std::streamsize>(take));
        std::cout.flush();
        if (!std::cout)
            return 124;
        remaining -= take;
    }
    return static_cast<int>(exit_code);
}

int FetchMode(int argc, char** argv) {
    if (argc != 6)
        return 2;
    const std::string url = argv[2];
    const std::string destination = argv[3];
    const uint64_t maximum = ParseU64(argv[4]);
    const uint64_t deadline_ms = ParseU64(argv[5]);
    if (url.rfind("http://127.0.0.1:", 0) != 0 || maximum == 0 || deadline_ms == 0 ||
        deadline_ms > 60U * 1000U) {
        return 2;
    }
    const uint64_t curl_seconds = deadline_ms / 1000U + 2U;
    const BoundedFileResult result = veld::compat::RunProcessToBoundedFile(
        {"curl", "--fail", "--silent", "--show-error", "--connect-timeout", "2", "--max-time",
         std::to_string(curl_seconds), "--max-filesize", std::to_string(maximum), "--location",
         "--max-redirs", "0", "--proto", "=http,https", "--proto-redir", "=https", url},
        destination, maximum, std::chrono::milliseconds(deadline_ms));
    std::cout << "status=" << static_cast<unsigned>(result.status) << " exit=" << result.exit_code
              << " bytes=" << result.bytes_written
              << " exists=" << (std::filesystem::exists(destination) ? 1 : 0) << "\n";
    return 0;
}

struct TestState {
    size_t checks{0};
    void Check(bool condition, const char* message) {
        if (!condition)
            throw std::runtime_error(message);
        ++checks;
    }
};

} // namespace

int main(int argc, char** argv) try {
    if (argc > 1 && std::string(argv[1]) == "--emit")
        return EmitMode(argc, argv);
    if (argc > 1 && std::string(argv[1]) == "--fetch")
        return FetchMode(argc, argv);
    if (argc != 1)
        return 2;

    namespace fs = std::filesystem;
    TestState test;
    const std::string self = veld::compat::ExecutablePath();
    test.Check(!self.empty(), "running executable path unavailable");
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() / ("veld-f8-bounded-" + std::to_string(nonce));
    test.Check(fs::create_directory(root), "test directory creation failed");
    struct Cleanup {
        fs::path path;
        ~Cleanup() {
            std::error_code ignored;
            fs::remove_all(path, ignored);
        }
    } cleanup{root};

    const fs::path exact = root / "exact.bin";
    auto result = veld::compat::RunProcessToBoundedFile(
        {self, "--emit", "8192", "0", "0"}, exact.string(), 8192, std::chrono::seconds(5));
    test.Check(result.status == BoundedFileStatus::Success, "exact maximum transfer failed");
    test.Check(result.bytes_written == 8192, "exact maximum count mismatch");
    test.Check(fs::file_size(exact) == 8192, "exact maximum file mismatch");

    const fs::path oversized = root / "oversized.bin";
    result = veld::compat::RunProcessToBoundedFile(
        {self, "--emit", "8193", "0", "0"}, oversized.string(), 8192, std::chrono::seconds(5));
    test.Check(result.status == BoundedFileStatus::ByteLimitExceeded,
               "oversized stream was not stopped at transfer boundary");
    test.Check(!fs::exists(oversized), "oversized partial file survived");

    const fs::path slow = root / "slow.bin";
    const auto before = std::chrono::steady_clock::now();
    result = veld::compat::RunProcessToBoundedFile(
        {self, "--emit", "1", "2000", "0"}, slow.string(), 8192, std::chrono::milliseconds(120));
    const auto elapsed = std::chrono::steady_clock::now() - before;
    test.Check(result.status == BoundedFileStatus::DeadlineExceeded,
               "slow stream did not hit parent deadline");
    test.Check(elapsed < std::chrono::seconds(1), "deadline did not terminate child promptly");
    test.Check(!fs::exists(slow), "deadline partial file survived");

    const fs::path failed = root / "failed.bin";
    result = veld::compat::RunProcessToBoundedFile({self, "--emit", "1024", "0", "7"},
                                                   failed.string(), 8192, std::chrono::seconds(5));
    test.Check(result.status == BoundedFileStatus::ChildFailed, "child failure was accepted");
    test.Check(result.exit_code == 7, "child failure code was lost");
    test.Check(!fs::exists(failed), "failed child partial file survived");

    const fs::path existing = root / "existing.bin";
    {
        std::ofstream out(existing, std::ios::binary);
        out << "sentinel";
    }
    result = veld::compat::RunProcessToBoundedFile(
        {self, "--emit", "1", "0", "0"}, existing.string(), 8192, std::chrono::seconds(5));
    test.Check(result.status == BoundedFileStatus::OpenFailed,
               "preexisting destination was overwritten");
    std::ifstream preserved(existing, std::ios::binary);
    std::string preserved_text;
    preserved >> preserved_text;
    test.Check(preserved_text == "sentinel", "preexisting file changed");

    const fs::path missing_parent = root / "absent" / "disk-error.bin";
    result = veld::compat::RunProcessToBoundedFile(
        {self, "--emit", "1", "0", "0"}, missing_parent.string(), 8192, std::chrono::seconds(5));
    test.Check(result.status == BoundedFileStatus::OpenFailed,
               "unwritable destination was accepted");
    test.Check(!fs::exists(missing_parent), "open failure left a partial file");

    const std::string parser_suffix = "\",\"height\":1,\"hash\":\"" + std::string(64, '0') +
                                      "\",\"sig\":\"" + std::string(6618, '0') + "\"}";
    std::string maximum_document = "{\"padding\":\"";
    test.Check(maximum_document.size() + parser_suffix.size() < veld::kMaxCheckpointDocumentBytes,
               "checkpoint parser fixture exceeds shared cap");
    maximum_document.append(
        veld::kMaxCheckpointDocumentBytes - maximum_document.size() - parser_suffix.size(), 'P');
    maximum_document += parser_suffix;
    test.Check(maximum_document.size() == veld::kMaxCheckpointDocumentBytes,
               "checkpoint parser exact-cap fixture size mismatch");
    g_largest_allocation.store(0, std::memory_order_relaxed);
    const auto parsed = veld::ParseCheckpointsJson(maximum_document);
    const size_t parser_allocation = g_largest_allocation.load(std::memory_order_relaxed);
    test.Check(parsed.size() == 1, "checkpoint parser exact-cap fixture was not exercised");
    test.Check(parser_allocation < 64U * 1024U,
               "checkpoint parser copied a complete object or oversized field");

    std::cout << "PASS bounded_download_tests checks=" << test.checks << "\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "FAIL bounded_download_tests: " << e.what() << "\n";
    return 1;
}
