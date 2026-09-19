#pragma once
#include "endorse_guard.h"
#include "../core/hash.h"
#include <cstdlib>
#include <memory>

namespace veld::compat {

// Safety state belongs to the validator identity, not a replaceable chain DB.
// Share it across datadirs and node/validator programs running as this OS user.
// The endorsement file's exclusive lifetime lease also owns finality voting.
class ValidatorSigningState {
  public:
    explicit ValidatorSigningState(std::string chain) : chain_(std::move(chain)) {}

    bool Acquire(const std::string& public_key, EndorseAntiEquivGuard& legacy) {
        std::lock_guard<std::mutex> lock(mu_);
        return Acquire_(public_key, legacy) != nullptr;
    }

    bool Record(const std::string& public_key, uint64_t height, const std::string& hash,
                EndorseAntiEquivGuard& legacy) {
        std::lock_guard<std::mutex> lock(mu_);
        auto* state = Acquire_(public_key, legacy);
        if (!state)
            return false;
        const auto key = std::to_string(height) + ":" + public_key;
        // Both histories precede signing. Legacy state remains usable on an
        // orderly move; the shared copy protects datadir restores on this host.
        if (!state->guard.record(key, hash) || !legacy.record(key, hash)) {
            error_ = "validator decision conflicts or safety journal is unavailable";
            return false;
        }
        return true;
    }

    std::string Directory(const std::string& public_key) {
        std::lock_guard<std::mutex> lock(mu_);
        const auto it = states_.find(public_key);
        return it == states_.end() || !it->second->ready ? "" : it->second->directory;
    }
    std::string error() {
        std::lock_guard<std::mutex> lock(mu_);
        return error_;
    }

  private:
    struct State {
        EndorseAntiEquivGuard guard;
        std::string directory;
        bool ready{false};
    };
    State* Acquire_(const std::string& public_key, EndorseAntiEquivGuard& legacy) {
        const auto found = states_.find(public_key);
        if (found != states_.end())
            return found->second->ready ? found->second.get() : nullptr;
        if (chain_.size() != 64 || public_key.empty() || public_key.size() % 2 ||
            public_key.size() > 8192 ||
            public_key.find_first_not_of("0123456789abcdef") != std::string::npos ||
            chain_.find_first_not_of("0123456789abcdef") != std::string::npos) {
            error_ = "invalid validator signing identity";
            return nullptr;
        }
#ifdef _WIN32
        const wchar_t* base = _wgetenv(L"LOCALAPPDATA");
#else
        const char* base = std::getenv("HOME");
#endif
        if (!base || !*base || !std::filesystem::path(base).is_absolute()) {
            error_ = "OS user safety-state directory is unavailable";
            return nullptr;
        }
        auto state = std::make_unique<State>();
        auto* result = state.get();
        states_.emplace(public_key, std::move(state));
        auto directory = std::filesystem::path(base) / ".veld-validator-safety";
        for (const auto& part : {std::string{}, chain_, HashToHex(Hash256d(public_key))}) {
            if (!part.empty())
                directory /= part;
            if (!channel::secure_file::EnsurePrivateDirectory(directory.string(), &error_))
                return nullptr;
        }
        result->directory = directory.string();
        if (!result->guard.load((directory / "endorsed.dat").string()) ||
            !legacy.copy_identity_to(public_key, result->guard)) {
            error_ = "validator identity is already in use, or signing history conflicts: " +
                     result->guard.error();
            return nullptr;
        }
        result->ready = true;
        return result;
    }
    std::mutex mu_;
    std::string chain_, error_;
    std::unordered_map<std::string, std::unique_ptr<State>> states_;
};
} // namespace veld::compat
