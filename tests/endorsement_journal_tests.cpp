#include "compat/endorse_guard.h"
#include "compat/validator_signing_state.h"
#include <fstream>
#include <filesystem>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>

static const std::string key = "42:" + std::string(3904, 'a');
static const std::string a(64, 'a'), b(64, 'b');

int main(int argc, char** argv) {
    if (argc != 3)
        return 2;
    const std::string mode = argv[1], path = argv[2];
    if (mode == "identity-a" || mode == "identity-b" || mode == "identity-hold") {
        EndorseAntiEquivGuard local;
        local.load(path);
        veld::compat::ValidatorSigningState shared(std::string(64, '0'));
        const bool ok = shared.Record(key.substr(3), 42, mode == "identity-b" ? b : a, local);
        std::cout << (ok ? "AUTHORIZED" : "REFUSED") << std::endl;
        if (ok && mode == "identity-hold") {
            std::string line;
            std::getline(std::cin, line);
        }
        return ok ? 0 : 3;
    }
    if (mode == "write-a" || mode == "write-b" || mode == "hold") {
        EndorseAntiEquivGuard g;
        g.load(path);
        const bool ok = g.record(key, mode == "write-b" ? b : a);
        std::cout << (ok ? "AUTHORIZED" : "REFUSED") << std::endl;
        if (ok && mode == "hold") {
            std::string line;
            std::getline(std::cin, line);
        }
        return ok ? 0 : 3;
    }
    if (mode == "two-instances") {
        EndorseAntiEquivGuard first, second;
        first.load(path);
        second.load(path);
        const bool one = first.record(key, a);
        const bool two = second.record(key, b);
        std::cout << "first=" << one << " conflicting=" << two << '\n';
        return one && !two ? 0 : 1;
    }
    if (mode == "threads") {
        EndorseAntiEquivGuard g;
        g.load(path);
        std::atomic<int> accepted_a{0}, accepted_b{0};
        std::vector<std::thread> threads;
        for (int i = 0; i < 16; ++i)
            threads.emplace_back([&, i] {
                if (g.record(key, i % 2 ? a : b))
                    ++(i % 2 ? accepted_a : accepted_b);
            });
        for (auto& t : threads)
            t.join();
        return (accepted_a == 8 && accepted_b == 0) || (accepted_b == 8 && accepted_a == 0) ? 0 : 1;
    }
    if (mode == "malformed-input") {
        EndorseAntiEquivGuard g;
        g.load(path);
        return !g.record("042:aa", a) && !g.record("42:AA", a) && !g.record("42:aa\n43:aa", a) &&
                       !g.record(key, "bad")
                   ? 0
                   : 1;
    }
    if (mode == "truncate-live") {
        EndorseAntiEquivGuard g;
        g.load(path);
        if (!g.record(key, a))
            return 1;
        std::error_code ec;
        std::filesystem::resize_file(path, 0, ec);
        // Windows refuses external writes while the live guard owns the file.
        if (ec)
            return g.record(key, a) && !g.record(key, b) ? 0 : 1;
        return !g.record(key, a) && !g.record("43:" + std::string(3904, 'a'), b) ? 0 : 1;
    }
    if (mode == "replace-live") {
        EndorseAntiEquivGuard g;
        g.load(path);
        if (!g.record(key, a))
            return 1;
        std::error_code ec;
        std::filesystem::rename(path, path + ".old", ec);
        if (ec)
            return g.record(key, a) && !g.record(key, b) ? 0 : 1;
        std::ofstream(path).close();
        return !g.record(key, a) && !g.record(key, b) ? 0 : 1;
    }
    return 2;
}
