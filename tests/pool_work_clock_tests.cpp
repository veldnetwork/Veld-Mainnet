#include "pool/client_transport.h"
#include <iostream>
#include <barrier>
#include <mutex>
int main(int argc, char** argv) try {
    using namespace veld::pool;
    using Clock = std::chrono::steady_clock;
    Require(argc == 3, "loopback endpoint and temporary CA required");
    Require(std::string(argv[1]).rfind("https://127.0.0.1:", 0) == 0, "loopback only");
#ifdef _WIN32
    WSADATA data{};
    Require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Winsock");
#endif
    TlsClient client(argv[1], argv[2]);
    std::barrier gate(12);
    std::mutex output;
    std::atomic<bool> failed{false};
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < 12; ++i)
        workers.emplace_back([&, i] {
            try {
                gate.arrive_and_wait();
                const auto began = Clock::now();
                auto sent = began;
#ifdef VELD_TEST_LEGACY_JOB_CLOCK
                auto job = client.Call("work", "{}");
#else
                auto job = client.Call("work", "{}", &sent);
#endif
                const auto ended = Clock::now();
                const auto ttl = Number(Text(Field(job, "ttl_ms")), 10000);
                const auto expiry = sent + std::chrono::milliseconds(ttl);
                auto ms = [](auto elapsed) {
                    return std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
                };
                Require(sent >= began && sent <= ended, "send timestamp ordering");
                std::lock_guard lock(output);
                std::cout << "{\"worker\":" << i << ",\"before_send_ms\":" << ms(sent - began)
                          << ",\"request_response_ms\":" << ms(ended - sent)
                          << ",\"remaining_ms\":" << ms(expiry - ended) << "}\n";
            } catch (const std::exception& error) {
                std::lock_guard lock(output);
                std::cerr << error.what() << '\n';
                failed = true;
            }
        });
    for (auto& worker : workers)
        worker.join();
    return failed ? 1 : 0;
} catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
}
