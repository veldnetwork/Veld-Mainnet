#include "network/tor_transport.h"

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace veld;
namespace fs = std::filesystem;

namespace {

int g_checks = 0;
#define CHECK(condition)                                                                           \
    do {                                                                                           \
        ++g_checks;                                                                                \
        if (!(condition))                                                                          \
            throw std::runtime_error(std::string("check failed at line ") +                        \
                                     std::to_string(__LINE__) + ": " #condition);                  \
    } while (false)

enum class Scenario {
    Correct,
    WrongServerHash,
    MalformedProtocol,
    TrailingEmptyMethod,
    StopAfterProtocol,
    AuthenticateThenRejectOnion,
    ReplayedServerNonce,
};

std::string ReadLine(net::SocketHandle socket) {
    std::string line;
    char byte = 0;
    while (line.size() < 4096U) {
        const int count = static_cast<int>(::recv(socket, &byte, 1, 0));
        if (count != 1)
            return {};
        line.push_back(byte);
        if (line.size() >= 2U && line.substr(line.size() - 2U) == "\r\n")
            return line;
    }
    return {};
}

bool Send(net::SocketHandle socket, const std::string& value) {
    return net::_tor::SendAll(socket, value.data(), value.size());
}

std::array<uint8_t, 32> IndependentHmac(const char* key, const std::array<uint8_t, 32>& cookie,
                                        const std::array<uint8_t, 32>& client_nonce,
                                        const std::array<uint8_t, 32>& server_nonce) {
    std::array<uint8_t, 96> message{};
    std::copy(cookie.begin(), cookie.end(), message.begin());
    std::copy(client_nonce.begin(), client_nonce.end(), message.begin() + 32);
    std::copy(server_nonce.begin(), server_nonce.end(), message.begin() + 64);
    const auto result = wallet_crypto::HMAC_SHA256(
        reinterpret_cast<const uint8_t*>(key), std::strlen(key), message.data(), message.size());
    compat::SecureZero(message.data(), message.size());
    return result;
}

struct FakeResult {
    bool saw_protocol{false};
    bool saw_challenge{false};
    bool controller_hash_valid{false};
    bool saw_add_onion{false};
    std::string wire;
};

class FakeServer {
  public:
    FakeServer(Scenario scenario, const std::array<uint8_t, 32>& cookie,
               const std::array<uint8_t, 32>& server_nonce)
        : scenario_(scenario), cookie_(cookie), server_nonce_(server_nonce) {
        net::_tor::EnsureNet();
        listener_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (!compat::IsValidSocket(listener_))
            throw std::runtime_error("fake Tor socket failed");
        int reuse = 1;
        (void)::setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR,
                           reinterpret_cast<const char*>(&reuse), sizeof(reuse));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (::bind(listener_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(listener_, 1) != 0) {
            VELD_CLOSE_SOCKET(listener_);
            throw std::runtime_error("fake Tor bind/listen failed");
        }
        socklen_t length = sizeof(address);
        if (::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
            VELD_CLOSE_SOCKET(listener_);
            throw std::runtime_error("fake Tor getsockname failed");
        }
        port_ = ntohs(address.sin_port);
        worker_ = std::thread([this] { Serve(); });
    }

    FakeServer(const FakeServer&) = delete;
    FakeServer& operator=(const FakeServer&) = delete;
    ~FakeServer() {
        if (compat::IsValidSocket(listener_))
            VELD_CLOSE_SOCKET(listener_);
        if (worker_.joinable())
            worker_.join();
    }

    uint16_t port() const {
        return port_;
    }
    FakeResult Finish() {
        if (worker_.joinable())
            worker_.join();
        return result_;
    }

  private:
    void Serve() {
        sockaddr_in peer{};
        socklen_t peer_length = sizeof(peer);
        const net::SocketHandle client =
            ::accept(listener_, reinterpret_cast<sockaddr*>(&peer), &peer_length);
        VELD_CLOSE_SOCKET(listener_);
        listener_ = compat::kInvalidSocket;
        if (!compat::IsValidSocket(client))
            return;
        net::_tor::SetTimeouts(client, 8000);

        const std::string protocol = ReadLine(client);
        result_.wire += protocol;
        result_.saw_protocol = protocol == "PROTOCOLINFO 1\r\n";
        if (!result_.saw_protocol) {
            VELD_CLOSE_SOCKET(client);
            return;
        }
        if (scenario_ == Scenario::MalformedProtocol) {
            (void)Send(client, "250-PROTOCOLINFO 1\r\n"
                               "250-AUTH METHODS=SAFECOOKIEEVIL COOKIEFILE=\"/outside\"\r\n"
                               "250 OK\r\n");
            (void)ReadLine(client);
            VELD_CLOSE_SOCKET(client);
            return;
        }
        if (scenario_ == Scenario::TrailingEmptyMethod) {
            (void)Send(client, "250-PROTOCOLINFO 1\r\n"
                               "250-AUTH METHODS=SAFECOOKIE, "
                               "COOKIEFILE=\"/outside\"\r\n"
                               "250 OK\r\n");
            (void)ReadLine(client);
            VELD_CLOSE_SOCKET(client);
            return;
        }
        (void)Send(client, "250-PROTOCOLINFO 1\r\n"
                           "250-AUTH METHODS=COOKIE,SAFECOOKIE "
                           "COOKIEFILE=\"/arbitrary/outside/control_auth_cookie\"\r\n"
                           "250-VERSION Tor=\"0.4.8-test\"\r\n"
                           "250 OK\r\n");
        const std::string challenge = ReadLine(client);
        result_.wire += challenge;
        if (scenario_ == Scenario::StopAfterProtocol) {
            result_.saw_challenge = !challenge.empty();
            VELD_CLOSE_SOCKET(client);
            return;
        }
        static constexpr char challenge_prefix[] = "AUTHCHALLENGE SAFECOOKIE ";
        if (challenge.rfind(challenge_prefix, 0) != 0 ||
            challenge.size() != sizeof(challenge_prefix) - 1U + 64U + 2U) {
            VELD_CLOSE_SOCKET(client);
            return;
        }
        std::array<uint8_t, 32> client_nonce{};
        result_.saw_challenge = net::_tor::DecodeExactHex(
            challenge.substr(sizeof(challenge_prefix) - 1U, 64U), client_nonce);
        if (!result_.saw_challenge) {
            VELD_CLOSE_SOCKET(client);
            return;
        }
        static constexpr char server_key[] =
            "Tor safe cookie authentication server-to-controller hash";
        auto server_hash = IndependentHmac(server_key, cookie_, client_nonce, server_nonce_);
        if (scenario_ == Scenario::WrongServerHash)
            server_hash[0] ^= 0x80U;
        const std::string reply = "250 AUTHCHALLENGE SERVERHASH=" + net::_tor::Hex(server_hash) +
                                  " SERVERNONCE=" + net::_tor::Hex(server_nonce_) + "\r\n";
        (void)Send(client, reply);

        const std::string authenticate = ReadLine(client);
        result_.wire += authenticate;
        if (scenario_ == Scenario::WrongServerHash || scenario_ == Scenario::ReplayedServerNonce) {
            VELD_CLOSE_SOCKET(client);
            return;
        }
        static constexpr char authenticate_prefix[] = "AUTHENTICATE ";
        if (authenticate.rfind(authenticate_prefix, 0) != 0 ||
            authenticate.size() != sizeof(authenticate_prefix) - 1U + 64U + 2U) {
            VELD_CLOSE_SOCKET(client);
            return;
        }
        std::array<uint8_t, 32> supplied_controller_hash{};
        if (!net::_tor::DecodeExactHex(authenticate.substr(sizeof(authenticate_prefix) - 1U, 64U),
                                       supplied_controller_hash)) {
            VELD_CLOSE_SOCKET(client);
            return;
        }
        static constexpr char controller_key[] =
            "Tor safe cookie authentication controller-to-server hash";
        const auto expected_controller_hash =
            IndependentHmac(controller_key, cookie_, client_nonce, server_nonce_);
        result_.controller_hash_valid = compat::ConstantTimeEqual(supplied_controller_hash.data(),
                                                                  expected_controller_hash.data(),
                                                                  supplied_controller_hash.size());
        if (!result_.controller_hash_valid || !Send(client, "250 OK\r\n")) {
            VELD_CLOSE_SOCKET(client);
            return;
        }
        const std::string add_onion = ReadLine(client);
        result_.wire += add_onion;
        result_.saw_add_onion = add_onion.rfind("ADD_ONION ", 0) == 0;
        if (scenario_ == Scenario::AuthenticateThenRejectOnion) {
            (void)Send(client, "551 ADD_ONION refused\r\n");
        } else {
            (void)Send(client,
                       "250-ServiceID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
                       "250 OK\r\n");
        }
        VELD_CLOSE_SOCKET(client);
    }

    Scenario scenario_;
    std::array<uint8_t, 32> cookie_{};
    std::array<uint8_t, 32> server_nonce_{};
    net::SocketHandle listener_{compat::kInvalidSocket};
    uint16_t port_{0};
    std::thread worker_;
    FakeResult result_;
};

fs::path MakeCookieDirectory(const fs::path& base, const std::string& name,
                             const std::vector<uint8_t>& bytes) {
    const fs::path directory = base / name;
    std::string error;
    if (!channel::secure_file::EnsurePrivateDirectory(directory.string(), &error))
        throw std::runtime_error("private Tor test directory: " + error);
    if (!bytes.empty() && !channel::secure_file::AtomicWriteNew(
                              (directory / "control_auth_cookie").string(), bytes, &error, true))
        throw std::runtime_error("Tor test cookie: " + error);
    return directory;
}

bool RunStart(net::TorController& controller, FakeServer& server, const fs::path& directory) {
    return controller.Start(28333, directory.string(), "127.0.0.1", server.port());
}

#ifdef _WIN32
bool CreateDirectoryJunction(const fs::path& link, const fs::path& target) {
    // Exercise the real Windows mount-point/reparse boundary without relying
    // on Developer Mode or symbolic-link privileges.  The paths are generated
    // by this fixture beneath its private output directory and contain no
    // quotes.
    std::wstring command =
        L"cmd.exe /d /c mklink /J \"" + link.wstring() + L"\" \"" + target.wstring() + L"\" >NUL";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!::CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                          nullptr, nullptr, &startup, &process)) {
        return false;
    }
    const DWORD wait = ::WaitForSingleObject(process.hProcess, 30000);
    DWORD exit_code = MAXDWORD;
    const bool exited = wait == WAIT_OBJECT_0 && ::GetExitCodeProcess(process.hProcess, &exit_code);
    ::CloseHandle(process.hThread);
    ::CloseHandle(process.hProcess);
    return exited && exit_code == 0 && fs::is_directory(link);
}
#endif

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 2)
            throw std::runtime_error("usage: test PRIVATE_OUTPUT_DIRECTORY");
        const fs::path base = fs::absolute(argv[1]);
        CHECK(fs::is_directory(base));

        std::array<uint8_t, 32> cookie{};
        std::array<uint8_t, 32> server_nonce{};
        for (size_t i = 0; i < cookie.size(); ++i) {
            cookie[i] = static_cast<uint8_t>(i + 1U);
            server_nonce[i] = static_cast<uint8_t>(0xa0U + i);
        }
        const std::vector<uint8_t> cookie_bytes(cookie.begin(), cookie.end());
        const std::string raw_cookie_hex = net::_tor::Hex(cookie);

        const fs::path correct_dir = MakeCookieDirectory(base, "correct", cookie_bytes);
        net::TorController correct_controller;
        FakeServer correct_server(Scenario::Correct, cookie, server_nonce);
        CHECK(RunStart(correct_controller, correct_server, correct_dir));
        const FakeResult correct = correct_server.Finish();
        CHECK(correct.saw_protocol);
        CHECK(correct.saw_challenge);
        CHECK(correct.controller_hash_valid);
        CHECK(correct.saw_add_onion);
        CHECK(correct.wire.find(raw_cookie_hex) == std::string::npos);
        CHECK(correct_controller.Active());
        correct_controller.Stop();

        const fs::path short_dir =
            MakeCookieDirectory(base, "short", std::vector<uint8_t>(31U, 0x41U));
        net::TorController short_controller;
        FakeServer short_server(Scenario::StopAfterProtocol, cookie, server_nonce);
        CHECK(!RunStart(short_controller, short_server, short_dir));
        const FakeResult short_result = short_server.Finish();
        CHECK(short_result.saw_protocol);
        CHECK(!short_result.saw_challenge);

        net::TorController wrong_hash_controller;
        FakeServer wrong_hash_server(Scenario::WrongServerHash, cookie, server_nonce);
        CHECK(!RunStart(wrong_hash_controller, wrong_hash_server, correct_dir));
        const FakeResult wrong_hash = wrong_hash_server.Finish();
        CHECK(wrong_hash.saw_challenge);
        CHECK(wrong_hash.wire.find("AUTHENTICATE ") == std::string::npos);

        net::TorController malformed_controller;
        FakeServer malformed_server(Scenario::MalformedProtocol, cookie, server_nonce);
        CHECK(!RunStart(malformed_controller, malformed_server, correct_dir));
        const FakeResult malformed = malformed_server.Finish();
        CHECK(malformed.saw_protocol);
        CHECK(!malformed.saw_challenge);

        net::TorController trailing_method_controller;
        FakeServer trailing_method_server(Scenario::TrailingEmptyMethod, cookie, server_nonce);
        CHECK(!RunStart(trailing_method_controller, trailing_method_server, correct_dir));
        const FakeResult trailing_method = trailing_method_server.Finish();
        CHECK(trailing_method.saw_protocol);
        CHECK(!trailing_method.saw_challenge);

        // Prime one successful SAFECOOKIE exchange without activating an
        // onion, then prove reuse of the exact server nonce is rejected even
        // when the attacker recomputes a hash for the fresh client nonce.
        net::TorController replay_controller;
        FakeServer prime_server(Scenario::AuthenticateThenRejectOnion, cookie, server_nonce);
        CHECK(!RunStart(replay_controller, prime_server, correct_dir));
        const FakeResult prime = prime_server.Finish();
        CHECK(prime.controller_hash_valid);
        CHECK(prime.saw_add_onion);
        FakeServer replay_server(Scenario::ReplayedServerNonce, cookie, server_nonce);
        CHECK(!RunStart(replay_controller, replay_server, correct_dir));
        const FakeResult replay = replay_server.Finish();
        CHECK(replay.saw_challenge);
        CHECK(replay.wire.find("AUTHENTICATE ") == std::string::npos);

        const fs::path link_root = MakeCookieDirectory(base, "linked", {});
        const fs::path outside_root = MakeCookieDirectory(base, "outside", cookie_bytes);
        bool link_created = false;
#ifdef _WIN32
        link_created =
            ::CreateHardLinkW((link_root / "control_auth_cookie").c_str(),
                              (outside_root / "control_auth_cookie").c_str(), nullptr) != 0;
#else
        std::error_code link_error;
        fs::create_symlink(outside_root / "control_auth_cookie", link_root / "control_auth_cookie",
                           link_error);
        link_created = !link_error;
#endif
        CHECK(link_created);
        net::TorController link_controller;
        FakeServer link_server(Scenario::StopAfterProtocol, cookie, server_nonce);
        CHECK(!RunStart(link_controller, link_server, link_root));
        const FakeResult link_result = link_server.Finish();
        CHECK(link_result.saw_protocol);
        CHECK(!link_result.saw_challenge);

#ifdef _WIN32
        // A directory junction is a reparse component, not merely a hard-link
        // leaf.  Reject it before opening the trusted cookie beneath it.
        const fs::path junction_target = MakeCookieDirectory(base, "junction-target", cookie_bytes);
        const fs::path junction_root = base / "junction-root";
        CHECK(CreateDirectoryJunction(junction_root, junction_target));
        net::TorController junction_controller;
        FakeServer junction_server(Scenario::StopAfterProtocol, cookie, server_nonce);
        CHECK(!RunStart(junction_controller, junction_server, junction_root));
        const FakeResult junction_result = junction_server.Finish();
        CHECK(junction_result.saw_protocol);
        CHECK(!junction_result.saw_challenge);
        CHECK(::RemoveDirectoryW(junction_root.c_str()) != 0);
        CHECK(fs::exists(junction_target / "control_auth_cookie"));
#endif

#ifndef _WIN32
        const fs::path fifo_root = MakeCookieDirectory(base, "fifo", {});
        CHECK(::mkfifo((fifo_root / "control_auth_cookie").c_str(), 0600) == 0);
        net::TorController fifo_controller;
        FakeServer fifo_server(Scenario::StopAfterProtocol, cookie, server_nonce);
        const auto fifo_start = std::chrono::steady_clock::now();
        CHECK(!RunStart(fifo_controller, fifo_server, fifo_root));
        CHECK(std::chrono::steady_clock::now() - fifo_start < std::chrono::seconds(1));
        const FakeResult fifo_result = fifo_server.Finish();
        CHECK(fifo_result.saw_protocol);
        CHECK(!fifo_result.saw_challenge);
#endif

        std::cout << "PASS tor_safecookie_tests checks=" << g_checks << "\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL tor_safecookie_tests: " << error.what() << "\n";
        return 1;
    }
}
