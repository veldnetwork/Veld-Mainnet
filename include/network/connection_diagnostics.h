#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <ostream>
#include <string>
#include <vector>
#include <openssl/rand.h>

namespace veld::net::connection_diagnostics {

enum class Reason : uint8_t {
    Connected, Unspecified, RemoteEof, ReceiveError, SendError, SendTimeout,
    InvalidFrame, ReceiveLimit, HandshakeTimeout, IdleOrFrameTimeout,
    PolicyRejection, PollError, NodeStop
};

inline const char* Name(Reason reason) noexcept {
    switch (reason) {
    case Reason::Connected: return "connected";
    case Reason::RemoteEof: return "remote_eof";
    case Reason::ReceiveError: return "receive_error";
    case Reason::SendError: return "send_error";
    case Reason::SendTimeout: return "send_timeout";
    case Reason::InvalidFrame: return "invalid_frame";
    case Reason::ReceiveLimit: return "receive_limit";
    case Reason::HandshakeTimeout: return "handshake_timeout";
    case Reason::IdleOrFrameTimeout: return "idle_or_frame_timeout";
    case Reason::PolicyRejection: return "policy_rejection";
    case Reason::PollError: return "poll_error";
    case Reason::NodeStop: return "node_stop";
    default: return "unspecified";
    }
}

// IDs belong to one process session and connection, never an IP or wallet.
inline const std::string& Session() {
    static const std::string session = [] {
        std::array<unsigned char, 16> bytes{};
        if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
            return std::string("unknown-session");
        constexpr char hex[] = "0123456789abcdef";
        std::string out;
        for (auto byte : bytes) { out += hex[byte >> 4]; out += hex[byte & 15]; }
        return out;
    }();
    return session;
}
inline std::string Id(uint64_t connection) {
    return Session() + "-" + std::to_string(connection);
}

struct Event {
    uint64_t sequence{}, connection{}, sent{}, received{};
    int64_t timestamp{};
    Reason reason{Reason::Unspecified};
    bool inbound{};
};
inline constexpr size_t CAPACITY = 128;
struct Journal {
    std::mutex mutex;
    std::array<Event, CAPACITY> events{};
    uint64_t sequence{};
    std::atomic<uint64_t> failed{0};
};
inline Journal& State() { static Journal journal; return journal; }

// Socket paths record bounded data only. The node's status thread writes logs.
inline void Record(uint64_t connection, Reason reason, bool inbound,
                   uint64_t sent, uint64_t received) noexcept {
    auto& state = State();
    try {
        std::lock_guard<std::mutex> lock(state.mutex);
        const auto sequence = ++state.sequence;
        state.events[(sequence - 1) % CAPACITY] = {
            sequence, connection, sent, received,
            static_cast<int64_t>(std::time(nullptr)), reason, inbound};
    } catch (...) { state.failed.fetch_add(1, std::memory_order_relaxed); }
}

inline std::vector<Event> Since(uint64_t& cursor, uint64_t& lost) {
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mutex);
    const uint64_t first = state.sequence >= CAPACITY
        ? state.sequence - CAPACITY + 1 : 1;
    lost = cursor + 1 < first ? first - cursor - 1 : 0;
    std::vector<Event> result;
    for (uint64_t next = std::max(first, cursor + 1); next <= state.sequence; ++next)
        result.push_back(state.events[(next - 1) % CAPACITY]);
    cursor = state.sequence;
    return result;
}

inline void WritePending(std::ostream& out, uint64_t& cursor) {
    uint64_t lost = 0;
    const auto events = Since(cursor, lost);
    const auto failed = State().failed.exchange(0, std::memory_order_relaxed);
    if (lost || failed)
        out << "{\"event\":\"connection_diagnostics_lost\",\"overwritten\":"
            << lost << ",\"failed\":" << failed << "}\n";
    for (const auto& event : events)
        out << "{\"event\":\"connection\",\"connection_id\":\""
            << Id(event.connection) << "\",\"reason\":\"" << Name(event.reason)
            << "\",\"timestamp\":" << event.timestamp
            << ",\"inbound\":" << (event.inbound ? "true" : "false")
            << ",\"bytes_sent\":" << event.sent
            << ",\"bytes_received\":" << event.received << "}\n";
}

} // namespace veld::net::connection_diagnostics
