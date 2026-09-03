#pragma once

#include "p2p.h"
#include "peer_state.h"
#include "../core/blockchain.h"
#include "../core/mempool.h"
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <queue>
#include <deque>
#include <list>
#include <condition_variable>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <sstream>
#include <ctime>
#include <chrono>
#include <climits>
#include <random>
#include <filesystem>
#include <new>
#include <optional>
#include <array>
#include <algorithm>
#ifndef _WIN32
#include <sys/ioctl.h>
#endif

namespace veld { namespace net {
inline std::atomic<bool> g_suppress_sync{false};
// Serializes console status output across threads. Multiple network threads
// emit "[sync] height=…" lines while the status thread emits the timestamped
// "[HH:MM:SS] height=…" line; without a shared lock their chained operator<<
// calls interleaved and garbled the console. PrintStatus() (veld-node.cpp)
// and the [sync] prints below all take this one mutex.
inline std::mutex g_stdout_mtx;
} }

#include "../compat/platform.h"
#include "nat_traversal.h"
#include "tor_transport.h"
#include "listener_activation_guard.h"
#include <fstream>
#include <iostream>
#include <iomanip>

namespace veld {
namespace net {

using veld::compat::MonotonicSeconds;
using SocketHandle = veld::compat::SocketHandle;

namespace _detail {
    inline std::atomic<uint64_t>& RecvInflightBytes() {
        static std::atomic<uint64_t> g{0};
        return g;
    }
    inline constexpr uint64_t G_RECV_INFLIGHT_CAP = 256ull * 1024ull * 1024ull;
    // The receive budget measures bytes that have actually arrived, never a
    // peer-controlled declared length.  A source-local ceiling prevents one
    // address (or one configured outbound hostname) from consuming the global
    // pool while still allowing one maximum-size canonical frame.
    inline constexpr uint64_t G_RECV_INFLIGHT_PER_SOURCE_CAP =
        32ull * 1024ull * 1024ull;
    inline std::mutex& RecvInflightMutex() {
        static std::mutex m;
        return m;
    }
    inline std::unordered_map<std::string, uint64_t>&
    RecvInflightBySource() {
        static std::unordered_map<std::string, uint64_t> by_source;
        return by_source;
    }
    inline std::atomic<uint64_t>& SendQueuedBytes() {
        static std::atomic<uint64_t> g{0};
        return g;
    }
    inline constexpr uint64_t G_SEND_QUEUED_CAP = 256ull * 1024ull * 1024ull;
    inline std::atomic<uint64_t>& SendQueuedFrames() {
        static std::atomic<uint64_t> g{0};
        return g;
    }
    inline constexpr uint64_t G_SEND_QUEUED_FRAME_CAP = 65'536;
}

class Connection {
public:
    static constexpr size_t RECV_BUFFER_SIZE = 1024 * 1024;
    static constexpr size_t MAX_MESSAGE_SIZE = 32 * 1024 * 1024;

    struct PayloadBounds {
        uint32_t minimum;
        uint32_t maximum;
    };

    // Structural wire envelopes, enforced immediately after the 24-byte
    // header in both blocking and event-loop parsers.  Unknown additive
    // commands retain a conservative compatibility allowance, but cannot use
    // the old generic 32-MiB body to force allocation/hash work.
    static PayloadBounds BoundsForCommand(const std::string& command) {
        if (command == MessageType::BLOCK)
            return {1, MAX_BLOCK_SIZE};
        if (command == MessageType::TX)
            return {1, static_cast<uint32_t>(Mempool::MAX_RELAY_TX_BYTES)};
        if (command == MessageType::VERSION)
            return {70, 325};  // fixed fields + uint8 user-agent
        if (command == MessageType::VERACK ||
            command == MessageType::GETADDR ||
            command == MessageType::MEMPOOL)
            return {0, 0};
        if (command == MessageType::PUNCHHELLO ||
            command == MessageType::GETPUNCH)
            // Admit the legacy empty frame far enough to capability-check and
            // ignore it. A v2-capable peer still has to pass the exact 16-byte
            // nonce parser in HandleProtocolMessage_.
            return {0, 16};
        if (command == MessageType::PING || command == MessageType::PONG)
            return {8, 8};
        if (command == MessageType::GETBLOCKS)
            return {69, 4 + 1 + 32 * 32 + 32};
        if (command == MessageType::INV || command == MessageType::GETDATA)
            return {2, 2 + 1000 * 36};
        if (command == MessageType::ADDR)
            return {1, 1 + 30 * 6};
        if (command == MessageType::REJECT)
            return {0, 256};
        if (command == MessageType::SOLUTION)
            return {74, 74};  // prev + height + nonce + len + P2PKH
        if (command == MessageType::COMINE)
            return {2063, 80 + 1 + 25 + 2 + 1952 + 2 + 3309};
        if (command == MessageType::TIPSIG)
            return {44, 44};
        if (command == MessageType::STATSIG)
            return {16, 16};
        if (command == MessageType::FINVOTE)
            return {static_cast<uint32_t>(P2P_FINALITY_VOTE_WIRE_BYTES),
                    static_cast<uint32_t>(P2P_FINALITY_VOTE_WIRE_BYTES)};
        if (command == MessageType::PUNCHREQ)
            return {1, 16 + 16 + 1 + 64};
        if (command == MessageType::PUNCHFWD)
            return {1, 16 + 1 + 64};
        if (command == MessageType::PUNCHLIST)
            return {1, 16 + 1 + 16 * (1 + 64 + 16)};
        if (command == MessageType::ONIONADV)
            return {1, 80};
        if (command == MessageType::SENDCMPCT)
            return {0, 16};
        if (command == MessageType::CMPCTBLOCK ||
            command == MessageType::BLOCKTXN)
            return {0, MAX_BLOCK_SIZE};
        if (command == MessageType::GETBLOCKTXN)
            return {0, 256 * 1024};
        return {0, 64 * 1024};
    }

    static bool DecodeCanonicalHeader(const uint8_t header[24],
                                      uint32_t expected_magic,
                                      std::string& command,
                                      uint32_t& payload_len) {
        const uint32_t magic = (uint32_t)header[0]
                             | ((uint32_t)header[1] << 8)
                             | ((uint32_t)header[2] << 16)
                             | ((uint32_t)header[3] << 24);
        if (magic != expected_magic) return false;

        command.clear();
        bool padding = false;
        for (size_t i = 4; i < 16; ++i) {
            const uint8_t c = header[i];
            if (c == 0) {
                padding = true;
                continue;
            }
            // Bitcoin-style canonical command field: printable ASCII followed
            // by zero padding only.  Reject embedded-NUL aliases and control
            // bytes so dispatch has exactly one byte representation.
            if (padding || c < 0x20 || c > 0x7e) return false;
            command.push_back(static_cast<char>(c));
        }
        if (command.empty()) return false;

        payload_len = (uint32_t)header[16]
                    | ((uint32_t)header[17] << 8)
                    | ((uint32_t)header[18] << 16)
                    | ((uint32_t)header[19] << 24);
        const PayloadBounds bounds = BoundsForCommand(command);
        return payload_len >= bounds.minimum &&
               payload_len <= bounds.maximum &&
               payload_len <= MAX_MESSAGE_SIZE;
    }

    explicit Connection(SocketHandle fd, const std::string& remote_addr, uint16_t remote_port, bool inbound = false)
        : identity_(NextIdentity_()), fd_(fd), remote_addr_(remote_addr), remote_port_(remote_port)
        , connected_(true), bytes_sent_(0), bytes_recv_(0), inbound_(inbound)
        , accepted_at_(std::chrono::steady_clock::now()), tip_received_(false) {}

    ~Connection() { Close(); }

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    static constexpr size_t EVENT_SEND_PER_CONNECTION_CAP =
        16ull * 1024ull * 1024ull;
    static constexpr size_t EVENT_SEND_PER_CONNECTION_FRAME_CAP = 4096;

    void EnableEventLoopIO() {
        event_loop_io_.store(true, std::memory_order_release);
    }

    bool EventLoopIOEnabled() const {
        return event_loop_io_.load(std::memory_order_acquire);
    }

    size_t QueuedSendBytes() const {
        std::lock_guard<std::mutex> lock(event_send_mutex_);
        return event_send_bytes_;
    }

    size_t QueuedSendFrames() const {
        std::lock_guard<std::mutex> lock(event_send_mutex_);
        return event_send_queue_.size();
    }

#ifdef VELD_TEST_HOOKS
    static uint64_t TestGlobalRecvInflightBytes() {
        return _detail::RecvInflightBytes().load(
            std::memory_order_acquire);
    }
    static uint64_t TestPerSourceRecvInflightBytes(
            const std::string& source) {
        std::lock_guard<std::mutex> lock(_detail::RecvInflightMutex());
        const auto& by_source = _detail::RecvInflightBySource();
        const auto found = by_source.find(source);
        return found == by_source.end() ? 0 : found->second;
    }
    bool TestReserveRecvInflightBytes(uint64_t bytes) {
        return ReserveRecvInflight_(bytes);
    }
    void TestAgeIncompleteFrame(uint32_t seconds) {
        recv_frame_started_at_.store(
            std::chrono::steady_clock::now() -
                std::chrono::seconds(seconds),
            std::memory_order_release);
    }
    static uint64_t TestGlobalQueuedSendFrames() {
        return _detail::SendQueuedFrames().load(std::memory_order_acquire);
    }
    static constexpr uint64_t TestGlobalQueuedSendFrameCap() {
        return _detail::G_SEND_QUEUED_FRAME_CAP;
    }
#endif

    bool HasPendingEventLoopSend() const {
        return QueuedSendBytes() != 0;
    }

    bool CanQueueEventLoopSend(size_t max_frame_bytes) const {
        if (!EventLoopIOEnabled())
            return connected_.load(std::memory_order_acquire);
        if (max_frame_bytes > EVENT_SEND_PER_CONNECTION_CAP ||
            max_frame_bytes > _detail::G_SEND_QUEUED_CAP) return false;
        std::lock_guard<std::mutex> lock(event_send_mutex_);
        if (!connected_.load(std::memory_order_acquire) ||
            event_send_bytes_ >
                EVENT_SEND_PER_CONNECTION_CAP - max_frame_bytes ||
            event_send_queue_.size() >=
                EVENT_SEND_PER_CONNECTION_FRAME_CAP) return false;
        const uint64_t global = _detail::SendQueuedBytes().load(
            std::memory_order_relaxed);
        const uint64_t global_frames = _detail::SendQueuedFrames().load(
            std::memory_order_relaxed);
        return global <= _detail::G_SEND_QUEUED_CAP - max_frame_bytes &&
               global_frames < _detail::G_SEND_QUEUED_FRAME_CAP;
    }

    // Drain at most `budget` bytes from complete queued frames.  Partial kernel
    // writes retain the exact front-frame offset; EAGAIN retains the queue and
    // returns success so POLLOUT can resume it later.  A fatal write closes the
    // connection and releases all remaining global queue accounting.
    bool FlushEventLoopSend(size_t budget) {
        if (!EventLoopIOEnabled()) return false;
        bool fatal = false;
        {
            std::unique_lock<std::mutex> qlock(event_send_mutex_);
            while (budget > 0 && !event_send_queue_.empty()) {
                if (!connected_.load(std::memory_order_acquire)) {
                    fatal = true;
                    break;
                }
                auto& front = event_send_queue_.front();
                if (event_send_offset_ >= front.size()) {
                    event_send_queue_.pop_front();
                    _detail::SendQueuedFrames().fetch_sub(
                        1, std::memory_order_relaxed);
                    event_send_offset_ = 0;
                    continue;
                }
                const size_t remaining = front.size() - event_send_offset_;
                const size_t want = std::min(remaining, budget);
                ssize_t sent = -1;
                {
                    std::shared_lock<std::shared_mutex> io_lock(fd_io_mutex_);
                    const SocketHandle fd = fd_.load(std::memory_order_acquire);
                    if (!connected_.load(std::memory_order_acquire) ||
                        !veld::compat::IsValidSocket(fd)) {
                        fatal = true;
                        break;
                    }
#ifdef _WIN32
                    if (!nonblocking_set_) {
                        u_long mode = 1;
                        if (::ioctlsocket((SOCKET)fd, FIONBIO, &mode) != 0) {
                            fatal = true;
                            break;
                        }
                        nonblocking_set_ = true;
                    }
                    sent = ::send(fd,
                        reinterpret_cast<const char*>(front.data()) +
                            event_send_offset_,
                        static_cast<int>(std::min<size_t>(want, INT_MAX)),
                        MSG_NOSIGNAL);
#else
                    sent = ::send(fd,
                        reinterpret_cast<const char*>(front.data()) +
                            event_send_offset_,
                        want, MSG_NOSIGNAL | MSG_DONTWAIT);
#endif
                }
                if (sent < 0) {
#ifdef _WIN32
                    const int err = WSAGetLastError();
                    if (err == WSAEWOULDBLOCK || err == WSAEINTR ||
                        err == WSAETIMEDOUT) {
                        break;
                    }
#else
                    if (errno == EAGAIN || errno == EWOULDBLOCK ||
                        errno == EINTR) {
                        break;
                    }
#endif
                    fatal = true;
                    break;
                }
                if (sent == 0) {
                    fatal = true;
                    break;
                }
                const size_t n = static_cast<size_t>(sent);
                event_send_offset_ += n;
                event_send_bytes_ -= n;
                _detail::SendQueuedBytes().fetch_sub(
                    n, std::memory_order_relaxed);
                bytes_sent_.fetch_add(n, std::memory_order_relaxed);
                budget -= n;
                if (event_send_offset_ == front.size()) {
                    event_send_queue_.pop_front();
                    _detail::SendQueuedFrames().fetch_sub(
                        1, std::memory_order_relaxed);
                    event_send_offset_ = 0;
                }
            }
        }
        if (fatal) {
            Close();
            return false;
        }
        return IsConnected();
    }

    bool Send(const std::vector<uint8_t>& data) {
        if (EventLoopIOEnabled()) return QueueEventLoopSend_(data);
        std::lock_guard<std::mutex> lock(send_mutex_);
        if (!connected_.load(std::memory_order_acquire)) return false;

        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);

        size_t total = 0;
        while (total < data.size()) {
            ssize_t sent = -1;
            {
                std::shared_lock<std::shared_mutex> io_lock(fd_io_mutex_);
                const SocketHandle fd = fd_.load(std::memory_order_acquire);
                if (!connected_.load(std::memory_order_acquire) ||
                    !veld::compat::IsValidSocket(fd))
                    return false;
                sent = ::send(fd, (const char*)data.data() + total,
                              data.size() - total, MSG_NOSIGNAL);
            }
            if (sent < 0) {
                bool retry = false;
#ifdef _WIN32
                int err = WSAGetLastError();
                retry = (err == WSAEWOULDBLOCK || err == WSAEINTR);
#else
                retry = (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
#endif
                if (retry) {
                    if (std::chrono::steady_clock::now() >= deadline) {
                        Close();
                        return false;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                Close();
                return false;
            }
            total += sent;
            bytes_sent_.fetch_add(sent, std::memory_order_relaxed);
        }
        return true;
    }

    bool Send(const P2PMessage& msg) {
        return Send(msg.Serialize());
    }

    bool TrySend(const std::vector<uint8_t>& data) {
        if (EventLoopIOEnabled()) return QueueEventLoopSend_(data);
        std::unique_lock<std::mutex> lock(send_mutex_, std::try_to_lock);
        if (!lock.owns_lock()) return false;
        ssize_t sent = -1;
        {
            std::shared_lock<std::shared_mutex> io_lock(fd_io_mutex_);
            const SocketHandle fd = fd_.load(std::memory_order_acquire);
            if (!connected_.load(std::memory_order_acquire) ||
                !veld::compat::IsValidSocket(fd))
                return false;
            sent = ::send(fd, (const char*)data.data(), data.size(), MSG_NOSIGNAL);
        }
        if (sent < 0) {
            return false;
        }
        if ((size_t)sent != data.size()) return false;

        bytes_sent_ += sent;
        return true;
    }

    bool TrySend(const P2PMessage& msg) {
        return TrySend(msg.Serialize());
    }

    bool RecvExact(uint8_t* buf, size_t n, int timeout_ms = 30000) {
        size_t total = 0;
        auto start = std::chrono::steady_clock::now();

        while (total < n) {
            if (!connected_.load(std::memory_order_acquire)) return false;
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > timeout_ms) return false;

            ssize_t received = -1;
            {
                std::shared_lock<std::shared_mutex> io_lock(fd_io_mutex_);
                const SocketHandle fd = fd_.load(std::memory_order_acquire);
                if (!connected_.load(std::memory_order_acquire) ||
                    !veld::compat::IsValidSocket(fd))
                    return false;
                received = ::recv(fd, (char*)buf + total, n - total, 0);
            }
            if (received == 0) { Close(); return false; }
            if (received < 0) {
#ifdef _WIN32
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK || err == WSAEINTR || err == WSAETIMEDOUT) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
#else
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
#endif
                Close();
                return false;
            }
            total += received;
            bytes_recv_.fetch_add(received, std::memory_order_relaxed);
            last_recv_at_.store(std::chrono::steady_clock::now(),
                                std::memory_order_release);
        }
        return true;
    }

    std::optional<P2PMessage> RecvMessage(uint32_t expected_magic) {
        uint8_t header[24];
        if (!RecvExact(header, 24, 5000)) {
            if (connected_) {
                P2PMessage timeout_msg(expected_magic, "", {});
                return timeout_msg;
            }
            return std::nullopt;
        }

        std::string command;
        uint32_t payload_len = 0;
        if (!DecodeCanonicalHeader(header, expected_magic,
                                   command, payload_len))
            return std::nullopt;

        std::vector<uint8_t> payload;
        struct InflightGuard {
            Connection* connection;
            ~InflightGuard() {
                if (connection) connection->ReleaseRecvInflight_();
            }
        } guard{this};
        if (payload_len > 0) {
            recv_frame_started_at_.store(
                std::chrono::steady_clock::now(),
                std::memory_order_release);
            constexpr size_t CHUNK = 64 * 1024;
            payload.reserve(std::min<size_t>(payload_len, CHUNK));
            uint8_t buf[CHUNK];
            size_t remaining = payload_len;
            while (remaining > 0) {
                size_t want = std::min(remaining, CHUNK);
                if (!RecvExact(buf, want)) return std::nullopt;
                if (!ReserveRecvInflight_(want)) return std::nullopt;
                payload.insert(payload.end(), buf, buf + want);
                remaining -= want;
            }
        }

        Hash256 chk = Hash256d(payload);
        if (chk[0] != header[20] || chk[1] != header[21] ||
            chk[2] != header[22] || chk[3] != header[23])
            return std::nullopt;

        return P2PMessage(expected_magic, command, std::move(payload));
    }

    enum class RecvState : uint8_t {
        NeedHeader  = 0,
        NeedPayload = 1,
    };
    struct RecvBuffer {
        RecvState           state = RecvState::NeedHeader;
        std::vector<uint8_t> bytes;
        size_t              need  = 24;
        std::string         pending_command;
        uint32_t            pending_payload_len = 0;
        // Close() may run from the reaper while the event-loop worker is
        // between receiving a header and draining its declared payload.  The
        // reservation therefore has to be releasable from either thread,
        // exactly once.
        std::atomic<uint64_t> inflight_accounted{0};
    };
    enum class TryRecvStatus : uint8_t {
        WouldBlock   = 0,
        MessageReady = 1,
        Error        = 2,
    };
    struct TryRecvResult {
        TryRecvStatus status = TryRecvStatus::WouldBlock;
        P2PMessage    msg{0, "", {}};
    };
    TryRecvResult TryRecvMessage(uint32_t expected_magic) {
        TryRecvResult out;
        if (!connected_.load(std::memory_order_acquire)) {
            out.status = TryRecvStatus::Error;
            return out;
        }
        if (RecvFrameAssemblyExpired(std::chrono::steady_clock::now())) {
            Close();
            out.status = TryRecvStatus::Error;
            return out;
        }

        constexpr size_t DRAIN_CHUNK = 64 * 1024;
        uint8_t buf[DRAIN_CHUNK];
        size_t want = std::min<size_t>(DRAIN_CHUNK, rx_.need);
        if (want == 0) want = DRAIN_CHUNK;
        ssize_t got = -1;
        {
            std::shared_lock<std::shared_mutex> io_lock(fd_io_mutex_);
            const SocketHandle fd = fd_.load(std::memory_order_acquire);
            if (!connected_.load(std::memory_order_acquire) ||
                !veld::compat::IsValidSocket(fd)) {
                out.status = TryRecvStatus::Error;
                return out;
            }
#ifdef _WIN32
            if (!nonblocking_set_) {
                u_long mode = 1;
                ::ioctlsocket((SOCKET)fd, FIONBIO, &mode);
                nonblocking_set_ = true;
            }
            got = ::recv(fd, (char*)buf, (int)want, 0);
#else
            got = ::recv(fd, (char*)buf, want, MSG_DONTWAIT);
#endif
        }
        if (got == 0) {
            ReleaseRecvInflight_();
            Close();
            out.status = TryRecvStatus::Error;
            return out;
        }
        if (got < 0) {
            int err =
#ifdef _WIN32
                WSAGetLastError();
            bool wouldblock = (err == WSAEWOULDBLOCK || err == WSAEINTR ||
                               err == WSAETIMEDOUT);
#else
                errno;
            bool wouldblock = (err == EAGAIN || err == EWOULDBLOCK || err == EINTR);
#endif
            if (wouldblock) {
                out.status = TryRecvStatus::WouldBlock;
                return out;
            }
            ReleaseRecvInflight_();
            Close();
            out.status = TryRecvStatus::Error;
            return out;
        }
        // Begin the absolute frame deadline with the first byte. Starting only
        // after a complete header would let a peer trickle those 24 bytes and
        // retain a connection slot indefinitely without payload allocation.
        auto no_frame_started = std::chrono::steady_clock::time_point{};
        recv_frame_started_at_.compare_exchange_strong(
            no_frame_started, std::chrono::steady_clock::now(),
            std::memory_order_acq_rel, std::memory_order_acquire);
        // Charge only bytes that crossed the socket. A peer-controlled header
        // may declare a large legal payload, but that declaration consumes no
        // global memory and cannot evict an honest peer before the bytes arrive.
        if (rx_.state == RecvState::NeedPayload &&
            !ReserveRecvInflight_(static_cast<uint64_t>(got))) {
            Close();
            out.status = TryRecvStatus::Error;
            return out;
        }
        rx_.bytes.insert(rx_.bytes.end(), buf, buf + got);
        bytes_recv_.fetch_add(got, std::memory_order_relaxed);
        last_recv_at_.store(std::chrono::steady_clock::now(),
                            std::memory_order_release);
        if ((size_t)got <= rx_.need) {
            rx_.need -= got;
        } else {
            rx_.need = 0;
        }

        if (rx_.state == RecvState::NeedHeader && rx_.bytes.size() >= 24) {
            const uint8_t* h = rx_.bytes.data();
            std::string command;
            uint32_t payload_len = 0;
            if (!DecodeCanonicalHeader(h, expected_magic,
                                       command, payload_len)) {
                Close();
                out.status = TryRecvStatus::Error;
                return out;
            }
            rx_.pending_command     = std::move(command);
            rx_.pending_payload_len = payload_len;
            rx_.state               = RecvState::NeedPayload;
            rx_.need                = payload_len;
        }

        if (rx_.state == RecvState::NeedPayload &&
            rx_.bytes.size() >= 24 + (size_t)rx_.pending_payload_len) {
            std::vector<uint8_t> payload(
                rx_.bytes.begin() + 24,
                rx_.bytes.begin() + 24 + rx_.pending_payload_len);
            const uint8_t* h = rx_.bytes.data();
            Hash256 chk = Hash256d(payload);
            if (chk[0] != h[20] || chk[1] != h[21] ||
                chk[2] != h[22] || chk[3] != h[23]) {
                ReleaseRecvInflight_();
                Close();
                out.status = TryRecvStatus::Error;
                return out;
            }
            out.msg    = P2PMessage(expected_magic, rx_.pending_command,
                                    std::move(payload));
            out.status = TryRecvStatus::MessageReady;
            ReleaseRecvInflight_();
            rx_.bytes.clear();
            // std::vector::clear() does not release allocated capacity. After receiving
            // a 32 MB block (MAX_MESSAGE_SIZE), this Connection's rx_.bytes
            // permanently holds 32 MB capacity — multiplied by 50-200 peers
            // on a fleet host, that's GB of just retained buffers. Release
            // capacity if it's grown beyond a small steady-state threshold.
            // 64 KB threshold means typical small messages (INV, PING,
            // VERSION, GETDATA) don't trigger shrink (no churn cost), but
            // a one-time 32 MB BLOCK release the memory back to allocator.
            constexpr size_t RX_SHRINK_THRESHOLD = 64 * 1024;
            if (rx_.bytes.capacity() > RX_SHRINK_THRESHOLD) {
                std::vector<uint8_t>().swap(rx_.bytes);
            }
            rx_.state = RecvState::NeedHeader;
            rx_.need  = 24;
            rx_.pending_command.clear();
            rx_.pending_payload_len = 0;
            return out;
        }

        out.status = TryRecvStatus::WouldBlock;
        return out;
    }

    void Close() {
        bool expected = true;
        const bool was_connected = connected_.compare_exchange_strong(
                expected, false, std::memory_order_acq_rel);
        // Release even when another closer already flipped connected_.  This
        // also catches the narrow publish-after-close race documented in
        // TryRecvMessage().  exchange(0) makes repeated calls idempotent.
        ReleaseRecvInflight_();
        ReleaseQueuedSend_();
        if (!was_connected)
            return;
        const SocketHandle fd_for_shutdown = fd_.load(std::memory_order_acquire);
        if (veld::compat::IsValidSocket(fd_for_shutdown)) {
#ifdef _WIN32
            ::shutdown((SOCKET)fd_for_shutdown, SD_BOTH);
#else
            ::shutdown(fd_for_shutdown, SHUT_RDWR);
#endif
        }
        // shutdown wakes any blocking recv/send. Wait until every in-flight
        // syscall has left its shared section before closing, so the descriptor
        // cannot be recycled underneath an old reader.
        std::unique_lock<std::shared_mutex> io_lock(fd_io_mutex_);
        const SocketHandle fd = fd_.exchange(veld::compat::kInvalidSocket,
                                             std::memory_order_acq_rel);
        if (veld::compat::IsValidSocket(fd)) {
            VELD_CLOSE_SOCKET(fd);
        }
    }

    bool IsConnected() const {
        return connected_.load(std::memory_order_acquire) &&
               veld::compat::IsValidSocket(
                   fd_.load(std::memory_order_acquire));
    }
    SocketHandle Fd()        const { return fd_.load(std::memory_order_acquire); }
    uint64_t    Identity()   const { return identity_; }
    std::string RemoteAddr() const { return remote_addr_; }
    uint16_t    RemotePort() const { return remote_port_; }
    uint64_t    BytesSent()  const { return bytes_sent_; }
    uint64_t    BytesRecv()  const { return bytes_recv_; }
    bool        IsInbound()  const { return inbound_; }

    std::chrono::steady_clock::time_point AcceptedAt() const { return accepted_at_; }
    bool TipReceived() const { return tip_received_.load(std::memory_order_acquire); }
    void MarkTipReceived() { tip_received_.store(true, std::memory_order_release); }

    bool VersionReceived() const { return version_received_.load(std::memory_order_acquire); }
    void MarkVersionReceived() { version_received_.store(true, std::memory_order_release); }
    bool HandshakeReady() const { return handshake_ready_.load(std::memory_order_acquire); }
    void MarkHandshakeReady() { handshake_ready_.store(true, std::memory_order_release); }
    uint64_t AdvertisedServices() const {
        return advertised_services_.load(std::memory_order_acquire);
    }
    void MarkAdvertisedServices(uint64_t services) {
        advertised_services_.store(services, std::memory_order_release);
    }

    uint64_t PeerNonce() const { return peer_nonce_.load(std::memory_order_acquire); }
    void MarkPeerNonce(uint64_t nonce) {
        peer_nonce_.store(nonce, std::memory_order_release);
    }

    // Bytes waiting in the kernel receive queue.  This is deliberately distinct
    // from BytesRecv(): the latter advances only after an application worker has
    // drained the socket.  Under CPU pressure a legitimate VERSION can already
    // be queued even though the protocol worker has not run yet; treating that
    // connection as a zero-byte slow-recv attacker caused the fleet churn loop.
    uint64_t PendingRecvBytes() const {
        std::shared_lock<std::shared_mutex> io_lock(fd_io_mutex_);
        const SocketHandle fd = fd_.load(std::memory_order_acquire);
        if (!connected_.load(std::memory_order_acquire) ||
            !veld::compat::IsValidSocket(fd)) return 0;
#ifdef _WIN32
        u_long pending = 0;
        if (::ioctlsocket((SOCKET)fd, FIONREAD, &pending) != 0) return 0;
        return (uint64_t)pending;
#else
        int pending = 0;
        if (::ioctl(fd, FIONREAD, &pending) != 0 || pending <= 0) return 0;
        return (uint64_t)pending;
#endif
    }
    bool HasHandshakeProgress() const {
        return BytesRecv() > 0 || PendingRecvBytes() > 0;
    }

    std::chrono::steady_clock::time_point LastRecvAt() const {
        return last_recv_at_.load(std::memory_order_acquire);
    }
    static constexpr uint32_t RECV_FRAME_ASSEMBLY_TIMEOUT_SECONDS = 120;
    bool RecvFrameAssemblyExpired(
            std::chrono::steady_clock::time_point now) const {
        const auto started = recv_frame_started_at_.load(
            std::memory_order_acquire);
        return started != std::chrono::steady_clock::time_point{} &&
               now >= started &&
               std::chrono::duration_cast<std::chrono::seconds>(
                   now - started).count() >=
                   static_cast<long long>(
                       RECV_FRAME_ASSEMBLY_TIMEOUT_SECONDS);
    }
    void MarkRecvNow() {
        last_recv_at_.store(std::chrono::steady_clock::now(),
                            std::memory_order_release);
    }

    uint64_t addr_dial_window_start = 0;
    uint32_t addr_dial_count = 0;
    uint64_t mempool_budget_window = 0;
    uint64_t mempool_budget_used   = 0;

private:
    static uint64_t NextIdentity_() {
        static std::atomic<uint64_t> next{1};
        uint64_t id = next.fetch_add(1, std::memory_order_relaxed);
        if (id == 0) id = next.fetch_add(1, std::memory_order_relaxed);
        return id;
    }

    bool QueueEventLoopSend_(const std::vector<uint8_t>& data) {
        if (data.empty()) return true;
        if (data.size() > EVENT_SEND_PER_CONNECTION_CAP ||
            data.size() > _detail::G_SEND_QUEUED_CAP)
            return false;
        std::lock_guard<std::mutex> lock(event_send_mutex_);
        if (!connected_.load(std::memory_order_acquire) ||
            !EventLoopIOEnabled() ||
            event_send_bytes_ > EVENT_SEND_PER_CONNECTION_CAP - data.size() ||
            event_send_queue_.size() >=
                EVENT_SEND_PER_CONNECTION_FRAME_CAP)
            return false;
        const uint64_t n = static_cast<uint64_t>(data.size());
        const uint64_t prior = _detail::SendQueuedBytes().fetch_add(
            n, std::memory_order_relaxed);
        if (prior > _detail::G_SEND_QUEUED_CAP - n) {
            _detail::SendQueuedBytes().fetch_sub(n, std::memory_order_relaxed);
            return false;
        }
        const uint64_t prior_frames = _detail::SendQueuedFrames().fetch_add(
            1, std::memory_order_relaxed);
        if (prior_frames >= _detail::G_SEND_QUEUED_FRAME_CAP) {
            _detail::SendQueuedFrames().fetch_sub(1,
                                                  std::memory_order_relaxed);
            _detail::SendQueuedBytes().fetch_sub(n,
                                                 std::memory_order_relaxed);
            return false;
        }
        try {
            event_send_queue_.push_back(data);
            event_send_bytes_ += data.size();
        } catch (...) {
            _detail::SendQueuedFrames().fetch_sub(1,
                                                  std::memory_order_relaxed);
            _detail::SendQueuedBytes().fetch_sub(n, std::memory_order_relaxed);
            return false;
        }
        return true;
    }

    void ReleaseQueuedSend_() {
        uint64_t remaining = 0;
        uint64_t remaining_frames = 0;
        {
            std::lock_guard<std::mutex> lock(event_send_mutex_);
            remaining = static_cast<uint64_t>(event_send_bytes_);
            remaining_frames = static_cast<uint64_t>(event_send_queue_.size());
            event_send_queue_.clear();
            event_send_offset_ = 0;
            event_send_bytes_ = 0;
        }
        if (remaining != 0) {
            _detail::SendQueuedBytes().fetch_sub(
                remaining, std::memory_order_relaxed);
        }
        if (remaining_frames != 0) {
            _detail::SendQueuedFrames().fetch_sub(
                remaining_frames, std::memory_order_relaxed);
        }
    }

    bool ReserveRecvInflight_(uint64_t bytes) {
        if (bytes == 0) return true;
        const std::string source = remote_addr_.empty()
            ? std::string("<unknown>") : remote_addr_;
        std::lock_guard<std::mutex> lock(_detail::RecvInflightMutex());
        if (!connected_.load(std::memory_order_acquire)) return false;
        const uint64_t total = _detail::RecvInflightBytes().load(
            std::memory_order_relaxed);
        auto& by_source = _detail::RecvInflightBySource();
        const auto found = by_source.find(source);
        const uint64_t source_total = found == by_source.end()
            ? 0 : found->second;
        if (bytes > _detail::G_RECV_INFLIGHT_CAP -
                        std::min(total, _detail::G_RECV_INFLIGHT_CAP) ||
            bytes > _detail::G_RECV_INFLIGHT_PER_SOURCE_CAP -
                        std::min(source_total,
                            _detail::G_RECV_INFLIGHT_PER_SOURCE_CAP))
            return false;
        try {
            if (found == by_source.end()) by_source.emplace(source, bytes);
            else found->second += bytes;
        } catch (...) {
            return false;
        }
        _detail::RecvInflightBytes().store(
            total + bytes, std::memory_order_relaxed);
        rx_.inflight_accounted.fetch_add(bytes,
                                          std::memory_order_relaxed);
        return true;
    }

    void ReleaseRecvInflight_() {
        const std::string source = remote_addr_.empty()
            ? std::string("<unknown>") : remote_addr_;
        std::lock_guard<std::mutex> lock(_detail::RecvInflightMutex());
        const uint64_t accounted = rx_.inflight_accounted.exchange(
            0, std::memory_order_acq_rel);
        if (accounted != 0) {
            const uint64_t total = _detail::RecvInflightBytes().load(
                std::memory_order_relaxed);
            _detail::RecvInflightBytes().store(
                total >= accounted ? total - accounted : 0,
                std::memory_order_relaxed);
            auto& by_source = _detail::RecvInflightBySource();
            auto found = by_source.find(source);
            if (found != by_source.end()) {
                if (found->second > accounted) found->second -= accounted;
                else by_source.erase(found);
            }
        }
        recv_frame_started_at_.store(
            std::chrono::steady_clock::time_point{},
            std::memory_order_release);
    }

    const uint64_t identity_;
    std::atomic<SocketHandle> fd_;
    std::string remote_addr_;
    uint16_t    remote_port_;
    std::atomic<bool> connected_;
    std::atomic<uint64_t> bytes_sent_;
    std::atomic<uint64_t> bytes_recv_;
    bool        inbound_ = false;
    std::mutex  send_mutex_;
    std::atomic<bool> event_loop_io_{false};
    mutable std::mutex event_send_mutex_;
    std::deque<std::vector<uint8_t>> event_send_queue_;
    size_t event_send_offset_{0};
    size_t event_send_bytes_{0};
    mutable std::shared_mutex fd_io_mutex_;
    std::chrono::steady_clock::time_point accepted_at_;
    std::atomic<bool> tip_received_;
    std::atomic<bool> version_received_{false};
    std::atomic<bool> handshake_ready_{false};
    std::atomic<uint64_t> peer_nonce_{0};
    std::atomic<uint64_t> advertised_services_{0};
    std::atomic<std::chrono::steady_clock::time_point> last_recv_at_{
        std::chrono::steady_clock::now()};
    std::atomic<std::chrono::steady_clock::time_point>
        recv_frame_started_at_{std::chrono::steady_clock::time_point{}};
    RecvBuffer rx_;
#ifdef _WIN32
    bool nonblocking_set_ = false;
#endif
};

class NodeServer {
public:
    // Peer-derived work-safety state is published through one pre-mutation
    // sequencer.  VeldNode's callback closes new work admission and returns an
    // opaque permit which retains Blockchain's consensus-transition guard until
    // the TCP mutation is fully visible.  The permit is deliberately opaque so
    // this transport layer cannot manufacture or inspect node authority.
    using PeerWorkViewTransitionPermit = std::shared_ptr<void>;
    using PeerWorkViewTransitionFn =
        std::function<PeerWorkViewTransitionPermit()>;

private:
    class PeerWorkViewWriteGuard_ {
    public:
        explicit PeerWorkViewWriteGuard_(NodeServer& owner) noexcept
            : owner_(owner), writer_lock_(owner.peer_work_view_writer_mutex_) {
            // Announce close-first intent while the old even generation remains
            // readable to an exact predecessor token/lease. Ordinary work sees
            // write_pending and fails closed; no peer-derived byte has changed.
            owner_.peer_work_view_write_pending_.store(
                true, std::memory_order_release);
            PeerWorkViewTransitionFn transition;
            {
                std::lock_guard<std::mutex> lock(
                    owner_.peer_work_view_transition_mutex_);
                transition = owner_.peer_work_view_transition_fn_;
            }
            callback_required_ = static_cast<bool>(transition);
            if (transition) {
                try {
                    transition_permit_ = transition();
                } catch (...) {
                    transition_permit_.reset();
                }
                if (!transition_permit_) {
                    owner_.peer_work_view_sequencer_failed_.store(
                        true, std::memory_order_release);
                }
            }
            if (!callback_required_ || transition_permit_) {
                owner_.peer_work_view_generation_.fetch_add(
                    1, std::memory_order_acq_rel);  // odd: mutation may publish
                generation_odd_ = true;
            }
        }

        PeerWorkViewWriteGuard_(const PeerWorkViewWriteGuard_&) = delete;
        PeerWorkViewWriteGuard_& operator=(
            const PeerWorkViewWriteGuard_&) = delete;

        ~PeerWorkViewWriteGuard_() noexcept {
            if (generation_odd_) {
                owner_.peer_work_view_generation_.fetch_add(
                    1, std::memory_order_release);  // even: fully published
            }
            // The node permit's destructor bumps its binding generation before
            // releasing the consensus-transition guard.  Publish the TCP even
            // generation first so the next guarded reader sees one coherent
            // post-mutation tuple.
            transition_permit_.reset();
            owner_.peer_work_view_write_pending_.store(
                false, std::memory_order_release);
        }

        bool MayPublish() const noexcept {
            return !callback_required_ || static_cast<bool>(transition_permit_);
        }

    private:
        NodeServer& owner_;
        std::unique_lock<std::mutex> writer_lock_;
        bool callback_required_{false};
        bool generation_odd_{false};
        PeerWorkViewTransitionPermit transition_permit_;
    };

public:
    enum class IngestEnqueueResult : uint8_t {
        Queued,
        Duplicate,
        Full,
    };

    // FINVOTE is off-chain gossip.  These results control only local relay,
    // duplicate caching and peer scoring; they do not participate in block or
    // finality consensus.  In particular, only AcceptedNew is re-gossiped.
    enum class FinalityVoteVerifyResult : uint8_t {
        AcceptedNew,
        AlreadyKnown,
        // Authenticated and retained solely for equivocation detection.  It is
        // duplicate-cached like a completed candidate but never relayed.
        EvidenceOnly,
        InvalidSignature,
        RejectedState,
    };
    using FinalityVotePrecheck =
        std::function<bool(const std::vector<uint8_t>&)>;
    using FinalityVoteVerifier =
        std::function<FinalityVoteVerifyResult(const std::vector<uint8_t>&)>;

    // Never let remote post-quantum verification consume all logical CPUs.
    // The 3,398-member maximum honest burst drains in about 1.7 seconds at the
    // implementation's ~1 ms/verify estimate with two workers, while small
    // machines retain a core for socket service and block processing.
    static size_t FinalityCryptoWorkerCount(unsigned hardware_threads) {
        return hardware_threads <= 3 ? 1u : 2u;
    }

    // Ban-credit policy for the mempool results whose distinction is
    // security-critical. Missing parents and deferred local NMS work carry
    // zero credit; an intrinsically invalid transaction remains punishable.
    // Kept callable so the regression suite locks both sides of the policy.
    static uint32_t MempoolRejectBanScore(Mempool::AddResult result) {
        return result == Mempool::AddResult::INVALID ? 10u : 0u;
    }

    static bool PreferInboundForDuplicate(uint64_t local_nonce,
                                          uint64_t peer_nonce) {
        return local_nonce > peer_nonce;
    }

    static bool MarkMempoolInventoryRequestIfDue(
            PeerState& ps, PeerState::tp_t now) {
        static constexpr auto MIN_INTERVAL = std::chrono::seconds(30);
        if (ps.last_mempool_served != PeerState::tp_t{} &&
            now - ps.last_mempool_served < MIN_INTERVAL) {
            return false;
        }
        ps.last_mempool_served = now;
        return true;
    }
    NodeServer(uint16_t port, uint32_t magic, Blockchain& chain, Mempool& mempool)
        : port_(port), magic_(magic), chain_(chain), mempool_(mempool)
        , running_(false), listen_fd_(veld::compat::kInvalidSocket)
        , inbound_count_(0), outbound_count_(0)
        , max_inbound_connections_(::veld::MAX_PEER_CONNECTIONS) {}

    ~NodeServer() { Stop(); }

    void SetPeerWorkViewTransitionFn(PeerWorkViewTransitionFn fn) {
        // Wiring is a lifecycle operation and never occurs while holding a peer
        // registry/height mutex.  Serialize it with writers so a mutation uses
        // either the old complete contract or the new complete contract.
        std::lock_guard<std::mutex> writer_lock(peer_work_view_writer_mutex_);
        std::lock_guard<std::mutex> callback_lock(
            peer_work_view_transition_mutex_);
        peer_work_view_transition_fn_ = std::move(fn);
        peer_work_view_sequencer_wired_.store(
            static_cast<bool>(peer_work_view_transition_fn_),
            std::memory_order_release);
    }

    void SetAdvertisedServices(uint64_t services) {
        local_services_.store(services | MessageType::NODE_FULL |
                                  MessageType::NODE_HOLE_PUNCH |
                                  MessageType::REQUIRED_NETWORK_IDENTITY_SERVICES,
                              std::memory_order_release);
    }

    uint64_t TopologyId() const { return self_nonce_; }

    std::string TopologyRole() const {
        const uint64_t services =
            local_services_.load(std::memory_order_acquire);
        if ((services & MessageType::NODE_FLEET) != 0) return "fleet";
        if ((services & MessageType::NODE_VALIDATOR) != 0) return "validator";
        if ((services & MessageType::NODE_MINER) != 0) return "miner";
        return "node";
    }

    static std::string ClassifyPeerTopologyRole(bool configured_fleet,
                                                uint64_t services) {
        // Fleet identity is assigned by the local canonical anchor set.  A
        // remote service bit alone is not an identity claim: independent
        // node-only builds may share the mining-disabled binary profile.
        if (configured_fleet) return "fleet";
        if ((services & MessageType::NODE_VALIDATOR) != 0) return "validator";
        if ((services & MessageType::NODE_MINER) != 0) return "miner";
        return "node";
    }

    bool Start(const std::function<bool()>& activation_guard = {},
               bool accept_inbound = true) {
        activation_guard_refused_.store(false, std::memory_order_release);
        // Serialize the full listener/worker lifecycle.  Besides rejecting an
        // accidental double-Start, this prevents a concurrent Start from
        // repopulating worker vectors while Stop is still joining the previous
        // generation.
        std::unique_lock<std::mutex> lifecycle_lock(lifecycle_mutex_);
        if (running_.load(std::memory_order_acquire) ||
            veld::compat::IsValidSocket(listen_fd_) ||
            accept_thread_.joinable() || !el_accept_threads_.empty() ||
            !el_workers_.empty()) {
            std::cerr << "  [p2p-policy] refusing Start on an active NodeServer\n";
            return false;
        }
        background_sync_mode_ = !accept_inbound;
        // Production uses bounded event-loop workers by default.  The legacy
        // thread-per-peer mode remains available only to an explicitly
        // acknowledged nonrelease test; a production-semantics binary must
        // never let remote authenticated sockets pin one OS thread each.
        use_event_loop_ = true;
        const char* env_eloop = std::getenv("VELD_USE_EVENT_LOOP");
        if (env_eloop && env_eloop[0]) {
            if (std::strcmp(env_eloop, "1") == 0) {
                use_event_loop_ = true;
            } else if (std::strcmp(env_eloop, "0") == 0) {
#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_DSTATE_QUALIFICATION)
                std::cerr << "  [p2p-policy] VELD_USE_EVENT_LOOP=0 is forbidden "
                             "in a production-semantics build\n";
                return false;
#else
                const char* unsafe = std::getenv(
                    "VELD_ALLOW_UNSAFE_THREAD_PER_PEER");
                if (!unsafe || std::strcmp(unsafe, "1") != 0) {
                    std::cerr << "  [p2p-policy] thread-per-peer requires "
                                 "VELD_ALLOW_UNSAFE_THREAD_PER_PEER=1 in a "
                                 "nonrelease test build\n";
                    return false;
                }
                use_event_loop_ = false;
#endif
            } else {
                std::cerr << "  [p2p-policy] VELD_USE_EVENT_LOOP must be exactly 0 or 1\n";
                return false;
            }
        }

        const char* inbound_source = "compiled-safe-default";
        if (const char* cap = std::getenv("VELD_MAX_INBOUND_CONNECTIONS")) {
            if (!cap[0]) {
                std::cerr << "  [p2p-policy] VELD_MAX_INBOUND_CONNECTIONS is empty\n";
                return false;
            }
            uint64_t parsed = 0;
            for (const unsigned char c : std::string(cap)) {
                if (c < '0' || c > '9' ||
                    parsed > (MAX_INBOUND_CONNECTIONS_HARD - (c - '0')) / 10) {
                    std::cerr << "  [p2p-policy] invalid VELD_MAX_INBOUND_CONNECTIONS\n";
                    return false;
                }
                parsed = parsed * 10 + (c - '0');
            }
            if (parsed > MAX_INBOUND_CONNECTIONS_HARD) {
                std::cerr << "  [p2p-policy] VELD_MAX_INBOUND_CONNECTIONS exceeds hard cap "
                          << MAX_INBOUND_CONNECTIONS_HARD << "\n";
                return false;
            }
            max_inbound_connections_ = static_cast<uint32_t>(parsed);
            inbound_source = "operator-env";
        }
        if (veld::DiagVerbose().load()) {
            std::cerr << "  [p2p-policy] io="
                      << (use_event_loop_ ? "bounded-event-loop" : "UNSAFE-thread-per-peer")
                      << " max_inbound=" << max_inbound_connections_
                      << " (" << inbound_source << ")\n";
            std::cerr.flush();
        }

        for (int tries = 0; tries < 16 && self_nonce_ == 0; ++tries) {
            uint8_t buf[8] = {0};
            if (!veld::compat::SecureRandom(buf, sizeof(buf))) {
                continue;
            }
            uint64_t n = 0;
            for (int i = 0; i < 8; ++i) n |= ((uint64_t)buf[i]) << (i * 8);
            self_nonce_ = n;
        }
        if (self_nonce_ == 0) {
            uint64_t fallback = (uint64_t)std::hash<std::thread::id>{}(std::this_thread::get_id())
                              ^ (uint64_t)std::chrono::steady_clock::now()
                                    .time_since_epoch().count()
                              ^ (uint64_t)reinterpret_cast<uintptr_t>(this);
            if (fallback == 0) fallback = 0x5645'4c44'5f4e'4f4eULL;
            self_nonce_ = fallback;
            std::cerr << "  [warn] CSPRNG returned 0 16x; self_nonce derived from "
                      << "pid+monotonic clock (self-connect detection still active).\n";
            std::cerr.flush();
        }

        if (accept_inbound) {
            if (!ListenerActivationPermitted(activation_guard)) {
                activation_guard_refused_.store(true, std::memory_order_release);
                return false;
            }

            listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
            if (!veld::compat::IsValidSocket(listen_fd_)) return false;

            int opt = 1;
            ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
            ::setsockopt(listen_fd_, SOL_SOCKET, SO_KEEPALIVE, (const char*)&opt, sizeof(opt));

            struct sockaddr_in addr{};
            addr.sin_family      = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port        = htons(port_);

            if (::bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                VELD_CLOSE_SOCKET(listen_fd_);
                listen_fd_ = veld::compat::kInvalidSocket;
                return false;
            }

            // Re-enter the signed window immediately before and after listen().
            // A process resumed after a long setup/suspend must not activate from
            // an earlier caller-side check.
            if (!ListenerActivationPermitted(activation_guard)) {
                activation_guard_refused_.store(true, std::memory_order_release);
                VELD_CLOSE_SOCKET(listen_fd_);
                listen_fd_ = veld::compat::kInvalidSocket;
                return false;
            }
            if (::listen(listen_fd_, SOMAXCONN) < 0) {
                VELD_CLOSE_SOCKET(listen_fd_);
                listen_fd_ = veld::compat::kInvalidSocket;
                return false;
            }

            // Four acceptors share this listener. It must be non-blocking: after
            // poll wakes several acceptors, one can drain the backlog before the
            // others call accept(). A blocking listener would strand those extra
            // threads and make Stop depend on platform-specific shutdown behavior.
#ifdef _WIN32
            u_long listener_nonblocking = 1;
            if (::ioctlsocket((SOCKET)listen_fd_, FIONBIO,
                              &listener_nonblocking) != 0) {
                VELD_CLOSE_SOCKET(listen_fd_);
                listen_fd_ = veld::compat::kInvalidSocket;
                return false;
            }
#else
            const int listener_flags = ::fcntl(listen_fd_, F_GETFL, 0);
            if (listener_flags == -1 ||
                ::fcntl(listen_fd_, F_SETFL, listener_flags | O_NONBLOCK) == -1) {
                VELD_CLOSE_SOCKET(listen_fd_);
                listen_fd_ = veld::compat::kInvalidSocket;
                return false;
            }
#endif
            if (!ListenerActivationPermitted(activation_guard)) {
                activation_guard_refused_.store(true, std::memory_order_release);
                VELD_CLOSE_SOCKET(listen_fd_);
                listen_fd_ = veld::compat::kInvalidSocket;
                return false;
            }
        }

        running_.store(true, std::memory_order_release);
        if (!StartFinalityVoteWorkers_()) {
            running_.store(false, std::memory_order_release);
            VELD_CLOSE_SOCKET(listen_fd_);
            listen_fd_ = veld::compat::kInvalidSocket;
            std::cerr << "  [p2p-policy] unable to start bounded FINVOTE workers\n";
            return false;
        }

        try {
        if (use_event_loop_) {
            int n_workers = 2;
            constexpr int ACCEPT_THREAD_COUNT = 4;
            unsigned hw = std::thread::hardware_concurrency();
            if (hw > 0 && hw <= 2) n_workers = 1;
            const char* worker_source = "auto";
            if (const char* nw = std::getenv("VELD_EVENT_LOOP_WORKERS")) {
                int parsed = std::atoi(nw);
                if (parsed > 0 && parsed <= 64) {
                    n_workers = parsed;
                    worker_source = "env";
                }
            }
            if (veld::DiagVerbose().load()) {
                std::cerr << "  [event-loop] acceptors="
                          << (accept_inbound ? ACCEPT_THREAD_COUNT : 0)
                          << " workers=" << n_workers
                          << " source=" << worker_source
                          << " hw=" << hw
                          << " ingest_workers=1\n";
                std::cerr.flush();
            }

            {
                std::lock_guard<std::mutex> workers_lock(worker_registry_mutex_);
                el_workers_.clear();
                el_workers_.reserve((size_t)n_workers);
                for (int i = 0; i < n_workers; ++i) {
                    auto w = std::make_unique<EventLoopWorker>();
                    w->worker_id = i;
                    w->running.store(true, std::memory_order_release);
                    el_workers_.push_back(std::move(w));
                }
                for (auto& wp : el_workers_) {
                    EventLoopWorker* raw = wp.get();
                    raw->thread = std::thread(
                        &NodeServer::EventLoopWorkerThreadEntry_, this, raw);
                    if (ShouldInjectStartFailure_(1))
                        throw std::runtime_error(
                            "injected event-worker start failure");
                }
            }

            ingest_running_.store(true, std::memory_order_release);
            ingest_worker_thread_ = std::thread(
                &NodeServer::BlockIngestThreadEntry_, this);
            if (ShouldInjectStartFailure_(2))
                throw std::runtime_error("injected ingest-worker start failure");

            if (accept_inbound) {
                for (int ai = 0; ai < ACCEPT_THREAD_COUNT; ++ai) {
                    el_accept_threads_.emplace_back(
                        &NodeServer::AcceptThreadEntry_, this);
                    if (ai == 1 && ShouldInjectStartFailure_(3))
                        throw std::runtime_error(
                            "injected partial-acceptor start failure");
                }
            }
        } else if (accept_inbound) {
            accept_thread_ = std::thread(
                &NodeServer::LegacyAcceptThreadEntry_, this);
        }
        } catch (const std::exception& e) {
            std::cerr << "  [p2p-policy] Start worker creation failed: "
                      << e.what() << "\n";
            RollbackFailedStartLocked_();
            return false;
        } catch (...) {
            std::cerr << "  [p2p-policy] Start worker creation failed\n";
            RollbackFailedStartLocked_();
            return false;
        }
        return true;
    }

    bool ActivationGuardRefused() const noexcept {
        return activation_guard_refused_.load(std::memory_order_acquire);
    }

    // ---- Opt-in residential reachability (--reachable). Auto-maps the P2P
    //      port via NAT-PMP/PCP/UPnP when behind NAT; a strict no-op on a
    //      public IP (cloud/fleet). Call AFTER Start() — the listener is
    //      already up. Node-local, consensus-inert, P2P-wire-transparent
    //      (it talks to the router, never to peers). See nat_traversal.h. ----
    void EnablePortMapping() { port_mapper_.Start(port_); }
    bool PortMapped() const { return port_mapper_.Reachable(); }
    std::string MappedEndpoint() const {
        auto m = port_mapper_.Snapshot();
        return m.ok ? (m.external_ip + ":" + std::to_string(m.external_port)) : "";
    }

    // ---- NAT hole-punch (opt-in fallback when port mapping fails).
    //      Seed-side coordination handlers are always-on (additive, bounded);
    //      the client driver below runs only after EnableHolePunch() (set on
    //      --reachable) AND only while the node isn't already reachable via
    //      Call HolePunchTick() from a periodic loop (~30s). ----
    void EnableHolePunch() { hole_punch_enabled_.store(true); }

    // ---- Tor hidden-service reachability (--tor; needs a local Tor
    //      daemon). TorTick() (periodic) lazily creates the .onion and broadcasts
    //      it; Tor-capable peers then dial us via SOCKS5. Opt-in, default-off. ----
    void EnableTor(const std::string& tor_data_directory) {
        {
            std::lock_guard<std::mutex> lock(tor_data_directory_mu_);
            tor_data_directory_ = tor_data_directory;
        }
        tor_want_.store(true);
    }
    bool TorActive() const { return tor_.Active(); }
    // Tor-only mode (--tor-only): the launcher runs a fetched-and-pinned Tor with
    // a static v3 hidden service; the node reads its .onion from the HS hostname
    // file, routes EVERY outbound dial through Tor's SOCKS5 (zero clearnet IP
    // exposure), and advertises only the .onion. No control port needed.
    void EnableTorOnly(const std::string& onion_hostname) {
        { std::lock_guard<std::mutex> lk(tor_only_onion_mu_); tor_only_onion_ = onion_hostname; }
        tor_only_.store(true);
    }
    bool TorOnly() const { return tor_only_.load(); }
    std::string OnionAddress() const {
        { std::lock_guard<std::mutex> lk(tor_only_onion_mu_);
          if (!tor_only_onion_.empty()) return tor_only_onion_; }
        return tor_.OnionAddress();
    }
    void TorTick() {
        // Tor-only: the HS is launcher-managed, so just (re)broadcast our .onion
        // so peers can dial us. No control-port ADD_ONION dance.
        if (tor_only_.load()) {
            std::string onion;
            { std::lock_guard<std::mutex> lk(tor_only_onion_mu_); onion = tor_only_onion_; }
            if (onion.empty()) return;
            std::string adv = onion + ":" + std::to_string(port_);
            std::vector<uint8_t> p(adv.begin(), adv.end());
            BroadcastMessage(P2PMessage(magic_, MessageType::ONIONADV, std::move(p)));
            return;
        }
        if (!tor_want_.load()) return;
        if (!tor_.Active()) {
            std::string tor_data_directory;
            {
                std::lock_guard<std::mutex> lock(tor_data_directory_mu_);
                tor_data_directory = tor_data_directory_;
            }
            if (tor_data_directory.empty()) return;
            tor_.Start(port_, tor_data_directory);
            if (!tor_.Active()) return;
        }
        std::string onion = tor_.OnionAddress();
        if (onion.empty()) return;
        std::string adv = onion + ":" + std::to_string(port_);
        std::vector<uint8_t> p(adv.begin(), adv.end());
        BroadcastMessage(P2PMessage(magic_, MessageType::ONIONADV, std::move(p)));
    }
    void HolePunchTick() {
        if (!hole_punch_enabled_.load()) return;
        if (port_mapper_.Reachable()) return;          // already reachable; nothing to do
        std::shared_ptr<Connection> coordinator;
        {
            std::lock_guard<std::mutex> lk(peers_mutex_);
            for (auto& kv : peer_connections_) {
                if (kv.second && !kv.second->IsInbound() &&
                    HolePunchCapable_(*kv.second)) {
                    coordinator = kv.second;
                    break;
                }
            }
        }
        if (!coordinator) return;

        const uint64_t now = MonotonicSeconds();
        PunchNonce hello_nonce{};
        PunchNonce request_nonce{};
        bool have_hello = false;
        bool send_get = false;
        {
            std::lock_guard<std::mutex> lk(punch_client_mutex_);
            auto& state = punch_client_coordinators_[coordinator->Identity()];
            auto bound = state.connection.lock();
            if (bound.get() != coordinator.get()) {
                state = PunchClientCoordinator{};
                state.connection = coordinator;
                state.connection_id = coordinator->Identity();
            }
            if (!state.hello_live || state.hello_expires_at <= now) {
                PunchNonce fresh{};
                if (NewPunchNonce_(fresh)) {
                    state.hello_nonce = fresh;
                    state.hello_expires_at = now + 600;
                    state.hello_live = true;
                }
            }
            if (state.hello_live) {
                hello_nonce = state.hello_nonce;
                have_hello = true;
            }
            if (!state.request_live || state.request_expires_at <= now) {
                PunchNonce fresh{};
                if (NewPunchNonce_(fresh)) {
                    state.request_nonce = fresh;
                    state.request_expires_at = now + 90;
                    state.request_live = true;
                    request_nonce = fresh;
                    send_get = true;
                }
            }
        }

        if (have_hello) {
            std::vector<uint8_t> payload;
            payload.reserve(hello_nonce.size());
            AppendPunchNonce_(payload, hello_nonce);
            coordinator->TrySend(P2PMessage(
                magic_, MessageType::PUNCHHELLO, std::move(payload)).Serialize());
        }
        if (send_get) {
            std::vector<uint8_t> payload;
            payload.reserve(request_nonce.size());
            AppendPunchNonce_(payload, request_nonce);
            coordinator->TrySend(P2PMessage(
                magic_, MessageType::GETPUNCH, std::move(payload)).Serialize());
        }

        std::vector<PunchCandidate> candidates;
        {
            std::lock_guard<std::mutex> lk(punch_client_mutex_);
            while (!punch_candidates_.empty() && candidates.size() < 3) {
                PunchCandidate candidate = std::move(punch_candidates_.front());
                punch_candidates_.pop_front();
                if (candidate.expires_at > now)
                    candidates.push_back(std::move(candidate));
            }
        }
        for (auto& candidate : candidates) {
            auto seed = candidate.coordinator.lock();
            if (!seed || seed->Identity() != candidate.coordinator_connection_id ||
                !HolePunchCapable_(*seed) || !TakePunchDialBudget_()) {
                continue;
            }
            std::string ip;
            uint16_t port = 0;
            if (!ParsePublicIPv4Endpoint(candidate.endpoint, ip, port) ||
                candidate.endpoint.size() > 64) {
                continue;
            }
            std::vector<uint8_t> payload;
            payload.reserve(16 + 16 + 1 + candidate.endpoint.size());
            AppendPunchNonce_(payload, candidate.request_nonce);
            AppendPunchNonce_(payload, candidate.target_nonce);
            payload.push_back(static_cast<uint8_t>(candidate.endpoint.size()));
            payload.insert(payload.end(), candidate.endpoint.begin(),
                           candidate.endpoint.end());
            if (seed->TrySend(P2PMessage(
                    magic_, MessageType::PUNCHREQ, std::move(payload)).Serialize())) {
                SpawnPunchDial_(ip, port);
            }
        }
    }

    void Stop() {
        std::unique_lock<std::mutex> lifecycle_lock(lifecycle_mutex_);
        {
            // Admission and the lifecycle transition share the registry lock,
            // giving a strict boundary: a connection is either fully registered
            // before shutdown's snapshot or observes running=false and rejects.
            std::lock_guard<std::mutex> registry_lock(peers_mutex_);
            running_.store(false, std::memory_order_release);
        }
        // Close asynchronous crypto admission at the same lifecycle boundary
        // as socket admission. Existing in-flight verification is bounded and
        // joined below; queued attacker work is cancelled rather than making
        // shutdown drain it.
        SignalFinalityVoteStop_();
        port_mapper_.Stop();
        // Wake listener polls first, but do not close or rewrite listen_fd_
        // while accept threads can still read it.  The former close + `=-1`
        // raced their poll/accept setup (TSan) and closing early also permits
        // the OS to recycle the descriptor number under a still-running reader.
        // All listener polls are bounded (<=250 ms), so join then close.
        const SocketHandle listener_fd = listen_fd_;
        if (veld::compat::IsValidSocket(listener_fd)) {
#ifdef _WIN32
            ::shutdown((SOCKET)listener_fd, SD_BOTH);
#else
            ::shutdown(listener_fd, SHUT_RDWR);
#endif
        }
        if (accept_thread_.joinable())
            accept_thread_.join();

        for (auto& at : el_accept_threads_)
            if (at.joinable()) at.join();
        el_accept_threads_.clear();
        if (veld::compat::IsValidSocket(listener_fd)) {
            VELD_CLOSE_SOCKET(listener_fd);
            listen_fd_ = veld::compat::kInvalidSocket;
        }

        // Closing every registered socket first releases legacy blocking peer
        // handlers.  Then quiesce all tracked producers/dialers before touching
        // el_workers_: a dial that completed during shutdown used to hand off
        // through a vector that Stop had already cleared.
        std::vector<std::shared_ptr<Connection>> to_close;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (auto& [key, conn] : peer_connections_) to_close.push_back(conn);
        }
        for (auto& c : to_close) if (c) c->Close();
        for (auto& c : to_close) CleanupConnectionState_(c);

        std::vector<PeerThreadSlot> drained;
        {
            std::lock_guard<std::mutex> tl(peer_threads_mutex_);
            drained.swap(peer_threads_);
        }
        for (auto& slot : drained) if (slot.t.joinable()) slot.t.join();

        // Public ConnectTo callers may be owned by a node watchdog rather than
        // peer_threads_.  Their leases reject new work after running=false and
        // release on every return path.  Quiesce them exactly before destroying
        // worker/registry state; resetting the counter would underflow a later
        // lease destructor and still leave a use-after-free window.
        {
            std::unique_lock<std::mutex> dial_lock(pending_dial_mutex_);
            pending_dial_cv_.wait(dial_lock, [&] {
                return pending_dials_.load(std::memory_order_acquire) == 0;
            });
        }

        {
            std::lock_guard<std::mutex> workers_lock(worker_registry_mutex_);
            for (auto& wp : el_workers_) {
                if (wp) wp->running.store(false, std::memory_order_release);
            }
        }
        for (auto& wp : el_workers_) {
            if (wp && wp->thread.joinable()) wp->thread.join();
        }
        {
            std::lock_guard<std::mutex> workers_lock(worker_registry_mutex_);
            el_workers_.clear();
        }
        // Every socket/event-loop producer is now quiescent. Join the
        // prefilter/verifiers before the callback owner (VeldNode) can begin
        // destruction, then erase all queue/hash/source reservations so a
        // Start -> Stop -> Start cycle is a clean generation.
        JoinFinalityVoteWorkers_();
        if (ingest_running_.load(std::memory_order_acquire)) {
            ingest_running_.store(false, std::memory_order_release);
            ingest_cv_.notify_all();
            if (ingest_worker_thread_.joinable())
                ingest_worker_thread_.join();
        }
        {
            // Stop may leave queued (not in-flight) jobs after the worker exits.
            // Release every byte/count/hash/source reservation so a subsequent
            // Start in the same process begins from a clean admission state.
            std::lock_guard<std::mutex> lk(ingest_mtx_);
            ClearBlockIngestStateLocked_();
        }

        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            peer_connections_.clear();
            peer_states_.clear();
            // Every accept/worker/legacy handler and producer is joined above.
            // Reset exact registry-derived counters so a Stop()/Start() cycle
            // cannot inherit phantom capacity.
            inbound_count_.store(0, std::memory_order_release);
            outbound_count_.store(0, std::memory_order_release);
        }
        ClearVolatileRuntimeState_(/*persist_dirty_bans=*/true);
    }

    // Return true only for a canonical, globally-routable IPv4 literal.  Peer
    // advertisements and NAT coordination are untrusted network inputs: they
    // must never turn the node into a loopback/LAN/cloud-metadata port scanner.
    // Operator-supplied --connect/seed targets still use ConnectTo directly and
    // may intentionally name private infrastructure.
    static bool IsPublicRoutableIPv4(const std::string& ip) {
        struct in_addr parsed{};
        if (::inet_pton(AF_INET, ip.c_str(), &parsed) != 1) return false;
        const uint32_t value = ntohl(parsed.s_addr);
        const uint8_t a = static_cast<uint8_t>(value >> 24);
        const uint8_t b = static_cast<uint8_t>(value >> 16);
        const uint8_t c = static_cast<uint8_t>(value >> 8);

        if (a == 0 || a == 10 || a == 127 || a >= 224) return false;
        if (a == 100 && b >= 64 && b <= 127) return false;       // RFC 6598
        if (a == 169 && b == 254) return false;                  // link-local
        if (a == 172 && b >= 16 && b <= 31) return false;
        if (a == 192 && b == 168) return false;
        if (a == 192 && b == 0 && c == 0) return false;          // IETF protocol
        if (a == 192 && b == 0 && c == 2) return false;          // TEST-NET-1
        if (a == 192 && b == 88 && c == 99) return false;        // deprecated 6to4
        if (a == 198 && (b == 18 || b == 19)) return false;      // benchmark
        if (a == 198 && b == 51 && c == 100) return false;       // TEST-NET-2
        if (a == 203 && b == 0 && c == 113) return false;        // TEST-NET-3
        return true;
    }

    // Operator clock anchors are identities, not DNS names.  Require the one
    // canonical dotted-decimal spelling so a hostname rotation, alternate
    // textual IPv4 form, or resolver disagreement can never silently change
    // the authoritative set. Private/loopback literals remain available for
    // explicitly configured lab/fleet networks.
    static bool IsCanonicalIPv4Literal(const std::string& ip) {
        struct in_addr parsed{};
        if (::inet_pton(AF_INET, ip.c_str(), &parsed) != 1) return false;
        char canonical[INET_ADDRSTRLEN] = {0};
        if (!::inet_ntop(AF_INET, &parsed, canonical, sizeof(canonical)))
            return false;
        return ip == canonical && ip != "0.0.0.0" &&
               ip != "255.255.255.255";
    }

    static bool ParsePublicIPv4Endpoint(const std::string& endpoint,
                                        std::string& ip_out,
                                        uint16_t& port_out) {
        const size_t colon = endpoint.find(':');
        if (colon == std::string::npos || colon == 0 ||
            colon != endpoint.rfind(':') || colon + 1 >= endpoint.size())
            return false;
        const std::string ip = endpoint.substr(0, colon);
        if (!IsPublicRoutableIPv4(ip)) return false;
        uint32_t port = 0;
        const std::string text = endpoint.substr(colon + 1);
        if (text.empty() || text.size() > 5) return false;
        for (unsigned char ch : text) {
            if (ch < '0' || ch > '9') return false;
            port = port * 10u + static_cast<uint32_t>(ch - '0');
            if (port > 65535u) return false;
        }
        if (port == 0) return false;
        ip_out = ip;
        port_out = static_cast<uint16_t>(port);
        return true;
    }

    static bool ParseCanonicalOnionEndpoint(const std::string& endpoint,
                                            std::string& host_out,
                                            uint16_t& port_out) {
        const size_t colon = endpoint.rfind(':');
        if (colon == std::string::npos || colon + 1 >= endpoint.size())
            return false;
        const std::string host = endpoint.substr(0, colon);
        // Tor v3: 56 lowercase base32 characters followed by exactly .onion.
        if (host.size() != 62 || host.compare(56, 6, ".onion") != 0)
            return false;
        for (size_t i = 0; i < 56; ++i) {
            const char ch = host[i];
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '2' && ch <= '7')))
                return false;
        }
        uint32_t port = 0;
        const std::string text = endpoint.substr(colon + 1);
        if (text.empty() || text.size() > 5) return false;
        for (unsigned char ch : text) {
            if (ch < '0' || ch > '9') return false;
            port = port * 10u + static_cast<uint32_t>(ch - '0');
            if (port > 65535u) return false;
        }
        if (port == 0) return false;
        host_out = host;
        port_out = static_cast<uint16_t>(port);
        return true;
    }

    class PendingDialLease {
    public:
        explicit PendingDialLease(NodeServer& owner) : owner_(&owner) {
            std::lock_guard<std::mutex> lock(owner.pending_dial_mutex_);
            const uint32_t pending = owner.pending_dials_.load(
                std::memory_order_acquire);
            const uint32_t connected = owner.outbound_count_.load(
                std::memory_order_acquire);
            if (owner.running_.load(std::memory_order_acquire) &&
                pending < MAX_PENDING_DIALS &&
                connected + pending < MAX_OUTBOUND_CONNECTIONS) {
                owner.pending_dials_.fetch_add(1, std::memory_order_acq_rel);
                return;
            }
            owner_ = nullptr;
        }
        PendingDialLease(const PendingDialLease&) = delete;
        PendingDialLease& operator=(const PendingDialLease&) = delete;
        PendingDialLease(PendingDialLease&& other) noexcept
            : owner_(other.owner_) { other.owner_ = nullptr; }
        PendingDialLease& operator=(PendingDialLease&&) = delete;
        ~PendingDialLease() {
            if (owner_) {
                std::lock_guard<std::mutex> lock(owner_->pending_dial_mutex_);
                if (owner_->pending_dials_.fetch_sub(
                        1, std::memory_order_acq_rel) == 1) {
                    owner_->pending_dial_cv_.notify_all();
                }
            }
        }
        explicit operator bool() const { return owner_ != nullptr; }

    private:
        NodeServer* owner_{nullptr};
    };

    bool ConnectTo(const std::string& host, uint16_t port,
                   bool explicitly_trusted = false,
                   bool fleet_anchor = false) {
        if (host.empty() || port == 0) return false;
        if (fleet_anchor &&
            (!explicitly_trusted || !IsCanonicalIPv4Literal(host)))
            return false;
        if (explicitly_trusted) {
            if (fleet_anchor) {
                if (!AddFleetAnchorIp(host)) return false;
            }
            else AddTrustedIP(host);
        }
        {
            // Preserve idempotent seed/watchdog semantics even when all eight
            // outbound slots are occupied.  The lease intentionally rejects new
            // work at that point, but an exact already-connected endpoint is not
            // new work and must continue to report success.
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (const auto& [_key, conn] : peer_connections_) {
                if (conn && conn->IsConnected() && !conn->IsInbound() &&
                    conn->RemoteAddr() == host && conn->RemotePort() == port) {
                    return true;
                }
            }
        }
        PendingDialLease lease(*this);
        if (!lease) return false;
        return ConnectToReserved_(host, port, explicitly_trusted, fleet_anchor);
    }

    // Caller owns a PendingDialLease.  Remote-triggered dials acquire it before
    // creating a thread, so the reservation bounds thread creation itself (not
    // merely the number that happen to reach connect()).
    bool ConnectToReserved_(const std::string& host, uint16_t port,
                            bool explicitly_trusted = false,
                            bool fleet_anchor = false) {
        if (host.empty() || port == 0) return false;
        if (!running_.load(std::memory_order_acquire)) return false;
        if (fleet_anchor &&
            (!explicitly_trusted || !IsCanonicalIPv4Literal(host)))
            return false;
        if (explicitly_trusted) {
            if (fleet_anchor) {
                if (!AddFleetAnchorIp(host)) return false;
            }
            else AddTrustedIP(host);
        }
        bool is_onion = (host.size() > 6 &&
                         host.compare(host.size() - 6, 6, ".onion") == 0);
        // Route through Tor's SOCKS5 when (a) the target is a .onion, or (b) we
        // are in tor-only mode — in which case EVERY dial (incl. clearnet seed
        // IPs) rides Tor so our real IP is never exposed. A non-tor-only node
        // that learns a .onion still needs an active Tor controller to reach it.
        if (is_onion || tor_only_.load()) {
            if (is_onion && !tor_only_.load() && !tor_.Active()) return false;
            SocketHandle ofd = Socks5Connect(host, port);
            if (!veld::compat::IsValidSocket(ofd)) return false;
            return FinishOutboundConnection(ofd, host, port);
        }
        struct addrinfo hints{}, *res;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0)
            return false;

        std::string resolved_ip;
        for (auto* it = res; it; it = it->ai_next) {
            if (it->ai_family != AF_INET) continue;
            char ip_buf[INET_ADDRSTRLEN] = {0};
            auto* sin = reinterpret_cast<struct sockaddr_in*>(it->ai_addr);
            ::inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf));
            // Trust is an operator decision, never a side effect of dialing an
            // address learned from an untrusted ADDR/PUNCH message.  The old
            // unconditional insertion made every discovered outbound peer
            // never-ban and exempt from inbound/per-subnet admission limits.
            if (explicitly_trusted) {
                if (fleet_anchor) AddFleetAnchorIp(std::string(ip_buf));
                else AddTrustedIP(std::string(ip_buf));
            }
            if (resolved_ip.empty()) resolved_ip = ip_buf;
        }

        if (!resolved_ip.empty()) {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            // CanDialOutboundIp reads the explicit trust set.  Use the same
            // peers->ban lock order as rotation/anchor selection so concurrent
            // operator configuration cannot race this lookup.
            std::lock_guard<std::mutex> ban_lock(ban_mutex_);
            // idempotent re-dial. If we already hold an OUTBOUND
            // connection to this IP, treat as success and skip. Without this,
            // the 30s seed-watchdog (which re-dials the whole seed set) would
            // stack duplicate outbounds onto seeds we are already connected to
            // — trusted seed IPs bypass the per-ip cap in CanDialOutboundIp.
            for (const auto& [pk, pc] : peer_connections_) {
                if (pc && pc->IsConnected() && !pc->IsInbound()
                    && (pc->RemoteAddr() == host || pc->RemoteAddr() == resolved_ip)) {
                    ::freeaddrinfo(res);
                    return true;
                }
            }
            if (!CanDialOutboundIp(resolved_ip)) {
                ::freeaddrinfo(res);
                return false;
            }
        }

        SocketHandle fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (!veld::compat::IsValidSocket(fd)) { ::freeaddrinfo(res); return false; }

        int ka = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&ka, sizeof(ka));
#ifdef TCP_KEEPIDLE
        int keepidle = 10;
        int keepintvl = 5;
        int keepcnt = 3;
        ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  (const char*)&keepidle,  sizeof(keepidle));
        ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (const char*)&keepintvl, sizeof(keepintvl));
        ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   (const char*)&keepcnt,   sizeof(keepcnt));
#endif
#ifdef _WIN32

        struct tcp_keepalive_vals {
            u_long onoff;
            u_long keepalivetime;
            u_long keepaliveinterval;
        } kav = { 1, 10000, 5000 };
        DWORD bytes_returned = 0;
        ::WSAIoctl(fd, 0x98000004 ,
                   &kav, sizeof(kav), nullptr, 0,
                   &bytes_returned, nullptr, nullptr);
#endif

#ifdef _WIN32
        DWORD tv_ms = 5000;
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv_ms, sizeof(tv_ms));
        DWORD rv_ms = 6000;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&rv_ms, sizeof(rv_ms));
#else
        struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0;
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        struct timeval rv; rv.tv_sec = 5; rv.tv_usec = 0;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rv, sizeof(rv));
#endif

        // A blocking ::connect() to an unreachable or firewalled seed does not
        // honour SO_SNDTIMEO for the connect phase — on Linux it parks in the
        // kernel SYN-retransmit path for tcp_syn_retries (~127s) before
        // ETIMEDOUT. This thread is one of the SpawnTrackedPeerThread dialers
        // (seed-watchdog re-dial every 30s, anchor dial, ADDR dial, outbound
        // rotation). NodeServer::Stop() joins those threads, but nothing
        // interrupts a blocking connect — so a single dialer parked in
        // connect() to a down seed makes Stop() block until the kernel gives
        // up, which is why the 20s shutdown-watchdog fires. Cure: dial
        // non-blocking and wait in short poll() slices that also watch
        // running_, so Stop() (which clears running_) frees the dialer within
        // one slice. We restore blocking mode after the connect completes so
        // the subsequent handshake/RecvExact path (which relies on blocking
        // semantics + SO_RCVTIMEO) is unchanged. The event-loop path sets its
        // own non-blocking mode independently in TryRecvMessage.
        {
            bool connect_ok = false;
#ifdef _WIN32
            u_long nb = 1;
            ::ioctlsocket((SOCKET)fd, FIONBIO, &nb);
#else
            int fl = ::fcntl(fd, F_GETFL, 0);
            if (fl != -1) ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
#endif
            int crc = ::connect(fd, res->ai_addr, res->ai_addrlen);
            if (crc == 0) {
                connect_ok = true;          // immediate (e.g. loopback)
            } else {
#ifdef _WIN32
                int cerr = WSAGetLastError();
                bool in_progress = (cerr == WSAEWOULDBLOCK || cerr == WSAEINPROGRESS);
#else
                bool in_progress = (errno == EINPROGRESS);
#endif
                if (in_progress) {
                    // Bounded, shutdown-aware wait for writability. Total budget
                    // matches the prior 5s SO_SNDTIMEO dial budget; sliced so a
                    // shutdown (running_ -> false) breaks out in <= one slice.
                    constexpr int SLICE_MS   = 200;
                    constexpr int BUDGET_MS  = 5000;
                    int waited = 0;
                    while (running_ && waited < BUDGET_MS) {
#ifdef _WIN32
                        WSAPOLLFD pfd{(SOCKET)fd, POLLOUT, 0};
                        int pr = ::WSAPoll(&pfd, 1, SLICE_MS);
#else
                        struct pollfd pfd{fd, POLLOUT, 0};
                        int pr = ::poll(&pfd, 1, SLICE_MS);
#endif
                        if (pr < 0) {
#ifndef _WIN32
                            if (errno == EINTR) { continue; }
#endif
                            break;
                        }
                        if (pr == 0) { waited += SLICE_MS; continue; }  // slice timeout
                        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
                        if (pfd.revents & POLLOUT) {
                            int so_err = 0;
                            socklen_t len = sizeof(so_err);
                            if (::getsockopt(fd, SOL_SOCKET, SO_ERROR,
                                             (char*)&so_err, &len) == 0
                                && so_err == 0) {
                                connect_ok = true;
                            }
                            break;
                        }
                    }
                }
            }

            if (!connect_ok) {
                VELD_CLOSE_SOCKET(fd);
                ::freeaddrinfo(res);
                return false;
            }

            // Restore blocking mode for the handshake / RecvExact path.
#ifdef _WIN32
            u_long bl = 0;
            ::ioctlsocket((SOCKET)fd, FIONBIO, &bl);
#else
            int fl2 = ::fcntl(fd, F_GETFL, 0);
            if (fl2 != -1) ::fcntl(fd, F_SETFL, fl2 & ~O_NONBLOCK);
#endif
        }
        ::freeaddrinfo(res);
        // Keep the canonical numeric endpoint in Connection.  Besides making
        // seed re-dials truly idempotent, this lets the duplicate-connection
        // resolver compare an inbound and outbound leg to the same node.
        return FinishOutboundConnection(fd,
            resolved_ip.empty() ? host : resolved_ip, port);
    }

    // Shared post-connect setup (register the conn, supersede stale duplicates,
    // spawn/hand-off the peer handler). Called by BOTH the clearnet dial path and
    // the Tor (.onion via SOCKS5) path, so they are byte-identical after the
    // socket connects. Behavior is unchanged from the prior inline code.
    bool FinishOutboundConnection(SocketHandle fd, const std::string& host, uint16_t port) {
        auto conn = std::make_shared<Connection>(fd, host, port);
        std::string key = host + ":" + std::to_string(port);

        std::vector<std::shared_ptr<Connection>> superseded_connections;
        bool admitted = false;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            std::vector<std::string> to_close;
            for (const auto& [k, c] : peer_connections_) {
                if (k == key) continue;
                // Keep a live inbound leg until both sides exchange VERSION.
                // Closing it here makes simultaneous cross-dials symmetric in
                // exactly the wrong way: each node closes the socket its peer
                // just dialled and both surviving outbound legs then die.  The
                // nonce-based resolver below chooses one direction after the
                // peer identity is known.  Only reap dead map entries here.
                if (c && !c->IsConnected() && c->RemoteAddr() == host)
                    to_close.push_back(k);
            }
            for (const auto& k : to_close) {
                auto it = peer_connections_.find(k);
                if (it != peer_connections_.end()) {
                    superseded_connections.push_back(it->second);
                    DecrConnCount_(it->second);
                    peer_connections_.erase(it);
                }
            }
            // Close any connection mapped to the same endpoint key before
            // replacing it, and keep the direction counters balanced.
            std::shared_ptr<Connection> same_key;
            admitted = RegisterAdmittedConnectionLocked_(
                key, conn, same_key);
            if (same_key) superseded_connections.push_back(same_key);
        }
        for (auto& old : superseded_connections)
            RetireDetachedConnection_(old);
        if (!admitted) {
            RetireDetachedConnection_(conn);
            return false;
        }

        // VERSION is the first application byte on the wire.  Send it in the
        // dial thread that just completed connect(), before any worker/thread
        // scheduling.  A memory-hard miner can starve newly spawned peer
        // handlers long enough for a seed's pre-VERSION reaper to fire.
        PeerManager initial_pm(magic_, chain_.Height(),
                               local_services_.load(std::memory_order_acquire));
        if (!conn->Send(initial_pm.BuildVersionMessage(
                chain_.Height(), self_nonce_))) {
            FinalizePeerConnection_(key, conn);
            return false;
        }

        if (use_event_loop_) {
            try {
                auto ps = std::make_shared<PeerState>();
                if (!HandOffNewPeerToWorker(key, conn, ps)) {
                    FinalizePeerConnection_(key, conn);
                    return false;
                }
            } catch (const std::exception& e) {
                std::cerr << "  [tcp] event-loop outbound handoff failed (" << e.what()
                          << ") — dropping outbound connection to " << key << "\n";
                std::cerr.flush();
                FinalizePeerConnection_(key, conn);
                return false;
            }
            return true;
        }

        try {
            if (!SpawnTrackedPeerThread([this, conn, key]() {
                    HandlePeer(conn, key, false, true);
                })) {
                FinalizePeerConnection_(key, conn);
                return false;
            }
        } catch (const std::system_error& e) {
            std::cerr << "  [tcp] peer-handler spawn failed (" << e.what()
                      << ") — dropping outbound connection to " << key << "\n";
            std::cerr.flush();
            FinalizePeerConnection_(key, conn);
            return false;
        } catch (const std::exception& e) {
            std::cerr << "  [tcp] unexpected spawn error: " << e.what() << "\n";
            std::cerr.flush();
            FinalizePeerConnection_(key, conn);
            return false;
        }

        return true;
    }

    PeerManager GetMessageBuilder() const {
        return PeerManager(magic_, chain_.Height(),
                           local_services_.load(std::memory_order_acquire));
    }

    void SetSolutionCallback(std::function<void(uint64_t, const Hash256&, uint64_t, const std::vector<uint8_t>&)> cb) {
        solution_cb_ = cb;
    }
    void SetCOMineCallback(std::function<bool(uint64_t, const Hash256&, uint64_t, const Hash256&, const std::vector<uint8_t>&)> cb) {
        comine_cb_ = cb;
    }
    void SetFinalityVotePrecheck(FinalityVotePrecheck cb) {
        finality_vote_precheck_ = std::move(cb);
    }
    void SetFinalityVoteVerifier(FinalityVoteVerifier cb) {
        finality_vote_verifier_ = std::move(cb);
    }
    void AddKnownPeer(const std::string& ip, uint16_t port) {
        if (ip.empty() || ip == "0.0.0.0" || ip == "127.0.0.1") return;
        std::lock_guard<std::mutex> lock(peer_addr_mutex_);
        const uint64_t now_epoch = (uint64_t)std::time(nullptr);
        auto it = known_peer_addrs_.find(ip);
        if (it != known_peer_addrs_.end()) {
            it->second = port;
            peer_addr_last_seen_[ip] = now_epoch;
            return;
        }
        // Reject a new entry before the per-subnet walk.  At capacity the old
        // ordering scanned all 1,000 entries for every attacker-controlled
        // address even though insertion was impossible.
        if (known_peer_addrs_.size() >= PEER_CACHE_MAX_ENTRIES) return;
        const std::string subnet = Subnet16Prefix(ip);
        const auto subnet_it = known_peer_subnet_counts_.find(subnet);
        if (subnet_it != known_peer_subnet_counts_.end() &&
            subnet_it->second >= ADDR_BOOK_PER_SUBNET_CAP) return;
        known_peer_addrs_[ip] = port;
        peer_addr_last_seen_[ip] = now_epoch;
        ++known_peer_subnet_counts_[subnet];
    }

    std::vector<std::pair<std::string, uint16_t>> GetKnownPeers(size_t max = 30) const {
        std::lock_guard<std::mutex> lock(peer_addr_mutex_);
        std::vector<std::pair<std::string, uint16_t>> result;
        for (auto& [ip, port] : known_peer_addrs_) {
            if (result.size() >= max) break;
            result.push_back({ip, port});
        }
        return result;
    }

    bool IsBanned(const std::string& ip) const {
        std::lock_guard<std::mutex> lock(ban_mutex_);
        auto it = banned_ips_.find(ip);
        if (it == banned_ips_.end()) return false;
        if (MonotonicSeconds() > it->second) {
            const_cast<NodeServer*>(this)->banned_ips_.erase(it);
            return false;
        }
        return true;
    }

    void SetBanFilePath(const std::string& path) {
        std::lock_guard<std::mutex> lock(ban_mutex_);
        ban_file_path_ = path;
    }

    void BanIP(const std::string& ip, uint32_t duration_seconds = 3600) {
        std::lock_guard<std::mutex> lock(ban_mutex_);
        banned_ips_[ip] = MonotonicSeconds() + duration_seconds;
        EnforceBanListCap_();
        bans_dirty_ = true;
        SaveBansToFileLocked_(true);
        EraseViolationLocked_(ip);
        std::cout << "  [DoS] Banned peer for " << duration_seconds << "s\n";
    }

    void AddTrustedIP(const std::string& ip) {
        if (ip.empty()) return;
        std::lock_guard<std::mutex> lock(ban_mutex_);
        trusted_ips_.insert(ip);
    }

#ifdef VELD_TEST_HOOKS
    bool IsTrustedIPForTesting(const std::string& ip) const {
        std::lock_guard<std::mutex> lock(ban_mutex_);
        return trusted_ips_.count(ip) != 0;
    }
#endif

    //  FLEET ANCHOR PROTECTION. Like AddTrustedIP but with
    // an additional reaper exemption: IPs added here are NEVER closed
    // by ReapIdlePeers (90 s silence) or ReapStuckHandshakes (60 s with
    // zero peer bytes / 120 s with queued progress) regardless of how long
    // they go silent. Used for
    // the always-on fleet infra hosts so a normal traffic burst at
    // distribution boundaries or a heavy reorg doesn't fragment the
    // fleet mesh by reaping legitimate peer-anchor connections.
    //
    // Same dynamic-set discipline as trusted_ips_ — IPs come from
    // operator config (CLI --fleet-anchor flag or VELD_FLEET_ANCHOR_IPS
    // env var, parsed in veld-node.cpp), never from hardcoded source.
    // Rotating an anchor IP is an operational config change with a
    // fleet-wide restart, not a code change.
    bool AddFleetAnchorIp(const std::string& ip) {
        if (!IsCanonicalIPv4Literal(ip)) return false;
        std::lock_guard<std::mutex> lock(ban_mutex_);
        const auto inserted = fleet_anchor_ips_.insert(ip).second;
        if (inserted) {
            fleet_anchor_indices_[ip] =
                static_cast<uint32_t>(fleet_anchor_indices_.size() + 1);
        }
        trusted_ips_.insert(ip);
        return true;
    }

#ifdef VELD_TEST_HOOKS
    bool IsFleetAnchorIpForTesting(const std::string& ip) const {
        return IsFleetAnchorIp_(ip);
    }
#endif

    bool IsFleetAnchorIp_(const std::string& ip) const {
        if (ip.empty()) return false;
        std::lock_guard<std::mutex> lock(ban_mutex_);
        return fleet_anchor_ips_.count(ip) > 0;
    }

    size_t LoadBansFromFile() {
        std::lock_guard<std::mutex> lock(ban_mutex_);
        if (ban_file_path_.empty()) return 0;
        std::ifstream f(ban_file_path_);
        if (!f) return 0;
        size_t loaded = 0;
        uint64_t now_epoch = (uint64_t)std::time(nullptr);
        uint64_t now_mono  = MonotonicSeconds();
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            size_t sp = line.find(' ');
            if (sp == std::string::npos) continue;
            std::string ip = line.substr(0, sp);
            uint64_t expiry_epoch = 0;
            try { expiry_epoch = std::stoull(line.substr(sp + 1)); } catch (...) { continue; }
            if (expiry_epoch <= now_epoch) continue;
            uint64_t remaining = expiry_epoch - now_epoch;
            if (remaining > 24 * 3600) remaining = 24 * 3600;
            banned_ips_[ip] = now_mono + remaining;
            ++loaded;
        }
        if (loaded > 0) {
            std::cout << "  [DoS] loaded " << loaded
                      << " persistent ban(s) from " << ban_file_path_ << "\n";
        }
        return loaded;
    }

    //  //  Peer-cache persistence: <datadir>/peers.dat
    //
    // Without persistence, a node that restarts had nothing but DNS
    // seed names + hardcoded bootstrap IPs to dial — an attacker who
    // could MITM the seed lookup (or who simply got there first in
    // the kernel's ARP/route table) could feed back attacker-
    // controlled IPs, populating ALL 8 outbound slots with hostile
    // peers and eclipsing the node from honest network view.
    //
    // With persistence, the node remembers up to PEER_CACHE_MAX_ENTRIES
    // (1000) IPs it has organically learned from prior runs — a
    // restarted node can dial peers it already trusts before any
    // DNS seeder gets consulted. Anchor provides a stronger
    // guarantee for the *4 longest-lived* peers; peer-cache provides
    // the broader fallback pool.
    //
    // Format on disk (text, line-based, atomically renamed):
    //   # veld known-peers persistent state — auto-generated by veld-node, do not edit
    //   # format: <ip> <port> <unix_epoch_last_seen>
    //   1.2.3.4 8333 1748352000
    //
    // Loader rejects:
    //   - any file > PEER_CACHE_MAX_FILE_BYTES (256 KB) — refuses
    //     to load a tampered/runaway file.
    //   - any entry with last_seen older than PEER_CACHE_MAX_AGE_SECONDS
    //     (30 days) — stale peers are dropped.
    //   - 0.0.0.0, 127.0.0.1, anything that fails dotted-quad parse.
    //   - ports of 0.
    //   - entries past PEER_CACHE_MAX_ENTRIES.
    //
    // Best-effort: any I/O failure logs to stderr but never raises;
    // a disk-full or permission error must NOT crash the node.
    void SetPeerCachePath(const std::string& path) {
        std::lock_guard<std::mutex> lock(peer_addr_mutex_);
        peer_cache_path_ = path;
    }

    size_t LoadPeerCache() {
        std::lock_guard<std::mutex> lock(peer_addr_mutex_);
        if (peer_cache_path_.empty()) return 0;
        std::error_code ec;
        auto fsize = std::filesystem::file_size(peer_cache_path_, ec);
        if (ec) return 0;
        if (fsize > PEER_CACHE_MAX_FILE_BYTES) {
            std::cerr << "  [peer-cache] refusing to load oversized file ("
                      << fsize << " bytes > " << PEER_CACHE_MAX_FILE_BYTES
                      << " cap) at " << peer_cache_path_ << "\n";
            std::cerr.flush();
            return 0;
        }
        std::ifstream f(peer_cache_path_);
        if (!f) return 0;
        size_t loaded = 0;
        const uint64_t now_epoch = (uint64_t)std::time(nullptr);
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            if (known_peer_addrs_.size() >= PEER_CACHE_MAX_ENTRIES) break;
            size_t sp1 = line.find(' ');
            if (sp1 == std::string::npos) continue;
            size_t sp2 = line.find(' ', sp1 + 1);
            if (sp2 == std::string::npos) continue;
            std::string ip = line.substr(0, sp1);
            if (ip.empty() || ip == "0.0.0.0" || ip == "127.0.0.1") continue;
            if (ip.find_first_not_of("0123456789.") != std::string::npos) continue;
            uint16_t port = 0;
            uint64_t last_seen = 0;
            try {
                int p = std::stoi(line.substr(sp1 + 1, sp2 - sp1 - 1));
                if (p <= 0 || p > 65535) continue;
                port = (uint16_t)p;
                last_seen = std::stoull(line.substr(sp2 + 1));
            } catch (...) { continue; }
            if (last_seen + PEER_CACHE_MAX_AGE_SECONDS < now_epoch) continue;
            if (last_seen > now_epoch + 3600) continue;
            auto existing = known_peer_addrs_.find(ip);
            if (existing != known_peer_addrs_.end()) {
                existing->second = port;
                peer_addr_last_seen_[ip] = last_seen;
                continue;
            }
            const std::string subnet = Subnet16Prefix(ip);
            const auto subnet_it = known_peer_subnet_counts_.find(subnet);
            if (subnet_it != known_peer_subnet_counts_.end() &&
                subnet_it->second >= ADDR_BOOK_PER_SUBNET_CAP) continue;
            known_peer_addrs_[ip] = port;
            peer_addr_last_seen_[ip] = last_seen;
            ++known_peer_subnet_counts_[subnet];
            ++loaded;
        }
        if (loaded > 0) {
            std::cout << "  [peer-cache] loaded " << loaded
                      << " known peer(s) from " << peer_cache_path_ << "\n";
        }
        return loaded;
    }

    void SavePeerCache() {
        std::lock_guard<std::mutex> lock(peer_addr_mutex_);
        if (peer_cache_path_.empty()) return;
        if (known_peer_addrs_.empty()) return;
        std::string tmp = peer_cache_path_ + ".tmp";
        try {
            std::ofstream f(tmp, std::ios::trunc);
            if (!f) return;
            f << "# veld known-peers persistent state — auto-generated by veld-node, do not edit\n";
            f << "# format: <ip> <port> <unix_epoch_last_seen>\n";
            const uint64_t now_epoch = (uint64_t)std::time(nullptr);
            size_t written = 0;
            for (const auto& [ip, port] : known_peer_addrs_) {
                if (written >= PEER_CACHE_MAX_ENTRIES) break;
                auto it = peer_addr_last_seen_.find(ip);
                uint64_t ls = (it == peer_addr_last_seen_.end()) ? now_epoch : it->second;
                if (ls + PEER_CACHE_MAX_AGE_SECONDS < now_epoch) continue;
                f << ip << ' ' << port << ' ' << ls << '\n';
                ++written;
            }
            f.flush();
            f.close();
            (void)ReplaceFileAtomically_(tmp, peer_cache_path_);
        } catch (...) {
        }
    }

    void SetAnchorsPath(const std::string& path) {
        std::lock_guard<std::mutex> lock(peer_addr_mutex_);
        anchors_path_ = path;
    }

    std::vector<std::pair<std::string, uint16_t>> LoadAnchors() {
        std::vector<std::pair<std::string, uint16_t>> out;
        std::lock_guard<std::mutex> lock(peer_addr_mutex_);
        if (anchors_path_.empty()) return out;
        std::error_code ec;
        auto fsize = std::filesystem::file_size(anchors_path_, ec);
        if (ec) return out;
        if (fsize > 4096) return out;
        std::ifstream f(anchors_path_);
        if (!f) return out;
        std::string line;
        while (std::getline(f, line) && out.size() < ANCHOR_COUNT) {
            if (line.empty() || line[0] == '#') continue;
            size_t sp = line.find(' ');
            if (sp == std::string::npos) continue;
            std::string ip = line.substr(0, sp);
            if (ip.empty() || ip == "0.0.0.0" || ip == "127.0.0.1") continue;
            if (ip.find_first_not_of("0123456789.") != std::string::npos) continue;
            int p = 0;
            try { p = std::stoi(line.substr(sp + 1)); } catch (...) { continue; }
            if (p <= 0 || p > 65535) continue;
            out.emplace_back(ip, (uint16_t)p);
        }
        if (!out.empty()) {
            std::cout << "  [anchors] loaded " << out.size()
                      << " outbound anchor(s) from " << anchors_path_ << "\n";
        }
        return out;
    }

    void DialAnchorsAsync() {
        auto anchors = LoadAnchors();
        if (anchors.empty()) return;
        for (const auto& [ip, port] : anchors) {
            SpawnTrackedDial_(ip, port);
        }
    }

    void SaveAnchors() {
        struct Candidate {
            std::string ip;
            uint16_t    port;
            std::chrono::steady_clock::time_point accepted_at;
        };
        std::vector<Candidate> cands;
        {
            std::lock_guard<std::mutex> plk(peers_mutex_);
            std::lock_guard<std::mutex> blk(ban_mutex_);
            for (const auto& [key, conn] : peer_connections_) {
                if (!conn) continue;
                if (conn->IsInbound()) continue;
                const std::string& ip = conn->RemoteAddr();
                if (trusted_ips_.count(ip)) continue;
                if (fleet_anchor_ips_.count(ip)) continue;
                if (ip.empty() || ip == "0.0.0.0" || ip == "127.0.0.1") continue;
                cands.push_back({ip, conn->RemotePort(), conn->AcceptedAt()});
            }
        }
        if (cands.empty()) return;
        std::sort(cands.begin(), cands.end(),
                  [](const Candidate& a, const Candidate& b) {
                      return a.accepted_at < b.accepted_at;
                  });
        if (cands.size() > ANCHOR_COUNT) cands.resize(ANCHOR_COUNT);

        std::lock_guard<std::mutex> lock(peer_addr_mutex_);
        if (anchors_path_.empty()) return;
        std::string tmp = anchors_path_ + ".tmp";
        try {
            std::ofstream f(tmp, std::ios::trunc);
            if (!f) return;
            f << "# veld outbound anchors — saved at Stop(), dialed at Start() before DNS bootstrap\n";
            f << "# format: <ip> <port>\n";
            for (const auto& c : cands) {
                f << c.ip << ' ' << c.port << '\n';
            }
            f.flush();
            f.close();
            (void)ReplaceFileAtomically_(tmp, anchors_path_);
        } catch (...) {
        }
    }

private:
    static bool ReplaceFileAtomically_(const std::string& tmp,
                                       const std::string& destination) {
#ifdef _WIN32
        // std::filesystem::rename does not replace an existing destination on
        // Windows. MoveFileEx provides the required peers/anchors/bans update
        // semantics and asks the OS to flush metadata before reporting success.
        return ::MoveFileExA(tmp.c_str(), destination.c_str(),
                             MOVEFILE_REPLACE_EXISTING |
                                 MOVEFILE_WRITE_THROUGH) != 0;
#else
        std::error_code ec;
        std::filesystem::rename(tmp, destination, ec);
        return !ec;
#endif
    }

    static constexpr size_t MAX_BANNED_IPS = 100'000;
    void EnforceBanListCap_() {
        if (banned_ips_.size() <= MAX_BANNED_IPS) return;
        std::vector<std::pair<uint64_t, std::string>> by_expiry;
        by_expiry.reserve(banned_ips_.size());
        for (const auto& [ip, exp] : banned_ips_) by_expiry.emplace_back(exp, ip);
        std::sort(by_expiry.begin(), by_expiry.end());
        size_t to_drop = banned_ips_.size() - (MAX_BANNED_IPS * 9 / 10);
        for (size_t i = 0; i < to_drop && i < by_expiry.size(); ++i) {
            banned_ips_.erase(by_expiry[i].second);
        }
    }

    void SaveBansToFileLocked_(bool force = false) {
        if (ban_file_path_.empty()) return;
        const uint64_t now_mono = MonotonicSeconds();
        if (!force && last_ban_persist_at_ != 0 &&
            now_mono < last_ban_persist_at_ + BAN_PERSIST_INTERVAL_SECONDS) {
            return;
        }
        std::string tmp = ban_file_path_ + ".tmp";
        try {
            std::ofstream f(tmp, std::ios::trunc);
            if (!f) return;
            f << "# veld banned-IPs persistent state — auto-generated by veld-node, do not edit\n";
            f << "# format: <ip> <epoch_unix_expiry>\n";
            uint64_t now_epoch = (uint64_t)std::time(nullptr);
            for (const auto& [ip, expiry_mono] : banned_ips_) {
                if (expiry_mono <= now_mono) continue;
                uint64_t remaining_s = expiry_mono - now_mono;
                if (remaining_s > 24 * 3600) remaining_s = 24 * 3600;
                f << ip << ' ' << (now_epoch + remaining_s) << '\n';
            }
            f.flush();
            f.close();
            if (ReplaceFileAtomically_(tmp, ban_file_path_)) {
                bans_dirty_ = false;
                last_ban_persist_at_ = now_mono;
                ++ban_persist_count_;
            }
        } catch (...) {
        }
    }

    void RetireConnectionsForBannedIp_(const std::string& ip) {
        std::vector<std::shared_ptr<Connection>> retired;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (auto it = peer_connections_.begin();
                 it != peer_connections_.end();) {
                if (it->second && it->second->RemoteAddr() == ip) {
                    retired.push_back(it->second);
                    DecrConnCount_(it->second);
                    it = peer_connections_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        // Close outside the registry lock.  Worker-owned PeerState bindings
        // observe the exact registry removal on their next bounded tick and
        // discard the stale object; cleanup keys accounting by object identity.
        for (auto& conn : retired) {
            conn->Close();
            CleanupConnectionState_(conn);
        }
    }
public:

    void RecordViolation(const std::string& ip, uint32_t weight = 1,
                         const char* tag = nullptr) {
        if (ip == "127.0.0.1" || ip == "::1" || ip.empty()) return;
        bool newly_banned = false;
        {
        std::lock_guard<std::mutex> lock(ban_mutex_);
        if (trusted_ips_.count(ip)) return;
        const bool log_only = (weight == 0);
        uint64_t now = MonotonicSeconds();
        uint32_t count = 0;
        if (!log_only) {
            auto it = violations_.find(ip);
            if (it == violations_.end()) {
                // Strict bounded LRU. Expired/oldest removal and insertion are
                // O(1), so rotating source IPs cannot force a 10k-entry sweep
                // on every packet or grow the table past its hard cap.
                while (!violation_order_.empty()) {
                    auto oldest = violations_.find(violation_order_.front());
                    if (oldest == violations_.end()) {
                        violation_order_.pop_front();
                        continue;
                    }
                    if (violations_.size() < VIOLATION_TABLE_CAP ||
                        now <= oldest->second.last_touch +
                                   VIOLATION_TTL_SECONDS) {
                        break;
                    }
                    EraseViolationLocked_(oldest);
                }
                if (violations_.size() >= VIOLATION_TABLE_CAP &&
                    !violation_order_.empty()) {
                    auto oldest = violations_.find(violation_order_.front());
                    if (oldest != violations_.end())
                        EraseViolationLocked_(oldest);
                    else
                        violation_order_.pop_front();
                }
                violation_order_.push_back(ip);
                auto order_it = std::prev(violation_order_.end());
                it = violations_.emplace(
                    ip, ViolationEntry{0, now, order_it}).first;
            } else {
                if (now > it->second.last_touch + VIOLATION_TTL_SECONDS)
                    it->second.count = 0;
                violation_order_.splice(violation_order_.end(),
                                        violation_order_,
                                        it->second.order_it);
                it->second.order_it = std::prev(violation_order_.end());
            }
            auto& entry = it->second;
            if (entry.count >= BAN_THRESHOLD ||
                weight >= BAN_THRESHOLD - entry.count) {
                entry.count = BAN_THRESHOLD;
            } else {
                entry.count += weight;
            }
            entry.last_touch = now;
            count = entry.count;
        } else {
            auto it = violations_.find(ip);
            if (it != violations_.end()) count = it->second.count;
        }
        constexpr uint32_t LOG_RATE_BURST  = 5;
        constexpr uint64_t LOG_RATE_WINDOW = 60;
        bool emit_line = true;
        uint32_t suppressed_in_window = 0;
        const std::string log_key = ip + "|" + (tag ? tag : "untagged");
        auto rate_it = violation_log_rate_.find(log_key);
        if (rate_it == violation_log_rate_.end()) {
            while (!violation_log_order_.empty()) {
                auto oldest = violation_log_rate_.find(
                    violation_log_order_.front());
                if (oldest == violation_log_rate_.end()) {
                    violation_log_order_.pop_front();
                    continue;
                }
                if (now <= oldest->second.last_touch +
                               VIOLATION_LOG_RETENTION_SECONDS) break;
                EraseViolationLogRateLocked_(oldest);
            }
            if (violation_log_rate_.size() >= VIOLATION_LOG_RATE_CAP &&
                !violation_log_order_.empty()) {
                auto oldest = violation_log_rate_.find(
                    violation_log_order_.front());
                if (oldest != violation_log_rate_.end())
                    EraseViolationLogRateLocked_(oldest);
                else
                    violation_log_order_.pop_front();
            }
            violation_log_order_.push_back(log_key);
            auto order_it = std::prev(violation_log_order_.end());
            rate_it = violation_log_rate_.emplace(
                log_key, ViolationLogRateEntry{now, 0, now, order_it}).first;
        } else {
            violation_log_order_.splice(violation_log_order_.end(),
                                        violation_log_order_,
                                        rate_it->second.order_it);
            rate_it->second.order_it =
                std::prev(violation_log_order_.end());
            rate_it->second.last_touch = now;
        }
        auto& rate = rate_it->second;
        if (now >= rate.window_start + LOG_RATE_WINDOW) {
            if (rate.count > LOG_RATE_BURST)
                suppressed_in_window = rate.count - LOG_RATE_BURST;
            rate.window_start = now;
            rate.count = 0;
        }
        ++rate.count;
        if (rate.count > LOG_RATE_BURST) emit_line = false;

        // The per-key limiter alone does not bound a distributed stream of new
        // IP/tag keys. Keep diagnostics available over time while enforcing a
        // process-instance aggregate line budget for each 60-second window.
        if (now >= violation_log_global_window_ + LOG_RATE_WINDOW) {
            violation_log_global_window_ = now;
            violation_log_global_count_ = 0;
        }
        if (emit_line) {
            if (violation_log_global_count_ >= VIOLATION_LOG_GLOBAL_BURST)
                emit_line = false;
            else
                ++violation_log_global_count_;
        }

        if (emit_line) {
            std::cerr << "  [violation] ip=" << ip
                      << " tag=" << (tag ? tag : "untagged")
                      << " weight=" << weight
                      << " count=" << count << "/" << BAN_THRESHOLD
                      << (log_only ? " (log-only)" : "") << "\n";
            if (suppressed_in_window > 0) {
                std::cerr << "  [violation] ip=" << ip
                          << " tag=" << (tag ? tag : "untagged")
                          << " (suppressed " << suppressed_in_window
                          << " line(s) in previous 60s window)\n";
            }
            std::cerr.flush();
        }
        if (!log_only &&
            count >= BAN_THRESHOLD && banned_ips_.find(ip) == banned_ips_.end()) {
            banned_ips_[ip] = now + 3600;
            EnforceBanListCap_();
            EraseViolationLocked_(ip);
            std::cout << "  [DoS] Banned peer " << ip << " for 1 hour"
                      << " (weight=" << weight
                      << " final_tag=" << (tag ? tag : "untagged") << ")\n";
            bans_dirty_ = true;
            SaveBansToFileLocked_(false);
            newly_banned = true;
        }
        // Expired bans are removed lazily by IsBanned and omitted from the
        // persisted file. Do not scan the (hard-capped) ban table here: this
        // function is remote-hot and log-only violations must remain O(1).
        }
        // A ban is an active-session decision, not merely an admission rule.
        // Retire every exact live socket only after releasing ban_mutex_ to
        // preserve the repository's peers->ban lock order.
        if (newly_banned) RetireConnectionsForBannedIp_(ip);
    }

    struct RateLimitDecision { bool allow; bool record_violation; };
    RateLimitDecision CheckRateLimit(const Connection& peer) {
        std::lock_guard<std::mutex> lock(ban_mutex_);
        uint64_t now = MonotonicSeconds();
        const Connection* identity = &peer;
        auto& window  = msg_windows_[identity];
        auto& count   = msg_counts_[identity];
        auto& vio_cnt = msg_violations_in_window_[identity];
        if (now > window) { window = now; count = 0; vio_cnt = 0; }
        ++count;
        if (count <= MAX_MSG_PER_SECOND) return {true, false};
        if (vio_cnt >= MAX_RATE_LIMIT_VIOLATIONS_PER_SECOND)
            return {false, false};
        ++vio_cnt;
        return {false, true};
    }

    void SetMinerScript(const std::vector<uint8_t>& script) { my_miner_script_ = script; }
    using ComineSigner = std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)>;
    void SetCOMineIdentity(const std::vector<uint8_t>& pubkey,
                           ComineSigner signer) {
        my_comine_pubkey_ = pubkey;
        my_comine_signer_ = std::move(signer);
    }
    void SetIBDComplete(bool v) { ibd_complete_flag_.store(v); }
    struct PeerHeightView {
        // Authoritative height derived only from block hashes this node has
        // accepted onto its current canonical chain.
        uint64_t verified_height{0};
        // Short-lived, unauthenticated fetch hint.  This is retained for
        // observability and bounded synchronization scheduling only.  It must
        // never drive mining, IBD completion, reorg, finality, or consensus.
        uint64_t version_fetch_hint_height{0};
        // Counted from the same exact connection snapshot.  IBD callers use
        // this only as a current-connectivity requirement.
        size_t distinct_version_ips{0};
        // Exact distinct-IP support for the diagnostic fetch hint.
        size_t version_fetch_hint_support{0};
        // Conservative lower bound announced by current outbound peers. The
        // second-highest distinct-IP value requires two outbound sources and
        // is used only to keep IBD/mining closed while locally validated
        // blocks catch up. It never validates a block or selects a chain.
        uint64_t outbound_sync_height{0};
        size_t distinct_outbound_sync_ips{0};
        // Work admission may consume the view only when this exact generation
        // was even and unchanged across the complete snapshot.
        uint64_t work_generation{0};
        bool work_view_stable{false};
        bool work_sequencer_wired{false};
        // Conservative time remaining before any currently-live outbound
        // height claim can expire. UINT64_MAX means no time-dependent claim is
        // contributing. Leases are capped strictly inside this boundary.
        uint64_t freshness_valid_for_ms{UINT64_MAX};
    };

    PeerHeightView GetPeerHeightView() const {
        // VERSION start_height is unauthenticated. Generic/inbound values stay
        // short-lived diagnostics. Exact current outbound announcements also
        // provide a conservative IBD floor: they may keep work paused, but
        // cannot validate a block or choose a chain.
        struct ActiveHeightSource {
            uint64_t    connection_id{0};
            std::string source_ip;
            bool        handshake_ready{false};
            bool        inbound{false};
        };
        const uint64_t generation_before =
            peer_work_view_generation_.load(std::memory_order_acquire);
        std::vector<ActiveHeightSource> active_sources;
        std::unordered_set<std::string> active_ips;

        std::vector<uint64_t> claims;
        claims.reserve(active_ips.size());
        std::vector<VerifiedPeerHeight> verified;
        verified.reserve(active_ips.size());
        size_t distinct_version_ips = 0;
        size_t version_fetch_hint_support = 0;
        uint64_t outbound_sync_height = 0;
        size_t distinct_outbound_sync_ips = 0;
        const uint64_t height_now = PeerHeightNow_();
        uint64_t earliest_freshness_deadline = UINT64_MAX;
        {
            std::lock_guard<std::mutex> lock(peer_heights_mutex_);
            active_sources.reserve(peer_work_sources_.size());
            active_ips.reserve(peer_work_sources_.size());
            for (const auto& [connection_id, source] : peer_work_sources_) {
                if (!source.version_received) continue;
                active_sources.push_back(
                    {connection_id, source.source_ip,
                     source.handshake_ready, source.inbound});
                if (source.handshake_ready)
                    active_ips.insert(source.source_ip);
            }
            struct SelectedClaim {
                uint64_t height{0};
                uint64_t updated_at{0};
                uint64_t connection_id{0};
            };
            std::unordered_map<std::string, SelectedClaim> selected;
            std::unordered_map<std::string, SelectedClaim> selected_outbound;
            selected.reserve(active_sources.size());
            selected_outbound.reserve(active_sources.size());
            for (const auto& live : active_sources) {
                auto claimed = peer_heights_.find(live.connection_id);
                if (claimed == peer_heights_.end() ||
                    claimed->second.source_ip != live.source_ip) continue;
                if (!live.handshake_ready) continue;
                if (!live.inbound) {
                    auto sync_claim = peer_sync_heights_.find(
                        live.connection_id);
                    if (sync_claim == peer_sync_heights_.end() ||
                        sync_claim->second.source_ip != live.source_ip ||
                        !VersionHeightHintFresh_(
                            sync_claim->second.updated_at, height_now))
                        continue;
                    const uint64_t claim_deadline =
                        sync_claim->second.updated_at >
                                UINT64_MAX - VERSION_HEIGHT_HINT_TTL_SECONDS - 1
                            ? UINT64_MAX
                            : sync_claim->second.updated_at +
                                  VERSION_HEIGHT_HINT_TTL_SECONDS + 1;
                    earliest_freshness_deadline = std::min(
                        earliest_freshness_deadline, claim_deadline);
                    auto outbound = selected_outbound.find(live.source_ip);
                    if (outbound == selected_outbound.end() ||
                        sync_claim->second.updated_at >
                            outbound->second.updated_at ||
                        (sync_claim->second.updated_at ==
                             outbound->second.updated_at &&
                         live.connection_id >
                             outbound->second.connection_id)) {
                        selected_outbound[live.source_ip] = SelectedClaim{
                            sync_claim->second.height,
                            sync_claim->second.updated_at,
                            live.connection_id};
                    }
                }
                if (!VersionHeightHintFresh_(claimed->second.updated_at,
                                             height_now)) continue;
                auto chosen = selected.find(live.source_ip);
                if (chosen == selected.end() ||
                    claimed->second.updated_at > chosen->second.updated_at ||
                    (claimed->second.updated_at == chosen->second.updated_at &&
                     live.connection_id > chosen->second.connection_id)) {
                    selected[live.source_ip] = SelectedClaim{
                        claimed->second.height, claimed->second.updated_at,
                        live.connection_id};
                }
            }
            distinct_version_ips = active_ips.size();
            for (const auto& [_ip, claim] : selected)
                claims.push_back(claim.height);
            std::vector<uint64_t> outbound_claims;
            outbound_claims.reserve(selected_outbound.size());
            for (const auto& [_ip, claim] : selected_outbound)
                outbound_claims.push_back(claim.height);
            distinct_outbound_sync_ips = outbound_claims.size();
            if (outbound_claims.size() >= 2) {
                std::sort(outbound_claims.begin(), outbound_claims.end(),
                          std::greater<uint64_t>());
                outbound_sync_height = outbound_claims[1];
            }
            for (const auto& ip : active_ips) {
                auto accepted = peer_verified_heights_.find(ip);
                if (accepted != peer_verified_heights_.end())
                    verified.push_back(accepted->second);
            }
        }
        // Revalidate after copying, without holding the peer-evidence mutex.
        // A reorg can turn a formerly canonical block into a side-branch block;
        // stale evidence must stop influencing IBD/mining immediately.
        uint64_t verified_best = 0;
        for (const auto& v : verified) {
            const std::string active = chain_.GetBlockHashAtHeight(v.height);
            if (!active.empty() && active == HashToHex(v.hash))
                verified_best = std::max(verified_best, v.height);
        }
        uint64_t version_fetch_hint = 0;
        if (claims.size() >= (size_t)VERSION_FETCH_HINT_MIN_SUPPORT) {
            std::sort(claims.begin(), claims.end(), std::greater<uint64_t>());
            const uint64_t raw_hint =
                claims[VERSION_FETCH_HINT_MIN_SUPPORT - 1];
            const uint64_t local_height = chain_.Height();
            const uint64_t max_hint =
                local_height > UINT64_MAX - VERSION_HEIGHT_HINT_MAX_AHEAD
                    ? UINT64_MAX
                    : local_height + VERSION_HEIGHT_HINT_MAX_AHEAD;
            if (raw_hint > local_height)
                version_fetch_hint = std::min(raw_hint, max_hint);
            version_fetch_hint_support = static_cast<size_t>(std::count(
                claims.begin(), claims.end(), raw_hint));
        }
        uint64_t freshness_valid_for_ms = UINT64_MAX;
        if (earliest_freshness_deadline != UINT64_MAX) {
            // MonotonicSeconds is coarse. Subtract a full second so this is a
            // lower bound even when the read occurred at the end of its current
            // second; leases using it therefore end strictly before expiry.
            if (height_now == UINT64_MAX ||
                earliest_freshness_deadline <= height_now ||
                earliest_freshness_deadline - height_now <= 1) {
                freshness_valid_for_ms = 0;
            } else {
                const uint64_t safe_seconds =
                    earliest_freshness_deadline - height_now - 1;
                freshness_valid_for_ms =
                    safe_seconds > UINT64_MAX / 1000
                        ? UINT64_MAX : safe_seconds * 1000;
            }
        }
        const uint64_t generation_after =
            peer_work_view_generation_.load(std::memory_order_acquire);
        const bool stable = (generation_before & 1U) == 0 &&
            generation_before == generation_after &&
            !peer_work_view_write_pending_.load(
                std::memory_order_acquire) &&
            !peer_work_view_sequencer_failed_.load(
                std::memory_order_acquire);
        const bool wired = peer_work_view_sequencer_wired_.load(
            std::memory_order_acquire);
        return PeerHeightView{
            verified_best,
            version_fetch_hint,
            distinct_version_ips,
            version_fetch_hint_support,
            outbound_sync_height,
            distinct_outbound_sync_ips,
            generation_after,
            stable,
            wired,
            freshness_valid_for_ms};
    }

    static std::optional<uint64_t> BoundPeerWorkLifetimeMs(
            const PeerHeightView& view, uint64_t requested_ms,
            uint64_t safety_margin_ms) noexcept {
        if (requested_ms == 0 || !view.work_sequencer_wired ||
            !view.work_view_stable)
            return std::nullopt;
        if (view.freshness_valid_for_ms == UINT64_MAX)
            return requested_ms;
        if (view.freshness_valid_for_ms <= safety_margin_ms)
            return std::nullopt;
        const uint64_t bounded = std::min(
            requested_ms,
            view.freshness_valid_for_ms - safety_margin_ms);
        return bounded == 0 ? std::nullopt
                            : std::optional<uint64_t>(bounded);
    }

    uint64_t GetPeerVerifiedHeight() const {
        return GetPeerHeightView().verified_height;
    }

    uint64_t GetPeerFetchHintHeight() const {
        return GetPeerHeightView().version_fetch_hint_height;
    }

    bool IsAnchorIP(const std::string& ip) const {
        return IsFleetAnchorIp_(ip);
    }
    int GetConnectedAnchorCount() const {
        // An operator-configured anchor is an outbound trust instruction, not
        // merely an IP label.  A configured host connecting inbound must not
        // keep the separate "at least one anchor" mining gate open after our
        // authoritative outbound path is lost.  Count identities rather than
        // sockets so duplicate dials cannot manufacture anchor availability.
        // Snapshot config before peers to preserve config -> peers lock order.
        std::unordered_set<std::string> configured_anchors;
        {
            std::lock_guard<std::mutex> ban_lock(ban_mutex_);
            configured_anchors = fleet_anchor_ips_;
        }
        std::unordered_set<std::string> active_ips;
        {
            std::lock_guard<std::mutex> peer_lock(peers_mutex_);
            for (const auto& [_key, conn] : peer_connections_) {
                if (!conn || !conn->IsConnected() ||
                    !conn->HandshakeReady() || conn->IsInbound())
                    continue;
                if (configured_anchors.count(conn->RemoteAddr()) == 0)
                    continue;
                active_ips.insert(conn->RemoteAddr());
            }
        }
        return static_cast<int>(active_ips.size());
    }
    uint64_t GetReceivedVersionCount() const { return received_version_count_.load(); }
    uint64_t GetGenesisMatchCount()    const { return genesis_match_count_.load(); }
    uint64_t GetGenesisMismatchCount() const { return genesis_mismatch_count_.load(); }

    struct PeerTipSnapshot {
        std::string ip;
        Hash256     hash;
        uint64_t    height;
        int64_t     updated_at;
    };
    std::vector<PeerTipSnapshot> SnapshotPeerTips(
            bool configured_outbound_anchors_only = false) const {
        struct LiveTipSource {
            uint64_t    connection_id{0};
            std::string source_ip;
            bool        inbound{false};
        };
        // Mining may request the operator-configured outbound anchor view.
        // Snapshot configuration before peers to preserve config -> peers
        // lock order. Other callers retain the complete diagnostic view.
        std::unordered_set<std::string> configured_anchors;
        if (configured_outbound_anchors_only) {
            std::lock_guard<std::mutex> ban_lock(ban_mutex_);
            configured_anchors = fleet_anchor_ips_;
        }
        std::vector<LiveTipSource> live_sources;
        {
            std::lock_guard<std::mutex> peer_lock(peers_mutex_);
            live_sources.reserve(peer_connections_.size());
            for (const auto& [_key, conn] : peer_connections_) {
                if (!conn || !conn->IsConnected() ||
                    !conn->HandshakeReady()) continue;
                if (configured_outbound_anchors_only &&
                    (conn->IsInbound() ||
                     configured_anchors.count(conn->RemoteAddr()) == 0))
                    continue;
                live_sources.push_back({conn->Identity(),
                                        conn->RemoteAddr(),
                                        conn->IsInbound()});
            }
        }

        // One exact live generation may vote at most once, and multiple live
        // sockets behind one IP remain one observation. Choose the freshest
        // exact matching generation, then the greater identity on a tie.
        std::unordered_map<std::string,
                           std::pair<uint64_t, PeerTipSnapshot>> selected;
        {
            std::lock_guard<std::mutex> tip_lock(peer_tips_mutex_);
            selected.reserve(live_sources.size());
            for (const auto& live : live_sources) {
                auto it = peer_tips_.find(live.connection_id);
                if (it == peer_tips_.end() ||
                    it->second.source_ip != live.source_ip ||
                    it->second.inbound != live.inbound) continue;
                PeerTipSnapshot candidate{live.source_ip, it->second.hash,
                                          it->second.height,
                                          it->second.updated_at};
                auto chosen = selected.find(live.source_ip);
                if (chosen == selected.end() ||
                    candidate.updated_at > chosen->second.second.updated_at ||
                    (candidate.updated_at == chosen->second.second.updated_at &&
                     live.connection_id > chosen->second.first)) {
                    selected[live.source_ip] =
                        {live.connection_id, std::move(candidate)};
                }
            }
        }
        std::vector<PeerTipSnapshot> out;
        out.reserve(selected.size());
        for (auto& [_ip, selected_tip] : selected)
            out.push_back(std::move(selected_tip.second));

        // Do not expose a tip after a reorg has moved it off the active chain.
        // Copy first so chain reads never invert peer-tip/chain locks.
        out.erase(std::remove_if(out.begin(), out.end(), [this](const auto& s) {
            const std::string active = chain_.GetBlockHashAtHeight(s.height);
            return active.empty() || active != HashToHex(s.hash);
        }), out.end());
        return out;
    }
    static constexpr size_t  PEER_TIPS_CAP        = 1024;
    static constexpr int64_t PEER_TIP_HARD_TTL_S  = 600;
    void ImportPeerTipSnapshots(const std::vector<PeerTipSnapshot>& snaps,
                                int64_t now_s) {
        // Disk-restored observations are recovery hints only. They have no
        // connection generation and therefore can never enter the active
        // mining/trust snapshot until a live peer reconfirms the hash.
        for (const auto& s : snaps) {
            if (s.ip.empty()) continue;
            if (now_s - s.updated_at > PEER_TIP_HARD_TTL_S) continue;
            if (s.updated_at > now_s + 60) continue;
            auto known = CanonicalPeerEvidence_(s.hash);
            if (!known.has_value() || *known != s.height) continue;
            std::lock_guard<std::mutex> lock(peer_tips_mutex_);
            if (peer_tip_recovery_hints_.size() >= PEER_TIPS_CAP &&
                peer_tip_recovery_hints_.count(s.ip) == 0) {
                auto oldest = std::min_element(
                    peer_tip_recovery_hints_.begin(),
                    peer_tip_recovery_hints_.end(),
                    [](const auto& a, const auto& b) {
                        return a.second.updated_at < b.second.updated_at;
                    });
                if (oldest != peer_tip_recovery_hints_.end())
                    peer_tip_recovery_hints_.erase(oldest);
            }
            peer_tip_recovery_hints_[s.ip] = PeerTipRecoveryHint{
                s.hash, s.height, s.updated_at};
        }
    }
    void RecordPeerTip(Connection& conn,
                       const Hash256& hash,
                       uint64_t height,
                       int64_t now_s) {
        if (!conn.IsConnected() || !conn.HandshakeReady() ||
            conn.RemoteAddr().empty()) return;
        if (HashIsZero(hash)) return;
        auto known = CanonicalPeerEvidence_(hash);
        if (!known.has_value()) return;
        // Never publish a wire-supplied height.  Even callers that already
        // checked the hash use the locally indexed height here so future call
        // sites cannot accidentally reintroduce an unsigned TIPSIG vote.
        height = *known;
        {
            std::lock_guard<std::mutex> peer_lock(peers_mutex_);
            bool exact_live = false;
            for (const auto& [_key, live] : peer_connections_) {
                if (live && live.get() == &conn && live->IsConnected() &&
                    live->HandshakeReady()) {
                    exact_live = true;
                    break;
                }
            }
            if (!exact_live) return;
        }
        std::lock_guard<std::mutex> lock(peer_tips_mutex_);
        const uint64_t connection_id = conn.Identity();
        for (auto it = peer_tips_.begin(); it != peer_tips_.end();) {
            if (now_s > it->second.updated_at + PEER_TIP_HARD_TTL_S)
                it = peer_tips_.erase(it);
            else
                ++it;
        }
        if (peer_tips_.count(connection_id) == 0 &&
            peer_tips_.size() >= PEER_TIPS_CAP) {
            auto oldest = std::min_element(
                peer_tips_.begin(), peer_tips_.end(),
                [](const auto& a, const auto& b) {
                    return a.second.updated_at < b.second.updated_at;
                });
            if (oldest != peer_tips_.end()) peer_tips_.erase(oldest);
        }
        auto& info = peer_tips_[connection_id];
        if (height < info.height) return;
        info.source_ip  = conn.RemoteAddr();
        info.inbound    = conn.IsInbound();
        info.hash       = hash;
        info.height     = height;
        info.updated_at = now_s;
    }

    struct ActiveClockDriftSnapshot {
        size_t distinct_ip_count{0};
        int64_t median_seconds{0};
    };

private:
    ActiveClockDriftSnapshot CollectClockDriftSnapshot_(
            const std::unordered_set<std::string>* configured_anchors,
            bool outbound_only) const {
        struct LiveClockSource {
            uint64_t    connection_id{0};
            std::string source_ip;
            bool        inbound{false};
        };
        std::lock_guard<std::mutex> peer_lock(peers_mutex_);
        std::vector<LiveClockSource> live_sources;
        live_sources.reserve(peer_connections_.size());
        for (const auto& [_key, conn] : peer_connections_) {
            if (!conn || !conn->IsConnected() || !conn->HandshakeReady())
                continue;
            if (outbound_only && conn->IsInbound()) continue;
            if (configured_anchors &&
                configured_anchors->count(conn->RemoteAddr()) == 0) continue;
            live_sources.push_back({conn->Identity(), conn->RemoteAddr(),
                                    conn->IsInbound()});
        }

        const uint64_t now = MonotonicSeconds();
        std::vector<int64_t> samples;
        {
            std::lock_guard<std::mutex> drift_lock(clock_drift_mutex_);
            // One vote per IP. If multiple exact live connections from an IP
            // are eligible, take the most recent matching generation sample
            // (then the greater identity as a deterministic tie-breaker).
            struct SelectedSample {
                int64_t  delta_seconds{0};
                uint64_t updated_at{0};
                uint64_t connection_id{0};
            };
            std::unordered_map<std::string, SelectedSample> selected;
            selected.reserve(live_sources.size());
            for (const auto& live : live_sources) {
                auto it = clock_drift_samples_.find(live.connection_id);
                if (it == clock_drift_samples_.end()) continue;
                if (now > it->second.updated_at + CLOCK_DRIFT_TTL_SECONDS)
                    continue;
                if (it->second.source_ip != live.source_ip ||
                    it->second.inbound != live.inbound) continue;
                auto chosen = selected.find(live.source_ip);
                if (chosen == selected.end() ||
                    it->second.updated_at > chosen->second.updated_at ||
                    (it->second.updated_at == chosen->second.updated_at &&
                     live.connection_id > chosen->second.connection_id)) {
                    selected[live.source_ip] = SelectedSample{
                        it->second.delta_seconds, it->second.updated_at,
                        live.connection_id};
                }
            }
            samples.reserve(selected.size());
            for (const auto& [_ip, sample] : selected)
                samples.push_back(sample.delta_seconds);
        }
        if (samples.empty()) return {};
        std::sort(samples.begin(), samples.end());
        return {samples.size(), samples[samples.size() / 2]};
    }

public:
    ActiveClockDriftSnapshot GetActiveClockDriftSnapshot() const {
        // The hard mining gate trusts only operator-configured fleet anchors
        // reached over our outbound connections. Arbitrary inbound/unconfigured
        // peers remain diagnostic-only and cannot form a Sybil halt quorum.
        // Snapshot config before peers to preserve config -> peers lock order.
        std::unordered_set<std::string> configured_anchors;
        {
            std::lock_guard<std::mutex> ban_lock(ban_mutex_);
            configured_anchors = fleet_anchor_ips_;
        }
        return CollectClockDriftSnapshot_(&configured_anchors, true);
    }

    ActiveClockDriftSnapshot GetDiagnosticClockDriftSnapshot() const {
        return CollectClockDriftSnapshot_(nullptr, false);
    }

    int64_t GetMedianPeerClockDriftSec() const {
        return GetDiagnosticClockDriftSnapshot().median_seconds;
    }
    size_t GetClockDriftSampleCount() const {
        return GetDiagnosticClockDriftSnapshot().distinct_ip_count;
    }
    void UpdateMiningProgress(uint64_t height, uint64_t best_nonce, const Hash256& best_hash) {
        my_mining_height_.store(height);
        my_best_nonce_.store(best_nonce);
        std::lock_guard<std::mutex> lock(best_hash_mutex_);
        my_best_hash_ = best_hash;
    }

    void BroadcastMessage(const P2PMessage& msg, const std::string& exclude = "") {
        std::vector<std::shared_ptr<Connection>> targets;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (auto& [key, conn] : peer_connections_) {
                if (key == exclude) continue;
                if (conn->IsConnected()) targets.push_back(conn);
            }
        }
        auto payload = msg.Serialize();
        for (auto& conn : targets) {
            (void)conn->TrySend(payload);
        }
    }

    void BroadcastBlock(const Block& block) {
        PeerManager pm(magic_, chain_.Height());
        auto inv = pm.BuildInvMessage({InvItem(InvType::BLOCK, block.GetHash())});
        BroadcastMessage(inv);
    }

    void BroadcastTransaction(const Transaction& tx) {
        PeerManager pm(magic_, chain_.Height());
        auto inv = pm.BuildInvMessage({InvItem(InvType::TX, tx.GetTxID())});
        BroadcastMessage(inv);
    }

    void BroadcastTipsig() {
        if (chain_.IsEmpty()) return;
        Block tip;
        try { tip = chain_.TipCopy(); } catch (...) { return; }
        PeerManager pm(magic_, chain_.Height());
        auto msg = pm.BuildTipsigMessage(tip.height, tip.GetHash());
        BroadcastMessage(msg);
    }

    static constexpr int STUCK_HANDSHAKE_GRACE_S = 90;
    static constexpr int PRE_VERSION_GRACE_S = 60;
    static constexpr int PRE_VERSION_PROGRESS_GRACE_S = 120;

    // One source of truth for the inbound handshake deadline.  In particular,
    // ReapIdlePeers must not apply its ordinary 90-second LastRecvAt cutoff to
    // a pre-VERSION socket whose VERSION bytes are already waiting in the
    // kernel receive queue: that socket has the explicitly bounded 120-second
    // progress grace below.  Keeping this policy callable also lets the
    // liveness regression exercise minute-scale deadlines without sleeping.
    static int InboundHandshakeDeadlineSeconds(const Connection& conn) {
        if (conn.VersionReceived()) return STUCK_HANDSHAKE_GRACE_S;
        return conn.HasHandshakeProgress()
            ? PRE_VERSION_PROGRESS_GRACE_S
            : PRE_VERSION_GRACE_S;
    }

    static bool InboundHandshakeDeadlineExpired(
            const Connection& conn,
            std::chrono::steady_clock::time_point now) {
        if (!conn.IsInbound() || conn.TipReceived()) return false;
        const auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - conn.AcceptedAt()).count();
        return age >= InboundHandshakeDeadlineSeconds(conn);
    }

    static bool ProtectInboundHandshakeFromIdleReap(
            const Connection& conn,
            std::chrono::steady_clock::time_point now) {
        return conn.IsInbound() && !conn.TipReceived() &&
               !InboundHandshakeDeadlineExpired(conn, now);
    }

    void DecrConnCount_(const std::shared_ptr<Connection>& c) {
        if (!c) return;
        if (c->IsInbound()) {
            if (inbound_count_.load() > 0) --inbound_count_;
        } else {
            if (outbound_count_.load() > 0) --outbound_count_;
        }
    }

    void IncrConnCount_(const std::shared_ptr<Connection>& c) {
        if (!c) return;
        if (c->IsInbound()) ++inbound_count_;
        else ++outbound_count_;
    }

    // peers_mutex_ must be held.  The map entry and its direction counter are
    // one registry object: replace/decrement/increment happens in one critical
    // section, and the caller closes the returned superseded socket afterward.
    bool RegisterAdmittedConnectionLocked_(
            const std::string& key,
            const std::shared_ptr<Connection>& conn,
            std::shared_ptr<Connection>& superseded,
            bool require_running = true) {
        if (!conn || (require_running &&
            !running_.load(std::memory_order_acquire))) return false;
        auto existing = peer_connections_.find(key);
        if (require_running) {
            if (conn->IsInbound()) {
                uint32_t current = inbound_count_.load(
                    std::memory_order_acquire);
                if (existing != peer_connections_.end() && existing->second &&
                    existing->second->IsInbound() && current > 0) --current;
                if (current >= max_inbound_connections_) return false;
            } else {
                uint32_t current = outbound_count_.load(
                    std::memory_order_acquire);
                if (existing != peer_connections_.end() && existing->second &&
                    !existing->second->IsInbound() && current > 0) --current;
                if (current >= MAX_OUTBOUND_CONNECTIONS) return false;
            }
        }
        if (existing != peer_connections_.end()) {
            if (existing->second == conn) return true;
            superseded = existing->second;
            DecrConnCount_(existing->second);
        }
        peer_connections_[key] = conn;
        IncrConnCount_(conn);
        return true;
    }

    bool RemoveAdmittedConnection_(const std::string& key,
                                   const std::shared_ptr<Connection>& expected) {
        bool removed = false;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            auto it = peer_connections_.find(key);
            if (it != peer_connections_.end() && it->second == expected) {
                DecrConnCount_(it->second);
                peer_connections_.erase(it);
                removed = true;
            }
        }
        // Always retire the caller-owned socket, even if a newer connection has
        // already taken over the same key.  Closing outside peers_mutex_ avoids
        // holding the registry lock while shutdown waits for an in-flight syscall.
        if (expected) expected->Close();
        return removed;
    }

    void CleanupConnectionState_(
            const std::shared_ptr<Connection>& expected) {
        if (!expected) return;
        CancelProtectedBlockRequest_(expected->Identity());
        // A pre-VERSION connection has never entered peer_work_sources_ and is
        // invisible to work admission. Every visible generation is retired
        // while the node's transition permit is held.
        std::unique_ptr<PeerWorkViewWriteGuard_> work_view_write;
        if (expected->VersionReceived())
            work_view_write =
                std::make_unique<PeerWorkViewWriteGuard_>(*this);
        if (!work_view_write || work_view_write->MayPublish()) {
            std::lock_guard<std::mutex> height_lock(peer_heights_mutex_);
            std::string source_ip = expected->RemoteAddr();
            const auto source = peer_work_sources_.find(expected->Identity());
            if (source != peer_work_sources_.end())
                source_ip = source->second.source_ip;
            peer_heights_.erase(expected->Identity());
            peer_sync_heights_.erase(expected->Identity());
            peer_work_sources_.erase(expected->Identity());

            // Locally verified evidence is IP-scoped. Retain it only while an
            // exact published source generation from that IP remains.
            bool replacement_is_live = false;
            for (const auto& [_id, other] : peer_work_sources_) {
                if (other.source_ip == source_ip) {
                    replacement_is_live = true;
                    break;
                }
            }
            if (!replacement_is_live)
                peer_verified_heights_.erase(source_ip);
        }
        work_view_write.reset();
        {
            std::lock_guard<std::mutex> lk(ban_mutex_);
            const Connection* identity = expected.get();
            msg_counts_.erase(identity);
            msg_windows_.erase(identity);
            msg_violations_in_window_.erase(identity);
            getblocks_bytes_.erase(identity);
            getblocks_windows_.erase(identity);
        }

        // Clock samples are exact-generation evidence. A same-IP replacement
        // must complete its own VERSION before it can influence either view.
        {
            std::lock_guard<std::mutex> drift_lock(clock_drift_mutex_);
            clock_drift_samples_.erase(expected->Identity());
        }
        {
            std::lock_guard<std::mutex> tip_lock(peer_tips_mutex_);
            peer_tips_.erase(expected->Identity());
        }

    }

    void RetireDetachedConnection_(
            const std::shared_ptr<Connection>& expected) {
        if (!expected) return;
        expected->Close();
        CleanupConnectionState_(expected);
    }

    bool FinalizePeerConnection_(
            const std::string& key,
            const std::shared_ptr<Connection>& expected) {
        const bool removed = RemoveAdmittedConnection_(key, expected);
        // Cleanup is exact-object keyed and therefore unconditional.  A reaper
        // may already have removed this socket from the endpoint map; waiting
        // for `removed` leaked one accounting entry per unique source port.
        CleanupConnectionState_(expected);
        return removed;
    }

    // Collapse simultaneous cross-dials/re-dials from the same IP and startup
    // nonce.  The direction rule is symmetric: the lower startup nonce keeps
    // its outbound leg while the higher nonce keeps that same socket inbound,
    // so both ends choose one physical connection.  The IP equality guard is
    // essential because VERSION nonces are not authenticated identities.
    bool CurrentLosesDuplicateNonce_(const std::string& key,
                                     Connection& conn,
                                     uint64_t peer_nonce) {
        if (peer_nonce == 0 || peer_nonce == self_nonce_) return false;
        conn.MarkPeerNonce(peer_nonce);

        const bool desired_inbound =
            PreferInboundForDuplicate(self_nonce_, peer_nonce);
        std::vector<std::pair<std::string, std::shared_ptr<Connection>>>
            superseded;
        bool current_loses = false;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (const auto& [other_key, other] : peer_connections_) {
                if (!other || other.get() == &conn || !other->IsConnected()) continue;
                if (other->RemoteAddr() != conn.RemoteAddr()) continue;
                if (other->PeerNonce() != peer_nonce) continue;

                const bool current_preferred = conn.IsInbound() == desired_inbound;
                const bool other_preferred   = other->IsInbound() == desired_inbound;
                bool other_wins = false;
                if (other_preferred != current_preferred) {
                    other_wins = other_preferred;
                } else if (other->AcceptedAt() != conn.AcceptedAt()) {
                    // Same direction means a reconnect.  The newer leg is the
                    // one still mapped by the dialer; retire its stale predecessor.
                    other_wins = other->AcceptedAt() > conn.AcceptedAt();
                } else {
                    other_wins = other_key < key;
                }
                if (other_wins) {
                    current_loses = true;
                    break;
                }
            }
            if (!current_loses) {
                for (const auto& [other_key, other] : peer_connections_) {
                    if (!other || other.get() == &conn || !other->IsConnected()) continue;
                    if (other->RemoteAddr() == conn.RemoteAddr() &&
                        other->PeerNonce() == peer_nonce) {
                        superseded.push_back({other_key, other});
                    }
                }
                for (const auto& [other_key, other] : superseded) {
                    auto it = peer_connections_.find(other_key);
                    if (it == peer_connections_.end() || it->second != other)
                        continue;
                    DecrConnCount_(it->second);
                    peer_connections_.erase(it);
                }
            }
        }
        if (current_loses) {
            std::cerr << "  [peer] duplicate node connection from "
                      << conn.RemoteAddr() << " (nonce=" << peer_nonce
                      << ") — keeping deterministic existing leg\n";
            std::cerr.flush();
            return true;
        }
        for (auto& [other_key, other] : superseded) {
            (void)other_key;
            RetireDetachedConnection_(other);
        }
        if (!superseded.empty()) {
            std::cerr << "  [peer] collapsed " << superseded.size()
                      << " duplicate connection(s) from " << conn.RemoteAddr()
                      << " (same startup nonce)\n";
            std::cerr.flush();
        }
        return false;
    }

    void ReapIdlePeers(uint32_t idle_threshold_secs = 90) {
        auto now = std::chrono::steady_clock::now();
        std::vector<std::shared_ptr<Connection>> to_close;
        std::vector<std::shared_ptr<Connection>> detached_dead;
        std::vector<std::string> closed_keys;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (auto it = peer_connections_.begin(); it != peer_connections_.end(); ) {
                auto& conn = it->second;
                if (!conn || !conn->IsConnected()) {
                    if (conn) detached_dead.push_back(conn);
                    DecrConnCount_(conn);
                    it = peer_connections_.erase(it);
                    continue;
                }
                if (conn->RecvFrameAssemblyExpired(now)) {
                    closed_keys.push_back(it->first);
                    to_close.push_back(conn);
                    DecrConnCount_(conn);
                    it = peer_connections_.erase(it);
                    continue;
                }
                if (IsFleetAnchorIp_(conn->RemoteAddr())) {
                    ++it; continue;
                }
                // The handshake reaper runs immediately before this method in
                // veld-node, but its longer queued-progress grace must remain
                // authoritative even if callers invoke the two independently.
                // Once that bounded grace expires, normal idle reaping may
                // close the socket as usual.
                if (ProtectInboundHandshakeFromIdleReap(*conn, now)) {
                    ++it; continue;
                }
                auto last = conn->LastRecvAt();
                auto idle = std::chrono::duration_cast<std::chrono::seconds>(
                    now - last).count();
                if (idle >= (long long)idle_threshold_secs) {
                    closed_keys.push_back(it->first);
                    to_close.push_back(conn);
                    DecrConnCount_(conn);
                    it = peer_connections_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (auto& c : detached_dead) RetireDetachedConnection_(c);
        if (!to_close.empty()) {
            std::cerr << "  [reaper] idle/frame-closed " << to_close.size()
                      << " peer(s) (silent >" << idle_threshold_secs
                      << "s or incomplete frame >"
                      << Connection::RECV_FRAME_ASSEMBLY_TIMEOUT_SECONDS
                      << "s):";
            for (size_t i = 0; i < closed_keys.size() && i < 5; ++i)
                std::cerr << " " << closed_keys[i];
            if (closed_keys.size() > 5)
                std::cerr << " (+" << (closed_keys.size() - 5) << " more)";
            std::cerr << "\n";
            std::cerr.flush();
            for (auto& c : to_close) RetireDetachedConnection_(c);
        }
    }

    void ReapStuckHandshakes() {
        auto now = std::chrono::steady_clock::now();
        std::vector<std::shared_ptr<Connection>> pre_version_close;
        std::vector<std::shared_ptr<Connection>> pre_tipsig_close;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (auto it = peer_connections_.begin(); it != peer_connections_.end(); ) {
                auto& conn = it->second;
                if (!conn || !conn->IsConnected() || !conn->IsInbound()) {
                    ++it; continue;
                }
                if (IsFleetAnchorIp_(conn->RemoteAddr())) {
                    ++it; continue;
                }
                if (conn->TipReceived()) { ++it; continue; }
                if (!conn->VersionReceived()) {
                    if (InboundHandshakeDeadlineExpired(*conn, now)) {
                        pre_version_close.push_back(conn);
                        DecrConnCount_(conn);
                        it = peer_connections_.erase(it);
                        continue;
                    }
                    ++it; continue;
                }
                if (InboundHandshakeDeadlineExpired(*conn, now)) {
                    pre_tipsig_close.push_back(conn);
                    DecrConnCount_(conn);
                    it = peer_connections_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        if (!pre_version_close.empty()) {
            std::cerr << "  [reaper] closing " << pre_version_close.size()
                      << " pre-VERSION inbound conn(s) (>" << PRE_VERSION_GRACE_S
                      << "s with no peer bytes, or >" << PRE_VERSION_PROGRESS_GRACE_S
                      << "s when bytes were queued but no valid VERSION completed)\n";
            std::cerr.flush();
            for (auto& c : pre_version_close) RetireDetachedConnection_(c);
        }
        if (!pre_tipsig_close.empty()) {
            std::cerr << "  [reaper] closing " << pre_tipsig_close.size()
                      << " stuck-handshake inbound conn(s) (>" << STUCK_HANDSHAKE_GRACE_S
                      << "s without TIPSIG)\n";
            std::cerr.flush();
            for (auto& c : pre_tipsig_close) RetireDetachedConnection_(c);
        }
    }

    static constexpr uint32_t PEER_ROTATION_INTERVAL_S = 3600;
    void RotateOneRandomOutbound() {
        if (outbound_count_.load() < MAX_OUTBOUND_CONNECTIONS) return;

        struct Candidate {
            std::string key;
            std::string ip;
            std::shared_ptr<Connection> conn;
        };
        std::vector<Candidate> cands;
        std::unordered_set<std::string> current_subnets;
        {
            std::lock_guard<std::mutex> plk(peers_mutex_);
            std::lock_guard<std::mutex> blk(ban_mutex_);
            for (const auto& [k, c] : peer_connections_) {
                if (!c) continue;
                if (c->IsInbound()) continue;
                const std::string& ip = c->RemoteAddr();
                current_subnets.insert(Subnet16Prefix(ip));
                if (trusted_ips_.count(ip)) continue;
                if (fleet_anchor_ips_.count(ip)) continue;
                cands.push_back({k, ip, c});
            }
        }
        if (cands.empty()) return;

        thread_local std::mt19937 rng(
            std::random_device{}() ^
            (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count());
        std::uniform_int_distribution<size_t> pick(0, cands.size() - 1);
        const Candidate& victim = cands[pick(rng)];

        std::shared_ptr<Connection> victim_conn;
        {
            std::lock_guard<std::mutex> plk(peers_mutex_);
            auto it = peer_connections_.find(victim.key);
            if (it != peer_connections_.end() && it->second == victim.conn) {
                victim_conn = it->second;
                DecrConnCount_(it->second);
                peer_connections_.erase(it);
            }
        }
        if (!victim_conn) return;
        RetireDetachedConnection_(victim_conn);
        std::cerr << "  [rotate] closed outbound " << victim.key
                  << " (eclipse-defense rotation)\n";
        std::cerr.flush();

        std::pair<std::string, uint16_t> replacement{"", 0};
        {
            std::lock_guard<std::mutex> lk(peer_addr_mutex_);
            std::vector<std::pair<std::string, uint16_t>> fresh, any;
            for (const auto& [ip, port] : known_peer_addrs_) {
                if (ip == victim.ip) continue;
                const std::string sn = Subnet16Prefix(ip);
                if (current_subnets.count(sn) == 0) fresh.emplace_back(ip, port);
                else                                any.emplace_back(ip, port);
            }
            const auto& pool = !fresh.empty() ? fresh : any;
            if (!pool.empty()) {
                std::uniform_int_distribution<size_t> p2(0, pool.size() - 1);
                replacement = pool[p2(rng)];
            }
        }
        if (replacement.first.empty()) return;

        SpawnTrackedDial_(replacement.first, replacement.second);
    }

    void BroadcastStatsig(uint64_t local_mempool_size, uint32_t local_peer_count) {
        PeerManager pm(magic_, chain_.Height());
        auto msg = pm.BuildStatsigMessage(local_mempool_size, local_peer_count);
        BroadcastMessage(msg);
    }

    struct PeerStatsSnapshot {
        std::string ip;
        uint64_t    mempool_size;
        uint32_t    peer_count;
        int64_t     updated_at;
    };
    std::vector<PeerStatsSnapshot> SnapshotPeerStats() const {
        std::vector<PeerStatsSnapshot> out;
        std::lock_guard<std::mutex> lock(peer_stats_mutex_);
        out.reserve(peer_stats_.size());
        const int64_t now_s = (int64_t)std::chrono::duration_cast<
            std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        for (const auto& [ip, info] : peer_stats_) {
            if (now_s > info.updated_at + PEER_STATS_HARD_TTL_S) continue;
            PeerStatsSnapshot s;
            s.ip           = ip;
            s.mempool_size = info.mempool_size;
            s.peer_count   = info.peer_count;
            s.updated_at   = info.updated_at;
            out.push_back(std::move(s));
        }
        return out;
    }
    static constexpr int64_t PEER_STATS_HARD_TTL_S = 600;
    void RecordPeerStats(const std::string& peer_ip,
                         uint64_t mempool_size,
                         uint32_t peer_count,
                         int64_t now_s) {
        if (peer_ip.empty()) return;
        std::lock_guard<std::mutex> lock(peer_stats_mutex_);
        while (!peer_stats_order_.empty()) {
            auto oldest = peer_stats_.find(peer_stats_order_.front());
            if (oldest == peer_stats_.end()) {
                peer_stats_order_.pop_front();
                continue;
            }
            if (now_s <= oldest->second.updated_at +
                             PEER_STATS_HARD_TTL_S) break;
            peer_stats_order_.erase(oldest->second.order_it);
            peer_stats_.erase(oldest);
        }
        auto it = peer_stats_.find(peer_ip);
        if (it == peer_stats_.end()) {
            if (peer_stats_.size() >= PEER_STATS_CAP &&
                !peer_stats_order_.empty()) {
                auto oldest = peer_stats_.find(peer_stats_order_.front());
                if (oldest != peer_stats_.end()) {
                    peer_stats_order_.erase(oldest->second.order_it);
                    peer_stats_.erase(oldest);
                } else {
                    peer_stats_order_.pop_front();
                }
            }
            peer_stats_order_.push_back(peer_ip);
            auto order_it = std::prev(peer_stats_order_.end());
            it = peer_stats_.emplace(
                peer_ip, PeerStatsInfo{0, 0, 0, order_it}).first;
        } else {
            peer_stats_order_.splice(peer_stats_order_.end(),
                                     peer_stats_order_,
                                     it->second.order_it);
            it->second.order_it = std::prev(peer_stats_order_.end());
        }
        auto& info = it->second;
        info.mempool_size = mempool_size;
        info.peer_count   = peer_count;
        info.updated_at   = now_s;
    }

    void RequestChainSyncFromAllPeers() {
        auto getblocks = BuildChainLocatorGetBlocks();
        BroadcastMessage(getblocks);
        if (!chain_.IsEmpty()) {
            auto tip = chain_.TipCopy();
            BroadcastBlock(tip);
        }
    }

    using BlockCallback = std::function<void(const Block&, const std::string& peer)>;
    using TxCallback    = std::function<void(const Transaction&, const std::string& peer)>;
    using BlockAckCallback = std::function<void(const Hash256&, const std::string& peer_addr)>;

    void SetBlockCallback(BlockCallback cb) { on_block_ = cb; }
    void SetTxCallback(TxCallback cb)       { on_tx_ = cb; }
    void SetBlockAckCallback(BlockAckCallback cb) { on_block_ack_ = cb; }

    void BroadcastBlockBytesDirectExcept(const std::vector<uint8_t>& block_payload,
                                         const std::set<std::string>& exclude_addrs) {
        P2PMessage msg(magic_, MessageType::BLOCK, block_payload);
        std::vector<std::shared_ptr<Connection>> targets;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (auto& [key, conn] : peer_connections_) {
                if (!conn->IsConnected()) continue;
                if (exclude_addrs.count(conn->RemoteAddr())) continue;
                targets.push_back(conn);
            }
        }
        for (auto& conn : targets) conn->Send(msg);
    }

    size_t ConnectedPeers() const {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        size_t count = 0;
        for (const auto& [k, c] : peer_connections_)
            if (c->IsConnected()) ++count;
        return count;
    }

    // Current, not cumulative, IBD evidence. A raw/half-open socket does not
    // count, and a peer stops counting as soon as its connection is gone. The
    // zero-height connectivity rule also counts distinct source IPs: two
    // sockets behind one source are one observation.
    size_t VersionReadyPeers() const {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        std::unordered_set<std::string> distinct_ips;
        distinct_ips.reserve(peer_connections_.size());
        for (const auto& [k, c] : peer_connections_)
            if (c && c->IsConnected() && c->VersionReceived())
                distinct_ips.insert(c->RemoteAddr());
        return distinct_ips.size();
    }

    // Endpoint-aware presence check used by the directed-peer and seed
    // watchdogs. Simultaneous cross-dials legitimately retain either the
    // inbound or outbound socket, so direction must not decide whether an
    // endpoint is already represented in the live mesh.
    bool IsPeerConnected(const std::string& key) const {
        const auto colon = key.rfind(':');
        const std::string host =
            (colon == std::string::npos) ? key : key.substr(0, colon);
        std::unordered_set<std::string> connected_endpoints;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            connected_endpoints.reserve(peer_connections_.size());
            for (const auto& [stored_key, conn] : peer_connections_) {
                if (!conn || !conn->IsConnected()) continue;
                if (stored_key == key) return true;
                connected_endpoints.insert(conn->RemoteAddr());
            }
        }
        if (connected_endpoints.count(host)) return true;

        // Resolve outside peers_mutex_: DNS may block. This also makes a
        // hostname-configured outbound target match a retained inbound socket,
        // whose RemoteAddr() is the peer's numeric source address.
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
            return false;
        bool match = false;
        for (auto* it = res; it && !match; it = it->ai_next) {
            if (it->ai_family != AF_INET) continue;
            char ip_buf[INET_ADDRSTRLEN] = {0};
            auto* sin = reinterpret_cast<struct sockaddr_in*>(it->ai_addr);
            ::inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf));
            match = connected_endpoints.count(std::string(ip_buf)) != 0;
        }
        ::freeaddrinfo(res);
        return match;
    }

    // Count how many supplied seed hosts are represented by a connected peer
    // in either direction. Used by the seed-watchdog log gate: the
    // generic ConnectedPeers() counts inbound miners too, so at scale it
    // never drops below seeds.size() even when a seed is genuinely down,
    // masking the "re-dialing dropped seed(s)" signal. Each seed (a
    // hostname) is resolved to its IPv4 address(es) and matched against the
    // RemoteAddr() of every connected peer; a seed counts once if any resolved
    // IP is active. A completed inbound connection from that seed satisfies
    // presence after simultaneous cross-dial collapse. Best-effort: a seed
    // whose DNS fails to resolve is simply not
    // counted as connected (correct — if we can't resolve it we can't be sure
    // we hold it, and the watchdog should err toward surfacing the warning).
    size_t CountConnectedSeeds(const std::vector<std::string>& seeds) const {
        // Snapshot connected peer endpoints under the lock, then resolve
        // seeds outside the lock (getaddrinfo can block and must not be held
        // under peers_mutex_, which is on hot P2P paths).
        std::unordered_set<std::string> connected_endpoints;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (const auto& [k, c] : peer_connections_) {
                if (c && c->IsConnected())
                    connected_endpoints.insert(c->RemoteAddr());
            }
        }
        size_t connected = 0;
        for (const auto& seed : seeds) {
            // Match the literal dial target first, then resolve hostnames for
            // connections recorded by IP.
            if (connected_endpoints.count(seed)) { ++connected; continue; }
            struct addrinfo hints{}, *res = nullptr;
            hints.ai_family   = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (::getaddrinfo(seed.c_str(), nullptr, &hints, &res) != 0)
                continue;
            bool match = false;
            for (auto* it = res; it && !match; it = it->ai_next) {
                if (it->ai_family != AF_INET) continue;
                char ip_buf[INET_ADDRSTRLEN] = {0};
                auto* sin = reinterpret_cast<struct sockaddr_in*>(it->ai_addr);
                ::inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf));
                if (connected_endpoints.count(std::string(ip_buf))) match = true;
            }
            ::freeaddrinfo(res);
            if (match) ++connected;
        }
        return connected;
    }

    struct PeerInfo {
        uint64_t    node_id{0};
        std::string addr;
        std::string ip;
        std::string role;
        uint32_t    role_index{0};
        uint16_t    port;
        bool        inbound;
        uint64_t    services;
        uint64_t    bytes_sent;
        uint64_t    bytes_recv;
    };

    std::vector<PeerInfo> GetPeerInfoList() const {
        std::unordered_set<std::string> configured_fleet;
        std::unordered_map<std::string, uint32_t> configured_fleet_indices;
        {
            std::lock_guard<std::mutex> ban_lock(ban_mutex_);
            configured_fleet = fleet_anchor_ips_;
            configured_fleet_indices = fleet_anchor_indices_;
        }
        std::lock_guard<std::mutex> lock(peers_mutex_);
        std::vector<PeerInfo> out;
        for (const auto& [k, c] : peer_connections_) {
            if (!c->IsConnected()) continue;
            PeerInfo pi;
            pi.node_id    = c->PeerNonce();
            pi.addr       = k;
            pi.ip         = c->RemoteAddr();
            pi.port       = c->RemotePort();
            pi.inbound    = c->IsInbound();
            pi.services   = c->AdvertisedServices();
            const bool is_configured_fleet =
                configured_fleet.count(pi.ip) != 0;
            pi.role = ClassifyPeerTopologyRole(is_configured_fleet,
                                               pi.services);
            if (is_configured_fleet) {
                const auto fleet_index = configured_fleet_indices.find(pi.ip);
                if (fleet_index != configured_fleet_indices.end())
                    pi.role_index = fleet_index->second;
            }
            pi.bytes_sent = c->BytesSent();
            pi.bytes_recv = c->BytesRecv();
            out.push_back(pi);
        }
        return out;
    }

    size_t GetKnownPeerCount() const {
        std::lock_guard<std::mutex> lock(peer_addr_mutex_);
        return known_peer_addrs_.size();
    }

    std::string GetNetworkStats() const {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        std::ostringstream oss;
        oss << "Port:       " << port_ << "\n";
        size_t connected_count = 0;
        for (const auto& [k, c] : peer_connections_)
            if (c->IsConnected()) ++connected_count;
        oss << "Connected:  " << connected_count << " peers\n";
        oss << "Inbound:    " << inbound_count_.load() << "\n";
        oss << "Outbound:   " << outbound_count_.load() << "\n";
        uint64_t total_sent = 0, total_recv = 0;
        for (const auto& [k, c] : peer_connections_) {
            total_sent += c->BytesSent();
            total_recv += c->BytesRecv();
        }
        oss << "Bytes sent: " << total_sent / 1024 << " KB\n";
        oss << "Bytes recv: " << total_recv / 1024 << " KB\n";
        return oss.str();
    }

#ifdef VELD_TEST_HOOKS
    // Test-only seam for exercising the real stateful message handler without
    // starting listener/worker threads. Public release builds cannot define
    // VELD_TEST_HOOKS (constants.h enforces that profile boundary).
    void TestDispatchPeerMessage(Connection& conn, const P2PMessage& msg) {
        PeerState ps;
        ps.their_version = true;
        PeerManager pm(magic_, chain_.Height());
        (void)PeerProtocolStep(ps, conn, pm, msg,
                               conn.RemoteAddr() + ":" +
                                   std::to_string(conn.RemotePort()),
                               conn.IsInbound());
    }

    // Stateful variant for one-shot handshake transition regressions.  Using a
    // fresh PeerState for every dispatch would hide VERSION/VERACK replay bugs.
    void TestDispatchPeerMessageWithState(PeerState& ps, Connection& conn,
                                          const P2PMessage& msg) {
        PeerManager pm(magic_, chain_.Height());
        (void)PeerProtocolStep(ps, conn, pm, msg,
                               conn.RemoteAddr() + ":" +
                                   std::to_string(conn.RemotePort()),
                               conn.IsInbound());
    }

    std::shared_ptr<mining::ExpensivePowBudget>
    TestPowBudgetForSource(const std::string& source) {
        return PowBudgetForSource_(source);
    }

    void TestPrimePunchClientExchange(
            const std::shared_ptr<Connection>& coordinator,
            const std::array<uint8_t, 16>& hello_nonce,
            const std::array<uint8_t, 16>& request_nonce,
            uint64_t hello_expires_at, uint64_t request_expires_at,
            bool hello_live = true, bool request_live = true) {
        if (!coordinator) return;
        std::lock_guard<std::mutex> lock(punch_client_mutex_);
        PunchClientCoordinator state;
        state.connection = coordinator;
        state.connection_id = coordinator->Identity();
        state.hello_nonce = hello_nonce;
        state.hello_expires_at = hello_expires_at;
        state.hello_live = hello_live;
        state.request_nonce = request_nonce;
        state.request_expires_at = request_expires_at;
        state.request_live = request_live;
        punch_client_coordinators_[coordinator->Identity()] = state;
    }

    size_t TestPunchRegistrationCount() {
        std::lock_guard<std::mutex> lock(punchable_mutex_);
        return punchable_.size();
    }

    size_t TestPunchSeedRequestCount() {
        std::lock_guard<std::mutex> lock(punchable_mutex_);
        return punch_seed_requests_.size();
    }

    size_t TestPunchCandidateCount() {
        std::lock_guard<std::mutex> lock(punch_client_mutex_);
        return punch_candidates_.size();
    }

    void TestSuppressPunchNetworkDials(bool suppress) {
        test_suppress_punch_network_dials_.store(suppress,
                                                  std::memory_order_release);
    }

    uint64_t TestAuthorizedPunchDialCount() const {
        return test_authorized_punch_dials_.load(std::memory_order_acquire);
    }

    bool TestTakePunchDialBudget() { return TakePunchDialBudget_(); }

    std::array<uint64_t, 3> TestVersionCounters() const {
        return {received_version_count_.load(std::memory_order_acquire),
                genesis_match_count_.load(std::memory_order_acquire),
                genesis_mismatch_count_.load(std::memory_order_acquire)};
    }

    // Exercise locally verified height publication. A locally indexed side
    // branch must remain ineligible even though consensus retained it in the
    // fork tree.
    void TestRecordAcceptedPeerBlockEvidence(const std::string& peer_ip,
                                             const Hash256& hash) {
        RecordVerifiedPeerHeight_(peer_ip, hash);
    }

    void TestRecordPeerTip(const std::shared_ptr<Connection>& conn,
                           const Hash256& hash, int64_t now_s) {
        if (!conn) return;
        RecordPeerTip(*conn, hash, 0, now_s);
    }

    size_t TestPeerTipRecoveryHintCount() const {
        std::lock_guard<std::mutex> lock(peer_tips_mutex_);
        return peer_tip_recovery_hints_.size();
    }

    IngestEnqueueResult TestEnqueueBlockIngest(
            Block blk, size_t wire_bytes, const std::string& source_key) {
        return EnqueueBlockIngest(std::move(blk), wire_bytes,
                                  source_key, nullptr);
    }

    IngestEnqueueResult TestEnqueueBlockIngestFromConnection(
            Block blk, size_t wire_bytes, const std::string& source_key,
            const std::shared_ptr<Connection>& conn) {
        return EnqueueBlockIngest(std::move(blk), wire_bytes,
                                  source_key, conn);
    }

    void TestUseQueuedBlockIngest(bool enabled) {
        use_event_loop_ = enabled;
    }

    bool TestRegisterProtectedBlockRequest(Connection& conn,
                                           const Hash256& block_hash,
                                           uint64_t now = 0) {
        return RegisterProtectedBlockRequest_(conn, block_hash, now);
    }

    void TestExpireProtectedBlockRequest(uint64_t connection_id) {
        std::lock_guard<std::mutex> lk(ingest_mtx_);
        auto it = protected_block_requests_.find(connection_id);
        if (it != protected_block_requests_.end()) it->second.expires_at = 0;
    }

    size_t TestProtectedBlockRequestCount() {
        std::lock_guard<std::mutex> lk(ingest_mtx_);
        return protected_block_requests_.size();
    }

    size_t TestPendingBlockIngestBytes() {
        std::lock_guard<std::mutex> lk(ingest_mtx_);
        return ingest_pending_bytes_;
    }

    size_t TestPendingBlockIngestCount() {
        std::lock_guard<std::mutex> lk(ingest_mtx_);
        return PendingBlockCountLocked_(ingest_protected_lane_,
                                        ingest_normal_lane_);
    }

    size_t TestPendingProtectedBlockIngestCount() {
        std::lock_guard<std::mutex> lk(ingest_mtx_);
        return ingest_protected_lane_.pending_jobs;
    }

    size_t TestPendingNormalBlockIngestCount() {
        std::lock_guard<std::mutex> lk(ingest_mtx_);
        return ingest_normal_lane_.pending_jobs;
    }

    struct TestBlockIngestView {
        bool        valid{false};
        bool        protected_request{false};
        std::string source;
        std::string block_hash;
        uint64_t    connection_id{0};
    };

    TestBlockIngestView TestStartAndReleaseNextPendingBlock() {
        PendingBlockIngest job;
        {
            std::lock_guard<std::mutex> lk(ingest_mtx_);
            if (!TakeNextBlockIngestLocked_(job)) return {};
        }
        TestBlockIngestView view{true, job.protected_request,
                                 job.sender_source, job.block_hash,
                                 job.sender_connection_id};
        ReleasePendingBlockAccounting_(job);
        return view;
    }

    // Runs one admitted item through the same production consensus routine as
    // BlockIngestWorker. This is intentionally not a validation mock: focused
    // regressions use it to prove reject-cache behavior without racing a
    // background thread.
    bool TestProcessOnePendingBlockIngest() {
        PendingBlockIngest job;
        {
            std::lock_guard<std::mutex> lk(ingest_mtx_);
            if (!TakeNextBlockIngestLocked_(job)) return false;
        }
        struct Guard {
            NodeServer* self;
            PendingBlockIngest* job;
            ~Guard() { self->ReleasePendingBlockAccounting_(*job); }
        } guard{this, &job};
        ProcessBlockIngestJob_(job);
        return true;
    }

    uint64_t TestBlockIngestConsensusCallCount() const {
        return test_block_ingest_consensus_calls_.load(
            std::memory_order_acquire);
    }
    void TestResetBlockIngestOutcomeCounters() noexcept {
        test_block_ingest_consensus_calls_.store(
            0, std::memory_order_release);
        test_block_ingest_relay_calls_.store(0, std::memory_order_release);
        test_block_ingest_penalty_calls_.store(0, std::memory_order_release);
    }
    uint64_t TestBlockIngestRelayCount() const noexcept {
        return test_block_ingest_relay_calls_.load(
            std::memory_order_acquire);
    }
    uint64_t TestBlockIngestPenaltyCount() const noexcept {
        return test_block_ingest_penalty_calls_.load(
            std::memory_order_acquire);
    }

    bool TestIsBlockRejected(const Hash256& hash) const {
        std::lock_guard<std::mutex> lk(rejected_mutex_);
        return RejectedBlockSeenLocked_(HashToHex(hash));
    }

    bool TestReleaseOnePendingBlock() {
        return TestStartAndReleaseNextPendingBlock().valid;
    }

    void TestClearPendingBlockIngest() {
        std::lock_guard<std::mutex> lk(ingest_mtx_);
        ClearBlockIngestStateLocked_();
    }

    bool TestProtectedBlockQosRevoked(const std::string& source_ip) {
        std::lock_guard<std::mutex> lk(ingest_mtx_);
        auto it = protected_block_qos_revoked_until_.find(source_ip);
        return it != protected_block_qos_revoked_until_.end() &&
               MonotonicSeconds() < it->second;
    }

    void TestApplyHardBlockReject(const std::string& source,
                                  uint64_t connection_id,
                                  bool protected_request,
                                  const std::string& tag) {
        PendingBlockIngest job;
        job.sender_source = source;
        job.sender_connection_id = connection_id;
        job.protected_request = protected_request;
        HandleHardBlockReject_(job, tag);
    }

    static constexpr size_t TestBlockIngestCap() {
        return LAYER_C_BLOCK_INGEST_CAP;
    }
    static constexpr size_t TestBlockIngestByteCap() {
        return LAYER_C_BLOCK_INGEST_MAX_BYTES;
    }
    static constexpr size_t TestBlockIngestProtectedCap() {
        return LAYER_C_BLOCK_INGEST_PROTECTED_CAP;
    }
    static constexpr size_t TestBlockIngestProtectedByteCap() {
        return LAYER_C_BLOCK_INGEST_PROTECTED_MAX_BYTES;
    }
    static constexpr size_t TestBlockIngestNormalByteCap() {
        return LAYER_C_BLOCK_INGEST_NORMAL_MAX_BYTES;
    }

    void TestSetStartFailureStage(int stage) {
        test_start_failure_stage_.store(stage, std::memory_order_release);
    }
    // One-shot exception injection into the production event-loop path.
    // 1=worker allocation/setup, 2=message dispatch, 3=peer timer,
    // 4=peer cleanup. Test-only; public-release builds reject VELD_TEST_HOOKS.
    void TestSetEventLoopExceptionStage(int stage) {
        test_event_loop_exception_stage_.store(stage,
                                               std::memory_order_release);
    }
    uint64_t TestContainedNetworkExceptionCount() const {
        return test_contained_network_exceptions_.load(
            std::memory_order_acquire);
    }
    bool TestLifecycleRunning() const {
        return running_.load(std::memory_order_acquire);
    }
    bool TestListenerIsOpen() const {
        return veld::compat::IsValidSocket(listen_fd_);
    }
    size_t TestEventWorkerCount() const {
        std::lock_guard<std::mutex> lk(worker_registry_mutex_);
        return el_workers_.size();
    }
    size_t TestAcceptorThreadCount() const {
        return el_accept_threads_.size();
    }
    size_t TestFinalityWorkerCount() const {
        return (finality_vote_prefilter_thread_.joinable() ? 1u : 0u) +
               finality_vote_crypto_threads_.size();
    }

    // Drives the exact production FINVOTE admission path (rate budget,
    // wire-id/lane classification, global accounting and worker queues)
    // without requiring thousands of live TCP sockets.
    bool TestEnqueueFinalityVote(const std::vector<uint8_t>& wire,
                                 const std::string& source_ip,
                                 const std::string& sender_key = "") {
        return EnqueueFinalityVote_(wire, source_ip, sender_key);
    }
    size_t TestPendingFinalityVoteCount() const {
        std::lock_guard<std::mutex> lk(finality_vote_mtx_);
        return finality_vote_pending_count_;
    }
    size_t TestPendingFinalityVoteBytes() const {
        std::lock_guard<std::mutex> lk(finality_vote_mtx_);
        return finality_vote_pending_bytes_;
    }
    static constexpr size_t TestFinalityVoteJobCap() {
        return FINALITY_VOTE_JOB_CAP;
    }
    static constexpr size_t TestFinalityVoteByteCap() {
        return FINALITY_VOTE_BYTE_CAP;
    }
    static constexpr size_t TestFinalityVotePerLaneCap() {
        return FINALITY_VOTE_PER_LANE_CAP;
    }
    static constexpr size_t TestFinalityVotePerSourcePendingCap() {
        return FINALITY_VOTE_PER_SOURCE_PENDING_CAP;
    }

    // Deterministic registry-race seam. Production admission uses this locked
    // replacement primitive and handler cleanup uses the finalizer below.
    void TestRegisterAdmittedConnection(
            const std::string& key,
            const std::shared_ptr<Connection>& conn) {
        std::shared_ptr<Connection> superseded;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            (void)RegisterAdmittedConnectionLocked_(
                key, conn, superseded, false);
        }
        if (superseded) RetireDetachedConnection_(superseded);
    }

    bool TestRegisterProductionConnection(
            const std::string& key,
            const std::shared_ptr<Connection>& conn) {
        std::shared_ptr<Connection> superseded;
        bool admitted = false;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            admitted = RegisterAdmittedConnectionLocked_(
                key, conn, superseded, true);
        }
        if (superseded) RetireDetachedConnection_(superseded);
        if (!admitted && conn) RetireDetachedConnection_(conn);
        return admitted;
    }

    bool TestFinalizePeerConnection(
            const std::string& key,
            const std::shared_ptr<Connection>& expected) {
        return FinalizePeerConnection_(key, expected);
    }

    bool TestMappedConnectionIs(
            const std::string& key,
            const std::shared_ptr<Connection>& expected) const {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        auto it = peer_connections_.find(key);
        return it != peer_connections_.end() && it->second == expected;
    }

    std::pair<uint32_t, uint32_t> TestDirectionCounts() const {
        return {inbound_count_.load(std::memory_order_acquire),
                outbound_count_.load(std::memory_order_acquire)};
    }

    void TestTouchConnectionAccounting(
            const std::shared_ptr<Connection>& conn) {
        if (!conn) return;
        (void)CheckRateLimit(*conn);
        std::lock_guard<std::mutex> lock(ban_mutex_);
        getblocks_windows_[conn.get()] = MonotonicSeconds();
        getblocks_bytes_[conn.get()] = 1;
    }

    bool TestConnectionAccountingPresent(
            const std::shared_ptr<Connection>& conn) const {
        if (!conn) return false;
        std::lock_guard<std::mutex> lock(ban_mutex_);
        return msg_counts_.count(conn.get()) != 0 &&
               getblocks_bytes_.count(conn.get()) != 0;
    }

    bool TestReservePendingGetData(const std::string& hash_hex,
                                   uint64_t now_ts) {
        return ReservePendingGetData_(hash_hex, now_ts);
    }
    void TestErasePendingGetData(const std::string& hash_hex) {
        ErasePendingGetData_(hash_hex);
    }
    size_t TestPendingGetDataCount() const {
        std::lock_guard<std::mutex> lock(pending_gd_mutex_);
        return pending_getdata_.size();
    }
    static constexpr size_t TestPendingGetDataCap() {
        return PENDING_GETDATA_CAP;
    }
    uint32_t TestPendingDialCount() const {
        return pending_dials_.load(std::memory_order_acquire);
    }
    static constexpr uint32_t TestMaxOutboundConnections() {
        return MAX_OUTBOUND_CONNECTIONS;
    }
    uint16_t TestListeningPort() const {
        const SocketHandle fd = listen_fd_;
        if (!veld::compat::IsValidSocket(fd)) return 0;
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
            return 0;
        return ntohs(addr.sin_port);
    }
    uint16_t TestInboundPeerCachePort() const {
        return InboundPeerCachePort_();
    }

    void TestRecordClockDrift(const std::shared_ptr<Connection>& conn,
                              int64_t seconds, uint64_t updated_at) {
        if (!conn) return;
        std::lock_guard<std::mutex> lock(clock_drift_mutex_);
        clock_drift_samples_[conn->Identity()] = ClockDriftSample{
            seconds, updated_at, conn->RemoteAddr(), conn->IsInbound()};
    }

    void TestRecordVersionClaim(
            const std::shared_ptr<Connection>& conn, uint64_t height) {
        if (!conn) return;
        PeerWorkViewWriteGuard_ work_view_write(*this);
        if (!work_view_write.MayPublish()) return;
        // Match the production publication order inside the same odd
        // generation: the connection flag becomes true before the exact
        // source entry is installed, but no stable reader can observe either
        // half until the write guard publishes the following even generation.
        conn->MarkVersionReceived();
        std::string peer_ip = conn->RemoteAddr();
        size_t colon = peer_ip.find_last_of(':');
        if (colon != std::string::npos) peer_ip = peer_ip.substr(0, colon);
        {
            std::lock_guard<std::mutex> lock(peer_heights_mutex_);
            const PeerHeightClaim claim{
                peer_ip, height, PeerHeightNow_()};
            peer_heights_[conn->Identity()] = claim;
            peer_sync_heights_[conn->Identity()] = claim;
            peer_work_sources_[conn->Identity()] = PeerWorkSource{
                peer_ip, conn->IsInbound(), true, conn->HandshakeReady()};
        }
    }

    void TestMarkPeerHandshakeReady(
            const std::shared_ptr<Connection>& conn) {
        if (!conn) return;
        PeerWorkViewWriteGuard_ work_view_write(*this);
        if (!work_view_write.MayPublish()) return;
        conn->MarkHandshakeReady();
        std::lock_guard<std::mutex> lock(peer_heights_mutex_);
        auto source = peer_work_sources_.find(conn->Identity());
        if (source != peer_work_sources_.end())
            source->second.handshake_ready = true;
    }

    void TestRecordPeerSyncHeight(Connection& conn, uint64_t height) {
        RecordPeerSyncHeight_(conn, height);
    }

    void TestRecordVerifiedPeerHeight(const std::string& peer_ip,
                                      const Hash256& hash) {
        RecordVerifiedPeerHeight_(peer_ip, hash);
    }

    size_t TestPeerWorkSourceCount() const {
        std::lock_guard<std::mutex> lock(peer_heights_mutex_);
        return peer_work_sources_.size();
    }

    size_t TestPeerHeightClaimCount() const {
        std::lock_guard<std::mutex> lock(peer_heights_mutex_);
        return peer_heights_.size();
    }

    size_t TestPeerSyncClaimCount() const {
        std::lock_guard<std::mutex> lock(peer_heights_mutex_);
        return peer_sync_heights_.size();
    }

    size_t TestVerifiedPeerEvidenceCount() const {
        std::lock_guard<std::mutex> lock(peer_heights_mutex_);
        return peer_verified_heights_.size();
    }

    void TestSetPeerHeightClock(uint64_t now) {
        test_peer_height_now_.store(now, std::memory_order_release);
    }

    static uint64_t TestVersionHeightHintTtlSeconds() {
        return VERSION_HEIGHT_HINT_TTL_SECONDS;
    }

    bool TestTakeInvItemWork(const std::string& ip, uint64_t count) {
        return TakeIpByteBudget(inv_items_per_ip_, ip, count,
                                INV_ITEM_WORK_BUDGET_PER_60S);
    }
    bool TestTakeAddrItemWork(const std::string& ip, uint64_t count) {
        return TakeIpByteBudget(addr_items_per_ip_, ip, count,
                                ADDR_ITEM_WORK_BUDGET_PER_60S);
    }
    bool TestTakeAddrGlobalItemWork(uint64_t count) {
        static const std::string GLOBAL_KEY = "*";
        return TakeIpByteBudget(addr_items_global_, GLOBAL_KEY, count,
                                ADDR_ITEM_WORK_BUDGET_GLOBAL_PER_60S);
    }
    bool TestTakeGetDataItemWork(const std::string& ip, uint64_t count) {
        return TakeIpByteBudget(getdata_items_per_ip_, ip, count,
                                GETDATA_ITEM_WORK_BUDGET_PER_60S);
    }
    bool TestTakeGetBlocksRequest(const std::string& ip) {
        return TakeIpRateToken(getblocks_req_per_ip_, ip,
                               GETBLOCKS_REQUESTS_PER_60S);
    }
    bool TestTakeGetDataResponseBytes(const std::string& ip,
                                      uint64_t bytes) {
        return TakeIpByteBudget(getdata_response_bytes_per_ip_, ip, bytes,
                                GETDATA_RESPONSE_BUDGET_PER_60S);
    }
    bool TestTakeGetBlocksResponseBytes(const std::string& ip,
                                        uint64_t bytes) {
        return ReserveGetBlocksResponseBytes_(ip, bytes);
    }
    bool TestTakeGetBlocksBodyWork(const std::string& ip) {
        return ReserveGetBlocksBodyWork_(ip);
    }
    bool TestSendBoundedRecoveryGetData(Connection& source,
                                        const Hash256& hash) {
        return SendBoundedRecoveryGetData_(source, hash);
    }
    size_t TestKnownPeerCount() const {
        std::lock_guard<std::mutex> lock(peer_addr_mutex_);
        return known_peer_addrs_.size();
    }
    uint64_t TestAddKnownPeerSubnetScanCount() const {
        std::lock_guard<std::mutex> lock(peer_addr_mutex_);
        return test_add_known_peer_subnet_scan_count_;
    }
    void TestResetAddKnownPeerSubnetScanCount() {
        std::lock_guard<std::mutex> lock(peer_addr_mutex_);
        test_add_known_peer_subnet_scan_count_ = 0;
    }
    static constexpr uint64_t TestInvItemWorkCap() {
        return INV_ITEM_WORK_BUDGET_PER_60S;
    }
    static constexpr uint64_t TestAddrItemWorkCap() {
        return ADDR_ITEM_WORK_BUDGET_PER_60S;
    }
    static constexpr uint64_t TestAddrGlobalItemWorkCap() {
        return ADDR_ITEM_WORK_BUDGET_GLOBAL_PER_60S;
    }
    static constexpr uint64_t TestGetDataItemWorkCap() {
        return GETDATA_ITEM_WORK_BUDGET_PER_60S;
    }
    static constexpr uint32_t TestGetBlocksRequestCap() {
        return GETBLOCKS_REQUESTS_PER_60S;
    }
    static constexpr uint64_t TestGetDataResponseByteCap() {
        return GETDATA_RESPONSE_BUDGET_PER_60S;
    }
    static constexpr uint64_t TestGetBlocksResponseByteCap() {
        return GETBLOCKS_RESPONSE_BYTES_PER_IP_PER_10M;
    }
    static constexpr uint64_t TestGetBlocksResponseWorkCap() {
        return GETBLOCKS_RESPONSE_WORK_PER_IP_PER_10M;
    }
    static constexpr uint32_t TestRecoveryGetDataGlobalCap() {
        return RECOVERY_GETDATA_GLOBAL_PER_60S;
    }
    static constexpr uint32_t TestBanThreshold() {
        return BAN_THRESHOLD;
    }
    size_t TestViolationTableSize() const {
        std::lock_guard<std::mutex> lock(ban_mutex_);
        return violations_.size();
    }
    uint32_t TestViolationScore(const std::string& source) const {
        std::lock_guard<std::mutex> lock(ban_mutex_);
        auto it = violations_.find(source);
        return it == violations_.end() ? 0u : it->second.count;
    }
    size_t TestViolationLogRateTableSize() const {
        std::lock_guard<std::mutex> lock(ban_mutex_);
        return violation_log_rate_.size();
    }
    static constexpr size_t TestViolationTableCap() {
        return VIOLATION_TABLE_CAP;
    }
    static constexpr size_t TestViolationLogRateTableCap() {
        return VIOLATION_LOG_RATE_CAP;
    }
    uint64_t TestBanPersistCount() const {
        std::lock_guard<std::mutex> lock(ban_mutex_);
        return ban_persist_count_;
    }
    bool TestBansDirty() const {
        std::lock_guard<std::mutex> lock(ban_mutex_);
        return bans_dirty_;
    }
    bool TestVolatileRuntimeStateEmpty() {
        {
            std::lock_guard<std::mutex> lock(ban_mutex_);
            if (!msg_counts_.empty() || !msg_windows_.empty() ||
                !msg_violations_in_window_.empty() ||
                !getblocks_bytes_.empty() || !getblocks_windows_.empty())
                return false;
        }
        {
            std::lock_guard<std::mutex> lock(peer_heights_mutex_);
            if (!peer_work_sources_.empty() || !peer_heights_.empty() ||
                !peer_sync_heights_.empty() ||
                !peer_verified_heights_.empty())
                return false;
        }
        {
            std::lock_guard<std::mutex> lock(clock_drift_mutex_);
            if (!clock_drift_samples_.empty()) return false;
        }
        {
            std::lock_guard<std::mutex> lock(peer_tips_mutex_);
            if (!peer_tips_.empty()) return false;
        }
        {
            std::lock_guard<std::mutex> lock(pending_gd_mutex_);
            if (!pending_getdata_.empty() || !pending_getdata_order_.empty())
                return false;
        }
        {
            std::lock_guard<std::mutex> lock(peer_stats_mutex_);
            if (!peer_stats_.empty() || !peer_stats_order_.empty())
                return false;
        }
        std::lock_guard<std::mutex> lock(ip_rate_mutex_);
        return ip_table_last_prune_.empty() && addr_dial_per_ip_.empty() &&
               comine_rx_per_ip_.empty() && finality_vote_rx_per_ip_.empty() &&
               accept_rate_per_ip_.empty() && mempool_req_per_ip_.empty() &&
               statsig_rx_per_ip_.empty() && getblocks_req_per_ip_.empty() &&
               punch_control_rx_per_ip_.empty() && punchfwd_rx_per_ip_.empty() &&
               onionadv_rx_per_ip_.empty() && onionadv_relay_at_.empty() &&
               solution_rx_per_ip_.empty() &&
               recovery_getdata_global_.empty() && tipsig_processed_at_.empty() &&
               tipsig_getblocks_at_.empty() && tipsig_getdata_at_.empty() &&
               orphan_getblocks_at_.empty() && orphan_parent_getdata_at_.empty() &&
               accept_drop_log_at_.empty() && tx_bytes_per_ip_.empty() &&
               addr_items_per_ip_.empty() && addr_items_global_.empty() &&
               inv_items_per_ip_.empty() && getdata_items_per_ip_.empty() &&
               getdata_response_bytes_per_ip_.empty() &&
               getblocks_response_bytes_per_ip_.empty() &&
               getblocks_response_work_per_ip_.empty() &&
               getblocks_response_bytes_global_.empty() &&
               getblocks_response_work_global_.empty();
    }
    static constexpr size_t TestPeerStatsCap() {
        return PEER_STATS_CAP;
    }
#endif

private:
    uint16_t   port_;
    uint32_t   magic_;
    Blockchain& chain_;
    Mempool&    mempool_;

    std::atomic<uint64_t> local_services_{
        MessageType::NODE_FULL | MessageType::NODE_HOLE_PUNCH |
        MessageType::REQUIRED_NETWORK_IDENTITY_SERVICES};
    std::atomic<bool>   running_;
    std::atomic<bool>   activation_guard_refused_{false};
    bool                background_sync_mode_{false};
    SocketHandle        listen_fd_;
    // Start/Stop generation serialization is separate from worker publication:
    // Stop may join a tracked producer, so handoff must never wait on the mutex
    // that Stop holds for the complete lifecycle transition.
    mutable std::mutex  lifecycle_mutex_;
    mutable std::mutex  worker_registry_mutex_;
    PortMapper          port_mapper_;   // opt-in residential reachability (--reachable)
    // NAT hole-punch v2 state. All entries bind a fresh nonce to one live
    // connection identity. None of these tables survives Stop/Start.
    using PunchNonce = std::array<uint8_t, 16>;
    struct PunchRegistration {
        uint64_t connection_id = 0;
        PunchNonce hello_nonce{};
        uint64_t expires_at = 0;
    };
    struct PunchSeedRequest {
        uint64_t requester_connection_id = 0;
        PunchNonce request_nonce{};
        uint64_t expires_at = 0;
        std::unordered_map<std::string, PunchNonce> offers;
    };
    struct PunchClientCoordinator {
        std::weak_ptr<Connection> connection;
        uint64_t connection_id = 0;
        PunchNonce hello_nonce{};
        uint64_t hello_expires_at = 0;
        bool hello_live = false;
        PunchNonce request_nonce{};
        uint64_t request_expires_at = 0;
        bool request_live = false;
    };
    struct PunchCandidate {
        std::weak_ptr<Connection> coordinator;
        uint64_t coordinator_connection_id = 0;
        PunchNonce request_nonce{};
        PunchNonce target_nonce{};
        std::string endpoint;
        uint64_t expires_at = 0;
    };
    std::atomic<bool>   hole_punch_enabled_{false};
    std::unordered_map<std::string, PunchRegistration> punchable_;
    std::unordered_map<uint64_t, PunchSeedRequest> punch_seed_requests_;
    std::mutex          punchable_mutex_;
    std::unordered_map<uint64_t, PunchClientCoordinator>
        punch_client_coordinators_;
    std::deque<PunchCandidate> punch_candidates_;
    std::mutex          punch_client_mutex_;
    std::deque<uint64_t> punch_dial_attempts_;
    std::mutex          punch_dial_mutex_;
    static constexpr size_t MAX_PUNCHABLE = 4096;
    static constexpr size_t MAX_PUNCH_REQUESTS = 4096;
    static constexpr size_t MAX_PUNCH_CANDIDATES = 64;
    static constexpr size_t MAX_PUNCH_DIALS_PER_MINUTE = 8;

    static bool NewPunchNonce_(PunchNonce& out) {
        return veld::compat::SecureRandom(out.data(), out.size());
    }
    static bool PunchNonceEqual_(const PunchNonce& a,
                                 const PunchNonce& b) noexcept {
        uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) diff |= a[i] ^ b[i];
        return diff == 0;
    }
    static void AppendPunchNonce_(std::vector<uint8_t>& out,
                                  const PunchNonce& nonce) {
        out.insert(out.end(), nonce.begin(), nonce.end());
    }
    static bool ReadPunchNonce_(const std::vector<uint8_t>& in, size_t& off,
                                PunchNonce& out) {
        if (off > in.size() || in.size() - off < out.size()) return false;
        std::copy(in.begin() + static_cast<std::ptrdiff_t>(off),
                  in.begin() + static_cast<std::ptrdiff_t>(off + out.size()),
                  out.begin());
        off += out.size();
        return true;
    }
    static bool HolePunchCapable_(const Connection& conn) {
        return conn.IsConnected() && conn.HandshakeReady() &&
               (conn.AdvertisedServices() & MessageType::NODE_HOLE_PUNCH) != 0;
    }
    bool TakePunchDialBudget_() {
        const uint64_t now = MonotonicSeconds();
        std::lock_guard<std::mutex> lk(punch_dial_mutex_);
        while (!punch_dial_attempts_.empty() &&
               punch_dial_attempts_.front() + 60 <= now) {
            punch_dial_attempts_.pop_front();
        }
        if (punch_dial_attempts_.size() >= MAX_PUNCH_DIALS_PER_MINUTE)
            return false;
        punch_dial_attempts_.push_back(now);
        return true;
    }
    // Tor state
    TorController       tor_;                                 // .onion hidden service (--tor)
    std::atomic<bool>   tor_only_{false};                     // --tor-only: all dials via SOCKS, onion-only
    std::string         tor_only_onion_;                      // our .onion (launcher HS hostname file)
    mutable std::mutex  tor_only_onion_mu_;
    std::atomic<bool>  tor_want_{false};
    std::string        tor_data_directory_;
    mutable std::mutex tor_data_directory_mu_;
    std::thread         accept_thread_;

    // Event-loop driver mode. Production uses the bounded event-loop policy. The
    // thread-per-peer path is nonrelease-only and needs an explicit unsafe
    // acknowledgement at Start().
    bool                use_event_loop_ = false;
#ifdef VELD_TEST_HOOKS
    std::atomic<int>    test_start_failure_stage_{0};
    std::atomic<int>    test_event_loop_exception_stage_{0};
    std::atomic<uint64_t> test_contained_network_exceptions_{0};
    std::atomic<uint64_t> test_block_ingest_consensus_calls_{0};
    std::atomic<uint64_t> test_block_ingest_relay_calls_{0};
    std::atomic<uint64_t> test_block_ingest_penalty_calls_{0};
    std::atomic<bool> test_suppress_punch_network_dials_{false};
    std::atomic<uint64_t> test_authorized_punch_dials_{0};
#endif

    // A protocol state is valid only for the exact Connection that created it.
    // Key-only state let a same-endpoint re-dial replace peer_connections_[key]
    // before its handoff arrived, pairing the new socket with the old handshake
    // state (or letting stale cleanup erase the replacement state).
    struct BoundPeerState {
        std::shared_ptr<Connection> conn;
        PeerStatePtr                state;
    };
    std::unordered_map<std::string, BoundPeerState> peer_states_;

    struct EventLoopWorker {
        int                 worker_id    = 0;
        std::thread         thread;
        std::atomic<bool>   running{true};
        size_t              io_cursor{0};
        size_t              timer_cursor{0};

        std::unordered_map<std::string, BoundPeerState> peer_states;

        struct PendingNewPeer {
            std::string                     key;
            std::shared_ptr<Connection>     conn;
            PeerStatePtr                    ps;
            bool                            needs_initial_version_send{false};
        };
        std::mutex                          incoming_mtx;
        std::deque<PendingNewPeer>          incoming;
    };

    struct PendingBlockIngest {
        Block                       new_block;
        std::string                 sender_key;
        std::string                 sender_source;
        std::string                 block_hash;
        size_t                      wire_bytes{0};
        uint64_t                    sender_connection_id{0};
        bool                        protected_request{false};
        std::weak_ptr<Connection>   sender_conn;
        // One source-local lease pool is shared by every connection and queued
        // item for the same canonical transport identity. Holding the shared
        // pointer in the job prevents reconnects or map expiry from creating a
        // second concurrent VeldHash allowance while this item is in flight.
        std::shared_ptr<mining::ExpensivePowBudget> source_pow_budget;
    };

    struct BlockIngestSourceQueue {
        std::deque<PendingBlockIngest> jobs;
        size_t pending_jobs{0};       // queued + one possible in-flight job
        size_t pending_bytes{0};
        bool   in_round_robin{false};
    };

    struct BlockIngestLane {
        std::unordered_map<std::string, BlockIngestSourceQueue> sources;
        std::deque<std::string> round_robin;
        std::unordered_set<std::string> pending_hashes;
        size_t queued_jobs{0};
        size_t pending_jobs{0};
        size_t pending_bytes{0};
    };

    struct ProtectedBlockRequestLease {
        std::string block_hash;
        Hash256     expected_prev{};
        uint64_t    expires_at{0};
    };

    static constexpr size_t LAYER_C_BLOCK_INGEST_CAP = 256;
    static constexpr size_t LAYER_C_BLOCK_INGEST_MAX_BYTES =
        64ull * 1024ull * 1024ull;
    static constexpr size_t LAYER_C_BLOCK_INGEST_PROTECTED_CAP = 16;
    static constexpr size_t LAYER_C_BLOCK_INGEST_PROTECTED_MAX_BYTES =
        16'000'000ull;
    static constexpr size_t LAYER_C_BLOCK_INGEST_NORMAL_CAP =
        LAYER_C_BLOCK_INGEST_CAP - LAYER_C_BLOCK_INGEST_PROTECTED_CAP;
    static constexpr size_t LAYER_C_BLOCK_INGEST_NORMAL_MAX_BYTES =
        LAYER_C_BLOCK_INGEST_MAX_BYTES -
        LAYER_C_BLOCK_INGEST_PROTECTED_MAX_BYTES;
    static constexpr size_t LAYER_C_BLOCK_INGEST_PER_SOURCE_CAP = 2;
    static constexpr size_t LAYER_C_BLOCK_INGEST_NORMAL_PER_SOURCE_MAX_BYTES =
        16ull * 1024ull * 1024ull;
    static constexpr size_t LAYER_C_BLOCK_INGEST_PROTECTED_PER_SOURCE_MAX_BYTES =
        static_cast<size_t>(MAX_BLOCK_SIZE);
    static constexpr uint64_t PROTECTED_BLOCK_REQUEST_TTL_SECONDS = 30;
    static constexpr uint64_t PROTECTED_BLOCK_QOS_REVOKE_SECONDS = 600;
    static constexpr size_t   PROTECTED_BLOCK_QOS_REVOKE_CAP = 256;
    std::mutex                              ingest_mtx_;
    std::condition_variable                 ingest_cv_;
    BlockIngestLane                         ingest_protected_lane_;
    BlockIngestLane                         ingest_normal_lane_;
    std::unordered_map<uint64_t, ProtectedBlockRequestLease>
                                            protected_block_requests_;
    std::unordered_map<std::string, uint64_t>
                                            protected_block_qos_revoked_until_;
    size_t                                  ingest_pending_bytes_{0};
    uint8_t                                 ingest_protected_streak_{0};
    bool                                    ingest_protected_preempt_{false};
    std::thread                             ingest_worker_thread_;
    std::atomic<bool>                       ingest_running_{false};

    struct SourcePowBudgetEntry {
        std::shared_ptr<mining::ExpensivePowBudget> budget;
        uint64_t last_seen{0};
    };
    static constexpr size_t SOURCE_POW_BUDGET_CAP = 256;
    static constexpr uint64_t SOURCE_POW_BUDGET_TTL_SECONDS = 600;
    std::mutex source_pow_budget_mtx_;
    std::unordered_map<std::string, SourcePowBudgetEntry> source_pow_budgets_;

    struct FinalityVoteJob {
        std::vector<uint8_t> wire;
        std::string          source_ip;
        std::string          sender_key;
        std::string          wire_id;       // binary SHA-256d, 32 bytes
        std::string          candidate_id;  // signed claim + key, no signature
        std::string          lane_key;      // epoch/root/phase/round/key hash
    };
    struct FinalityRawSourceQueue {
        std::deque<FinalityVoteJob> jobs;
        bool scheduled{false};
    };
    struct FinalityPreparedLane {
        std::deque<FinalityVoteJob> jobs;
        bool scheduled{false};
        bool in_flight{false};
    };

    // CertAssembler admits at most 8,192 votes and its maximum live safety /
    // liveness envelope is two votes for each of 3,398 members (6,796).  Match
    // that count here and independently cap payload bytes.  Count bounds the
    // strings/container overhead which byte accounting cannot see.
    static constexpr size_t FINALITY_VOTE_JOB_CAP = 8'192;
    static constexpr size_t FINALITY_VOTE_BYTE_CAP =
        48ull * 1024ull * 1024ull;
    static constexpr size_t FINALITY_VOTE_PER_LANE_CAP = 2;
    // One normal relay may carry the entire 3,398-member honest snapshot.
    // Leave headroom for retries while reserving half of the global envelope
    // for other sources; the counter follows jobs through every queue stage.
    // An unbounded Sybil set can still fill the process-global remainder: at
    // that boundary gossip fails closed and honest votes must retry.  That is
    // the unavoidable liveness tradeoff of bounded unauthenticated intake;
    // event-loop CPU and RSS remain bounded and consensus rules do not change.
    static constexpr size_t FINALITY_VOTE_PER_SOURCE_PENDING_CAP = 4'096;
    static constexpr size_t FINALITY_VOTE_SOURCE_TABLE_CAP = 4'096;
    static constexpr uint32_t FINALITY_VOTE_PER_IP_PER_60S = 8'192;
    static constexpr size_t FINALITY_VOTE_RECENT_CAP = 8'192;
    static constexpr uint64_t FINALITY_VOTE_RECENT_TTL_SECONDS = 600;
    static_assert(P2P_FINALITY_VOTE_WIRE_BYTES * FINALITY_VOTE_JOB_CAP <=
                      FINALITY_VOTE_BYTE_CAP,
                  "FINVOTE queue byte cap must hold its count cap");

    mutable std::mutex finality_vote_mtx_;
    std::condition_variable finality_vote_raw_cv_;
    std::condition_variable finality_vote_ready_cv_;
    std::unordered_map<std::string, FinalityRawSourceQueue>
        finality_vote_raw_by_source_;
    std::deque<std::string> finality_vote_raw_rr_;
    std::unordered_map<std::string, FinalityPreparedLane>
        finality_vote_prepared_lanes_;
    std::deque<std::string> finality_vote_lane_rr_;
    std::unordered_set<std::string> finality_vote_pending_ids_;
    std::unordered_set<std::string> finality_vote_pending_candidate_ids_;
    std::unordered_map<std::string, size_t> finality_vote_lane_counts_;
    std::unordered_map<std::string, size_t> finality_vote_source_counts_;
    std::unordered_map<std::string, uint64_t> finality_vote_recent_invalid_;
    std::deque<std::pair<std::string, uint64_t>>
        finality_vote_recent_invalid_order_;
    struct FinalityCompletedCandidate {
        std::string lane_key;
        uint64_t timestamp{0};
    };
    // Successful verification closes one semantic candidate, not the whole
    // signer/round lane.  A second distinct claim must still reach the state
    // layer so an equivocation pair cannot be hidden by whichever vote arrived
    // first.  The lane becomes terminal only after two completed candidates.
    std::unordered_map<std::string, FinalityCompletedCandidate>
        finality_vote_completed_candidates_;
    std::deque<std::pair<std::string, uint64_t>>
        finality_vote_completed_candidate_order_;
    std::unordered_map<std::string, size_t>
        finality_vote_completed_lane_counts_;
    size_t finality_vote_pending_count_{0};
    size_t finality_vote_pending_bytes_{0};
    std::thread finality_vote_prefilter_thread_;
    std::vector<std::thread> finality_vote_crypto_threads_;
    std::atomic<bool> finality_vote_running_{false};
    std::atomic<bool> finality_vote_accepting_{false};

    std::vector<std::unique_ptr<EventLoopWorker>> el_workers_;
    std::vector<std::thread>                      el_accept_threads_;

    mutable std::mutex  peers_mutex_;
    std::unordered_map<std::string, std::shared_ptr<Connection>> peer_connections_;

    struct PeerThreadSlot {
        std::thread                           t;
        std::shared_ptr<std::atomic<bool>>    done;
    };
    std::mutex                   peer_threads_mutex_;
    std::vector<PeerThreadSlot>  peer_threads_;

    template <typename Fn>
    bool SpawnTrackedPeerThread(Fn&& fn) {
        // Registration and thread creation are one Stop-visible transaction.
        // Creating first and locking afterward let Stop drain an empty vector,
        // then the producer appended a joinable thread that outlived `this`.
        std::lock_guard<std::mutex> tl(peer_threads_mutex_);
        if (!running_.load(std::memory_order_acquire)) return false;

        std::vector<PeerThreadSlot> kept;
        kept.reserve(peer_threads_.size());
        for (auto& slot : peer_threads_) {
            if (slot.done && slot.done->load(std::memory_order_acquire)) {
                if (slot.t.joinable()) slot.t.join();
            } else {
                kept.push_back(std::move(slot));
            }
        }
        peer_threads_.swap(kept);
        if (peer_threads_.size() >= MAX_TRACKED_PEER_THREADS) return false;

        try {
            // Reserve before constructing std::thread.  If allocation failed
            // after the thread was started, destroying the joinable temporary
            // would call std::terminate.
            peer_threads_.reserve(peer_threads_.size() + 1);
            auto done = std::make_shared<std::atomic<bool>>(false);
            std::thread t([fn = std::forward<Fn>(fn), done]() mutable {
                try { fn(); } catch (...) {  }
                done->store(true, std::memory_order_release);
            });
            peer_threads_.push_back({std::move(t), std::move(done)});
            return true;
        } catch (...) {
            return false;
        }
    }

    bool SpawnTrackedDial_(const std::string& host, uint16_t port,
                           bool explicitly_trusted = false,
                           bool fleet_anchor = false) {
        PendingDialLease lease(*this);
        if (!lease) return false;
        return SpawnTrackedPeerThread(
            [this, host, port, explicitly_trusted, fleet_anchor,
             lease = std::move(lease)]() mutable {
                (void)lease; // RAII reservation lives through DNS/connect/setup.
                try {
                    ConnectToReserved_(host, port,
                                       explicitly_trusted, fleet_anchor);
                } catch (...) {
                }
            });
    }

    bool SpawnPunchDial_(const std::string& host, uint16_t port) {
#ifdef VELD_TEST_HOOKS
        test_authorized_punch_dials_.fetch_add(1,
                                               std::memory_order_acq_rel);
        if (test_suppress_punch_network_dials_.load(
                std::memory_order_acquire)) {
            return true;
        }
#endif
        return SpawnTrackedDial_(host, port);
    }

    std::atomic<uint32_t> inbound_count_;
    std::atomic<uint32_t> outbound_count_;
    std::atomic<uint32_t> pending_dials_{0};
    mutable std::mutex    pending_dial_mutex_;
    std::condition_variable pending_dial_cv_;
    uint32_t              max_inbound_connections_;

    static constexpr uint32_t MAX_INBOUND_CONNECTIONS_HARD = 2048;
    static constexpr uint32_t MAX_OUTBOUND_CONNECTIONS = 8;
    static constexpr uint32_t MAX_PENDING_DIALS = 16;
    static constexpr size_t   MAX_TRACKED_PEER_THREADS = 128;
    // A NAT may legitimately host several nodes, so the general per-IP cap stays
    // larger.  Unauthenticated pre-VERSION sockets are much cheaper to duplicate
    // and are capped separately to prevent reconnect churn from stacking dozens.
    static constexpr uint32_t PRE_VERSION_PER_IP_CAP = 4;

    static constexpr uint32_t PER_IP_OUTBOUND_CAP     = 1;
    static constexpr uint32_t PER_SUBNET_OUTBOUND_CAP = 2;

    static constexpr uint32_t ADDR_BOOK_PER_SUBNET_CAP = 8;
    static constexpr uint32_t ADDR_REQUEST_WINDOW_S    = 120;
    static constexpr uint8_t  ADDR_GREETING_MAX_COUNT  = 5;

    static std::string Subnet16Prefix(const std::string& ip) {
        size_t a = ip.find('.');
        if (a == std::string::npos) return ip;
        size_t b = ip.find('.', a + 1);
        if (b == std::string::npos) return ip;
        return ip.substr(0, b);
    }

    // Normalize peer addresses before applying per-IP connection limits.
    // Preserve bare IPv6 literals and remove ports only from bracketed IPv6 or
    // IPv4 endpoint forms.
    static std::string StripPort_(const std::string& addr) {
        if (!addr.empty() && addr.front() == '[') {          // [v6]:port
            const size_t close = addr.find(']');
            if (close != std::string::npos) return addr.substr(0, close + 1);
            return addr;
        }
        if (addr.find(':') != addr.rfind(':')) return addr;  // bare IPv6
        const size_t colon = addr.rfind(':');
        if (colon == std::string::npos) return addr;
        return addr.substr(0, colon);
    }

    bool CanDialOutboundIp(const std::string& target_ip) const {
        const std::string target = StripPort_(target_ip);
        if (trusted_ips_.count(target) || trusted_ips_.count(target_ip))
            return true;
        const std::string target_subnet = Subnet16Prefix(target);
        uint32_t per_ip = 0, per_subnet = 0;
        for (const auto& [k, c] : peer_connections_) {
            if (!c) continue;
            if (c->IsInbound()) continue;
            const std::string peer_ip = StripPort_(c->RemoteAddr());
            if (trusted_ips_.count(peer_ip)) continue;
            if (peer_ip == target) ++per_ip;
            if (Subnet16Prefix(peer_ip) == target_subnet) ++per_subnet;
        }
        if (per_ip      >= PER_IP_OUTBOUND_CAP)     return false;
        if (per_subnet  >= PER_SUBNET_OUTBOUND_CAP) return false;
        return true;
    }
    static constexpr uint32_t MAX_MSG_PER_SECOND = 2000;
    static constexpr uint32_t MAX_RATE_LIMIT_VIOLATIONS_PER_SECOND = 10;
    static constexpr uint32_t BAN_THRESHOLD = 100;

    mutable std::mutex                          peer_addr_mutex_;
    std::unordered_map<std::string, uint16_t>  known_peer_addrs_;
    std::unordered_map<std::string, uint32_t>  known_peer_subnet_counts_;
#ifdef VELD_TEST_HOOKS
    uint64_t test_add_known_peer_subnet_scan_count_{0};
#endif
    //  Parallel
    // last-seen timestamp map (epoch seconds, NOT monotonic — written
    // to disk and compared against real wall-clock on next load).
    // Updated by AddKnownPeer on every learn; consulted by
    // SavePeerCache to emit "fresh" entries and by LoadPeerCache to
    // skip entries older than PEER_CACHE_MAX_AGE_SECONDS. Lives in
    // its own map (not a struct rewrite of known_peer_addrs_) to
    // minimize blast radius — every caller of known_peer_addrs_
    // continues to compile unchanged; peer_addr_last_seen_ is only
    // touched by the four cache methods + AddKnownPeer.
    std::unordered_map<std::string, uint64_t>   peer_addr_last_seen_;
    std::string                                 peer_cache_path_;
    std::string                                 anchors_path_;
    static constexpr uint64_t PEER_CACHE_MAX_AGE_SECONDS = 30 * 24 * 3600ULL;
    static constexpr size_t   PEER_CACHE_MAX_ENTRIES     = 1000;
    static constexpr size_t   PEER_CACHE_MAX_FILE_BYTES  = 256 * 1024;
    static constexpr size_t   ANCHOR_COUNT               = 4;

    mutable std::mutex                          ban_mutex_;
    std::unordered_map<std::string, uint64_t>  banned_ips_;
    std::string                                 ban_file_path_;
    static constexpr uint64_t BAN_PERSIST_INTERVAL_SECONDS = 60;
    bool                                        bans_dirty_{false};
    uint64_t                                    last_ban_persist_at_{0};
    uint64_t                                    ban_persist_count_{0};
    static constexpr size_t VIOLATION_TABLE_CAP = 10'000;
    struct ViolationEntry {
        uint32_t count{0};
        uint64_t last_touch{0};
        std::list<std::string>::iterator order_it;
    };
    std::unordered_map<std::string, ViolationEntry> violations_;
    std::list<std::string> violation_order_;
    static constexpr uint64_t VIOLATION_TTL_SECONDS = 3600;
    static constexpr size_t VIOLATION_LOG_RATE_CAP = 4096;
    static constexpr uint64_t VIOLATION_LOG_RETENTION_SECONDS = 600;
    static constexpr uint32_t VIOLATION_LOG_GLOBAL_BURST = 100;
    struct ViolationLogRateEntry {
        uint64_t window_start{0};
        uint32_t count{0};
        uint64_t last_touch{0};
        std::list<std::string>::iterator order_it;
    };
    std::unordered_map<std::string, ViolationLogRateEntry>
        violation_log_rate_;
    std::list<std::string> violation_log_order_;
    uint64_t violation_log_global_window_{0};
    uint32_t violation_log_global_count_{0};

    using ViolationMap =
        std::unordered_map<std::string, ViolationEntry>;
    void EraseViolationLocked_(ViolationMap::iterator it) {
        if (it == violations_.end()) return;
        violation_order_.erase(it->second.order_it);
        violations_.erase(it);
    }
    void EraseViolationLocked_(const std::string& ip) {
        EraseViolationLocked_(violations_.find(ip));
    }
    using ViolationLogRateMap =
        std::unordered_map<std::string, ViolationLogRateEntry>;
    void EraseViolationLogRateLocked_(ViolationLogRateMap::iterator it) {
        if (it == violation_log_rate_.end()) return;
        violation_log_order_.erase(it->second.order_it);
        violation_log_rate_.erase(it);
    }
    // Endpoint strings are reusable.  Bind per-connection accounting to the
    // exact live object so stale cleanup cannot erase a same-key replacement's
    // budget (and every retired object can be erased unconditionally).
    std::unordered_map<const Connection*, uint32_t> msg_counts_;
    std::unordered_map<const Connection*, uint64_t> msg_windows_;
    std::unordered_map<const Connection*, uint32_t>
        msg_violations_in_window_;
    static constexpr uint64_t GETBLOCKS_BUDGET_BYTES = 200ull * 1024 * 1024;
    static constexpr uint64_t GETBLOCKS_BUDGET_WINDOW_SECONDS = 600;
    std::unordered_map<const Connection*, uint64_t> getblocks_bytes_;
    std::unordered_map<const Connection*, uint64_t> getblocks_windows_;
    std::unordered_set<std::string>            trusted_ips_;
    std::unordered_set<std::string>            fleet_anchor_ips_;
    std::unordered_map<std::string, uint32_t>  fleet_anchor_indices_;

    mutable std::mutex                           ip_rate_mutex_;
    std::unordered_map<const void*, uint64_t>    ip_table_last_prune_;
    struct IpRateSlot {
        uint64_t window_start = 0;
        uint32_t count        = 0;
    };
    std::unordered_map<std::string, IpRateSlot> addr_dial_per_ip_;
    std::unordered_map<std::string, IpRateSlot> comine_rx_per_ip_;
    std::unordered_map<std::string, IpRateSlot> finality_vote_rx_per_ip_;
    std::unordered_map<std::string, IpRateSlot> accept_rate_per_ip_;
    std::unordered_map<std::string, IpRateSlot> mempool_req_per_ip_;
    std::unordered_map<std::string, IpRateSlot> statsig_rx_per_ip_;
    std::unordered_map<std::string, IpRateSlot> getblocks_req_per_ip_;
    std::unordered_map<std::string, IpRateSlot> punch_control_rx_per_ip_;
    std::unordered_map<std::string, IpRateSlot> punchfwd_rx_per_ip_;
    std::unordered_map<std::string, IpRateSlot> onionadv_rx_per_ip_;
    std::unordered_map<std::string, uint64_t> onionadv_relay_at_;
    std::unordered_map<std::string, IpRateSlot> solution_rx_per_ip_;
    std::unordered_map<std::string, IpRateSlot> recovery_getdata_global_;
    std::unordered_map<std::string, uint64_t> tipsig_processed_at_;
    std::unordered_map<std::string, uint64_t> tipsig_getblocks_at_;
    std::unordered_map<std::string, uint64_t> tipsig_getdata_at_;
    std::unordered_map<std::string, uint64_t> orphan_getblocks_at_;
    std::unordered_map<std::string, uint64_t> orphan_parent_getdata_at_;
    std::unordered_map<std::string, uint64_t> accept_drop_log_at_;

    struct IpByteSlot {
        uint64_t window_start = 0;
        uint64_t bytes        = 0;
    };
    std::unordered_map<std::string, IpByteSlot> tx_bytes_per_ip_;
    std::unordered_map<std::string, IpByteSlot> addr_items_per_ip_;
    std::unordered_map<std::string, IpByteSlot> addr_items_global_;
    std::unordered_map<std::string, IpByteSlot> inv_items_per_ip_;
    std::unordered_map<std::string, IpByteSlot> getdata_items_per_ip_;
    std::unordered_map<std::string, IpByteSlot>
        getdata_response_bytes_per_ip_;
    std::unordered_map<std::string, IpByteSlot>
        getblocks_response_bytes_per_ip_;
    std::unordered_map<std::string, IpByteSlot>
        getblocks_response_work_per_ip_;
    std::unordered_map<std::string, IpByteSlot>
        getblocks_response_bytes_global_;
    std::unordered_map<std::string, IpByteSlot>
        getblocks_response_work_global_;
    // Per-source remote work envelopes. IBD block streaming uses GETBLOCKS and
    // is unaffected by INV/GETDATA item caps; the limits remain far above
    // honest control-plane cadence while bounding hash-table/disk lookup work.
    static constexpr uint64_t INV_ITEM_WORK_BUDGET_PER_60S = 32'000;
    static constexpr uint64_t GETDATA_ITEM_WORK_BUDGET_PER_60S = 32'000;
    static constexpr uint64_t ADDR_ITEM_WORK_BUDGET_PER_60S = 1'024;
    static constexpr uint64_t ADDR_ITEM_WORK_BUDGET_GLOBAL_PER_60S = 4'096;
    static constexpr uint32_t GETBLOCKS_REQUESTS_PER_60S = 120;
    static constexpr uint64_t GETDATA_RESPONSE_BUDGET_PER_60S =
        256ull * 1024ull * 1024ull;
    // Reconnects must not reset bulk-response work.  The per-IP envelope
    // mirrors the existing per-connection 200 MiB / 10 minute policy, while a
    // process-wide bucket caps distributed disk/body-load pressure.
    static constexpr uint64_t GETBLOCKS_RESPONSE_BYTES_PER_IP_PER_10M =
        200ull * 1024ull * 1024ull;
    static constexpr uint64_t GETBLOCKS_RESPONSE_WORK_PER_IP_PER_10M = 8'000;
    static constexpr uint64_t GETBLOCKS_RESPONSE_BYTES_GLOBAL_PER_60S =
        1ull * 1024ull * 1024ull * 1024ull;
    static constexpr uint64_t GETBLOCKS_RESPONSE_WORK_GLOBAL_PER_60S =
        32'000;
    static constexpr uint32_t RECOVERY_GETDATA_GLOBAL_PER_60S = 256;

    bool TakeIpRateToken(std::unordered_map<std::string, IpRateSlot>& tbl,
                          const std::string& ip, uint32_t cap_per_60s) {
        std::lock_guard<std::mutex> lk(ip_rate_mutex_);
        uint64_t now_s = MonotonicSeconds();
        static constexpr size_t IP_RATE_TABLE_CAP = 4096;
        auto found = tbl.find(ip);
        if (found == tbl.end() && tbl.size() >= IP_RATE_TABLE_CAP) {
            // A distributed fill must not turn every packet from an existing
            // peer into a 4,096-entry scan. Unknown-key reclamation runs at
            // most once per table per monotonic second; otherwise fail closed.
            uint64_t& last_prune = ip_table_last_prune_[&tbl];
            if (now_s > last_prune) {
                last_prune = now_s;
                for (auto it = tbl.begin(); it != tbl.end();) {
                    if (now_s > it->second.window_start + 60)
                        it = tbl.erase(it);
                    else
                        ++it;
                }
            }
            if (tbl.size() >= IP_RATE_TABLE_CAP) return false;
            found = tbl.end();
        }
        if (found == tbl.end())
            found = tbl.emplace(ip, IpRateSlot{}).first;
        auto& slot = found->second;
        if (now_s > slot.window_start + 60) {
            slot.window_start = now_s;
            slot.count        = 0;
        }
        if (slot.count >= cap_per_60s) return false;
        ++slot.count;
        return true;
    }

    bool TakeIpByteBudget(std::unordered_map<std::string, IpByteSlot>& tbl,
                          const std::string& ip, uint64_t bytes,
                          uint64_t cap, uint64_t window_seconds = 60) {
        std::lock_guard<std::mutex> lk(ip_rate_mutex_);
        uint64_t now_s = MonotonicSeconds();
        static constexpr size_t IP_BYTE_TABLE_CAP = 4096;
        auto found = tbl.find(ip);
        if (found == tbl.end() && tbl.size() >= IP_BYTE_TABLE_CAP) {
            uint64_t& last_prune = ip_table_last_prune_[&tbl];
            if (now_s > last_prune) {
                last_prune = now_s;
                for (auto it = tbl.begin(); it != tbl.end();) {
                    if (now_s > it->second.window_start + window_seconds)
                        it = tbl.erase(it);
                    else
                        ++it;
                }
            }
            if (tbl.size() >= IP_BYTE_TABLE_CAP) return false;
            found = tbl.end();
        }
        if (found == tbl.end())
            found = tbl.emplace(ip, IpByteSlot{}).first;
        auto& slot = found->second;
        if (now_s > slot.window_start + window_seconds) {
            slot.window_start = now_s;
            slot.bytes        = 0;
        }
        if (bytes > cap || slot.bytes > cap - bytes) return false;
        slot.bytes += bytes;
        return true;
    }

    bool IpByteBudgetHasRoom_(
            std::unordered_map<std::string, IpByteSlot>& tbl,
            const std::string& key, uint64_t cap,
            uint64_t window_seconds) {
        std::lock_guard<std::mutex> lk(ip_rate_mutex_);
        const uint64_t now_s = MonotonicSeconds();
        auto found = tbl.find(key);
        if (found == tbl.end()) return true;
        auto& slot = found->second;
        if (now_s > slot.window_start + window_seconds) {
            slot.window_start = now_s;
            slot.bytes = 0;
            return true;
        }
        return slot.bytes < cap;
    }

    bool ReserveGetBlocksBodyWork_(const std::string& ip) {
        static const std::string GLOBAL_KEY = "*";
        // Avoid even one disk/body load after either byte envelope is known to
        // be exhausted.  Exact byte reservation follows serialization and is
        // rechecked atomically under the same rate mutex.
        if (!IpByteBudgetHasRoom_(getblocks_response_bytes_per_ip_, ip,
                                  GETBLOCKS_RESPONSE_BYTES_PER_IP_PER_10M,
                                  600) ||
            !IpByteBudgetHasRoom_(getblocks_response_bytes_global_, GLOBAL_KEY,
                                  GETBLOCKS_RESPONSE_BYTES_GLOBAL_PER_60S,
                                  60)) {
            return false;
        }
        if (!TakeIpByteBudget(getblocks_response_work_per_ip_, ip, 1,
                              GETBLOCKS_RESPONSE_WORK_PER_IP_PER_10M,
                              600)) {
            return false;
        }
        return TakeIpByteBudget(getblocks_response_work_global_, GLOBAL_KEY, 1,
                                GETBLOCKS_RESPONSE_WORK_GLOBAL_PER_60S,
                                60);
    }

    bool ReserveGetBlocksResponseBytes_(const std::string& ip,
                                        uint64_t bytes) {
        static const std::string GLOBAL_KEY = "*";
        if (!TakeIpByteBudget(getblocks_response_bytes_per_ip_, ip, bytes,
                              GETBLOCKS_RESPONSE_BYTES_PER_IP_PER_10M,
                              600)) {
            return false;
        }
        return TakeIpByteBudget(getblocks_response_bytes_global_, GLOBAL_KEY,
                                bytes,
                                GETBLOCKS_RESPONSE_BYTES_GLOBAL_PER_60S,
                                60);
    }

    bool SendBoundedRecoveryGetData_(Connection& source,
                                     const Hash256& block_hash) {
        static const std::string GLOBAL_KEY = "*";
        if (!TakeIpRateToken(recovery_getdata_global_, GLOBAL_KEY,
                             RECOVERY_GETDATA_GLOBAL_PER_60S)) {
            return false;
        }
        PeerManager pm(magic_, chain_.Height());
        return source.Send(pm.BuildGetDataMessage(
            {InvItem(InvType::BLOCK, block_hash)}));
    }

    bool TakeKeyCooldown(std::unordered_map<std::string, uint64_t>& tbl,
                         const std::string& key, uint64_t cooldown_seconds,
                         uint64_t retention_seconds, size_t hard_cap) {
        if (key.empty() || hard_cap == 0) return false;
        std::lock_guard<std::mutex> lk(ip_rate_mutex_);
        const uint64_t now_s = MonotonicSeconds();
        auto found = tbl.find(key);
        if (found != tbl.end()) {
            if (now_s < found->second + cooldown_seconds) return false;
            found->second = now_s;
            return true;
        }
        if (tbl.size() >= hard_cap) {
            // Unknown-key reclamation is throttled per table. Existing keys are
            // always O(1), and a source-address spray cannot trigger a full
            // table walk for every packet.
            uint64_t& last_prune = ip_table_last_prune_[&tbl];
            if (now_s > last_prune) {
                last_prune = now_s;
                for (auto it = tbl.begin(); it != tbl.end();) {
                    if (now_s > it->second + retention_seconds)
                        it = tbl.erase(it);
                    else
                        ++it;
                }
            }
            if (tbl.size() >= hard_cap) return false;
        }
        tbl.emplace(key, now_s);
        return true;
    }

    mutable std::mutex              rejected_mutex_;
    static constexpr size_t   REJECT_CACHE_CAP     = 10000;
    static constexpr uint64_t REJECT_TTL_SECONDS   = 3600;
    std::unordered_map<std::string, uint64_t> rejected_blocks_;
    std::deque<std::string> rejected_blocks_fifo_;

    mutable std::mutex              solution_seen_mutex_;
    static constexpr size_t   SOLUTION_SEEN_CACHE_CAP   = 10000;
    static constexpr uint64_t SOLUTION_SEEN_TTL_SECONDS = 60;
    std::unordered_map<std::string, uint64_t> solution_seen_;
    std::deque<std::string> solution_seen_fifo_;

    bool MarkSolutionSeenIfNew_(const std::string& sol_hex) {
        std::lock_guard<std::mutex> lk(solution_seen_mutex_);
        uint64_t now_s = MonotonicSeconds();
        while (!solution_seen_fifo_.empty()) {
            auto it = solution_seen_.find(solution_seen_fifo_.front());
            if (it == solution_seen_.end()) {
                solution_seen_fifo_.pop_front();
                continue;
            }
            if (now_s - it->second > SOLUTION_SEEN_TTL_SECONDS) {
                solution_seen_.erase(it);
                solution_seen_fifo_.pop_front();
                continue;
            }
            break;
        }
        if (solution_seen_.count(sol_hex)) return true;
        solution_seen_[sol_hex] = now_s;
        solution_seen_fifo_.push_back(sol_hex);
        while (solution_seen_.size() > SOLUTION_SEEN_CACHE_CAP &&
               !solution_seen_fifo_.empty()) {
            solution_seen_.erase(solution_seen_fifo_.front());
            solution_seen_fifo_.pop_front();
        }
        return false;
    }

    static constexpr uint64_t PROACTIVE_PUSH_LIMIT_AT_HANDSHAKE = 10;

    bool RejectedBlockSeenLocked_(const std::string& hash_hex) const {
        auto it = rejected_blocks_.find(hash_hex);
        if (it == rejected_blocks_.end()) return false;
        uint64_t now_ts = MonotonicSeconds();
        return (now_ts - it->second) <= REJECT_TTL_SECONDS;
    }

    void RejectedBlockInsertLocked_(const std::string& hash_hex) {
        uint64_t now_ts = MonotonicSeconds();
        while (!rejected_blocks_fifo_.empty()) {
            const auto& front = rejected_blocks_fifo_.front();
            auto it = rejected_blocks_.find(front);
            if (it == rejected_blocks_.end()) {
                rejected_blocks_fifo_.pop_front();
                continue;
            }
            if ((now_ts - it->second) > REJECT_TTL_SECONDS) {
                rejected_blocks_.erase(it);
                rejected_blocks_fifo_.pop_front();
            } else {
                break;
            }
        }
        auto [it, inserted] = rejected_blocks_.try_emplace(hash_hex, now_ts);
        if (!inserted) { it->second = now_ts; return; }
        rejected_blocks_fifo_.push_back(hash_hex);
        while (rejected_blocks_.size() > REJECT_CACHE_CAP &&
               !rejected_blocks_fifo_.empty()) {
            rejected_blocks_.erase(rejected_blocks_fifo_.front());
            rejected_blocks_fifo_.pop_front();
        }
    }

public:
    void MarkBlockRejected(const std::string& hash_hex) {
        std::lock_guard<std::mutex> lk(rejected_mutex_);
        RejectedBlockInsertLocked_(hash_hex);
    }
    bool UnmarkBlockRejected(const std::string& hash_hex) {
        std::lock_guard<std::mutex> lk(rejected_mutex_);
        auto it = rejected_blocks_.find(hash_hex);
        if (it == rejected_blocks_.end()) return false;
        rejected_blocks_.erase(it);
        return true;
    }

    size_t ClearRejectCache() {
        std::lock_guard<std::mutex> lk(rejected_mutex_);
        size_t n = rejected_blocks_.size();
        rejected_blocks_.clear();
        rejected_blocks_fifo_.clear();
        return n;
    }
    size_t ClearOrphanPool() {
        std::lock_guard<std::mutex> lk(orphan_mutex_);
        size_t n = orphan_count_;
        orphan_pool_.clear();
        orphan_fifo_.clear();
        orphan_count_by_ip_.clear();
        orphan_bytes_by_ip_.clear();
        orphan_count_ = 0;
        orphan_bytes_ = 0;
        return n;
    }
private:

    struct PendingGetDataEntry {
        uint64_t ts{0};
        std::list<std::string>::iterator order_it;
    };
    mutable std::mutex pending_gd_mutex_;
    std::unordered_map<std::string, PendingGetDataEntry> pending_getdata_;
    std::list<std::string> pending_getdata_order_;
    static constexpr uint64_t PENDING_GETDATA_TTL_SECONDS = 60;
    static constexpr size_t   PENDING_GETDATA_CAP = 4096;

    void PrunePendingGetDataLocked_(uint64_t now_ts) {
        while (!pending_getdata_order_.empty()) {
            const std::string& oldest = pending_getdata_order_.front();
            auto it = pending_getdata_.find(oldest);
            if (it == pending_getdata_.end()) {
                pending_getdata_order_.pop_front();
                continue;
            }
            if (now_ts <= it->second.ts + PENDING_GETDATA_TTL_SECONDS)
                break;
            pending_getdata_order_.erase(it->second.order_it);
            pending_getdata_.erase(it);
        }
    }

    bool ReservePendingGetData_(const std::string& hash_hex,
                                uint64_t now_ts) {
        std::lock_guard<std::mutex> lock(pending_gd_mutex_);
        PrunePendingGetDataLocked_(now_ts);
        if (pending_getdata_.count(hash_hex) != 0) return false;
        if (pending_getdata_.size() >= PENDING_GETDATA_CAP) return false;
        pending_getdata_order_.push_back(hash_hex);
        auto order_it = std::prev(pending_getdata_order_.end());
        pending_getdata_.emplace(
            hash_hex, PendingGetDataEntry{now_ts, order_it});
        return true;
    }

    void ErasePendingGetData_(const std::string& hash_hex) {
        std::lock_guard<std::mutex> lock(pending_gd_mutex_);
        auto it = pending_getdata_.find(hash_hex);
        if (it == pending_getdata_.end()) return;
        pending_getdata_order_.erase(it->second.order_it);
        pending_getdata_.erase(it);
    }

    mutable std::mutex              orphan_mutex_;
    struct OrphanBlockEntry {
        Block block;
        std::string source;
        std::shared_ptr<mining::ExpensivePowBudget> source_pow_budget;
    };
    std::unordered_map<std::string, std::vector<OrphanBlockEntry>>
        orphan_pool_;
    static constexpr size_t MAX_ORPHAN_POOL = 256;
    // An unknown parent postpones memory-hard PoW verification. Once that
    // parent arrives, keep the unverified sibling fan-out strictly bounded so
    // one valid parent cannot trigger an attacker-selected verification burst.
    static constexpr size_t MAX_ORPHANS_PER_PARENT = 2;
    size_t orphan_count_ = 0;
    size_t orphan_bytes_ = 0;
    struct OrphanRec {
        uint64_t    ts;
        std::string prev_hex;
        Hash256     block_hash;
        size_t      size;
        std::string src_ip;
    };
    std::deque<OrphanRec> orphan_fifo_;
    std::unordered_map<std::string, size_t> orphan_count_by_ip_;
    std::unordered_map<std::string, size_t> orphan_bytes_by_ip_;
    static constexpr size_t   MAX_ORPHAN_PER_PEER       = 32;
    static_assert(IBD_GETBLOCKS_BATCH_BLOCKS <= MAX_ORPHAN_PER_PEER,
                  "IBD responses must fit the per-peer orphan frontier");
    static constexpr size_t   MAX_ORPHAN_BYTES_PER_PEER = 16 * 1024 * 1024;
    static constexpr uint64_t ORPHAN_TTL_SECONDS        = 600;

    BlockCallback    on_block_;
    TxCallback       on_tx_;
    BlockAckCallback on_block_ack_;
    std::function<void(uint64_t, const Hash256&, uint64_t, const std::vector<uint8_t>&)> solution_cb_;
    std::function<bool(uint64_t, const Hash256&, uint64_t, const Hash256&, const std::vector<uint8_t>&)> comine_cb_;
    FinalityVotePrecheck finality_vote_precheck_;
    FinalityVoteVerifier finality_vote_verifier_;
    std::vector<uint8_t> my_miner_script_;
    std::vector<uint8_t> my_comine_pubkey_;
    ComineSigner         my_comine_signer_;
    std::atomic<bool>    ibd_complete_flag_{false};
    std::atomic<int64_t> last_tipsig_catchup_at_seconds_{0};
    uint64_t self_nonce_{0};
    static constexpr size_t VERSION_FETCH_HINT_MIN_SUPPORT = 2;
    static constexpr uint64_t VERSION_HEIGHT_HINT_TTL_SECONDS = 120;
    static constexpr uint64_t VERSION_HEIGHT_HINT_MAX_AHEAD = 4'096;
    // Lock order for every work-view writer is:
    //   peer_work_view_writer_mutex_ -> node consensus-transition permit ->
    //   peer_heights_mutex_.
    // No callback is ever invoked while a peer registry/height mutex is held.
    mutable std::mutex peer_work_view_writer_mutex_;
    mutable std::mutex peer_work_view_transition_mutex_;
    PeerWorkViewTransitionFn peer_work_view_transition_fn_;
    std::atomic<uint64_t> peer_work_view_generation_{0};
    std::atomic<bool> peer_work_view_write_pending_{false};
    std::atomic<bool> peer_work_view_sequencer_wired_{false};
    std::atomic<bool> peer_work_view_sequencer_failed_{false};
    mutable std::mutex peer_heights_mutex_;
    // `peer_heights_` contains exact-connection unsigned VERSION hints.  They
    // are bounded, current-generation-only, and expire after two minutes even
    // if a connection remains open.  They never contribute to authoritative
    // height or work admission.
    // `peer_verified_heights_` contains only
    // hash/height pairs verified against our active chain (not merely a known
    // side branch).  Retaining the hash lets readers invalidate the evidence
    // immediately if a reorg moves that block off the active chain.
    // GetPeerHeightView filters both maps through the exact published,
    // handshake-ready source generation set. Disconnect retirement is itself
    // sequenced, so it lowers the result at the same linearization boundary
    // when the departing peer was its only evidence.
    struct PeerHeightClaim {
        std::string source_ip;
        uint64_t    height{0};
        uint64_t    updated_at{0};
    };
    struct PeerWorkSource {
        std::string source_ip;
        bool inbound{false};
        bool version_received{false};
        bool handshake_ready{false};
    };
    // This exact-generation source registry, rather than live socket atomics,
    // is the authoritative input to work admission. It is published together
    // with VERSION/VERACK and erased together with connection cleanup while the
    // node transition permit is held.
    std::unordered_map<uint64_t, PeerWorkSource> peer_work_sources_;
    std::unordered_map<uint64_t, PeerHeightClaim> peer_heights_;
    // Current outbound sync-floor announcements. VERSION initializes the
    // exact connection generation and TIPSIG refreshes it as the peer tip
    // advances. Readers accept only current handshake-ready outbound sources.
    std::unordered_map<uint64_t, PeerHeightClaim> peer_sync_heights_;
    struct VerifiedPeerHeight {
        Hash256  hash{};
        uint64_t height{0};
    };
    std::unordered_map<std::string, VerifiedPeerHeight>
        peer_verified_heights_;

#ifdef VELD_TEST_HOOKS
    std::atomic<uint64_t> test_peer_height_now_{0};
#endif

    uint64_t PeerHeightNow_() const {
#ifdef VELD_TEST_HOOKS
        const uint64_t forced =
            test_peer_height_now_.load(std::memory_order_acquire);
        if (forced != 0) return forced;
#endif
        return MonotonicSeconds();
    }

    static bool VersionHeightHintFresh_(uint64_t updated_at,
                                        uint64_t now) {
        return updated_at <= now &&
               now - updated_at <= VERSION_HEIGHT_HINT_TTL_SECONDS;
    }

    std::optional<uint64_t> CanonicalPeerEvidence_(
            const Hash256& hash) const {
        if (HashIsZero(hash)) return std::nullopt;
        // GetHeightByHash consults the canonical index without loading the
        // block body; side-branch-only hashes intentionally return null.
        return chain_.GetHeightByHash(hash);
    }

    void RecordVerifiedPeerHeight_(const std::string& peer_ip,
                                   const Hash256& hash) {
        if (peer_ip.empty()) return;
        PeerWorkViewWriteGuard_ work_view_write(*this);
        if (!work_view_write.MayPublish()) return;
        auto derived_height = CanonicalPeerEvidence_(hash);
        if (!derived_height.has_value()) return;
        std::lock_guard<std::mutex> lock(peer_heights_mutex_);
        auto& current = peer_verified_heights_[peer_ip];
        if (*derived_height >= current.height)
            current = VerifiedPeerHeight{hash, *derived_height};
    }

    void RecordPeerSyncHeight_(Connection& conn, uint64_t height) {
        if (!conn.IsConnected() || conn.RemoteAddr().empty()) return;
        std::string peer_ip = conn.RemoteAddr();
        size_t colon = peer_ip.find_last_of(':');
        if (colon != std::string::npos) peer_ip = peer_ip.substr(0, colon);
        PeerWorkViewWriteGuard_ work_view_write(*this);
        if (!work_view_write.MayPublish()) return;
        std::lock_guard<std::mutex> lock(peer_heights_mutex_);
        const auto source = peer_work_sources_.find(conn.Identity());
        if (source == peer_work_sources_.end() ||
            !source->second.handshake_ready ||
            source->second.source_ip != peer_ip)
            return;
        peer_sync_heights_[conn.Identity()] = PeerHeightClaim{
            peer_ip, height, PeerHeightNow_()};
    }

    void ForgetPeerHeightEvidence_(const std::string& peer_ip) {
        if (peer_ip.empty()) return;
        PeerWorkViewWriteGuard_ work_view_write(*this);
        if (!work_view_write.MayPublish()) return;
        std::lock_guard<std::mutex> lock(peer_heights_mutex_);
        peer_verified_heights_.erase(peer_ip);
    }

    struct PeerTipInfo {
        std::string source_ip;
        bool        inbound{false};
        Hash256  hash{};
        uint64_t height{0};
        int64_t  updated_at{0};
    };
    struct PeerTipRecoveryHint {
        Hash256  hash{};
        uint64_t height{0};
        int64_t  updated_at{0};
    };
    mutable std::mutex peer_tips_mutex_;
    std::unordered_map<uint64_t, PeerTipInfo> peer_tips_;
    std::unordered_map<std::string, PeerTipRecoveryHint>
        peer_tip_recovery_hints_;

    struct PeerStatsInfo {
        uint64_t mempool_size{0};
        uint32_t peer_count{0};
        int64_t  updated_at{0};
        std::list<std::string>::iterator order_it;
    };
    static constexpr size_t PEER_STATS_CAP = 4096;
    mutable std::mutex peer_stats_mutex_;
    std::unordered_map<std::string, PeerStatsInfo> peer_stats_;
    std::list<std::string> peer_stats_order_;
    std::atomic<uint64_t> received_version_count_{0};
    std::atomic<uint64_t> genesis_match_count_{0};
    std::atomic<uint64_t> genesis_mismatch_count_{0};
    static constexpr size_t   CLOCK_DRIFT_WINDOW = 16;
    static constexpr uint64_t CLOCK_DRIFT_TTL_SECONDS = 3600;
    struct ClockDriftSample {
        int64_t  delta_seconds{0};
        uint64_t updated_at{0};
        std::string source_ip;
        bool        inbound{false};
    };
    mutable std::mutex clock_drift_mutex_;
    std::unordered_map<uint64_t, ClockDriftSample> clock_drift_samples_;
    std::atomic<uint64_t> my_best_nonce_{0};
    std::atomic<uint64_t> my_mining_height_{0};
    mutable std::mutex    best_hash_mutex_;
    Hash256               my_best_hash_{};

    void ProcessOrphanChain(const Hash256& parent_hash, PeerManager& pm,
                            Connection& conn, const std::string& key,
                            uint32_t depth = 0) {
        if (depth >= 500) return;
        std::vector<OrphanBlockEntry> to_process;
        {
            std::lock_guard<std::mutex> ol(orphan_mutex_);
            std::string parent_hex = HashToHex(parent_hash);
            auto it = orphan_pool_.find(parent_hex);
            if (it == orphan_pool_.end()) return;
            to_process = std::move(it->second);
            if (orphan_count_ >= to_process.size())
                orphan_count_ -= to_process.size();
            else
                orphan_count_ = 0;
            for (const auto& entry : to_process) {
                size_t sz = entry.block.Serialize().size();
                if (orphan_bytes_ >= sz) orphan_bytes_ -= sz;
                else orphan_bytes_ = 0;
            }
            orphan_pool_.erase(it);
            for (auto fit = orphan_fifo_.begin(); fit != orphan_fifo_.end(); ) {
                if (fit->prev_hex != parent_hex) {
                    ++fit;
                    continue;
                }
                if (!fit->src_ip.empty()) {
                    auto cit = orphan_count_by_ip_.find(fit->src_ip);
                    if (cit != orphan_count_by_ip_.end()) {
                        if (cit->second > 0) --cit->second;
                        if (cit->second == 0)
                            orphan_count_by_ip_.erase(cit);
                    }
                    auto bit = orphan_bytes_by_ip_.find(fit->src_ip);
                    if (bit != orphan_bytes_by_ip_.end()) {
                        if (bit->second > fit->size)
                            bit->second -= fit->size;
                        else
                            orphan_bytes_by_ip_.erase(bit);
                    }
                }
                fit = orphan_fifo_.erase(fit);
            }
        }
        for (auto& entry : to_process) {
            if (!entry.source_pow_budget) continue;
            Block& orphan = entry.block;
            const auto admission = chain_.AddBlockDirect(
                orphan, false, true, false,
                mining::PowAdmissionContext::Peer(
                    entry.source, entry.source_pow_budget));
            if (admission.IsAccepted()) {
                uint64_t h = chain_.Height();
                RecordVerifiedPeerHeight_(entry.source, orphan.GetHash());
                int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                if (StripPort_(conn.RemoteAddr()) == entry.source)
                    RecordPeerTip(conn, orphan.GetHash(), orphan.height, now_s);
                if (h <= 10 || h % 100 == 0) {
                    if (!veld::net::g_suppress_sync.load() &&
                        !background_sync_mode_) {
                        std::lock_guard<std::mutex> lk(veld::net::g_stdout_mtx);
                        std::cout << "  [sync] height=" << h
                                  << "  supply=" << std::fixed << std::setprecision(2)
                                  << chain_.TotalSupplyVeld() << " VELD";
                        if (veld::DiagVerbose().load()) std::cout << " (reordered)";
                        std::cout << "\n";
                        std::cout.flush();
                    }
                }
                if (on_block_) on_block_(orphan, key);
                if (ibd_complete_flag_.load()) {
                    BroadcastMessage(
                        pm.BuildInvMessage({InvItem(InvType::BLOCK, orphan.GetHash())}),
                        key
                    );
                }
                ProcessOrphanChain(orphan.GetHash(), pm, conn, key, depth + 1);
            } else {
                const std::string tag = chain_.GetLastRejectTag();
                if (IsHardBlockReject_(tag))
                    RecordViolation(entry.source, 15, tag.c_str());
            }
        }
    }

    P2PMessage BuildChainLocatorGetBlocks() const {
        PeerManager pm(magic_, chain_.Height());
        if (chain_.IsEmpty()) {
            Hash256 zero{}; zero.fill(0);
            return pm.BuildGetBlocksMessage(zero);
        }
        uint64_t h = chain_.Height();

        std::vector<Hash256> extra;
        uint64_t step = 1;
        while (h > step && extra.size() < 16) {
            try {
                extra.push_back(chain_.GetBlock(h - step).GetHash());
            } catch (...) { break; }
            step *= 2;
        }
        try { extra.push_back(chain_.GetBlock(0).GetHash()); } catch (...) {}

        return pm.BuildGetBlocksMessage(chain_.TipCopy().GetHash(), extra);
    }

    void AcceptLoop() {
        while (running_) {
            struct PeerFdEntry {
                SocketHandle fd;
                std::shared_ptr<Connection> conn;
                std::string key;
            };
            std::vector<PeerFdEntry> peer_fds;
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                peer_fds.reserve(peer_connections_.size());
                for (const auto& [k, c] : peer_connections_) {
                    if (!c || !c->IsConnected()) continue;
                    SocketHandle f = c->Fd();
                    if (!veld::compat::IsValidSocket(f)) continue;
                    peer_fds.push_back({f, c, k});
                }
            }
#ifdef _WIN32
            std::vector<WSAPOLLFD> pfds;
            pfds.reserve(peer_fds.size() + 1);
            pfds.push_back({(SOCKET)listen_fd_, POLLIN, 0});
            for (const auto& e : peer_fds) {
                pfds.push_back({(SOCKET)e.fd, 0, 0});
            }
            int pr = ::WSAPoll(pfds.data(), (ULONG)pfds.size(), 250);
#else
            std::vector<struct pollfd> pfds;
            pfds.reserve(peer_fds.size() + 1);
            pfds.push_back({listen_fd_, POLLIN, 0});
            for (const auto& e : peer_fds) {
                pfds.push_back({e.fd, 0, 0});
            }
            int pr = ::poll(pfds.data(), pfds.size(), 250);
#endif
            if (pr == 0) continue;
            if (pr < 0) {
                if (running_) std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            const short DEATH_BITS = POLLERR;
            std::vector<std::shared_ptr<Connection>> died;
            std::vector<std::string> died_keys;
            for (size_t i = 1; i < pfds.size(); ++i) {
                short rev = pfds[i].revents;
                if (rev & DEATH_BITS) {
                    auto& conn = peer_fds[i - 1].conn;
                    if (!conn || !conn->IsConnected()) continue;
                    died.push_back(conn);
                    died_keys.push_back(peer_fds[i - 1].key);
                }
            }
            if (!died.empty()) {
                static std::atomic<uint64_t> pollerr_close_total{0};
                uint64_t total = pollerr_close_total.fetch_add(died.size()) + died.size();
                if (total / 100 != (total - died.size()) / 100) {
                    std::cerr << "  [phase-b] POLLERR closed " << died.size()
                              << " peer fd(s) this tick (cumulative=" << total << "):";
                    for (size_t i = 0; i < died_keys.size() && i < 3; ++i)
                        std::cerr << " " << died_keys[i];
                    if (died_keys.size() > 3)
                        std::cerr << " (+" << (died_keys.size() - 3) << " more)";
                    std::cerr << "\n";
                    std::cerr.flush();
                }
                for (auto& c : died) c->Close();
            }
            if ((pfds[0].revents & POLLIN) == 0) continue;

            struct sockaddr_in client_addr{};
            socklen_t addr_len = sizeof(client_addr);

            SocketHandle client_fd = ::accept(listen_fd_,
                (struct sockaddr*)&client_addr, &addr_len);

            if (!veld::compat::IsValidSocket(client_fd)) {
                if (running_) std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            std::string remote_addr;
            std::string key;
            auto conn = AdmitInboundConnection(client_fd, client_addr,
                                                key, remote_addr);
            if (!conn) continue;

            // Do not make the peer's first VERSION wait behind creation and
            // scheduling of a per-peer thread.  This accept loop remains the
            // default unless VELD_USE_EVENT_LOOP is explicitly enabled.
            PeerManager initial_pm(magic_, chain_.Height(),
                                   local_services_.load(std::memory_order_acquire));
            if (!conn->Send(initial_pm.BuildVersionMessage(
                    chain_.Height(), self_nonce_))) {
                FinalizePeerConnection_(key, conn);
                continue;
            }

            if (!SpawnTrackedPeerThread([this, conn, key]() {
                    HandlePeer(conn, key, true, true);
                })) {
                FinalizePeerConnection_(key, conn);
            }
        }
    }

    // Per-message dispatch slot. PeerProtocolStep is the event-loop driver's entry
    // point — given a fully-parsed P2PMessage and the peer's
    // externalized PeerState, it advances the per-peer protocol by
    // exactly one step and returns one of three outcomes:
    //
    //   Handled   — the message was processed in full; caller MUST
    //               continue to the next message (do NOT also run
    //               the legacy inline dispatch in HandlePeer for
    //               this same message — that would double-process).
    //
    //   NotHandled — this command isn't migrated yet; caller should
    //               fall through to HandlePeer's inline dispatch.
    //               Step 2 starts with PING / PONG only here; future
    //               steps move more handlers into this function until
    //               the inline chain is empty and HandlePeer's loop
    //               can be retired (Phase C step 4).
    //
    //   DropPeer  — fatal protocol violation or unrecoverable state;
    //               caller MUST break out of its loop and let the
    //               cleanup path run.
    //
    // No state mutates that the legacy inline dispatch wouldn't
    // mutate for the same message. Behavior is bit-identical to the
    // pre-extraction code path on a per-handler basis.
    enum class StepResult : uint8_t { Handled = 0, NotHandled = 1, DropPeer = 2 };
    StepResult PeerProtocolStep(PeerState& ps, Connection& conn,
                                PeerManager& pm, const P2PMessage& msg,
                                const std::string& key, bool ) {
        if (msg.command == MessageType::PING) {
            uint64_t nonce = 0;
            if (msg.payload.size() >= 8)
                for (int i = 0; i < 8; ++i)
                    nonce |= ((uint64_t)msg.payload[i] << (i * 8));
            conn.TrySend(pm.BuildPongMessage(nonce));
            return StepResult::Handled;
        }
        if (msg.command == MessageType::PONG) {
            (void)msg;
            return StepResult::Handled;
        }
        if (msg.command == MessageType::FINVOTE) {
            // Event-loop work stops at exact framing, two small hashes and a
            // bounded queue insertion. Canonical snapshot lookup happens on
            // the prefilter thread; ML-DSA verification happens only on the
            // capped crypto pool.  An accepted worker relays later.
            (void)EnqueueFinalityVote_(msg.payload, conn.RemoteAddr(), key);
            return StepResult::Handled;
        }
        if (msg.command == MessageType::GETADDR) {
            // Build the reply with the current chain height rather than the
            // PeerManager snapshot created when the connection opened.
            PeerManager fresh_pm(magic_, chain_.Height());
            auto peers = GetKnownPeers(30);
            conn.Send(fresh_pm.BuildAddrMessage(peers));
            return StepResult::Handled;
        }
        if (msg.command == MessageType::MEMPOOL) {
            // A MEMPOOL request has a zero-byte payload but a potentially large
            // CPU/lock response: stateful-root revalidation plus inventory
            // selection over as many as 50k entries.  The generic 2,000 msg/s
            // limiter is intentionally tuned for cheap relay bursts and is not
            // a defense for this command.  Serve at most once per connection
            // per 30 seconds and four times per source IP per minute (including
            // reconnects/NAT fan-out).  Normal peers request every 120 seconds.
            const auto now = PeerState::clock_t::now();
            if (!MarkMempoolInventoryRequestIfDue(ps, now) ||
                !TakeIpRateToken(mempool_req_per_ip_, conn.RemoteAddr(), 4)) {
                return StepResult::Handled;
            }
            // Advertise only canonical-input roots.  A child remains stored and
            // is announced normally on admission, but MEMPOOL inventory withholds
            // it until its parent confirms because block consensus does not allow
            // same-block parent/child spends. Stale/orphan roots stay withheld.
            auto txs = mempool_.GetBlockTransactions(
                500, MAX_BLOCK_SIZE, &chain_);
            std::vector<InvItem> items;
            for (const auto& tx : txs)
                items.emplace_back(InvType::TX, tx.GetTxID());
            if (!items.empty())
                conn.Send(pm.BuildInvMessage(items));
            return StepResult::Handled;
        }
        if (msg.command == MessageType::VERSION) {
            // VERSION is a one-shot state transition.  Replays previously
            // repeated duplicate-nonce scans, evidence writes, and clock work.
            if (ps.their_version || conn.VersionReceived())
                return StepResult::Handled;
            // VERSION handler.
            // Peer announces protocol version + start_height + nonce
            // + genesis hash; we sanity-check, gate self-connects and
            // genesis mismatches, populate a bounded fetch hint + peer-
            // tip sentinel + clock-drift sample, then reply VERACK and
            // possibly transition to handshake_done.
            //
            // BIT-IDENTICAL to inline. Notable preservation points:
            //
            // Defence layers (each layer drops the connection on fail):
            //   1) payload missing any mandatory field through the 32-byte
            //      genesis hash → "short_version"/"genesis_mismatch" and drop.
            //      A legacy 28-byte prefix is not chain-bound IBD evidence.
            //   2) Self-connect: their nonce == self_nonce_ →
            //      DropPeer (NO violation — we dialed ourselves, not
            //      an abuser). Layout: nonce at offset (29 + ua_len + 1).
            //      self_nonce_ may be 0 only if Start() CSPRNG failed;
            //      that path now aborts the binary before reaching
            //      here, so the != 0 guard is belt-and-suspenders.
            //   3) Genesis mismatch (or absent — pre- binary):
            //      DropPeer + weight-1 "genesis_mismatch" violation.
            //      Layout: genesis_hash at offset (28 + 1 + ua_len + 1
            //      + 8). Weight 1 so honest binary upgrades
            //      don't get banned for the brief mismatch burst.
            //
            // PeerState mutations:
            //   - ps.their_start_height = peer's claimed height (clamped
            //     to MAX_PLAUSIBLE_HEIGHT = 1e9 to prevent UINT64_MAX
            //     IBD-trap).
            //   - ps.their_version = true (only on success, AFTER
            //     genesis check passes).
            //   - ps.handshake_done = (version_sent && version_acked
            //     && their_version) — same three-way AND as VERACK.
            //
            // External state mutations (under appropriate mutexes):
            //   - peer_heights_[connection identity] = their_height plus IP —
            //     an unsigned, active-connection fetch hint. It expires after
            //     two minutes and is capped relative to our local height.
            //     GetPeerVerifiedHeight ignores this map entirely and derives
            //     its result only from locally accepted canonical block
            //     evidence.
            //     VERSION never enters peer_tips_; only locally known/accepted
            //     block hashes may vote there.
            //   - clock_drift_samples_ append (under clock_drift_mutex_).
            //     Per-IP cap = CLOCK_DRIFT_PER_IP, window cap =
            //     CLOCK_DRIFT_WINDOW. Samples used by mining gate
            //     when median drift > 600s. Junk samples (delta >
            //     +/- 1 year) silently dropped (peer's misconfigured
            //     clock, not evidence about ours).
            //   - received_version_count_.fetch_add(1) — observability.
            //   - genesis_mismatch_count_ / genesis_match_count_:
            //     atomic counters for operator visibility.
            //
            // Proactive block push on first-time handshake_done: same
            // logic as VERACK handler but ONLY fires here if handshake
            // completed in this branch (just_became_ready). Note: this
            // path does NOT have the sleep_for(10ms) yield that VERACK
            // has — historical comment says TCP's own flow control
            // handles backpressure on healthy connections (was found
            // to add IBD latency without benefit).
            if (msg.payload.size() < 29) {
                RecordViolation(conn.RemoteAddr(), 1, "short_version");
                return StepResult::DropPeer;
            }
            const size_t ua_len = (size_t)msg.payload[28];
            const size_t nonce_off = 28 + 1 + ua_len + 1;
            const size_t genesis_off = nonce_off + 8;
            if (msg.payload.size() < genesis_off + 32) {
                std::cerr << "  [peer] genesis-hash absent from VERSION by "
                          << conn.RemoteAddr() << " — dropping unbound peer\n";
                std::cerr.flush();
                genesis_mismatch_count_.fetch_add(1);
                RecordViolation(conn.RemoteAddr(), 1, "genesis_mismatch");
                return StepResult::DropPeer;
            }
            uint64_t announced_services = 0;
            for (int i = 0; i < 8; ++i)
                announced_services |=
                    ((uint64_t)msg.payload[4 + i]) << (i * 8);
            if ((announced_services &
                    MessageType::REQUIRED_NETWORK_IDENTITY_SERVICES) !=
                    MessageType::REQUIRED_NETWORK_IDENTITY_SERVICES) {
                std::cerr << "  [peer] network-identity services mismatch from "
                          << conn.RemoteAddr()
                          << " — peer lacks required rolling-reserve semantics\n";
                std::cerr.flush();
                RecordViolation(conn.RemoteAddr(), 1,
                                "network_identity_mismatch");
                return StepResult::DropPeer;
            }
            uint64_t announced_nonce = 0;
            for (int i = 0; i < 8; ++i)
                announced_nonce |= ((uint64_t)msg.payload[nonce_off + i]) << (i * 8);
            if (self_nonce_ != 0 && announced_nonce == self_nonce_) {
                std::cerr << "  [peer] self-connect detected from "
                          << conn.RemoteAddr()
                          << " (nonce matches our own startup nonce); dropping\n";
                std::cerr.flush();
                return StepResult::DropPeer;
            }
            {
                static const std::vector<uint8_t> LOCAL_GENESIS_BYTES = [] {
                    auto bytes = HexToBytes(GENESIS_HASH);
#ifdef VELD_TEST_HOOKS
                    // A pre-genesis source handoff has no coordinated-search
                    // hash yet. Test-only socket regressions
                    // bind both ends to the explicit all-zero placeholder so
                    // they can exercise the production parser/thread path.
                    // Public-release profiles reject VELD_TEST_HOOKS.
                    if (bytes.empty() && GENESIS_HASH[0] == '\0')
                        bytes.assign(32, 0);
#endif
                    return bytes;
                }();
                if (LOCAL_GENESIS_BYTES.size() != 32) {
                    std::cerr << "  [peer] local GENESIS_HASH is invalid; "
                              << "refusing every VERSION fail-closed\n";
                    std::cerr.flush();
                    return StepResult::DropPeer;
                }
                bool mismatch = false;
                for (int i = 0; i < 32; ++i) {
                    if (msg.payload[genesis_off + i] != LOCAL_GENESIS_BYTES[i]) {
                        mismatch = true;
                        break;
                    }
                }
                if (mismatch) {
                    std::ostringstream oss;
                    oss << std::hex << std::setfill('0');
                    for (int i = 0; i < 8; ++i)
                        oss << std::setw(2) << (int)msg.payload[genesis_off + i];
                    std::cerr << "  [peer] genesis-hash MISMATCH from "
                              << conn.RemoteAddr() << " — their genesis "
                              << oss.str() << "... != ours " << GENESIS_HASH
                              << " (first 8B). Dropping. Mismatched-genesis "
                              << "disconnect count: "
                              << (genesis_mismatch_count_.fetch_add(1) + 1)
                              << "\n";
                    std::cerr.flush();
                    RecordViolation(conn.RemoteAddr(), 1, "genesis_mismatch");
                    return StepResult::DropPeer;
                }
                genesis_match_count_.fetch_add(1);
            }
            if (announced_nonce != 0 &&
                CurrentLosesDuplicateNonce_(key, conn, announced_nonce)) {
                return StepResult::DropPeer;
            }
            // Advisory only. Role/capability bits are never authorization or
            // consensus inputs; the GUI uses them solely to label its direct
            // peer graph. Genesis validation above prevents cross-network
            // sessions from appearing in that graph.
            conn.MarkAdvertisedServices(announced_services);
            {
                uint64_t their_height = 0;
                for (int i = 0; i < 8; ++i)
                    their_height |= ((uint64_t)msg.payload[20 + i] << (i * 8));
                constexpr uint64_t MAX_PLAUSIBLE_HEIGHT = 1'000'000'000ULL;
                if (their_height > MAX_PLAUSIBLE_HEIGHT) {
                    std::cerr << "  [peer] VERSION claims implausible height "
                              << their_height << " — clamping to 0\n";
                    their_height = 0;
                }
                {
                    std::string peer_ip = conn.RemoteAddr();
                    size_t colon = peer_ip.find_last_of(':');
                    if (colon != std::string::npos) peer_ip = peer_ip.substr(0, colon);
                    std::lock_guard<std::mutex> lock(peer_heights_mutex_);
                    const PeerHeightClaim claim{
                        peer_ip, their_height, PeerHeightNow_()};
                    peer_heights_[conn.Identity()] = claim;
                    peer_sync_heights_[conn.Identity()] = claim;
                }

                ps.their_start_height = their_height;
                received_version_count_.fetch_add(1);

                {
                    uint64_t peer_ts = 0;
                    for (int i = 0; i < 8; ++i)
                        peer_ts |= ((uint64_t)msg.payload[12 + i] << (i * 8));
                    const int64_t local_ts_signed =
                        static_cast<int64_t>(std::time(nullptr));
                    constexpr uint64_t MAX_CLOCK_SAMPLE_DELTA =
                        86400ull * 365ull;
                    int64_t delta = 0;
                    bool admissible_delta = false;
                    if (local_ts_signed >= 0) {
                        const uint64_t local_ts =
                            static_cast<uint64_t>(local_ts_signed);
                        if (peer_ts >= local_ts) {
                            const uint64_t distance = peer_ts - local_ts;
                            if (distance < MAX_CLOCK_SAMPLE_DELTA) {
                                delta = static_cast<int64_t>(distance);
                                admissible_delta = true;
                            }
                        } else {
                            const uint64_t distance = local_ts - peer_ts;
                            if (distance < MAX_CLOCK_SAMPLE_DELTA) {
                                delta = -static_cast<int64_t>(distance);
                                admissible_delta = true;
                            }
                        }
                    }
                    if (admissible_delta) {
                        std::lock_guard<std::mutex> lock(clock_drift_mutex_);
                        const uint64_t now_mono = MonotonicSeconds();
                        for (auto it = clock_drift_samples_.begin();
                             it != clock_drift_samples_.end();) {
                            if (now_mono > it->second.updated_at +
                                    CLOCK_DRIFT_TTL_SECONDS) {
                                it = clock_drift_samples_.erase(it);
                            } else {
                                ++it;
                            }
                        }
                        const uint64_t connection_id = conn.Identity();
                        if (clock_drift_samples_.count(connection_id) == 0 &&
                            clock_drift_samples_.size() >= CLOCK_DRIFT_WINDOW) {
                            auto oldest = std::min_element(
                                clock_drift_samples_.begin(),
                                clock_drift_samples_.end(),
                                [](const auto& a, const auto& b) {
                                    return a.second.updated_at <
                                           b.second.updated_at;
                                });
                            if (oldest != clock_drift_samples_.end())
                                clock_drift_samples_.erase(oldest);
                        }
                        clock_drift_samples_[connection_id] =
                            ClockDriftSample{delta, now_mono,
                                             conn.RemoteAddr(),
                                             conn.IsInbound()};
                    }
                }

                uint32_t peer_proto_ver = 0;
                for (int i = 0; i < 4; ++i)
                    peer_proto_ver |= ((uint32_t)msg.payload[i] << (i * 8));
                if (peer_proto_ver < PROTOCOL_VERSION) {
                    std::cerr << "[p2p] peer " << conn.RemoteAddr()
                              << " uses protocol v" << peer_proto_ver
                              << " (we are v" << PROTOCOL_VERSION
                              << ") — chained-tx relay may lag\n";
                }
            }
            conn.TrySend(pm.BuildVerackMessage());
            bool just_became_ready = false;
            {
                // This is the single VERSION publication point. The raw claim
                // inserted above is intentionally invisible until its exact
                // source generation and handshake flags are installed here.
                PeerWorkViewWriteGuard_ work_view_write(*this);
                if (!work_view_write.MayPublish()) {
                    std::lock_guard<std::mutex> lock(peer_heights_mutex_);
                    peer_heights_.erase(conn.Identity());
                    peer_sync_heights_.erase(conn.Identity());
                    return StepResult::DropPeer;
                }
                ps.their_version = true;
                conn.MarkVersionReceived();
                if (ps.version_sent && ps.version_acked && ps.their_version) {
                    if (!ps.handshake_done) just_became_ready = true;
                    ps.handshake_done = true;
                    conn.MarkHandshakeReady();
                }
                std::string peer_ip = conn.RemoteAddr();
                size_t colon = peer_ip.find_last_of(':');
                if (colon != std::string::npos)
                    peer_ip = peer_ip.substr(0, colon);
                std::lock_guard<std::mutex> lock(peer_heights_mutex_);
                peer_work_sources_[conn.Identity()] = PeerWorkSource{
                    peer_ip, conn.IsInbound(), true, conn.HandshakeReady()};
            }

            if (just_became_ready) {
                if (conn.TrySend(BuildChainLocatorGetBlocks())) {
                    const auto now = std::chrono::steady_clock::now();
                    ps.last_getblocks = now;
                    ps.last_ibd_progress = now;
                    ps.ibd_observed_height = chain_.Height();
                }
                conn.TrySend(P2PMessage(magic_, MessageType::MEMPOOL));
            }
            if (just_became_ready && ibd_complete_flag_.load()) {
                uint64_t our_tip = chain_.Height();
                if (our_tip > ps.their_start_height) {
                    uint64_t send_from = ps.their_start_height + 1;
                    uint64_t n_to_send = our_tip - ps.their_start_height;
                    if (n_to_send > PROACTIVE_PUSH_LIMIT_AT_HANDSHAKE)
                        n_to_send = PROACTIVE_PUSH_LIMIT_AT_HANDSHAKE;
                    size_t bytes_sent = 0;
                    bool announced_first_body = false;
                    for (uint64_t offset = 0; offset < n_to_send; ++offset) {
                        if (!conn.CanQueueEventLoopSend(
                                static_cast<size_t>(MAX_BLOCK_SIZE) + 24u)) break;
                        Block blk;
                        try { blk = chain_.GetBlock(send_from + offset); }
                        catch (...) { break; }
                        auto payload = blk.Serialize();
                        if (bytes_sent + payload.size() >
                            MAX_GETBLOCKS_RESPONSE_BYTES) break;
                        if (!announced_first_body) {
                            if (!conn.TrySend(pm.BuildInvMessage(
                                    {InvItem(InvType::BLOCK,
                                             blk.GetHash())}))) break;
                            announced_first_body = true;
                        }
                        if (!conn.TrySend(P2PMessage(
                                magic_, MessageType::BLOCK, payload))) break;
                        bytes_sent += payload.size();
                    }
                }
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::VERACK) {
            // VERACK handler.
            // Peer acks our VERSION; if we've also seen their VERSION
            // we transition to handshake_done and immediately kick off
            // block sync (GETBLOCKS + MEMPOOL request + proactive push).
            //
            // BIT-IDENTICAL to inline. Notable preservation points:
            //   - This handler MUTATES PeerState: version_acked,
            //     handshake_done, last_getblocks and IBD progress state.
            //     All access is through ps.<field>.
            //   - handshake_done = (version_sent && version_acked &&
            //     their_version) — three-way AND. version_sent is set
            //     in HandlePeer's prologue (Send VERSION on connect);
            //     their_version is set in the VERSION handler.
            //   - On handshake_done: send GETBLOCKS (chain locator),
            //     reset the last-GETBLOCKS and IBD-progress timers, send
            //     MEMPOOL request, and proactively
            //     push blocks if we're past the peer's start_height.
            //   - Proactive push gated on ibd_complete_flag_ — a
            //     syncing peer shouldn't seed others.
            //   - their_start_height was populated by VERSION handler
            //     (which can arrive before OR after VERACK depending
            //     on relay race; either ordering reaches handshake_done
            //     by the same path).
            //   - n_to_send capped at MAX_GETBLOCKS_RESPONSE; bytes
            //     capped at MAX_GETBLOCKS_RESPONSE_BYTES.
            //   - sleep_for(10ms) every 100 blocks during push: NOT
            //     accidental — yields to other writers on the same
            //     send path so a long push doesn't starve PING/PONG
            //     timer messages on this connection. Preserve.
            if (ps.version_acked) return StepResult::Handled;
            const bool just_became_ready = !ps.handshake_done &&
                ps.version_sent && ps.their_version;
            if (just_became_ready) {
                PeerWorkViewWriteGuard_ work_view_write(*this);
                if (!work_view_write.MayPublish())
                    return StepResult::DropPeer;
                ps.version_acked = true;
                ps.handshake_done = true;
                conn.MarkHandshakeReady();
                std::lock_guard<std::mutex> lock(peer_heights_mutex_);
                auto source = peer_work_sources_.find(conn.Identity());
                if (source == peer_work_sources_.end())
                    return StepResult::DropPeer;
                source->second.handshake_ready = true;
            } else {
                ps.version_acked = true;
            }

            if (just_became_ready) {
                if (conn.TrySend(BuildChainLocatorGetBlocks())) {
                    const auto now = std::chrono::steady_clock::now();
                    ps.last_getblocks = now;
                    ps.last_ibd_progress = now;
                    ps.ibd_observed_height = chain_.Height();
                }
                P2PMessage mempool_req(magic_, MessageType::MEMPOOL);
                conn.TrySend(mempool_req);

                if (ibd_complete_flag_.load()) {
                    uint64_t our_tip = chain_.Height();
                    if (our_tip > ps.their_start_height) {
                        uint64_t send_from = ps.their_start_height + 1;
                        uint64_t n_to_send = our_tip - ps.their_start_height;
                        if (n_to_send > PROACTIVE_PUSH_LIMIT_AT_HANDSHAKE)
                            n_to_send = PROACTIVE_PUSH_LIMIT_AT_HANDSHAKE;
                        size_t sent_count = 0;
                        size_t bytes_sent = 0;
                        bool announced_first_body = false;
                        for (uint64_t offset = 0; offset < n_to_send; ++offset) {
                            if (!conn.CanQueueEventLoopSend(
                                    static_cast<size_t>(MAX_BLOCK_SIZE) + 24u)) break;
                            Block blk;
                            try { blk = chain_.GetBlock(send_from + offset); }
                            catch (...) { break; }
                            auto payload = blk.Serialize();
                            if (bytes_sent + payload.size() >
                                MAX_GETBLOCKS_RESPONSE_BYTES) break;
                            if (!announced_first_body) {
                                if (!conn.Send(pm.BuildInvMessage(
                                        {InvItem(InvType::BLOCK,
                                                 blk.GetHash())}))) break;
                                announced_first_body = true;
                            }
                            if (!conn.Send(P2PMessage(
                                    magic_, MessageType::BLOCK, payload))) break;
                            bytes_sent += payload.size();
                            ++sent_count;
                            if (sent_count % 100 == 0)
                                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        }
                    }
                }
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::COMINE) {
            // Mainnet Option-B derives near-miss credit exclusively from
            // on-chain NMS transactions. Legacy gossiped COMINE frames have no
            // authority and must not spend ML-DSA verification/callback/storage
            // work or be relayed. Keep the parser code below only for builds
            // that explicitly compile the legacy consensus policy.
            if constexpr (OPTION_B_CONSENSUS_GATE_ENABLED)
                return StepResult::Handled;
            if (msg.payload.size() < 2062) return StepResult::Handled;

            {
                const std::string sender_ip = conn.RemoteAddr();
                if (!TakeIpRateToken(comine_rx_per_ip_, sender_ip, 24))
                    return StepResult::Handled;
            }

            Hash256 prev_hash;
            std::copy(msg.payload.begin(), msg.payload.begin()+32, prev_hash.begin());
            uint64_t height = 0;
            for (int i=0;i<8;i++) height |= ((uint64_t)msg.payload[32+i] << (i*8));
            uint64_t best_nonce = 0;
            for (int i=0;i<8;i++) best_nonce |= ((uint64_t)msg.payload[40+i] << (i*8));
            Hash256 best_hash;
            std::copy(msg.payload.begin()+48, msg.payload.begin()+80, best_hash.begin());

            uint64_t our_mining_h = my_mining_height_.load(std::memory_order_relaxed);
            if (our_mining_h == 0) return StepResult::Handled;
            if (height != our_mining_h && height + 1 != our_mining_h)
                return StepResult::Handled;

            uint8_t script_len = msg.payload[80];
            if (script_len != 25) return StepResult::Handled;
            std::vector<uint8_t> miner_script(
                msg.payload.begin()+81, msg.payload.begin()+81+script_len);
            if (miner_script[0] != 0x76 || miner_script[1] != 0xA9 ||
                miner_script[2] != 0x14 || miner_script[23] != 0x88 ||
                miner_script[24] != 0xAC) {
                return StepResult::Handled;
            }
            size_t cursor = 81u + script_len;
            if (cursor + 2 > msg.payload.size()) return StepResult::Handled;
            uint16_t pk_len = (uint16_t)msg.payload[cursor] | ((uint16_t)msg.payload[cursor+1] << 8);
            cursor += 2;
            if (pk_len != 1952 || cursor + pk_len > msg.payload.size())
                return StepResult::Handled;
            std::vector<uint8_t> pubkey(msg.payload.begin()+cursor, msg.payload.begin()+cursor+pk_len);
            cursor += pk_len;
            if (cursor + 2 > msg.payload.size()) return StepResult::Handled;
            uint16_t sig_len = (uint16_t)msg.payload[cursor] | ((uint16_t)msg.payload[cursor+1] << 8);
            cursor += 2;
            if (sig_len == 0 || sig_len > 3309 || cursor + sig_len > msg.payload.size())
                return StepResult::Handled;
            std::vector<uint8_t> signature(msg.payload.begin()+cursor, msg.payload.begin()+cursor+sig_len);

            {
                std::array<uint8_t,1952> pk_arr;
                std::copy(pubkey.begin(), pubkey.end(), pk_arr.begin());
                auto h160 = ::veld::Hash160Compute(pk_arr);
                bool h160_ok = true;
                for (int i=0;i<20;i++) if (h160[i] != miner_script[3+i]) { h160_ok = false; break; }
                if (!h160_ok) return StepResult::Handled;
            }
            std::vector<uint8_t> challenge;
            challenge.insert(challenge.end(), prev_hash.begin(), prev_hash.end());
            for (int i=0;i<8;i++) challenge.push_back((height >> (i*8)) & 0xFF);
            for (int i=0;i<8;i++) challenge.push_back((best_nonce >> (i*8)) & 0xFF);
            challenge.insert(challenge.end(), best_hash.begin(), best_hash.end());
            challenge.insert(challenge.end(), miner_script.begin(), miner_script.end());
            ::veld::Hash256 challenge_hash = ::veld::Hash256d(challenge.data(), challenge.size());
            {
                std::array<uint8_t,1952> pk_arr;
                std::copy(pubkey.begin(), pubkey.end(), pk_arr.begin());
                if (!::veld::Verify(pk_arr, challenge_hash, signature))
                    return StepResult::Handled;
            }
            bool accepted = false;
            if (comine_cb_)
                accepted = comine_cb_(height, prev_hash, best_nonce, best_hash, miner_script);
            if (accepted) BroadcastMessage(msg, key);
            return StepResult::Handled;
        }
        if (msg.command == MessageType::SOLUTION) {
            // Under mainnet Option-B the winning/near-miss proof is the block or
            // on-chain NMS transaction, not an unauthenticated SOLUTION hint.
            // Dropping here prevents arbitrary peers from reaching callbacks,
            // ML-DSA signing, pending-solution storage, or relay.
            if constexpr (OPTION_B_CONSENSUS_GATE_ENABLED)
                return StepResult::Handled;
            // SOLUTION handler. Peer announces a block solution (nonce + solver
            // script). We register it via solution_cb_ and, if we're
            // mining the same height, respond with COMINE carrying
            // our best partial nonce (co-mining contribution).
            //
            // BIT-IDENTICAL to inline. Notable preservation points:
            //   Wire format v3 (PoW hard fork): nonce widened
            //     4→8 bytes. Min payload size = 49 (32 prev + 8 height
            //     + 8 nonce + 1 script_len). Smaller = silent ignore.
            //   - script_len MUST be exactly 25 (canonical P2PKH:
            //     OP_DUP OP_HASH160 0x14 <20-byte hash> OP_EQUALVERIFY
            //     OP_CHECKSIG). Other lengths silent fall-through.
            //   - P2PKH byte structure validated (5 specific bytes);
            //     non-P2PKH returns Handled (NOT a violation —
            //     attacker poisoning the callback shape is just dropped).
            //   - solution_cb_ fires with (height, prev_hash, nonce,
            //     solver_script). Used by the mining loop to register
            //     the partial solver against our local mining state.
            //   - COMINE response sent ONLY when ALL conditions hold:
            //       height == our_height + 1 (we're mining the next)
            //       ibd_complete_flag_ (we're not catching up)
            //       my_miner_script_ non-empty (we have a payout addr)
            //       my_mining_height_ == height (we're mining this h)
            //       my_comine_pubkey_.size() == 1952 (PQ pubkey is set)
            //       my_comine_signer_ callable (PQ signer ready)
            //   - COMINE challenge = SHA256d(prev_hash || height_le ||
            //     bn_le8 || best_hash || my_miner_script_). Builds
            //     the byte buffer manually here — exact ordering MUST
            //     match the verifier's reconstruction in COMINE handler
            //     (and in p2p.h's BuildCOMineMessage). Don't refactor
            //     the byte-building loops without checking COMINE.
            //   - LOCAL PeerManager pm constructed with chain_.Height()
            //     (CURRENT — not the stale outer pm) for
            //     BuildCOMineMessage. Preserves inline behavior; DO NOT
            //     "simplify" by using the passed-in pm parameter.
            //   - my_comine_signer_ wrapped in try/catch: a signer
            //     exception silently drops this response; never crashes
            //     the peer thread.
            //   - Forward original SOLUTION via BroadcastMessage(msg,
            //     key) so other peers see it (key excludes the sender).
            if (msg.payload.size() >= 49) {
                Hash256 prev_hash;
                std::copy(msg.payload.begin(), msg.payload.begin()+32, prev_hash.begin());
                uint64_t height = 0;
                for (int i=0;i<8;i++) height |= ((uint64_t)msg.payload[32+i] << (i*8));
                uint64_t nonce = 0;
                for (int i=0;i<8;i++) nonce |= ((uint64_t)msg.payload[40+i] << (i*8));
                uint8_t script_len = msg.payload[48];
                if (msg.payload.size() >= 49u + script_len && script_len == 25) {
                    std::vector<uint8_t> solver_script(
                        msg.payload.begin()+49, msg.payload.begin()+49+script_len);
                    if (solver_script[0] != 0x76 || solver_script[1] != 0xA9 ||
                        solver_script[2] != 0x14 || solver_script[23] != 0x88 ||
                        solver_script[24] != 0xAC) {
                        return StepResult::Handled;
                    }

                    // Deduplicate before either callback or ML-DSA signing.
                    // Replayed 74-byte SOLUTION frames previously forced both
                    // expensive paths up to the generic 2k-message/s limit.
                    std::vector<uint8_t> sol_id;
                    sol_id.reserve(32 + 8 + 8 + (size_t)script_len);
                    sol_id.insert(sol_id.end(), prev_hash.begin(), prev_hash.end());
                    for (int i = 0; i < 8; ++i)
                        sol_id.push_back((height >> (i*8)) & 0xFF);
                    for (int i = 0; i < 8; ++i)
                        sol_id.push_back((nonce >> (i*8)) & 0xFF);
                    sol_id.insert(sol_id.end(), solver_script.begin(),
                                  solver_script.end());
                    const std::string sol_hex = HashToHex(Hash256d(sol_id));
                    if (MarkSolutionSeenIfNew_(sol_hex))
                        return StepResult::Handled;
                    if (!TakeIpRateToken(solution_rx_per_ip_,
                                         conn.RemoteAddr(), 32))
                        return StepResult::Handled;

                    if (solution_cb_) solution_cb_(height, prev_hash, nonce, solver_script);
                    uint64_t our_height = chain_.Height();
                    if (height == our_height + 1
                        && ibd_complete_flag_.load()
                        && my_miner_script_.size() > 0
                        && my_mining_height_.load() == height
                        && my_comine_pubkey_.size() == 1952
                        && my_comine_signer_) {
                        PeerManager fresh_pm(magic_, chain_.Height());
                        Hash256 bh;
                        { std::lock_guard<std::mutex> lk(best_hash_mutex_); bh = my_best_hash_; }
                        uint64_t bn = my_best_nonce_.load();
                        std::vector<uint8_t> challenge;
                        challenge.insert(challenge.end(), prev_hash.begin(), prev_hash.end());
                        for (int i=0;i<8;i++) challenge.push_back((height >> (i*8)) & 0xFF);
                        for (int i=0;i<8;i++) challenge.push_back((bn >> (i*8)) & 0xFF);
                        challenge.insert(challenge.end(), bh.begin(), bh.end());
                        challenge.insert(challenge.end(), my_miner_script_.begin(), my_miner_script_.end());
                        std::vector<uint8_t> sig;
                        try { sig = my_comine_signer_(challenge); } catch (...) {}
                        if (!sig.empty()) {
                            conn.Send(fresh_pm.BuildCOMineMessage(prev_hash, height, bn, bh,
                                my_miner_script_, my_comine_pubkey_, sig));
                        }
                    }
                    BroadcastMessage(msg, key);
                }
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::TX) {
            if (msg.payload.empty()) {
                RecordViolation(conn.RemoteAddr(), 10, "tx_empty");
                return StepResult::Handled;
            }

            {
                static constexpr size_t MEMPOOL_BYTES_PER_PEER_PER_MIN = 2 * 1024 * 1024;
                uint64_t now_sec = MonotonicSeconds();
                if (now_sec > conn.mempool_budget_window + 60) {
                    conn.mempool_budget_window = now_sec;
                    conn.mempool_budget_used = 0;
                }
                if (conn.mempool_budget_used + msg.payload.size() > MEMPOOL_BYTES_PER_PEER_PER_MIN) {
                    RecordViolation(conn.RemoteAddr(), 5, "tx_byte_budget");
                    return StepResult::Handled;
                }
                conn.mempool_budget_used += msg.payload.size();
            }
            {
                static constexpr uint64_t MEMPOOL_BYTES_PER_IP_PER_MIN = 4 * 1024 * 1024;
                std::string ip_only = conn.RemoteAddr();
                {
                    size_t colon = ip_only.find_last_of(':');
                    if (colon != std::string::npos) ip_only = ip_only.substr(0, colon);
                }
                if (!TakeIpByteBudget(tx_bytes_per_ip_, ip_only,
                                      msg.payload.size(),
                                      MEMPOOL_BYTES_PER_IP_PER_MIN)) {
                    RecordViolation(conn.RemoteAddr(), 5, "tx_byte_budget_ip");
                    return StepResult::Handled;
                }
            }

            Transaction tx;
            size_t consumed = Transaction::Deserialize(msg.payload, 0, tx);
            if (consumed == 0 || consumed != msg.payload.size() ||
                tx.Serialize() != msg.payload) {
                RecordViolation(conn.RemoteAddr(), 15, "tx_deser");
                return StepResult::Handled;
            }
            // A canonical response consumes the request slot even if later
            // policy/consensus validation rejects it.  Otherwise a bad or stale
            // response suppresses retry from another peer until TTL expiry.
            ErasePendingGetData_(HashToHex(tx.GetTxID()));

            if (tx.IsValid()) {
                uint64_t input_total = 0, output_total = tx.TotalOutput();
                bool inputs_known = true;
                bool input_value_overflow = false;
                std::vector<InvItem> missing_parents;
                if (!tx.IsCoinbase()) {
                    for (const auto& inp : tx.inputs) {
                        auto utxo = chain_.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                        uint64_t value = 0;
                        if (utxo) {
                            value = utxo->value;
                        } else {
                            auto parent = mempool_.Get(inp.prev_tx_hash);
                            if (!parent || inp.prev_out_index >= parent->tx.outputs.size()) {
                                inputs_known = false;
                                if (missing_parents.size() < 16)
                                    missing_parents.emplace_back(InvType::TX, inp.prev_tx_hash);
                                continue;
                            }
                            value = parent->tx.outputs[inp.prev_out_index].value;
                        }
                        if (value > UINT64_MAX - input_total) {
                            input_value_overflow = true;
                            break;
                        }
                        input_total += value;
                    }
                }
                if (!inputs_known) {
                    // A missing parent is an orphan/race, not proof of abuse.
                    // The old tx_input_invalid weight repeatedly banned honest
                    // relays whose mempool graph differed by one transaction.
                    RecordViolation(conn.RemoteAddr(), 0, "tx_input_missing");
                    if (!missing_parents.empty())
                        conn.TrySend(pm.BuildGetDataMessage(missing_parents));
                    return StepResult::Handled;
                }
                if (input_value_overflow || input_total < output_total) {
                    RecordViolation(conn.RemoteAddr(), 10, "tx_value_invalid");
                    return StepResult::Handled;
                }
                uint64_t fee = input_total - output_total;
                if (fee < MIN_TX_FEE) {
                    RecordViolation(conn.RemoteAddr(), 5, "tx_fee_low");
                    return StepResult::Handled;
                }

                std::shared_ptr<mining::ExpensivePowBudget> nms_pow_budget;
                if (ExtractNmsFromTx(tx)) {
                    nms_pow_budget = PowBudgetForSource_(
                        StripPort_(conn.RemoteAddr()));
                    if (!nms_pow_budget) {
                        RecordViolation(conn.RemoteAddr(), 0,
                                        "nms_pow_budget_unavailable");
                        return StepResult::Handled;
                    }
                }
                auto add_res = mempool_.Add(
                    tx, fee, (uint32_t)chain_.Height(), chain_,
                    nms_pow_budget.get());
                if (add_res == Mempool::AddResult::ACCEPTED) {
                    if (on_tx_) on_tx_(tx, key);
                    BroadcastMessage(
                        pm.BuildInvMessage({InvItem(InvType::TX, tx.GetTxID())}),
                        key
                    );
                } else {
                    switch (add_res) {
                        case Mempool::AddResult::INVALID:
                            RecordViolation(conn.RemoteAddr(),
                                            MempoolRejectBanScore(add_res),
                                            "tx_mempool_invalid");
                            break;
                        case Mempool::AddResult::MISSING_INPUT:
                            // Parent disappeared after the handler's unlocked
                            // preflight but before Mempool::Add acquired its
                            // lock.  Treat this TOCTOU exactly like the ordinary
                            // missing-parent path above: request/drop, no ban.
                            RecordViolation(conn.RemoteAddr(),
                                            MempoolRejectBanScore(add_res),
                                            "tx_input_missing_race");
                            break;
                        case Mempool::AddResult::DEFERRED_LOCAL_WORK:
                            // Do not retain an attacker-sized remote payload
                            // in a second queue. The bounded source budget stays
                            // keyed to this canonical peer identity, and an
                            // exact retransmit can retry once capacity returns.
                            RecordViolation(conn.RemoteAddr(),
                                            MempoolRejectBanScore(add_res),
                                            "tx_nms_local_work_deferred");
                            break;
                        case Mempool::AddResult::MALFORMED_VALIDATOR_OP:
                            RecordViolation(conn.RemoteAddr(), 10,
                                            "tx_malformed_validator_op");
                            break;
                        case Mempool::AddResult::FEE_TOO_LOW:
                            RecordViolation(conn.RemoteAddr(), 5,
                                            "tx_mempool_fee_too_low");
                            break;
                        case Mempool::AddResult::DOUBLE_SPEND:
                            // A conflicting local mempool view is not a peer
                            // offence.  Drop it without feeding a ban cascade.
                            RecordViolation(conn.RemoteAddr(), 0,
                                            "tx_double_spend");
                            break;
                        case Mempool::AddResult::STAKE_EXCEEDS_BALANCE:
                            RecordViolation(conn.RemoteAddr(), 5,
                                            "tx_stake_exceeds_balance");
                            break;
                        case Mempool::AddResult::FULL:
                        case Mempool::AddResult::DUPLICATE:
                        case Mempool::AddResult::STAKE_ALREADY_PENDING:
                        case Mempool::AddResult::COINBASE_IMMATURE:
                        case Mempool::AddResult::VALIDATOR_STATE_COOLDOWN:
                        case Mempool::AddResult::RUNTIME_ADMISSION_CLOSED:
                            RecordViolation(conn.RemoteAddr(), 0,
                                            "tx_mempool_race");
                            break;
                        case Mempool::AddResult::PUBLIC_TESTNET_EXTERNAL_VALUE_DISABLED:
                            RecordViolation(conn.RemoteAddr(), 0,
                                            "tx_external_value_disabled");
                            break;
                        case Mempool::AddResult::ACCEPTED:
                            break;
                    }
                }
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::ADDR) {
            // ADDR handler.
            // Peer shares known peer addresses; we add them to our
            // address book and may dial a few.
            //
            // BIT-IDENTICAL to inline. Notable preservation points:
            //   - msg.payload.size() < 1: silent fall-through (no
            //     violation); inline behavior. Returns Handled.
            //   - Per-connection ADDR dial budget: 16 dials per 60s
            //     window, tracked via conn.addr_dial_window_start /
            //     conn.addr_dial_count (these are public Connection
            //     fields, NOT PeerState fields). Window resets when
            //     now_s > start + 60.
            //   - Per-IP dial budget: TakeIpRateToken on
            //     sender IP, max 16 per 60s — closes the bypass
            //     where one attacker IP opens 64 sockets each with
            //     a fresh 16-dial budget.
            //   - Per-message dial cap: 4 (anti-amplification).
            //   - Concurrency: peers_mutex_ guards peer_connections_
            //     existence check before dialing.
            //   - Spawn failure (pthread EAGAIN): caught + logged,
            //     dial dropped, doesn't crash the node.
            //   - All `continue`s in the body are FOR-LOOP continues
            //     (inner — stay valid in function scope).
            //
            // // GETADDR-gating: previously this handler accepted ANY
            // ADDR message a peer pushed at us. An attacker who
            // controlled a single peer could spam unsolicited ADDR
            // (200 IPs per message, 1 message per second) and
            // fill our address book with attacker-controlled IPs
            // from a single subnet — biasing every future outbound
            // dial toward the attacker's mesh.
            //
            // The gate now requires either:
            //   (a) we sent GETADDR to THIS peer within the last
            //       ADDR_REQUEST_WINDOW_S seconds (legitimate response),
            //   OR
            //   (b) this is the FIRST ADDR we've received from THIS
            //       peer post-handshake AND the count is ≤
            //       ADDR_GREETING_MAX_COUNT (legitimate post-handshake
            //       greeting that some implementations send unprompted).
            //
            // Anything else → drop without dialing + weight-1
            // "addr_unsolicited" violation so a burst attacker
            // accumulates ban credit gradually. Why weight 1: legit
            // peers may rarely double-send if their internal cache
            // refresh races our request; we don't want to ban a
            // momentarily-confused honest peer on the first offense.
            //
            // Note: even when the gate ACCEPTS the message, the
            // per-message dial cap (4) and per-connection 60s dial
            // budget (16) still apply — gate is additive, not
            // replacement.
            if (msg.payload.empty()) return StepResult::Handled;
            const uint8_t adv_count_hdr = msg.payload[0];
            static constexpr uint8_t MAX_ADDR_ENTRIES = 30;
            const size_t expected_size =
                1u + 6u * static_cast<size_t>(adv_count_hdr);
            if (adv_count_hdr > MAX_ADDR_ENTRIES ||
                msg.payload.size() != expected_size) {
                RecordViolation(conn.RemoteAddr(), 5, "addr_malformed");
                return StepResult::Handled;
            }
            const auto now_steady = std::chrono::steady_clock::now();
            const auto since_req = std::chrono::duration_cast<std::chrono::seconds>(
                now_steady - ps.last_getaddr_sent).count();
            const bool inside_req_window =
                (ps.last_getaddr_sent.time_since_epoch().count() != 0) &&
                (since_req >= 0) &&
                (since_req <= (int64_t)ADDR_REQUEST_WINDOW_S) &&
                !ps.addr_response_consumed;
            const bool greeting_ok = !ps.any_addr_received &&
                                     ps.handshake_done &&
                                     (adv_count_hdr <= ADDR_GREETING_MAX_COUNT);
            if (!inside_req_window && !greeting_ok) {
                RecordViolation(conn.RemoteAddr(), 1, "addr_unsolicited");
                return StepResult::Handled;
            }
            // Consume the authorization before parsing/dialing.  A malformed
            // or work-budget-exhausted response must not leave a reusable
            // 120-second CPU authorization behind.
            if (inside_req_window) ps.addr_response_consumed = true;
            ps.any_addr_received = true;

            if (msg.payload.size() >= 1) {
                uint8_t count = msg.payload[0];
                if (!TakeIpByteBudget(addr_items_per_ip_, conn.RemoteAddr(),
                                      count,
                                      ADDR_ITEM_WORK_BUDGET_PER_60S)) {
                    return StepResult::Handled;
                }
                static const std::string GLOBAL_KEY = "*";
                if (!TakeIpByteBudget(addr_items_global_, GLOBAL_KEY, count,
                                      ADDR_ITEM_WORK_BUDGET_GLOBAL_PER_60S)) {
                    return StepResult::Handled;
                }
                size_t pos = 1;
                uint64_t now_s = MonotonicSeconds();
                if (now_s > conn.addr_dial_window_start + 60) {
                    conn.addr_dial_window_start = now_s;
                    conn.addr_dial_count = 0;
                }
                const std::string sender_ip = conn.RemoteAddr();
                int dials_in_this_msg = 0;
                for (uint8_t i = 0; i < count && pos + 6 <= msg.payload.size(); ++i) {
                    uint32_t ip_raw = msg.payload[pos]
                                    | ((uint32_t)msg.payload[pos+1] << 8)
                                    | ((uint32_t)msg.payload[pos+2] << 16)
                                    | ((uint32_t)msg.payload[pos+3] << 24);
                    uint16_t port = msg.payload[pos+4] | ((uint16_t)msg.payload[pos+5] << 8);
                    pos += 6;
                    struct in_addr addr;
                    addr.s_addr = ip_raw;
                    char ip_str[INET_ADDRSTRLEN];
                    ::inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
                    const std::string advertised_ip(ip_str);
                    // ADDR is peer-controlled.  Keep private, loopback,
                    // multicast, benchmark and documentation ranges out of the
                    // address book and dial path; direct operator/LAN peers are
                    // unaffected because they do not pass through ADDR.
                    if (port == 0 || !IsPublicRoutableIPv4(advertised_ip))
                        continue;
                    AddKnownPeer(advertised_ip, port);
                    if (dials_in_this_msg >= 4) continue;
                    if (conn.addr_dial_count >= 16) continue;
                    if (!TakeIpRateToken(addr_dial_per_ip_, sender_ip, 16)) continue;
                    {
                        std::lock_guard<std::mutex> lk(peers_mutex_);
                        std::string pkey = std::string(ip_str) + ":" + std::to_string(port);
                        // this ADDR-driven dial is the
                        // actual eclipse vector, yet CanDialOutboundIp had
                        // exactly one caller — the operator/manual connect path.
                        // Without it all MAX_OUTBOUND_CONNECTIONS slots can be
                        // filled from a single /16. ADDR_BOOK_PER_SUBNET_CAP
                        // bounds the address BOOK, not the dial. Safe here:
                        // CanDialOutboundIp takes no lock of its own, and we
                        // already hold peers_mutex_.
                        if (!peer_connections_.count(pkey) && !IsBanned(ip_str)
                            && CanDialOutboundIp(ip_str)
                            && outbound_count_.load() < MAX_OUTBOUND_CONNECTIONS) {
                            const bool spawned =
                                SpawnTrackedDial_(advertised_ip, port);
                            if (spawned) {
                                ++dials_in_this_msg;
                                ++conn.addr_dial_count;
                            }
                        }
                    }
                }
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::STATSIG) {
            // STATSIG handler. Peer broadcasts its (mempool_size, peer_count)
            // every ~30s; we record it via RecordPeerStats so the
            // explorer can render network-wide aggregates.
            //
            // BIT-IDENTICAL to inline. Notable preservation points:
            //   - Payload size MUST be exactly 16 bytes; otherwise
            //     "statsig_malformed" weight-5, return Handled.
            //   - Protocol version field at offset 0..3: must be
            //     in (0, PROTOCOL_VERSION]. Out-of-range = weight-1
            //     "statsig_bad_version", return Handled. Ceiling
            //     tracks PROTOCOL_VERSION because BuildStatsigMessage
            //     in p2p.h writes that value (so receiver auto-tracks
            //     future bumps without needing a separate edit).
            //   - mempool_size > 1,000,000: weight-1 "statsig_
            //     implausible_mempool", return Handled.
            //   - peer_count > 10,000: weight-1 "statsig_implausible_
            //     peer_count", return Handled.
            //   - peer_ip: strip :port suffix to fold multiple
            //     connections from same host (matches peer_heights_
            //     keying convention).
            //   - now_s uses steady_clock here (NOT system_clock —
            //     differs from INV/VERSION which use system_clock for
            //     unix-epoch peer-tips.cache; preserving inline behavior
            //     to avoid behavior drift).
            //
            // Note on local `their_version`: the inline body declares
            // a uint32_t local that shadows HandlePeer's bool reference
            // alias to PeerState::their_version. In this function we
            // have no such alias to shadow — `their_version` is just a
            // local uint32_t, no name conflict. PeerState::their_version
            // (the handshake bool) is unaffected.
            if (msg.payload.size() != 16) {
                RecordViolation(conn.RemoteAddr(), 5, "statsig_malformed");
                return StepResult::Handled;
            }
            uint32_t their_version = 0;
            for (int i = 0; i < 4; ++i)
                their_version |= ((uint32_t)msg.payload[i] << (i * 8));
            if (their_version == 0 || their_version > PROTOCOL_VERSION) {
                RecordViolation(conn.RemoteAddr(), 1, "statsig_bad_version");
                return StepResult::Handled;
            }
            uint64_t mempool_size = 0;
            for (int i = 0; i < 8; ++i)
                mempool_size |= ((uint64_t)msg.payload[4 + i] << (i * 8));
            uint32_t peer_count = 0;
            for (int i = 0; i < 4; ++i)
                peer_count |= ((uint32_t)msg.payload[12 + i] << (i * 8));
            if (mempool_size > 1'000'000ULL) {
                RecordViolation(conn.RemoteAddr(), 1, "statsig_implausible_mempool");
                return StepResult::Handled;
            }
            if (peer_count > 10'000u) {
                RecordViolation(conn.RemoteAddr(), 1, "statsig_implausible_peer_count");
                return StepResult::Handled;
            }
            std::string peer_ip = conn.RemoteAddr();
            size_t colon = peer_ip.find_last_of(':');
            if (colon != std::string::npos) peer_ip = peer_ip.substr(0, colon);
            // Honest nodes publish roughly every 30 seconds. Allow modest
            // jitter/reconnect duplication while preventing a valid-frame
            // stream from repeatedly churning the aggregate table.
            if (!TakeIpRateToken(statsig_rx_per_ip_, peer_ip, 4))
                return StepResult::Handled;
            int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            RecordPeerStats(peer_ip, mempool_size, peer_count, now_s);
            return StepResult::Handled;
        }
        if (msg.command == MessageType::GETDATA) {
            // GETDATA handler. Peer requests specific block or tx hashes; we
            // serve them as BLOCK/TX messages, with REJECT for
            // unknown blocks.
            //
            // BIT-IDENTICAL to inline. Notable preservation points:
            //   - Truncated payload (<2 bytes): silent ignore (no
            //     violation), inline behavior. Returns Handled.
            //   - count > 1000: weight-25 "getdata_oversized"
            //     violation, returns Handled.
            //   - Per-response 32 MB cap (GETDATA_RESPONSE_CAP)
            //     breaks the inner loop early once exceeded; peer
            //     can re-request via fresh GETDATA. NOT a violation.
            //   - For unknown BLOCK requests, we send a REJECT
            //     message (no body — uses MessageType::REJECT).
            //   - For TX, no REJECT on miss (caller's pending_getdata
            //     TTL handles eventual cleanup).
            if (msg.payload.size() < 2) return StepResult::Handled;

            size_t pos = 0;
            uint16_t count = (uint16_t)(msg.payload[pos] | (msg.payload[pos+1] << 8));
            pos += 2;
            if (count > 1000) {
                RecordViolation(conn.RemoteAddr(), 25, "getdata_oversized");
                return StepResult::Handled;
            }
            if (!TakeIpByteBudget(getdata_items_per_ip_, conn.RemoteAddr(),
                                  count,
                                  GETDATA_ITEM_WORK_BUDGET_PER_60S)) {
                return StepResult::Handled;
            }

            size_t getdata_response_bytes = 0;
            constexpr size_t GETDATA_RESPONSE_CAP = 32 * 1024 * 1024;

            for (uint16_t i = 0; i < count; ++i) {
                if (pos + 36 > msg.payload.size()) break;

                uint32_t type_raw = (uint32_t)msg.payload[pos]
                    | ((uint32_t)msg.payload[pos+1] << 8)
                    | ((uint32_t)msg.payload[pos+2] << 16)
                    | ((uint32_t)msg.payload[pos+3] << 24);
                pos += 4;

                Hash256 hash;
                std::copy(msg.payload.begin() + pos,
                          msg.payload.begin() + pos + 32,
                          hash.begin());
                pos += 32;

                InvType itype = static_cast<InvType>(type_raw);

                if (itype == InvType::BLOCK) {
                    if (!conn.CanQueueEventLoopSend(
                            static_cast<size_t>(MAX_BLOCK_SIZE) + 24u)) break;
                    auto blk_opt = chain_.GetBlockByHash(hash);
                    if (blk_opt.has_value()) {
                        auto payload = blk_opt->Serialize();
                        if (payload.size() > GETDATA_RESPONSE_CAP -
                                std::min(getdata_response_bytes,
                                         GETDATA_RESPONSE_CAP)) {
                            break;
                        }
                        if (!TakeIpByteBudget(
                                getdata_response_bytes_per_ip_,
                                conn.RemoteAddr(), payload.size() + 24u,
                                GETDATA_RESPONSE_BUDGET_PER_60S)) break;
                        if (!conn.Send(P2PMessage(
                                magic_, MessageType::BLOCK, payload))) break;
                        getdata_response_bytes += payload.size();
                    } else {
                        P2PMessage reject(magic_, MessageType::REJECT);
                        if (!conn.Send(reject)) break;
                    }
                } else if (itype == InvType::TX) {
                    if (!conn.CanQueueEventLoopSend(
                            Mempool::MAX_RELAY_TX_BYTES + 24u)) break;
                    auto entry = mempool_.Get(hash);
                    if (entry.has_value()) {
                        auto payload = entry->tx.Serialize();
                        if (payload.size() > GETDATA_RESPONSE_CAP -
                                std::min(getdata_response_bytes,
                                         GETDATA_RESPONSE_CAP)) break;
                        if (!TakeIpByteBudget(
                                getdata_response_bytes_per_ip_,
                                conn.RemoteAddr(), payload.size() + 24u,
                                GETDATA_RESPONSE_BUDGET_PER_60S)) break;
                        if (!conn.Send(P2PMessage(
                                magic_, MessageType::TX, payload))) break;
                        getdata_response_bytes += payload.size();
                    }
                }
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::INV) {
            if (msg.payload.size() < 2) {
                RecordViolation(conn.RemoteAddr(), 15, "inv_truncated");
                return StepResult::Handled;
            }

            size_t pos = 0;
            uint16_t count = (uint16_t)(msg.payload[pos] | (msg.payload[pos+1] << 8));
            pos += 2;
            if (count > 1000) {
                RecordViolation(conn.RemoteAddr(), 25, "inv_oversized");
                return StepResult::Handled;
            }
            if (!TakeIpByteBudget(inv_items_per_ip_, conn.RemoteAddr(), count,
                                  INV_ITEM_WORK_BUDGET_PER_60S)) {
                return StepResult::Handled;
            }
            std::vector<InvItem> want;

            for (uint16_t i = 0; i < count; ++i) {
                if (pos + 36 > msg.payload.size()) break;

                uint32_t type_raw = (uint32_t)msg.payload[pos]
                    | ((uint32_t)msg.payload[pos+1] << 8)
                    | ((uint32_t)msg.payload[pos+2] << 16)
                    | ((uint32_t)msg.payload[pos+3] << 24);
                pos += 4;

                Hash256 hash;
                std::copy(msg.payload.begin() + pos,
                          msg.payload.begin() + pos + 32,
                          hash.begin());
                pos += 32;

                InvType itype = static_cast<InvType>(type_raw);

                if (itype == InvType::BLOCK) {
                    bool in_ibd = !ibd_complete_flag_.load();
                    auto known_height =
                        chain_.GetKnownBlockHeightByHash(hash);
                    // Generic peers cannot turn their own INV into priority.
                    // During IBD, however, an exact live outbound configured
                    // anchor may announce the first GETBLOCKS body so we can
                    // issue a hash-bound GETDATA request before that body is
                    // admitted. The response still has to extend the captured
                    // canonical tip and passes every consensus gate.
                    const bool anchor_ibd_request = in_ibd &&
                        IsLiveConfiguredOutboundAnchor_(conn);
                    if ((!in_ibd || anchor_ibd_request) &&
                        !known_height.has_value()) {
                        std::string hash_hex = HashToHex(hash);
                        bool rejected = false;
                        {
                            std::lock_guard<std::mutex> rl(rejected_mutex_);
                            rejected = RejectedBlockSeenLocked_(hash_hex);
                        }
                        if (!rejected && ReservePendingGetData_(
                                hash_hex, MonotonicSeconds())) {
                            want.emplace_back(InvType::BLOCK, hash);
                        }
                    } else if (known_height.has_value()) {
                        if (HashIsZero(hash)) continue;
                        // Only canonical index evidence may vote for the peer
                        // tip; a known side branch merely suppresses redundant
                        // body download.
                        auto canonical_height = chain_.GetHeightByHash(hash);
                        if (!canonical_height.has_value()) continue;
                        std::string peer_ip = conn.RemoteAddr();
                        size_t colon = peer_ip.find_last_of(':');
                        if (colon != std::string::npos) peer_ip = peer_ip.substr(0, colon);
                        RecordVerifiedPeerHeight_(peer_ip, hash);
                        int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
                        RecordPeerTip(conn, hash, *canonical_height, now_s);
                        if (on_block_ack_) on_block_ack_(hash, peer_ip);
                    }
                } else if (itype == InvType::TX) {
                    if (!mempool_.Contains(hash)) {
                        std::string hash_hex = HashToHex(hash);
                        if (ReservePendingGetData_(
                                hash_hex, MonotonicSeconds())) {
                            want.emplace_back(InvType::TX, hash);
                        }
                    }
                }
            }

            std::string protected_request_hash;
            if (!want.empty()) {
                for (const auto& item : want) {
                    if (item.type == InvType::BLOCK &&
                        RegisterProtectedBlockRequest_(conn, item.hash)) {
                        protected_request_hash = HashToHex(item.hash);
                        break; // one outstanding protected lease/connection
                    }
                }
            }
            if (!want.empty() && !conn.Send(pm.BuildGetDataMessage(want))) {
                if (!protected_request_hash.empty())
                    CancelProtectedBlockRequest_(conn.Identity(),
                                                 protected_request_hash);
                // Nothing was put on the wire/queue; do not suppress a request
                // for these objects from another healthy peer for a full TTL.
                for (const auto& item : want)
                    ErasePendingGetData_(HashToHex(item.hash));
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::GETBLOCKS) {
            // GETBLOCKS handler. Peer sends a chain locator (set of recent block
            // hashes) + optional stop hash; we find the deepest one
            // we recognize and send block messages from there forward
            // up to per-peer byte/count budgets.
            //
            // BIT-IDENTICAL to inline. Notable preservation points:
            //   - The outer comment about IBD-gate removal stays in
            //     the original location (above this handler in
            //     HandlePeer); it's the why-history.
            //   - Malformed payload (<69 bytes header+min-locator) is
            //     a silent "ignore", NOT a violation. Inline behavior.
            //   - Locator-count > 32 records a 5-weight violation and
            //     stops processing — inline did `continue` (skip rest
            //     of HandlePeer iter); equivalent here is `return
            //     StepResult::Handled` (we're done with this message).
            //   - Per-peer GETBLOCKS byte budget uses ban_mutex_ to
            //     guard getblocks_windows_/getblocks_bytes_. Window
            //     rolls every GETBLOCKS_BUDGET_WINDOW_SECONDS.
            //   - When budget exhausted: silent fall-through (no
            //     violation — honest large resyncs hit this too).
            //   - Stop-hash ends the response early when a sent
            //     block matches.
            //   - bytes_this_response counts payload bytes only; the
            //     ~24-byte header is ignored (dwarfed by payload).
            if (msg.payload.size() < 4 + 1 + 32 + 32) {
            } else {
                if (!TakeIpRateToken(getblocks_req_per_ip_,
                                     conn.RemoteAddr(),
                                     GETBLOCKS_REQUESTS_PER_60S)) {
                    return StepResult::Handled;
                }
                size_t pos = 4;
                uint8_t locator_count = msg.payload[pos++];

                if (locator_count > 32) {
                    RecordViolation(conn.RemoteAddr(), 5, "oversized_locator");
                    return StepResult::Handled;
                }

                uint64_t start_height = 0;
                bool found_locator = false;
                for (uint8_t lc = 0; lc < locator_count; ++lc) {
                    if (pos + 32 > msg.payload.size()) break;
                    Hash256 locator;
                    std::copy(msg.payload.begin() + pos,
                              msg.payload.begin() + pos + 32,
                              locator.begin());
                    pos += 32;

                    auto locator_height = chain_.GetHeightByHash(locator);
                    if (locator_height.has_value()) {
                        start_height = *locator_height;
                        found_locator = true;
                        break;
                    }
                }

                Hash256 stop_hash{};
                if (pos + 32 <= msg.payload.size())
                    std::copy(msg.payload.begin() + pos,
                              msg.payload.begin() + pos + 32,
                              stop_hash.begin());
                bool has_stop = !HashIsZero(stop_hash);

                if (!found_locator) start_height = 0;
                {
                    uint64_t send_from = start_height + 1;

                    uint64_t remaining_budget;
                    {
                        std::lock_guard<std::mutex> lk(ban_mutex_);
                        uint64_t now_sec = MonotonicSeconds();
                        const Connection* identity = &conn;
                        auto& win = getblocks_windows_[identity];
                        auto& used = getblocks_bytes_[identity];
                        if (now_sec >= win + GETBLOCKS_BUDGET_WINDOW_SECONDS) {
                            win = now_sec;
                            used = 0;
                        }
                        remaining_budget = (used >= GETBLOCKS_BUDGET_BYTES)
                            ? 0 : (GETBLOCKS_BUDGET_BYTES - used);
                        remaining_budget = std::min<uint64_t>(
                            remaining_budget, MAX_GETBLOCKS_RESPONSE_BYTES);
                    }
                    if (remaining_budget == 0) {
                    } else {
                        size_t sent_count = 0;
                        uint64_t bytes_this_response = 0;
                        bool announced_first_body = false;
                        const uint64_t tip_height = chain_.Height();
                        for (size_t offset = 0;
                             offset < MAX_GETBLOCKS_RESPONSE &&
                             send_from <= tip_height &&
                             offset <= tip_height - send_from;
                             ++offset) {
                            // Refuse disk lookup/copy when the worst-case next
                            // frame cannot fit.  Send performs the exact locked
                            // recheck after serialization.
                            if (!conn.CanQueueEventLoopSend(
                                    static_cast<size_t>(MAX_BLOCK_SIZE) + 24u))
                                break;
                            // Reconnect-stable per-source and process-global
                            // work admission happens before the disk/body
                            // lookup.  The legacy Connection* byte bucket is
                            // retained as an additional local ceiling.
                            if (!ReserveGetBlocksBodyWork_(
                                    conn.RemoteAddr())) break;
                            Block blk;
                            try {
                                blk = chain_.GetBlock(send_from + offset);
                            } catch (...) {
                                break;
                            }
                            auto payload = blk.Serialize();
                            if (bytes_this_response + payload.size() > remaining_budget) break;
                            P2PMessage first_inv;
                            size_t first_inv_wire_bytes = 0;
                            if (!announced_first_body) {
                                PeerManager announce_pm(magic_, chain_.Height());
                                first_inv = announce_pm.BuildInvMessage(
                                    {InvItem(InvType::BLOCK, blk.GetHash())});
                                first_inv_wire_bytes = first_inv.Serialize().size();
                            }
                            if (!ReserveGetBlocksResponseBytes_(
                                    conn.RemoteAddr(), payload.size() + 24u +
                                        first_inv_wire_bytes))
                                break;
                            if (!announced_first_body) {
                                // Ordered INV -> BLOCK makes an exact local
                                // GETDATA lease reachable during IBD. Old
                                // clients ignore the redundant INV and still
                                // receive the unchanged direct stream.
                                if (!conn.Send(first_inv)) break;
                                announced_first_body = true;
                            }
                            // In event-loop mode Send is a bounded complete-frame
                            // enqueue.  Stop immediately when the slow-reader
                            // queue is full and account only frames accepted by
                            // that queue.
                            if (!conn.Send(P2PMessage(
                                    magic_, MessageType::BLOCK, payload))) break;
                            bytes_this_response += payload.size();
                            ++sent_count;
                            if (has_stop && blk.GetHash() == stop_hash) break;
                        }
                        std::lock_guard<std::mutex> lk(ban_mutex_);
                        getblocks_bytes_[&conn] += bytes_this_response;
                    }
                }
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::TIPSIG) {
            if (msg.payload.size() != 44) {
                RecordViolation(conn.RemoteAddr(), 5, "tipsig_size");
                return StepResult::Handled;
            }
            uint32_t their_version = (uint32_t)msg.payload[0]
                | ((uint32_t)msg.payload[1] << 8)
                | ((uint32_t)msg.payload[2] << 16)
                | ((uint32_t)msg.payload[3] << 24);
            uint64_t their_height = 0;
            for (int i = 0; i < 8; ++i)
                their_height |= ((uint64_t)msg.payload[4 + i]) << (i * 8);
            Hash256 their_hash;
            std::copy(msg.payload.begin() + 12,
                      msg.payload.begin() + 44,
                      their_hash.begin());

            if (their_version < PROTOCOL_VERSION) {
                RecordViolation(conn.RemoteAddr(), 1, "tipsig_version_old");
                return StepResult::Handled;
            }
            if (HashIsZero(their_hash)) {
                RecordViolation(conn.RemoteAddr(), 1, "tipsig_hash_zero");
                return StepResult::Handled;
            }
            uint64_t our_height = chain_.Height();
            if (their_height > our_height + 1'000'000ULL) {
                RecordViolation(conn.RemoteAddr(), 5, "tipsig_height_absurd");
                return StepResult::Handled;
            }

            // Only a structurally valid, protocol-current TIPSIG completes the
            // inbound handshake.  The old ordering marked the connection before
            // even checking payload length, letting one empty `tipsig` frame
            // bypass the stuck-handshake reaper indefinitely.
            conn.MarkTipReceived();
            RecordPeerSyncHeight_(conn, their_height);

            std::string tipsig_source_ip = conn.RemoteAddr();
            size_t tipsig_source_colon = tipsig_source_ip.find_last_of(':');
            if (tipsig_source_colon != std::string::npos)
                tipsig_source_ip = tipsig_source_ip.substr(0,
                                                           tipsig_source_colon);
            if (!TakeKeyCooldown(tipsig_processed_at_, tipsig_source_ip,
                                 5, 600, 4096)) {
                return StepResult::Handled;
            }

            // TIPSIG is unsigned.  It may trigger a bounded fetch, but it may
            // vote on peer tip/height only when the hash is already in our local
            // validated chain index and its claimed height matches that index.
            // An unknown hash becomes trusted only after the BLOCK path accepts
            // it and records the chain-derived height.
            const auto known_tip_height =
                chain_.GetKnownBlockHeightByHash(their_hash);
            if (known_tip_height.has_value() &&
                *known_tip_height != their_height) {
                RecordViolation(conn.RemoteAddr(), 5, "tipsig_height_mismatch");
                return StepResult::Handled;
            }
            {
                std::string ip_only = conn.RemoteAddr();
                size_t colon = ip_only.find_last_of(':');
                if (colon != std::string::npos) ip_only = ip_only.substr(0, colon);
                const auto canonical_height = chain_.GetHeightByHash(their_hash);
                if (canonical_height.has_value()) {
                    RecordVerifiedPeerHeight_(ip_only, their_hash);
                    int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    RecordPeerTip(conn, their_hash, *canonical_height, now_s);
                }
            }

            uint64_t our_height_for_compare = our_height;
            Hash256  our_hash{};
            if (!chain_.IsEmpty()) {
                try {
                    Block our_tip = chain_.TipCopy();
                    our_height_for_compare = our_tip.height;
                    our_hash = our_tip.GetHash();
                } catch (...) {}
            }
            bool divergent = false;
            if (their_height > our_height_for_compare) {
                divergent = true;
            } else if (their_height == our_height_for_compare && !(their_hash == our_hash)) {
                divergent = true;
            }
            if (divergent) {
                std::string src_ip = conn.RemoteAddr();
                {
                    size_t colon = src_ip.find_last_of(':');
                    if (colon != std::string::npos) src_ip = src_ip.substr(0, colon);
                }
                uint64_t now_ts = MonotonicSeconds();
                const bool send_now = TakeKeyCooldown(
                    tipsig_getblocks_at_, src_ip, 10, 600, 4096);
                if (send_now) {
                    conn.Send(BuildChainLocatorGetBlocks());
                }

                const bool already_have_their_tip =
                    known_tip_height.has_value();
                if (!already_have_their_tip) {
                    Hash256 fetch_target = their_hash;
                    {
                        std::lock_guard<std::mutex> ol(orphan_mutex_);
                        std::unordered_map<std::string, std::string> hash_to_prev;
                        hash_to_prev.reserve(orphan_fifo_.size());
                        for (const auto& rec : orphan_fifo_) {
                            hash_to_prev[HashToHex(rec.block_hash)] = rec.prev_hex;
                        }
                        std::string cur_hex = HashToHex(their_hash);
                        int max_walk = (int)MAX_ORPHAN_PER_PEER + 16;
                        while (max_walk-- > 0) {
                            auto it = hash_to_prev.find(cur_hex);
                            if (it == hash_to_prev.end()) break;
                            cur_hex = it->second;
                        }
                        if (cur_hex.size() == 64) {
                            fetch_target = HexToHash(cur_hex);
                        }
                    }
                    bool walked = !(fetch_target == their_hash);
                    if (walked) {
                        if (chain_.GetKnownBlockHeightByHash(
                                fetch_target).has_value()) {
                            fetch_target = their_hash;
                            walked = false;
                            goto skip_tipsig_getdata;
                        }
                    }
                    {
                    const bool send_getdata = TakeKeyCooldown(
                        tipsig_getdata_at_, src_ip, 10, 600, 4096);
                    if (send_getdata) {
                        uint64_t my_height_now = chain_.Height();
                        bool gap_broadcast = (their_height > my_height_now + 2);
                        // An unsigned announcement may request its object only
                        // from the announcing peer. A process-global admission
                        // bucket bounds reconnect and multi-IP streams.
                        const bool fetch_queued =
                            SendBoundedRecoveryGetData_(conn, fetch_target);
                        if (fetch_queued && gap_broadcast) {
                            int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::steady_clock::now().time_since_epoch()).count();
                            int64_t last = last_tipsig_catchup_at_seconds_.load(std::memory_order_relaxed);
                            if (last == 0 || now_s - last >= 10) {
                                last_tipsig_catchup_at_seconds_.store(now_s, std::memory_order_relaxed);
                                RequestChainSyncFromAllPeers();
                                if (veld::DiagVerbose().load() &&
                                    !veld::net::g_suppress_sync.load() &&
                                    !background_sync_mode_) {
                                    std::cout << "  [layer3] tip-pull CATCHUP-GETBLOCKS broadcast"
                                              << " (gap=" << (their_height - my_height_now)
                                              << " src=" << src_ip << ")\n";
                                    std::cout.flush();
                                }
                            }
                        }
                        if (veld::DiagVerbose().load() && fetch_queued &&
                            !veld::net::g_suppress_sync.load() &&
                            !background_sync_mode_) {
                            if (walked) {
                                std::cout << "  [layer3] tip-pull GETDATA "
                                          << HashToHex(fetch_target).substr(0, 16)
                                          << "... from announcer (their_tip="
                                          << HashToHex(their_hash).substr(0, 16)
                                          << "... walked back through "
                                          << "orphan ancestors; src=" << src_ip
                                          << " peer h=" << their_height << ")\n";
                            } else if (gap_broadcast) {
                                std::cout << "  [layer3] tip-pull GETDATA "
                                          << HashToHex(their_hash).substr(0, 16)
                                          << "... from announcer (gap=" << (their_height - my_height_now)
                                          << " src=" << src_ip
                                          << " peer h=" << their_height << ")\n";
                            } else {
                                std::cout << "  [layer3] tip-pull GETDATA "
                                          << HashToHex(their_hash).substr(0, 16)
                                          << "... from " << src_ip
                                          << " (peer h=" << their_height << ")\n";
                            }
                            std::cout.flush();
                        }
                    }
                    }
                    skip_tipsig_getdata: ;
                }
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::BLOCK) {
            // BLOCK handler.
            // moved, the inline cascade becomes 100% no-op slots and
            // HandlePeer body shrinks to: outbound VERSION send, recv
            // loop with PeerProtocolStep + RunPeerTimers, and the empty
            // chain. Phase C step 4 deletes the cascade entirely.
            //
            // BIT-IDENTICAL to inline. Notable preservation points:
            //
            // Defence layers (in order, each may bail with Handled):
            //   1) payload.empty() -> block_empty weight 10.
            //   2) payload larger than the consensus block limit ->
            //      block_oversized weight 25.  The generic P2P frame cap is
            //      intentionally larger, so BLOCK must enforce its own limit
            //      before parsing or hashing any attacker-chosen surplus.
            //   3) Block::Deserialize must consume the complete payload ->
            //      block_deser weight 15.  A canonical block followed by junk
            //      is not a second valid wire encoding of the same block.
            //   4) PoW is verified by AddBlockDirect at the chain-derived
            //      height. No peer-height/tip evidence is published before
            //      that authoritative acceptance.
            //   5) Already-have-this-hash short-circuit: silent accept.
            //   6) Pre-rejected-cache short-circuit: silent drop.
            //
            // PeerState mutations (via ps.<field>):
            //   - ps.last_getblocks = now() after post-IBD GETBLOCKS.
            //
            // External state mutations:
            //   - per-peer locally verified height evidence after acceptance.
            //   - chain_.AddBlockDirect with pow_already_verified=true.
            //   - RecordPeerTip with REAL hash on accept.
            //   - on_block_(new_block, key) callback.
            //   - BroadcastMessage(INV) post-IBD; sender NOT excluded.
            //   - ProcessOrphanChain(hash, pm, conn, key) -- recurses
            //     into orphan pool. Signature accepts Connection& now
            //   - On reject: orphan-pool insert with TTL/FIFO/per-IP
            //     caps, orphan-triggered GETBLOCKS-back throttle
            //     (10s/peer), orphan-parent-direct-fetch GETDATA
            //     broadcast (10s per (ip,parent)).
            //   - Reject-tag allowlist: only TRULY-BAD tags poison
            //     rejected_blocks_ cache. Transient tags NOT cached.
            //
            // Function-local statics (orphan_getblocks_throttle,
            // orphan_parent_getdata_throttle) preserved verbatim --
            // process-lifetime semantics identical when hosted in
            // PeerProtocolStep instead of HandlePeer.
            if (msg.payload.empty()) {
                RecordViolation(conn.RemoteAddr(), 10, "block_empty");
                RevokeMalformedProtectedBlockQos_(conn);
                return StepResult::Handled;
            }
            if (msg.payload.size() > (size_t)MAX_BLOCK_SIZE) {
                RecordViolation(conn.RemoteAddr(), 25, "block_oversized");
                RevokeMalformedProtectedBlockQos_(conn);
                return StepResult::Handled;
            }

            Block new_block;
            size_t consumed = Block::Deserialize(msg.payload, 0, new_block);
            if (consumed == 0 || consumed != msg.payload.size() ||
                new_block.Serialize() != msg.payload) {
                std::cerr << "[P2P] Block deserialize failed, payload size=" << msg.payload.size() << "\n";
                std::cerr.flush();
                RecordViolation(conn.RemoteAddr(), 15, "block_deser");
                RevokeMalformedProtectedBlockQos_(conn);
                return StepResult::Handled;
            }
            const std::string received_block_hash =
                HashToHex(new_block.GetHash());

            // Blockchain::AddBlockDirect verifies proof of work using the
            // chain-derived height. The wire object has no authoritative height,
            // so it must not be verified against a handler-supplied epoch here.

            auto known_block = chain_.GetBlockByHash(new_block.GetHash());
            if (known_block.has_value()) {
                // A block hash commits only the header.  Do not let a peer use
                // a known-good header as a free bypass for an arbitrary 8 MB
                // body: the legacy short-circuit returned before Merkle/body
                // validation.  The locally indexed canonical body is already
                // available, so require exact equality without another
                // memory-hard PoW check.
                if (known_block->Serialize() != msg.payload) {
                    RecordViolation(conn.RemoteAddr(), 15,
                                    "block_known_body_mismatch");
                    // A configured anchor answering an exact local request
                    // with a body that disagrees with the already-authenticated
                    // header loses protected QoS. Check/revoke before consuming
                    // the one-shot lease; unrelated BLOCK traffic cannot revoke
                    // a lease for a different hash.
                    RevokeMalformedProtectedBlockQos_(
                        conn, received_block_hash);
                    ErasePendingGetData_(received_block_hash);
                    return StepResult::Handled;
                } else if (chain_.IsCanonicalBlock(new_block.GetHash()) ||
                           !chain_.IsVolatileSideBlock(
                               new_block.GetHash())) {
                    // A byte-exact known duplicate is a valid response. It
                    // consumes the exact lease but is not a QoS fault.
                    CancelProtectedBlockRequest_(
                        conn.Identity(), received_block_hash);
                    ErasePendingGetData_(received_block_hash);
                    return StepResult::Handled;
                }
                // A byte-exact retained side block may represent a previously
                // deferred reorg. Let AddBlockDirect run its bounded retry;
                // canonical known blocks alone use the no-work short circuit.
            }

            bool rejected_cached = false;
            {
                std::lock_guard<std::mutex> rl(rejected_mutex_);
                rejected_cached =
                    RejectedBlockSeenLocked_(received_block_hash);
            }
            if (rejected_cached) {
                ErasePendingGetData_(received_block_hash);
                // The response was consumed even though validation was
                // memoized. Do not leave an exact connection-bound lease
                // available to linger or be refreshed by a later replay.
                CancelProtectedBlockRequest_(
                    conn.Identity(), received_block_hash);
                return StepResult::Handled;
            }

            if (use_event_loop_) {
                bool parent_known =
                    HashIsZero(new_block.header.prev_block_hash) ||
                    chain_.GetBlockByHash(new_block.header.prev_block_hash).has_value();
                if (parent_known) {
                    std::shared_ptr<Connection> sender_sp;
                    {
                        std::lock_guard<std::mutex> lk(peers_mutex_);
                        auto it = peer_connections_.find(key);
                        if (it != peer_connections_.end() &&
                            it->second.get() == &conn) {
                            sender_sp = it->second;
                        }
                    }
                    const auto enq = EnqueueBlockIngest(
                        std::move(new_block), msg.payload.size(), key, sender_sp);
                    if (enq == IngestEnqueueResult::Full) {
                        // Queue saturation is flow control, not peer misconduct.
                        // Drop the message without assigning ban weight.
                        RecordViolation(conn.RemoteAddr(), 0, "block_ingest_overflow");
                    }
                    // Duplicate means this exact block hash is already pending
                    // consensus validation. It changes neither accounting nor
                    // peer ban credit and can be requested again after release.
                    ErasePendingGetData_(received_block_hash);
                    return StepResult::Handled;
                }
            }

            ErasePendingGetData_(received_block_hash);
            auto source_pow_budget = PowBudgetForSource_(
                StripPort_(conn.RemoteAddr()));
            if (!source_pow_budget) {
                // The identity registry is deliberately bounded. Registry
                // pressure is local flow control, never peer misconduct and
                // never a permanent block-hash rejection.
                RecordViolation(conn.RemoteAddr(), 0,
                                "pow_peer_budget_registry_exhausted");
                return StepResult::Handled;
            }
            const auto admission = chain_.AddBlockDirect(
                new_block,
                false,
                true,
                false,
                mining::PowAdmissionContext::Peer(
                    StripPort_(conn.RemoteAddr()), source_pow_budget));
            if (admission.IsAccepted()) {
                uint64_t h = chain_.Height();
                {
                    std::string peer_ip = conn.RemoteAddr();
                    size_t colon = peer_ip.find_last_of(':');
                    if (colon != std::string::npos) peer_ip = peer_ip.substr(0, colon);
                    // AddBlockDirect overwrites the wire object's height with
                    // the parent-index-derived value before returning.  Record
                    // that accepted block height, not the current main-tip
                    // height (which can differ for a valid side branch).
                    RecordVerifiedPeerHeight_(peer_ip, new_block.GetHash());
                    int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    RecordPeerTip(conn, new_block.GetHash(), new_block.height,
                                  now_s);
                }
                if ((h <= 10 || h % 100 == 0) &&
                    !veld::net::g_suppress_sync.load() &&
                    !background_sync_mode_) {
                    std::lock_guard<std::mutex> lk(veld::net::g_stdout_mtx);
                    std::cout << "  [sync] height=" << h
                              << "  supply=" << std::fixed << std::setprecision(2)
                              << chain_.TotalSupplyVeld() << " VELD\n";
                    std::cout.flush();
                }
                if (on_block_) on_block_(new_block, key);
                // Include the sender in the post-accept INV broadcast. Its INV
                // handler (line ~2350) sees "we already have this block",
                // skips GETDATA, and fires on_block_ack_ → satisfies the
                // originator-side ACK quorum on Layer-1's
                // pending_broadcasts_. Without this, freshly mined blocks
                // delivered correctly via Layer-1 BroadcastBlockBytesDirect
                // (or via the regular INV→GETDATA→BLOCK flow) never get
                // an acknowledgment signal from receivers. Cost: one extra
                // ~38B INV per accepted block per direct-sender peer —
                // negligible. Loop-safety: receiver-side dedup ("we have
                // this block") in the INV handler short-circuits before
                // any further INV/GETDATA fan-out.
                if (ibd_complete_flag_.load()) {
                    BroadcastMessage(
                        pm.BuildInvMessage({InvItem(InvType::BLOCK, new_block.GetHash())}),
                        ""
                    );
                }
                ProcessOrphanChain(new_block.GetHash(), pm, conn, key);
                if (ibd_complete_flag_.load()) {
                    conn.Send(BuildChainLocatorGetBlocks());
                    ps.last_getblocks = std::chrono::steady_clock::now();
                }
            } else {
                // DoS (direct path): penalise a peer that
                // delivered a block failing a HARD consensus gate; benign
                // orphan / duplicate rejects fall through to the handling below.
                {
                    const std::string& rt = chain_.GetLastRejectTag();
                    if (IsHardBlockReject_(rt)) {
                        RecordViolation(conn.RemoteAddr(), 15, rt.c_str());
                    }
                }
                bool parent_known = chain_.GetBlockByHash(new_block.header.prev_block_hash).has_value();
                if (!parent_known && !HashIsZero(new_block.header.prev_block_hash)) {

                    std::string prev_hex = HashToHex(new_block.header.prev_block_hash);
                    std::string src_ip = StripPort_(conn.RemoteAddr());
                    std::lock_guard<std::mutex> ol(orphan_mutex_);
                    static constexpr size_t MAX_ORPHAN_BYTES = 100 * 1024 * 1024;
                    size_t block_size = new_block.Serialize().size();
                    uint64_t now_ts = MonotonicSeconds();
                    auto remove_victim = [&](const OrphanRec& victim) {
                        auto bucket_it = orphan_pool_.find(victim.prev_hex);
                        if (bucket_it != orphan_pool_.end()) {
                            auto& vec = bucket_it->second;
                            for (auto it = vec.begin(); it != vec.end(); ++it) {
                                if (it->block.GetHash() == victim.block_hash) {
                                    vec.erase(it); break;
                                }
                            }
                            if (vec.empty()) orphan_pool_.erase(bucket_it);
                        }
                        orphan_count_--;
                        orphan_bytes_ -= victim.size;
                        if (!victim.src_ip.empty()) {
                            auto cit = orphan_count_by_ip_.find(victim.src_ip);
                            if (cit != orphan_count_by_ip_.end()) {
                                if (cit->second > 0) cit->second--;
                                if (cit->second == 0) orphan_count_by_ip_.erase(cit);
                            }
                            auto bit = orphan_bytes_by_ip_.find(victim.src_ip);
                            if (bit != orphan_bytes_by_ip_.end()) {
                                if (bit->second >= victim.size) bit->second -= victim.size;
                                else bit->second = 0;
                                if (bit->second == 0) orphan_bytes_by_ip_.erase(bit);
                            }
                        }
                    };
                    while (!orphan_fifo_.empty() &&
                           (now_ts - orphan_fifo_.front().ts) > ORPHAN_TTL_SECONDS) {
                        remove_victim(orphan_fifo_.front());
                        orphan_fifo_.pop_front();
                    }
                    size_t peer_count = orphan_count_by_ip_.count(src_ip)
                                      ? orphan_count_by_ip_[src_ip] : 0;
                    size_t peer_bytes = orphan_bytes_by_ip_.count(src_ip)
                                      ? orphan_bytes_by_ip_[src_ip] : 0;
                    if (peer_count >= MAX_ORPHAN_PER_PEER ||
                        peer_bytes + block_size > MAX_ORPHAN_BYTES_PER_PEER) {
                    } else {
                        while ((orphan_count_ >= MAX_ORPHAN_POOL ||
                                orphan_bytes_ + block_size > MAX_ORPHAN_BYTES) &&
                               !orphan_fifo_.empty()) {
                            remove_victim(orphan_fifo_.front());
                            orphan_fifo_.pop_front();
                        }
                        if (block_size <= MAX_ORPHAN_BYTES &&
                            orphan_count_ < MAX_ORPHAN_POOL &&
                            orphan_bytes_ + block_size <= MAX_ORPHAN_BYTES) {
                            Hash256 bh = new_block.GetHash();
                            auto& bucket = orphan_pool_[prev_hex];
                            bool already_present = false;
                            for (const auto& existing : bucket) {
                                if (existing.block.GetHash() == bh) {
                                    already_present = true;
                                    break;
                                }
                            }
                            // Do not let one withheld valid parent amplify into
                            // an unbounded synchronous VeldHash burst.
                            if (!already_present &&
                                bucket.size() < MAX_ORPHANS_PER_PARENT) {
                                bucket.push_back(OrphanBlockEntry{
                                    new_block, src_ip, source_pow_budget});
                                orphan_count_++;
                                orphan_bytes_ += block_size;
                                orphan_count_by_ip_[src_ip]++;
                                orphan_bytes_by_ip_[src_ip] += block_size;
                                orphan_fifo_.push_back(
                                    {now_ts, prev_hex, bh, block_size, src_ip});
                                const bool send_getblocks = TakeKeyCooldown(
                                    orphan_getblocks_at_, src_ip,
                                    10, 600, 4096);
                                if (send_getblocks)
                                    conn.Send(BuildChainLocatorGetBlocks());
                                // Fetch orphan parents directly. The locator
                                // walk above can fail when its byte budget is
                                // exhausted or no advertised locator is known.
                                // Ask only the announcing peer for the exact
                                // missing parent; never amplify an
                                // unauthenticated orphan across all peers.
                                {
                                    std::string parent_key =
                                        src_ip + ":" + prev_hex;
                                    const bool send_parent_getdata =
                                        TakeKeyCooldown(
                                            orphan_parent_getdata_at_,
                                            parent_key, 10, 600, 4096);
                                    if (send_parent_getdata) {
                                        const bool queued =
                                            SendBoundedRecoveryGetData_(
                                                conn,
                                                new_block.header.prev_block_hash);
                                        if (veld::DiagVerbose().load() &&
                                            queued &&
                                            !veld::net::g_suppress_sync.load() &&
                                            !background_sync_mode_) {
                                            std::cout
                                                << "  [sync-buffer] GETDATA "
                                                << prev_hex.substr(0, 16)
                                                << "... from announcer "
                                                << src_ip
                                                << "; orphan child h~"
                                                << (chain_.Height() + 1)
                                                << " hash="
                                                << HashToHex(bh).substr(0, 16)
                                                << "...)\n";
                                            std::cout.flush();
                                        }
                                    }
                                }
                                if (veld::DiagVerbose().load() &&
                                    orphan_count_ % 100 == 0 &&
                                    !veld::net::g_suppress_sync.load() &&
                                    !background_sync_mode_) {
                                    std::lock_guard<std::mutex> lk(
                                        veld::net::g_stdout_mtx);
                                    std::cout
                                        << "  [sync] orphan pool: "
                                        << orphan_count_ << " blocks buffered ("
                                        << (orphan_bytes_ / 1024 / 1024)
                                        << " MB)\n";
                                    std::cout.flush();
                                }
                            }
                        }
                    }
                } else {
                    const std::string tag = chain_.GetLastRejectTag();
                    CacheHeaderAuthenticatedBlockReject_(
                        tag, HashToHex(new_block.GetHash()));
                    // Transient rejects (orphan_*, bits_mismatch_lwma,
                    // coinbase_exceeds_subsidy_cap, nms_validation_failed,
                    // consensus_pool_payout_mismatch, timestamp_*) are
                    // NOT cached. They may flip to accepting if the
                    // missing parent arrives, the LWMA window fills, or
                    // a different ancestor's state catches up.
                }
            }
            return StepResult::Handled;
        }

        // ===================== NAT hole-punch v2 =====================
        // Consensus-inert. Every action is gated by the advertised capability,
        // full handshake, exact live connection identity, expiring random
        // correlations, and a separate local dial budget. A coordinator can
        // forward only the requester's observed endpoint and only for an offer
        // it issued on that same connection.
        const bool is_punch_command =
            msg.command == MessageType::PUNCHHELLO ||
            msg.command == MessageType::GETPUNCH ||
            msg.command == MessageType::PUNCHREQ ||
            msg.command == MessageType::PUNCHLIST ||
            msg.command == MessageType::PUNCHFWD;
        if (is_punch_command &&
            !TakeIpRateToken(punch_control_rx_per_ip_,
                             conn.RemoteAddr(), 32)) {
            return StepResult::Handled;
        }
        if (is_punch_command &&
            (!ps.handshake_done || !HolePunchCapable_(conn))) {
            return StepResult::Handled;
        }
        const bool is_punch_client_action =
            msg.command == MessageType::PUNCHLIST ||
            msg.command == MessageType::PUNCHFWD;
        if (is_punch_client_action &&
            !hole_punch_enabled_.load(std::memory_order_acquire)) {
            return StepResult::Handled;
        }
        if (msg.command == MessageType::PUNCHHELLO) {
            size_t off = 0;
            PunchNonce nonce{};
            if (!ReadPunchNonce_(msg.payload, off, nonce) ||
                off != msg.payload.size()) {
                return StepResult::Handled;
            }
            const std::string endpoint = conn.RemoteAddr() + ":" +
                                         std::to_string(conn.RemotePort());
            std::string endpoint_ip;
            uint16_t endpoint_port = 0;
            if (!ParsePublicIPv4Endpoint(endpoint, endpoint_ip, endpoint_port))
                return StepResult::Handled;
            const uint64_t now = MonotonicSeconds();
            std::lock_guard<std::mutex> lk(punchable_mutex_);
            for (auto it = punchable_.begin(); it != punchable_.end();) {
                if (it->second.expires_at <= now) it = punchable_.erase(it);
                else ++it;
            }
            if (punchable_.size() < MAX_PUNCHABLE ||
                punchable_.count(endpoint)) {
                punchable_[endpoint] = PunchRegistration{
                    conn.Identity(), nonce, now + 600};
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::GETPUNCH) {
            size_t off = 0;
            PunchNonce request_nonce{};
            if (!ReadPunchNonce_(msg.payload, off, request_nonce) ||
                off != msg.payload.size()) {
                return StepResult::Handled;
            }
            std::vector<std::pair<std::string, PunchNonce>> offers;
            {
                const uint64_t now = MonotonicSeconds();
                std::lock_guard<std::mutex> lk(punchable_mutex_);
                for (auto it = punchable_.begin();
                     it != punchable_.end() && offers.size() < 16;) {
                    if (it->second.expires_at <= now) {
                        it = punchable_.erase(it);
                        continue;
                    }
                    if (it->second.connection_id != conn.Identity())
                        offers.push_back({it->first, it->second.hello_nonce});
                    ++it;
                }
                for (auto it = punch_seed_requests_.begin();
                     it != punch_seed_requests_.end();) {
                    if (it->second.expires_at <= now)
                        it = punch_seed_requests_.erase(it);
                    else
                        ++it;
                }
                if (punch_seed_requests_.size() >= MAX_PUNCH_REQUESTS &&
                    !punch_seed_requests_.count(conn.Identity())) {
                    offers.clear();
                } else {
                    PunchSeedRequest pending;
                    pending.requester_connection_id = conn.Identity();
                    pending.request_nonce = request_nonce;
                    pending.expires_at = now + 90;
                    for (const auto& offer : offers)
                        pending.offers.emplace(offer.first, offer.second);
                    punch_seed_requests_[conn.Identity()] = std::move(pending);
                }
            }
            std::vector<uint8_t> payload;
            payload.reserve(17 + offers.size() * 81);
            AppendPunchNonce_(payload, request_nonce);
            payload.push_back(static_cast<uint8_t>(offers.size()));
            for (const auto& offer : offers) {
                const auto& a = offer.first;
                uint8_t l = static_cast<uint8_t>(std::min(a.size(), size_t{64}));
                payload.push_back(l);
                payload.insert(payload.end(), a.begin(), a.begin() + l);
                AppendPunchNonce_(payload, offer.second);
            }
            conn.TrySend(P2PMessage(magic_, MessageType::PUNCHLIST, std::move(payload)).Serialize());
            return StepResult::Handled;
        }
        if (msg.command == MessageType::PUNCHREQ) {
            size_t off = 0;
            PunchNonce request_nonce{};
            PunchNonce target_nonce{};
            if (!ReadPunchNonce_(msg.payload, off, request_nonce) ||
                !ReadPunchNonce_(msg.payload, off, target_nonce) ||
                off >= msg.payload.size()) {
                return StepResult::Handled;
            }
            const uint8_t len = msg.payload[off++];
            if (len == 0 || len > 64 || off + len != msg.payload.size())
                return StepResult::Handled;
            const std::string target(
                reinterpret_cast<const char*>(msg.payload.data() + off), len);
            std::string target_ip;
            uint16_t target_port = 0;
            if (!ParsePublicIPv4Endpoint(target, target_ip, target_port))
                return StepResult::Handled;

            const std::string requester = conn.RemoteAddr() + ":" +
                                          std::to_string(conn.RemotePort());
            std::string requester_ip;
            uint16_t requester_port = 0;
            if (!ParsePublicIPv4Endpoint(requester, requester_ip,
                                         requester_port))
                return StepResult::Handled;

            std::shared_ptr<Connection> target_connection;
            {
                std::lock_guard<std::mutex> lk(peers_mutex_);
                auto it = peer_connections_.find(target);
                if (it != peer_connections_.end()) target_connection = it->second;
            }
            if (!target_connection || !HolePunchCapable_(*target_connection))
                return StepResult::Handled;

            bool authorized = false;
            {
                const uint64_t now = MonotonicSeconds();
                std::lock_guard<std::mutex> lk(punchable_mutex_);
                auto request = punch_seed_requests_.find(conn.Identity());
                auto registration = punchable_.find(target);
                if (request != punch_seed_requests_.end() &&
                    registration != punchable_.end() &&
                    request->second.requester_connection_id == conn.Identity() &&
                    request->second.expires_at > now &&
                    registration->second.expires_at > now &&
                    registration->second.connection_id ==
                        target_connection->Identity() &&
                    PunchNonceEqual_(request->second.request_nonce,
                                     request_nonce) &&
                    PunchNonceEqual_(registration->second.hello_nonce,
                                     target_nonce)) {
                    auto offered = request->second.offers.find(target);
                    if (offered != request->second.offers.end() &&
                        PunchNonceEqual_(offered->second, target_nonce)) {
                        request->second.offers.erase(offered);
                        if (request->second.offers.empty())
                            punch_seed_requests_.erase(request);
                        punchable_.erase(registration);
                        authorized = true;
                    }
                }
            }
            if (authorized) {
                std::vector<uint8_t> payload;
                payload.reserve(16 + 1 + requester.size());
                AppendPunchNonce_(payload, target_nonce);
                payload.push_back(static_cast<uint8_t>(requester.size()));
                payload.insert(payload.end(), requester.begin(), requester.end());
                target_connection->TrySend(P2PMessage(
                    magic_, MessageType::PUNCHFWD, std::move(payload)).Serialize());
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::PUNCHLIST) {
            size_t off = 0;
            PunchNonce request_nonce{};
            if (!ReadPunchNonce_(msg.payload, off, request_nonce) ||
                off >= msg.payload.size()) {
                return StepResult::Handled;
            }
            const uint8_t count = msg.payload[off++];
            if (count > 16) return StepResult::Handled;
            std::vector<std::pair<std::string, PunchNonce>> parsed;
            std::unordered_set<std::string> unique;
            for (uint8_t i = 0; i < count; ++i) {
                if (off >= msg.payload.size()) return StepResult::Handled;
                const uint8_t len = msg.payload[off++];
                if (len == 0 || len > 64 || off + len > msg.payload.size())
                    return StepResult::Handled;
                std::string endpoint(
                    reinterpret_cast<const char*>(msg.payload.data() + off), len);
                off += len;
                PunchNonce target_nonce{};
                if (!ReadPunchNonce_(msg.payload, off, target_nonce))
                    return StepResult::Handled;
                std::string candidate_ip;
                uint16_t candidate_port = 0;
                if (!ParsePublicIPv4Endpoint(endpoint, candidate_ip,
                                             candidate_port) ||
                    !unique.insert(endpoint).second) {
                    return StepResult::Handled;
                }
                parsed.push_back({std::move(endpoint), target_nonce});
            }
            if (off != msg.payload.size()) return StepResult::Handled;

            const uint64_t now = MonotonicSeconds();
            std::lock_guard<std::mutex> lk(punch_client_mutex_);
            auto state = punch_client_coordinators_.find(conn.Identity());
            if (state == punch_client_coordinators_.end())
                return StepResult::Handled;
            auto bound = state->second.connection.lock();
            if (bound.get() != &conn || !state->second.request_live ||
                state->second.request_expires_at <= now ||
                !PunchNonceEqual_(state->second.request_nonce, request_nonce)) {
                return StepResult::Handled;
            }
            state->second.request_live = false;
            for (const auto& item : parsed) {
                if (punch_candidates_.size() >= MAX_PUNCH_CANDIDATES) break;
                PunchCandidate candidate;
                candidate.coordinator = state->second.connection;
                candidate.coordinator_connection_id = conn.Identity();
                candidate.request_nonce = request_nonce;
                candidate.target_nonce = item.second;
                candidate.endpoint = item.first;
                candidate.expires_at = state->second.request_expires_at;
                punch_candidates_.push_back(std::move(candidate));
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::PUNCHFWD) {
            size_t off = 0;
            PunchNonce hello_nonce{};
            if (!ReadPunchNonce_(msg.payload, off, hello_nonce) ||
                off >= msg.payload.size()) {
                return StepResult::Handled;
            }
            const uint8_t len = msg.payload[off++];
            if (len == 0 || len > 64 || off + len != msg.payload.size())
                return StepResult::Handled;
            const std::string endpoint(
                reinterpret_cast<const char*>(msg.payload.data() + off), len);
            std::string ip;
            uint16_t port = 0;
            if (!ParsePublicIPv4Endpoint(endpoint, ip, port) ||
                !TakeIpRateToken(punchfwd_rx_per_ip_, conn.RemoteAddr(), 8)) {
                return StepResult::Handled;
            }
            bool authorized = false;
            {
                const uint64_t now = MonotonicSeconds();
                std::lock_guard<std::mutex> lk(punch_client_mutex_);
                auto state = punch_client_coordinators_.find(conn.Identity());
                if (state != punch_client_coordinators_.end()) {
                    auto bound = state->second.connection.lock();
                    if (bound.get() == &conn && state->second.hello_live &&
                        state->second.hello_expires_at > now &&
                        PunchNonceEqual_(state->second.hello_nonce,
                                         hello_nonce)) {
                        state->second.hello_live = false;
                        authorized = true;
                    }
                }
            }
            if (authorized && TakePunchDialBudget_()) {
                SpawnPunchDial_(ip, port);
            }
            return StepResult::Handled;
        }
        if (msg.command == MessageType::ONIONADV) {          // Tor: relay and dial an advertised .onion
            // Every node relays a valid, rate-limited onion advertisement so
            // Tor miners can discover each other through ordinary clearnet
            // seeds. Tor-capable nodes also dial it. A short endpoint cooldown
            // terminates gossip loops and bounds amplification.
            if (msg.payload.size() <= 80 &&
                TakeIpRateToken(onionadv_rx_per_ip_,
                                conn.RemoteAddr(), 4)) {
                std::string a(msg.payload.begin(), msg.payload.end());
                std::string onion;
                uint16_t port = 0;
                if (ParseCanonicalOnionEndpoint(a, onion, port)) {
                    const std::string own_onion = OnionAddress();
                    if (onion == own_onion && port == port_)
                        return StepResult::Handled;
                    if (TakeKeyCooldown(onionadv_relay_at_, a,
                                        60, 600, 4096)) {
                        BroadcastMessage(msg, conn.RemoteAddr());
                    }
                    if (tor_.Active() ||
                        tor_only_.load(std::memory_order_acquire)) {
                        SpawnTrackedDial_(onion, port);
                    }
                }
            }
            return StepResult::Handled;
        }

        return StepResult::NotHandled;
    }

    bool RunPeerTimers(PeerState& ps, Connection& conn, PeerManager& pm) {
        auto now = std::chrono::steady_clock::now();
        if (!ps.handshake_done) {
            const auto age = std::chrono::duration_cast<std::chrono::seconds>(
                now - ps.conn_started).count();
            if (!conn.VersionReceived()) {
                const bool peer_bytes_observed = conn.HasHandshakeProgress();
                const int deadline = peer_bytes_observed
                    ? PRE_VERSION_PROGRESS_GRACE_S
                    : PRE_VERSION_GRACE_S;
                if (age >= deadline) return true;
            } else if (age >= STUCK_HANDSHAKE_GRACE_S) {
                return true;
            }
        }
        if (std::chrono::duration_cast<std::chrono::seconds>(now - ps.last_ping).count() >= 15) {
            if (conn.TrySend(pm.BuildPingMessage(0xDEADBEEF))) {
                ps.last_ping = now;
            }
        }
        if (ps.handshake_done && !ps.getaddr_sent) {
            if (conn.TrySend(pm.BuildGetAddrMessage())) {
                ps.getaddr_sent = true;
                ps.last_getaddr_sent = std::chrono::steady_clock::now();
                ps.addr_response_consumed = false;
            }
        }
        if (ps.handshake_done &&
            std::chrono::duration_cast<std::chrono::seconds>(now - ps.last_mempool_req).count() >= 120) {
            P2PMessage mempool_req(magic_, MessageType::MEMPOOL);
            if (conn.TrySend(mempool_req)) {
                ps.last_mempool_req = now;
            }
        }
        if (ps.handshake_done) {
            bool in_ibd = !ibd_complete_flag_.load();
            auto ms_since_gb = std::chrono::duration_cast<std::chrono::milliseconds>(now - ps.last_getblocks).count();
            bool should_request = false;
            if (in_ibd) {
                should_request = IbdGetBlocksRetryDue(
                    ps, chain_.Height(), now);
            } else {
                if (ms_since_gb >= 5000) should_request = true;
            }
            if (should_request) {
                if (conn.TrySend(BuildChainLocatorGetBlocks())) {
                    ps.last_getblocks = now;
                }
            }
        }
        return false;
    }

    bool HandOffNewPeerToWorker(const std::string& key,
                                std::shared_ptr<Connection> conn,
                                PeerStatePtr ps,
                                bool needs_initial_version_send = false) {
        std::lock_guard<std::mutex> workers_lock(worker_registry_mutex_);
        if (!running_.load(std::memory_order_acquire) ||
            el_workers_.empty() || !conn || !ps) {
            return false;
        }
        // VERSION is sent synchronously before handoff. Every subsequent write
        // is a complete-frame queue operation drained by this peer's worker;
        // handlers can no longer block the whole event loop on a slow reader.
        conn->EnableEventLoopIO();
        uint64_t h = 1469598103934665603ULL;
        for (unsigned char c : key) {
            h ^= c;
            h *= 1099511628211ULL;
        }
        size_t idx = (size_t)(h % el_workers_.size());
        auto& w = *el_workers_[idx];
        std::lock_guard<std::mutex> lock(w.incoming_mtx);
        w.incoming.push_back({key, std::move(conn), std::move(ps),
                              needs_initial_version_send});
        return true;
    }

    // Cheap, fixed-offset claimed-principal classification.  This is not
    // authentication: the node prefilter still resolves the key against the
    // canonical epoch snapshot.  It merely prevents one claimed validator /
    // phase / round from occupying more than two queue slots before that
    // classification.  The public key is hashed so attacker-controlled binary
    // bytes never become an unordered-map collision surface.
    static bool FinalityClaimedKeys_(const std::vector<uint8_t>& wire,
                                    std::string& lane_out,
                                    std::string& candidate_out) {
        constexpr size_t PREFIX_BYTES = 4;
        constexpr size_t EPOCH_ROOT_PHASE_ROUND_BYTES = 8 + 32 + 1 + 4;
        constexpr size_t PUBKEY_OFFSET =
            4 + 8 + 32 + 1 + 4 + 8 + 32 + 8 + 32;
        constexpr size_t TARGET_OFFSET =
            4 + 8 + 32 + 1 + 4 + 8 + 32;
        constexpr size_t TARGET_BYTES = 8 + 32;
        static_assert(PUBKEY_OFFSET + ::veld::dilithium::PUBKEY_BYTES +
                          ::veld::dilithium::SIG_MAX_BYTES ==
                      P2P_FINALITY_VOTE_WIRE_BYTES,
                      "FINVOTE principal offset must match wire profile");
        if (wire.size() != P2P_FINALITY_VOTE_WIRE_BYTES ||
            std::memcmp(wire.data(), "FVT1", PREFIX_BYTES) != 0)
            return false;
        const Hash256 key_hash = Hash256d(
            wire.data() + PUBKEY_OFFSET, ::veld::dilithium::PUBKEY_BYTES);
        lane_out.clear();
        lane_out.reserve(EPOCH_ROOT_PHASE_ROUND_BYTES + key_hash.size());
        lane_out.append(
            reinterpret_cast<const char*>(wire.data() + PREFIX_BYTES),
            EPOCH_ROOT_PHASE_ROUND_BYTES);
        lane_out.append(reinterpret_cast<const char*>(key_hash.data()),
                        key_hash.size());
        // ML-DSA signing may be randomized, and a signer may carry a different
        // justified source while voting for the SAME target.  Neither is a
        // slashable second candidate.  Bind candidate identity to the lane
        // (epoch/root/phase/round/signer) plus target height/hash only, leaving
        // the second lane slot available for an actual sibling target.
        std::vector<uint8_t> candidate_material;
        candidate_material.reserve(lane_out.size() + TARGET_BYTES);
        candidate_material.insert(candidate_material.end(), lane_out.begin(),
                                  lane_out.end());
        candidate_material.insert(
            candidate_material.end(),
            wire.begin() + static_cast<std::ptrdiff_t>(TARGET_OFFSET),
            wire.begin() + static_cast<std::ptrdiff_t>(
                TARGET_OFFSET + TARGET_BYTES));
        const Hash256 candidate_hash = Hash256d(candidate_material);
        candidate_out.assign(
            reinterpret_cast<const char*>(candidate_hash.data()),
            candidate_hash.size());
        return true;
    }

    void PruneFinalityVoteRecentLocked_(uint64_t now) {
        while (!finality_vote_recent_invalid_order_.empty()) {
            const auto& front = finality_vote_recent_invalid_order_.front();
            auto it = finality_vote_recent_invalid_.find(front.first);
            if (it == finality_vote_recent_invalid_.end() ||
                it->second != front.second) {
                finality_vote_recent_invalid_order_.pop_front();
                continue;
            }
            if (now <= front.second + FINALITY_VOTE_RECENT_TTL_SECONDS)
                break;
            finality_vote_recent_invalid_.erase(it);
            finality_vote_recent_invalid_order_.pop_front();
        }
        while (!finality_vote_completed_candidate_order_.empty()) {
            const auto& front =
                finality_vote_completed_candidate_order_.front();
            auto it = finality_vote_completed_candidates_.find(front.first);
            if (it == finality_vote_completed_candidates_.end() ||
                it->second.timestamp != front.second) {
                finality_vote_completed_candidate_order_.pop_front();
                continue;
            }
            if (now <= front.second + FINALITY_VOTE_RECENT_TTL_SECONDS)
                break;
            auto lane = finality_vote_completed_lane_counts_.find(
                it->second.lane_key);
            if (lane != finality_vote_completed_lane_counts_.end()) {
                if (lane->second > 1) --lane->second;
                else finality_vote_completed_lane_counts_.erase(lane);
            }
            finality_vote_completed_candidates_.erase(it);
            finality_vote_completed_candidate_order_.pop_front();
        }
    }

    template <typename Table, typename Order>
    static void InsertFinalityVoteRecentLocked_(Table& table, Order& order,
                                                 const std::string& key,
                                                 uint64_t now) {
        table[key] = now;
        order.emplace_back(key, now);
        while (table.size() > FINALITY_VOTE_RECENT_CAP && !order.empty()) {
            const auto oldest = std::move(order.front());
            order.pop_front();
            auto it = table.find(oldest.first);
            if (it != table.end() && it->second == oldest.second)
                table.erase(it);
        }
    }

    bool InsertFinalityVoteCompletedCandidateLocked_(
            const FinalityVoteJob& job, uint64_t now) {
        if (finality_vote_completed_candidates_.count(job.candidate_id) != 0)
            return true;
        bool inserted_candidate = false;
        bool inserted_order = false;
        bool incremented_lane = false;
        try {
            auto [candidate, inserted] =
                finality_vote_completed_candidates_.emplace(
                    job.candidate_id,
                    FinalityCompletedCandidate{job.lane_key, now});
            (void)candidate;
            if (!inserted) return true;
            inserted_candidate = true;
            finality_vote_completed_candidate_order_.emplace_back(
                job.candidate_id, now);
            inserted_order = true;
            auto [lane, _inserted] =
                finality_vote_completed_lane_counts_.try_emplace(
                    job.lane_key, 0);
            (void)_inserted;
            ++lane->second;
            incremented_lane = true;
        } catch (...) {
            if (incremented_lane) {
                auto lane = finality_vote_completed_lane_counts_.find(
                    job.lane_key);
                if (lane != finality_vote_completed_lane_counts_.end()) {
                    if (lane->second > 1) --lane->second;
                    else finality_vote_completed_lane_counts_.erase(lane);
                }
            }
            if (inserted_order &&
                !finality_vote_completed_candidate_order_.empty() &&
                finality_vote_completed_candidate_order_.back().first ==
                    job.candidate_id)
                finality_vote_completed_candidate_order_.pop_back();
            if (inserted_candidate)
                finality_vote_completed_candidates_.erase(job.candidate_id);
            return false;
        }
        while (finality_vote_completed_candidates_.size() >
                   FINALITY_VOTE_RECENT_CAP &&
               !finality_vote_completed_candidate_order_.empty()) {
            const auto oldest =
                std::move(finality_vote_completed_candidate_order_.front());
            finality_vote_completed_candidate_order_.pop_front();
            auto it = finality_vote_completed_candidates_.find(oldest.first);
            if (it == finality_vote_completed_candidates_.end() ||
                it->second.timestamp != oldest.second)
                continue;
            auto lane = finality_vote_completed_lane_counts_.find(
                it->second.lane_key);
            if (lane != finality_vote_completed_lane_counts_.end()) {
                if (lane->second > 1) --lane->second;
                else finality_vote_completed_lane_counts_.erase(lane);
            }
            finality_vote_completed_candidates_.erase(it);
        }
        return true;
    }

    void ReleaseFinalityVoteJobLocked_(const FinalityVoteJob& job) {
        if (finality_vote_pending_ids_.erase(job.wire_id) == 0) return;
        finality_vote_pending_candidate_ids_.erase(job.candidate_id);
        if (finality_vote_pending_count_ > 0)
            --finality_vote_pending_count_;
        if (job.wire.size() <= finality_vote_pending_bytes_)
            finality_vote_pending_bytes_ -= job.wire.size();
        else
            finality_vote_pending_bytes_ = 0;
        auto lane = finality_vote_lane_counts_.find(job.lane_key);
        if (lane != finality_vote_lane_counts_.end()) {
            if (lane->second > 1) --lane->second;
            else finality_vote_lane_counts_.erase(lane);
        }
        auto source = finality_vote_source_counts_.find(job.source_ip);
        if (source != finality_vote_source_counts_.end()) {
            if (source->second > 1) --source->second;
            else finality_vote_source_counts_.erase(source);
        }
    }

    void ClearFinalityVoteStateLocked_() {
        finality_vote_raw_by_source_.clear();
        finality_vote_raw_rr_.clear();
        finality_vote_prepared_lanes_.clear();
        finality_vote_lane_rr_.clear();
        finality_vote_pending_ids_.clear();
        finality_vote_pending_candidate_ids_.clear();
        finality_vote_lane_counts_.clear();
        finality_vote_source_counts_.clear();
        finality_vote_recent_invalid_.clear();
        finality_vote_recent_invalid_order_.clear();
        finality_vote_completed_candidates_.clear();
        finality_vote_completed_candidate_order_.clear();
        finality_vote_completed_lane_counts_.clear();
        finality_vote_pending_count_ = 0;
        finality_vote_pending_bytes_ = 0;
    }

    bool EnqueueFinalityVote_(const std::vector<uint8_t>& wire,
                              const std::string& source_ip,
                              const std::string& sender_key) {
        if (wire.size() != P2P_FINALITY_VOTE_WIRE_BYTES ||
            source_ip.empty() || IsBanned(source_ip) ||
            !TakeIpRateToken(finality_vote_rx_per_ip_, source_ip,
                             FINALITY_VOTE_PER_IP_PER_60S))
            return false;

        const Hash256 digest = Hash256d(wire);
        const std::string wire_id(
            reinterpret_cast<const char*>(digest.data()), digest.size());
        std::string lane_key;
        std::string candidate_id;
        if (!FinalityClaimedKeys_(wire, lane_key, candidate_id)) return false;

        FinalityVoteJob job{
            wire, source_ip, sender_key, wire_id, candidate_id, lane_key};
        std::lock_guard<std::mutex> lk(finality_vote_mtx_);
        const uint64_t now = MonotonicSeconds();
        PruneFinalityVoteRecentLocked_(now);
        if (!finality_vote_accepting_.load(std::memory_order_acquire) ||
            finality_vote_pending_ids_.count(wire_id) != 0 ||
            finality_vote_pending_candidate_ids_.count(candidate_id) != 0 ||
            finality_vote_recent_invalid_.count(wire_id) != 0 ||
            finality_vote_completed_candidates_.count(candidate_id) != 0)
            return false;
        const auto lane_count = finality_vote_lane_counts_.find(lane_key);
        const auto completed_lane_count =
            finality_vote_completed_lane_counts_.find(lane_key);
        const size_t pending_in_lane =
            lane_count == finality_vote_lane_counts_.end()
                ? 0 : lane_count->second;
        const size_t completed_in_lane =
            completed_lane_count == finality_vote_completed_lane_counts_.end()
                ? 0 : completed_lane_count->second;
        if (pending_in_lane + completed_in_lane >=
                FINALITY_VOTE_PER_LANE_CAP)
            return false;
        if (finality_vote_pending_count_ >= FINALITY_VOTE_JOB_CAP ||
            wire.size() > FINALITY_VOTE_BYTE_CAP -
                              std::min(finality_vote_pending_bytes_,
                                       FINALITY_VOTE_BYTE_CAP))
            return false;
        const auto source_count =
            finality_vote_source_counts_.find(source_ip);
        if (source_count != finality_vote_source_counts_.end() &&
            source_count->second >=
                FINALITY_VOTE_PER_SOURCE_PENDING_CAP)
            return false;
        if (source_count == finality_vote_source_counts_.end() &&
            finality_vote_source_counts_.size() >=
                FINALITY_VOTE_SOURCE_TABLE_CAP)
            return false;

        bool inserted_id = false;
        bool inserted_candidate = false;
        bool incremented_lane = false;
        bool incremented_source = false;
        bool pushed_job = false;
        bool pushed_rr = false;
        try {
            auto [source_it, _new_source] =
                finality_vote_raw_by_source_.try_emplace(source_ip);
            auto [id_it, id_new] =
                finality_vote_pending_ids_.insert(wire_id);
            (void)id_it;
            if (!id_new) return false;
            inserted_id = true;
            auto [candidate_it, candidate_new] =
                finality_vote_pending_candidate_ids_.insert(candidate_id);
            (void)candidate_it;
            if (!candidate_new) {
                finality_vote_pending_ids_.erase(wire_id);
                return false;
            }
            inserted_candidate = true;
            ++finality_vote_lane_counts_[lane_key];
            incremented_lane = true;
            ++finality_vote_source_counts_[source_ip];
            incremented_source = true;
            source_it->second.jobs.push_back(std::move(job));
            pushed_job = true;
            if (!source_it->second.scheduled) {
                finality_vote_raw_rr_.push_back(source_ip);
                source_it->second.scheduled = true;
                pushed_rr = true;
            }
            ++finality_vote_pending_count_;
            finality_vote_pending_bytes_ += wire.size();
        } catch (...) {
            auto source_it = finality_vote_raw_by_source_.find(source_ip);
            if (pushed_rr && !finality_vote_raw_rr_.empty() &&
                finality_vote_raw_rr_.back() == source_ip) {
                finality_vote_raw_rr_.pop_back();
                if (source_it != finality_vote_raw_by_source_.end())
                    source_it->second.scheduled = false;
            }
            if (pushed_job && source_it != finality_vote_raw_by_source_.end() &&
                !source_it->second.jobs.empty())
                source_it->second.jobs.pop_back();
            if (inserted_id) finality_vote_pending_ids_.erase(wire_id);
            if (inserted_candidate)
                finality_vote_pending_candidate_ids_.erase(candidate_id);
            if (incremented_lane) {
                auto lane = finality_vote_lane_counts_.find(lane_key);
                if (lane != finality_vote_lane_counts_.end()) {
                    if (lane->second > 1) --lane->second;
                    else finality_vote_lane_counts_.erase(lane);
                }
            }
            if (incremented_source) {
                auto source = finality_vote_source_counts_.find(source_ip);
                if (source != finality_vote_source_counts_.end()) {
                    if (source->second > 1) --source->second;
                    else finality_vote_source_counts_.erase(source);
                }
            }
            if (source_it != finality_vote_raw_by_source_.end() &&
                source_it->second.jobs.empty() &&
                !source_it->second.scheduled)
                finality_vote_raw_by_source_.erase(source_it);
            return false;
        }
        finality_vote_raw_cv_.notify_one();
        return true;
    }

    void FinalityVotePrefilterWorker_() {
        for (;;) {
            FinalityVoteJob job;
            {
                std::unique_lock<std::mutex> lk(finality_vote_mtx_);
                finality_vote_raw_cv_.wait(lk, [this] {
                    return !finality_vote_running_.load(
                               std::memory_order_acquire) ||
                           !finality_vote_raw_rr_.empty();
                });
                if (!finality_vote_running_.load(std::memory_order_acquire))
                    return;
                bool found = false;
                while (!finality_vote_raw_rr_.empty() && !found) {
                    std::string source =
                        std::move(finality_vote_raw_rr_.front());
                    finality_vote_raw_rr_.pop_front();
                    auto it = finality_vote_raw_by_source_.find(source);
                    if (it == finality_vote_raw_by_source_.end()) continue;
                    it->second.scheduled = false;
                    if (it->second.jobs.empty()) {
                        finality_vote_raw_by_source_.erase(it);
                        continue;
                    }
                    job = std::move(it->second.jobs.front());
                    it->second.jobs.pop_front();
                    found = true;
                    if (!it->second.jobs.empty()) {
                        finality_vote_raw_rr_.push_back(source);
                        it->second.scheduled = true;
                    } else {
                        finality_vote_raw_by_source_.erase(it);
                    }
                }
                if (!found) continue;
            }

            bool eligible = false;
            try {
                eligible = finality_vote_precheck_ &&
                           finality_vote_precheck_(job.wire);
            } catch (...) {
                eligible = false;
            }

            bool ready = false;
            {
                std::lock_guard<std::mutex> lk(finality_vote_mtx_);
                const uint64_t now = MonotonicSeconds();
                PruneFinalityVoteRecentLocked_(now);
                if (!finality_vote_running_.load(std::memory_order_acquire) ||
                    !eligible ||
                    finality_vote_completed_candidates_.count(
                        job.candidate_id) != 0) {
                    ReleaseFinalityVoteJobLocked_(job);
                    continue;
                }
                bool pushed_job = false;
                bool pushed_rr = false;
                try {
                    auto& lane = finality_vote_prepared_lanes_[job.lane_key];
                    // Keep the local job intact until both container writes
                    // succeed so an allocation failure can release its exact
                    // byte/hash/lane accounting.
                    lane.jobs.push_back(job);
                    pushed_job = true;
                    if (!lane.scheduled && !lane.in_flight) {
                        finality_vote_lane_rr_.push_back(job.lane_key);
                        lane.scheduled = true;
                        pushed_rr = true;
                    }
                    ready = true;
                } catch (...) {
                    auto lane =
                        finality_vote_prepared_lanes_.find(job.lane_key);
                    if (lane != finality_vote_prepared_lanes_.end()) {
                        if (pushed_rr && !finality_vote_lane_rr_.empty() &&
                            finality_vote_lane_rr_.back() == job.lane_key) {
                            finality_vote_lane_rr_.pop_back();
                            lane->second.scheduled = false;
                        }
                        if (pushed_job && !lane->second.jobs.empty())
                            lane->second.jobs.pop_back();
                        if (!lane->second.in_flight &&
                            lane->second.jobs.empty())
                            finality_vote_prepared_lanes_.erase(lane);
                    }
                    ReleaseFinalityVoteJobLocked_(job);
                }
            }
            if (ready) finality_vote_ready_cv_.notify_one();
        }
    }

    void FinalityVoteCryptoWorker_() {
        for (;;) {
            FinalityVoteJob job;
            {
                std::unique_lock<std::mutex> lk(finality_vote_mtx_);
                finality_vote_ready_cv_.wait(lk, [this] {
                    return !finality_vote_running_.load(
                               std::memory_order_acquire) ||
                           !finality_vote_lane_rr_.empty();
                });
                if (!finality_vote_running_.load(std::memory_order_acquire))
                    return;
                bool found = false;
                while (!finality_vote_lane_rr_.empty() && !found) {
                    std::string lane_key =
                        std::move(finality_vote_lane_rr_.front());
                    finality_vote_lane_rr_.pop_front();
                    auto it = finality_vote_prepared_lanes_.find(lane_key);
                    if (it == finality_vote_prepared_lanes_.end()) continue;
                    it->second.scheduled = false;
                    if (it->second.in_flight || it->second.jobs.empty()) {
                        if (!it->second.in_flight && it->second.jobs.empty())
                            finality_vote_prepared_lanes_.erase(it);
                        continue;
                    }
                    job = std::move(it->second.jobs.front());
                    it->second.jobs.pop_front();
                    it->second.in_flight = true;
                    found = true;
                }
                if (!found) continue;
            }

            FinalityVoteVerifyResult result =
                FinalityVoteVerifyResult::RejectedState;
            try {
                if (finality_vote_running_.load(std::memory_order_acquire) &&
                    finality_vote_verifier_)
                    result = finality_vote_verifier_(job.wire);
            } catch (...) {
                result = FinalityVoteVerifyResult::RejectedState;
            }

            const bool accepted =
                result == FinalityVoteVerifyResult::AcceptedNew;
            const bool completed = accepted ||
                result == FinalityVoteVerifyResult::AlreadyKnown ||
                result == FinalityVoteVerifyResult::EvidenceOnly;
            {
                std::lock_guard<std::mutex> lk(finality_vote_mtx_);
                const uint64_t now = MonotonicSeconds();
                auto lane = finality_vote_prepared_lanes_.find(job.lane_key);
                ReleaseFinalityVoteJobLocked_(job);
                if (result == FinalityVoteVerifyResult::InvalidSignature) {
                    try {
                        InsertFinalityVoteRecentLocked_(
                            finality_vote_recent_invalid_,
                            finality_vote_recent_invalid_order_,
                            job.wire_id, now);
                    } catch (...) {
                        // Cache allocation failure must not kill a worker. The
                        // per-IP rate limit and ban score remain in force.
                    }
                }
                if (completed)
                    (void)InsertFinalityVoteCompletedCandidateLocked_(
                        job, now);
                if (lane != finality_vote_prepared_lanes_.end()) {
                    lane->second.in_flight = false;
                    if (!lane->second.jobs.empty() &&
                        finality_vote_running_.load(std::memory_order_acquire)) {
                        finality_vote_lane_rr_.push_back(job.lane_key);
                        lane->second.scheduled = true;
                    } else {
                        finality_vote_prepared_lanes_.erase(lane);
                    }
                }
            }

            if (result == FinalityVoteVerifyResult::InvalidSignature)
                RecordViolation(job.source_ip, 20,
                                "finvote_signature_invalid");
            if (accepted && running_.load(std::memory_order_acquire)) {
                BroadcastMessage(P2PMessage(
                    magic_, MessageType::FINVOTE, job.wire), job.sender_key);
            }
        }
    }

    void FinalityVotePrefilterThreadEntry_() noexcept {
        while (finality_vote_running_.load(std::memory_order_acquire)) {
            try {
                FinalityVotePrefilterWorker_();
                return;
            } catch (const std::exception& e) {
                NoteContainedNetworkException_();
                LogNetworkThreadException_("FINVOTE prefilter worker",
                                           e.what());
            } catch (...) {
                NoteContainedNetworkException_();
                LogNetworkThreadException_("FINVOTE prefilter worker",
                                           "unknown exception");
            }
            if (finality_vote_running_.load(std::memory_order_acquire))
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    void FinalityVoteCryptoThreadEntry_() noexcept {
        while (finality_vote_running_.load(std::memory_order_acquire)) {
            try {
                FinalityVoteCryptoWorker_();
                return;
            } catch (const std::exception& e) {
                NoteContainedNetworkException_();
                LogNetworkThreadException_("FINVOTE crypto worker",
                                           e.what());
            } catch (...) {
                NoteContainedNetworkException_();
                LogNetworkThreadException_("FINVOTE crypto worker",
                                           "unknown exception");
            }
            if (finality_vote_running_.load(std::memory_order_acquire))
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    bool StartFinalityVoteWorkers_() {
        {
            std::lock_guard<std::mutex> lk(finality_vote_mtx_);
            ClearFinalityVoteStateLocked_();
            finality_vote_running_.store(true, std::memory_order_release);
            finality_vote_accepting_.store(true, std::memory_order_release);
        }
        try {
            const size_t workers = FinalityCryptoWorkerCount(
                std::thread::hardware_concurrency());
            finality_vote_crypto_threads_.clear();
            finality_vote_crypto_threads_.reserve(workers);
            finality_vote_prefilter_thread_ = std::thread(
                &NodeServer::FinalityVotePrefilterThreadEntry_, this);
            for (size_t i = 0; i < workers; ++i) {
                finality_vote_crypto_threads_.emplace_back(
                    &NodeServer::FinalityVoteCryptoThreadEntry_, this);
            }
            return true;
        } catch (...) {
            finality_vote_accepting_.store(false, std::memory_order_release);
            finality_vote_running_.store(false, std::memory_order_release);
            finality_vote_raw_cv_.notify_all();
            finality_vote_ready_cv_.notify_all();
            if (finality_vote_prefilter_thread_.joinable())
                finality_vote_prefilter_thread_.join();
            for (auto& t : finality_vote_crypto_threads_)
                if (t.joinable()) t.join();
            finality_vote_crypto_threads_.clear();
            std::lock_guard<std::mutex> lk(finality_vote_mtx_);
            ClearFinalityVoteStateLocked_();
            return false;
        }
    }

    void SignalFinalityVoteStop_() {
        {
            std::lock_guard<std::mutex> lk(finality_vote_mtx_);
            finality_vote_accepting_.store(false, std::memory_order_release);
            finality_vote_running_.store(false, std::memory_order_release);
        }
        finality_vote_raw_cv_.notify_all();
        finality_vote_ready_cv_.notify_all();
    }

    void JoinFinalityVoteWorkers_() {
        if (finality_vote_prefilter_thread_.joinable())
            finality_vote_prefilter_thread_.join();
        for (auto& t : finality_vote_crypto_threads_)
            if (t.joinable()) t.join();
        finality_vote_crypto_threads_.clear();
        std::lock_guard<std::mutex> lk(finality_vote_mtx_);
        ClearFinalityVoteStateLocked_();
    }

    bool ShouldInjectStartFailure_(int stage) {
#ifdef VELD_TEST_HOOKS
        int expected = stage;
        return test_start_failure_stage_.compare_exchange_strong(
            expected, 0, std::memory_order_acq_rel);
#else
        (void)stage;
        return false;
#endif
    }

    // Clear connection-generation/runtime admission state shared by a normal
    // Stop and a partial Start rollback. Persistent bans and their scores are
    // deliberately retained; only a completed normal Stop flushes dirty ban
    // state to disk.
    void ClearVolatileRuntimeState_(bool persist_dirty_bans) {
        {
            std::lock_guard<std::mutex> lock(ban_mutex_);
            msg_counts_.clear();
            msg_windows_.clear();
            msg_violations_in_window_.clear();
            getblocks_bytes_.clear();
            getblocks_windows_.clear();
            if (persist_dirty_bans && bans_dirty_)
                SaveBansToFileLocked_(true);
        }
        {
            PeerWorkViewWriteGuard_ work_view_write(*this);
            if (work_view_write.MayPublish()) {
                std::lock_guard<std::mutex> lock(peer_heights_mutex_);
                peer_work_sources_.clear();
                peer_heights_.clear();
                peer_sync_heights_.clear();
                peer_verified_heights_.clear();
            }
        }
        {
            std::lock_guard<std::mutex> lock(clock_drift_mutex_);
            clock_drift_samples_.clear();
        }
        {
            std::lock_guard<std::mutex> lock(peer_tips_mutex_);
            peer_tips_.clear();
        }
        {
            std::lock_guard<std::mutex> lock(pending_gd_mutex_);
            pending_getdata_.clear();
            pending_getdata_order_.clear();
        }
        {
            std::lock_guard<std::mutex> lock(peer_stats_mutex_);
            peer_stats_.clear();
            peer_stats_order_.clear();
        }
        {
            std::lock_guard<std::mutex> lock(ip_rate_mutex_);
            ip_table_last_prune_.clear();
            addr_dial_per_ip_.clear();
            comine_rx_per_ip_.clear();
            finality_vote_rx_per_ip_.clear();
            accept_rate_per_ip_.clear();
            mempool_req_per_ip_.clear();
            statsig_rx_per_ip_.clear();
            getblocks_req_per_ip_.clear();
            punch_control_rx_per_ip_.clear();
            punchfwd_rx_per_ip_.clear();
            onionadv_rx_per_ip_.clear();
            onionadv_relay_at_.clear();
            solution_rx_per_ip_.clear();
            recovery_getdata_global_.clear();
            tipsig_processed_at_.clear();
            tipsig_getblocks_at_.clear();
            tipsig_getdata_at_.clear();
            orphan_getblocks_at_.clear();
            orphan_parent_getdata_at_.clear();
            accept_drop_log_at_.clear();
            tx_bytes_per_ip_.clear();
            addr_items_per_ip_.clear();
            addr_items_global_.clear();
            inv_items_per_ip_.clear();
            getdata_items_per_ip_.clear();
            getdata_response_bytes_per_ip_.clear();
            getblocks_response_bytes_per_ip_.clear();
            getblocks_response_work_per_ip_.clear();
            getblocks_response_bytes_global_.clear();
            getblocks_response_work_global_.clear();
        }
        {
            std::lock_guard<std::mutex> lock(punchable_mutex_);
            punchable_.clear();
            punch_seed_requests_.clear();
        }
        {
            std::lock_guard<std::mutex> lock(punch_client_mutex_);
            punch_client_coordinators_.clear();
            punch_candidates_.clear();
        }
        {
            std::lock_guard<std::mutex> lock(punch_dial_mutex_);
            punch_dial_attempts_.clear();
        }
#ifdef VELD_TEST_HOOKS
        test_suppress_punch_network_dials_.store(false,
                                                  std::memory_order_release);
        test_authorized_punch_dials_.store(0, std::memory_order_release);
#endif
    }

    // Start() owns lifecycle_mutex_ while calling this. It intentionally does
    // not call public Stop(), which would recursively lock the same mutex.
    // Every post-FINVOTE producer is quiesced before its registry/state is
    // cleared, so a failed partial generation is immediately restartable.
    void RollbackFailedStartLocked_() {
        {
            std::lock_guard<std::mutex> peers_lock(peers_mutex_);
            running_.store(false, std::memory_order_release);
        }
        SignalFinalityVoteStop_();

        const SocketHandle listener_fd = listen_fd_;
        if (veld::compat::IsValidSocket(listener_fd)) {
#ifdef _WIN32
            ::shutdown((SOCKET)listener_fd, SD_BOTH);
#else
            ::shutdown(listener_fd, SHUT_RDWR);
#endif
        }
        if (accept_thread_.joinable()) accept_thread_.join();
        for (auto& at : el_accept_threads_)
            if (at.joinable()) at.join();
        el_accept_threads_.clear();
        if (veld::compat::IsValidSocket(listener_fd)) {
            VELD_CLOSE_SOCKET(listener_fd);
            listen_fd_ = veld::compat::kInvalidSocket;
        }

        std::vector<std::shared_ptr<Connection>> to_close;
        {
            std::lock_guard<std::mutex> peers_lock(peers_mutex_);
            for (auto& [_key, conn] : peer_connections_)
                if (conn) to_close.push_back(conn);
        }
        for (auto& conn : to_close) conn->Close();
        for (auto& conn : to_close) CleanupConnectionState_(conn);

        std::vector<PeerThreadSlot> peer_threads;
        {
            std::lock_guard<std::mutex> peer_lock(peer_threads_mutex_);
            peer_threads.swap(peer_threads_);
        }
        for (auto& slot : peer_threads)
            if (slot.t.joinable()) slot.t.join();
        {
            std::unique_lock<std::mutex> dial_lock(pending_dial_mutex_);
            pending_dial_cv_.wait(dial_lock, [&] {
                return pending_dials_.load(std::memory_order_acquire) == 0;
            });
        }

        {
            std::lock_guard<std::mutex> workers_lock(worker_registry_mutex_);
            for (auto& wp : el_workers_)
                if (wp) wp->running.store(false, std::memory_order_release);
        }
        for (auto& wp : el_workers_)
            if (wp && wp->thread.joinable()) wp->thread.join();
        {
            std::lock_guard<std::mutex> workers_lock(worker_registry_mutex_);
            el_workers_.clear();
        }

        if (ingest_running_.exchange(false, std::memory_order_acq_rel)) {
            ingest_cv_.notify_all();
        }
        if (ingest_worker_thread_.joinable())
            ingest_worker_thread_.join();

        JoinFinalityVoteWorkers_();
        {
            std::lock_guard<std::mutex> ingest_lock(ingest_mtx_);
            ClearBlockIngestStateLocked_();
        }
        {
            std::lock_guard<std::mutex> peers_lock(peers_mutex_);
            peer_connections_.clear();
            peer_states_.clear();
            inbound_count_.store(0, std::memory_order_release);
            outbound_count_.store(0, std::memory_order_release);
        }
        ClearVolatileRuntimeState_(/*persist_dirty_bans=*/false);
    }

    static std::string IngestSource_(const std::string& sender_key,
                                     const std::shared_ptr<Connection>& conn) {
        if (conn && !conn->RemoteAddr().empty())
            return StripPort_(conn->RemoteAddr());
        return StripPort_(sender_key);
    }

    static size_t PendingBlockCountLocked_(const BlockIngestLane& a,
                                           const BlockIngestLane& b) {
        return a.pending_jobs + b.pending_jobs;
    }

    void PruneProtectedBlockPolicyLocked_(uint64_t now) {
        for (auto it = protected_block_requests_.begin();
             it != protected_block_requests_.end();) {
            if (now > it->second.expires_at)
                it = protected_block_requests_.erase(it);
            else
                ++it;
        }
        for (auto it = protected_block_qos_revoked_until_.begin();
             it != protected_block_qos_revoked_until_.end();) {
            if (now >= it->second)
                it = protected_block_qos_revoked_until_.erase(it);
            else
                ++it;
        }
    }

    bool IsLiveConfiguredOutboundAnchor_(Connection& conn) const {
        if (conn.IsInbound() || !conn.IsConnected() ||
            !IsFleetAnchorIp_(conn.RemoteAddr())) {
            return false;
        }
        std::lock_guard<std::mutex> peers_lock(peers_mutex_);
        for (const auto& [_key, live] : peer_connections_) {
            if (live && live.get() == &conn && live->IsConnected() &&
                !live->IsInbound()) {
                return true;
            }
        }
        return false;
    }

    bool RegisterProtectedBlockRequest_(Connection& conn,
                                        const Hash256& block_hash,
                                        uint64_t now = 0) {
        if (!IsLiveConfiguredOutboundAnchor_(conn) || chain_.IsEmpty()) {
            return false;
        }
        const Hash256 expected_prev = chain_.TipCopy().GetHash();
        if (now == 0) now = MonotonicSeconds();
        std::lock_guard<std::mutex> lk(ingest_mtx_);
        PruneProtectedBlockPolicyLocked_(now);
        const uint64_t id = conn.Identity();
        auto revoked = protected_block_qos_revoked_until_.find(
            conn.RemoteAddr());
        if (revoked != protected_block_qos_revoked_until_.end() &&
            now < revoked->second) {
            return false;
        }
        const std::string hash_hex = HashToHex(block_hash);
        auto existing = protected_block_requests_.find(id);
        if (existing != protected_block_requests_.end()) {
            if (existing->second.block_hash != hash_hex ||
                existing->second.expected_prev != expected_prev) {
                return false; // one outstanding protected request/connection
            }
            existing->second.expires_at =
                now + PROTECTED_BLOCK_REQUEST_TTL_SECONDS;
            return true;
        }
        if (protected_block_requests_.size() >=
            static_cast<size_t>(MAX_OUTBOUND_CONNECTIONS)) {
            return false;
        }
        protected_block_requests_.emplace(
            id, ProtectedBlockRequestLease{
                    hash_hex, expected_prev,
                    now + PROTECTED_BLOCK_REQUEST_TTL_SECONDS});
        return true;
    }

    void CancelProtectedBlockRequest_(uint64_t connection_id,
                                      const std::string& block_hash = {}) {
        if (connection_id == 0) return;
        std::lock_guard<std::mutex> lk(ingest_mtx_);
        auto it = protected_block_requests_.find(connection_id);
        if (it == protected_block_requests_.end()) return;
        if (!block_hash.empty() && it->second.block_hash != block_hash) return;
        protected_block_requests_.erase(it);
    }

    static bool LaneHasQueued_(const BlockIngestLane& lane) {
        return lane.queued_jobs != 0;
    }

    bool QueueBlockInLaneLocked_(BlockIngestLane& lane,
                                 PendingBlockIngest&& job,
                                 size_t lane_cap,
                                 size_t lane_max_bytes,
                                 size_t per_source_max_bytes) {
        auto found = lane.sources.find(job.sender_source);
        const size_t source_jobs = found == lane.sources.end()
            ? 0 : found->second.pending_jobs;
        const size_t source_bytes = found == lane.sources.end()
            ? 0 : found->second.pending_bytes;
        if (lane.pending_jobs >= lane_cap ||
            lane.pending_bytes > lane_max_bytes - job.wire_bytes ||
            source_jobs >= LAYER_C_BLOCK_INGEST_PER_SOURCE_CAP ||
            source_bytes > per_source_max_bytes - job.wire_bytes ||
            PendingBlockCountLocked_(ingest_protected_lane_,
                                     ingest_normal_lane_) >=
                LAYER_C_BLOCK_INGEST_CAP ||
            ingest_pending_bytes_ >
                LAYER_C_BLOCK_INGEST_MAX_BYTES - job.wire_bytes) {
            return false;
        }

        const std::string source = job.sender_source;
        const std::string hash = job.block_hash;
        bool inserted_source = false;
        bool added_rr = false;
        try {
            auto result = lane.sources.try_emplace(source);
            inserted_source = result.second;
            auto& sq = result.first->second;
            sq.jobs.push_back(std::move(job));
            if (!sq.in_round_robin) {
                lane.round_robin.push_back(source);
                sq.in_round_robin = true;
                added_rr = true;
            }
            lane.pending_hashes.insert(hash);
            ++sq.pending_jobs;
            sq.pending_bytes += sq.jobs.back().wire_bytes;
            ++lane.queued_jobs;
            ++lane.pending_jobs;
            lane.pending_bytes += sq.jobs.back().wire_bytes;
            ingest_pending_bytes_ += sq.jobs.back().wire_bytes;
            return true;
        } catch (...) {
            auto sit = lane.sources.find(source);
            if (sit != lane.sources.end()) {
                auto& jobs = sit->second.jobs;
                for (auto it = jobs.begin(); it != jobs.end(); ++it) {
                    if (it->block_hash == hash) {
                        jobs.erase(it);
                        break;
                    }
                }
                if (added_rr) {
                    auto rr = std::find(lane.round_robin.begin(),
                                        lane.round_robin.end(), source);
                    if (rr != lane.round_robin.end())
                        lane.round_robin.erase(rr);
                    sit->second.in_round_robin = false;
                }
                if (inserted_source && sit->second.jobs.empty() &&
                    sit->second.pending_jobs == 0) {
                    lane.sources.erase(sit);
                }
            }
            lane.pending_hashes.erase(hash);
            return false;
        }
    }

    bool PopBlockFromLaneLocked_(BlockIngestLane& lane,
                                 PendingBlockIngest& out) {
        while (!lane.round_robin.empty()) {
            const std::string source = std::move(lane.round_robin.front());
            lane.round_robin.pop_front();
            auto sit = lane.sources.find(source);
            if (sit == lane.sources.end()) continue;
            auto& sq = sit->second;
            sq.in_round_robin = false;
            if (sq.jobs.empty()) continue;
            out = std::move(sq.jobs.front());
            sq.jobs.pop_front();
            --lane.queued_jobs;
            if (!sq.jobs.empty()) {
                lane.round_robin.push_back(source);
                sq.in_round_robin = true;
            }
            return true;
        }
        return false;
    }

    bool TakeNextBlockIngestLocked_(PendingBlockIngest& out) {
        const bool have_protected = LaneHasQueued_(ingest_protected_lane_);
        const bool have_normal = LaneHasQueued_(ingest_normal_lane_);
        if (!have_protected && !have_normal) return false;

        bool take_protected = have_protected &&
            (ingest_protected_preempt_ || !have_normal ||
             ingest_protected_streak_ < 3);
        if (take_protected) {
            ingest_protected_preempt_ = false;
            if (ingest_protected_streak_ < 3) ++ingest_protected_streak_;
            if (PopBlockFromLaneLocked_(ingest_protected_lane_, out))
                return true;
        }
        ingest_protected_streak_ = 0;
        if (PopBlockFromLaneLocked_(ingest_normal_lane_, out)) return true;
        if (PopBlockFromLaneLocked_(ingest_protected_lane_, out)) {
            ingest_protected_streak_ = 1;
            return true;
        }
        return false;
    }

    void ReleasePendingBlockAccountingLocked_(
            const PendingBlockIngest& job) {
        BlockIngestLane& lane = job.protected_request
            ? ingest_protected_lane_ : ingest_normal_lane_;
        if (lane.pending_hashes.erase(job.block_hash) == 0) return;
        auto sit = lane.sources.find(job.sender_source);
        if (sit != lane.sources.end()) {
            if (sit->second.pending_jobs > 0) --sit->second.pending_jobs;
            if (sit->second.pending_bytes >= job.wire_bytes)
                sit->second.pending_bytes -= job.wire_bytes;
            else
                sit->second.pending_bytes = 0;
            if (sit->second.pending_jobs == 0 && sit->second.jobs.empty())
                lane.sources.erase(sit);
        }
        if (lane.pending_jobs > 0) --lane.pending_jobs;
        if (lane.pending_bytes >= job.wire_bytes)
            lane.pending_bytes -= job.wire_bytes;
        else
            lane.pending_bytes = 0;
        if (ingest_pending_bytes_ >= job.wire_bytes)
            ingest_pending_bytes_ -= job.wire_bytes;
        else
            ingest_pending_bytes_ = 0;
    }

    void ReleasePendingBlockAccounting_(const PendingBlockIngest& job) {
        std::lock_guard<std::mutex> lk(ingest_mtx_);
        ReleasePendingBlockAccountingLocked_(job);
    }

    void ClearBlockIngestStateLocked_() {
        ingest_protected_lane_ = BlockIngestLane{};
        ingest_normal_lane_ = BlockIngestLane{};
        protected_block_requests_.clear();
        protected_block_qos_revoked_until_.clear();
        ingest_pending_bytes_ = 0;
        ingest_protected_streak_ = 0;
        ingest_protected_preempt_ = false;
    }

    void RevokeProtectedBlockQos_(const PendingBlockIngest& rejected) {
        if (!rejected.protected_request ||
            rejected.sender_connection_id == 0) return;
        std::lock_guard<std::mutex> lk(ingest_mtx_);
        const uint64_t now = MonotonicSeconds();
        PruneProtectedBlockPolicyLocked_(now);
        if (protected_block_qos_revoked_until_.size() >=
                PROTECTED_BLOCK_QOS_REVOKE_CAP &&
            protected_block_qos_revoked_until_.count(
                rejected.sender_source) == 0) {
            auto oldest = std::min_element(
                protected_block_qos_revoked_until_.begin(),
                protected_block_qos_revoked_until_.end(),
                [](const auto& a, const auto& b) {
                    return a.second < b.second;
                });
            if (oldest != protected_block_qos_revoked_until_.end())
                protected_block_qos_revoked_until_.erase(oldest);
        }
        protected_block_qos_revoked_until_[rejected.sender_source] =
            now + PROTECTED_BLOCK_QOS_REVOKE_SECONDS;
        protected_block_requests_.erase(rejected.sender_connection_id);

        // Purge queued protected work from this configured source across
        // connection generations. The current in-flight item is released by
        // its accounting guard after this call.
        for (auto& [source, sq] : ingest_protected_lane_.sources) {
            for (auto it = sq.jobs.begin(); it != sq.jobs.end();) {
                if (it->sender_source != rejected.sender_source) {
                    ++it;
                    continue;
                }
                ingest_protected_lane_.pending_hashes.erase(it->block_hash);
                if (sq.pending_jobs > 0) --sq.pending_jobs;
                if (sq.pending_bytes >= it->wire_bytes)
                    sq.pending_bytes -= it->wire_bytes;
                if (ingest_protected_lane_.queued_jobs > 0)
                    --ingest_protected_lane_.queued_jobs;
                if (ingest_protected_lane_.pending_jobs > 0)
                    --ingest_protected_lane_.pending_jobs;
                if (ingest_protected_lane_.pending_bytes >= it->wire_bytes)
                    ingest_protected_lane_.pending_bytes -= it->wire_bytes;
                if (ingest_pending_bytes_ >= it->wire_bytes)
                    ingest_pending_bytes_ -= it->wire_bytes;
                it = sq.jobs.erase(it);
            }
            if (sq.jobs.empty() && sq.in_round_robin) {
                auto rr = std::find(ingest_protected_lane_.round_robin.begin(),
                                    ingest_protected_lane_.round_robin.end(),
                                    source);
                if (rr != ingest_protected_lane_.round_robin.end())
                    ingest_protected_lane_.round_robin.erase(rr);
                sq.in_round_robin = false;
            }
        }
        for (auto it = ingest_protected_lane_.sources.begin();
             it != ingest_protected_lane_.sources.end();) {
            if (it->second.pending_jobs == 0 && it->second.jobs.empty())
                it = ingest_protected_lane_.sources.erase(it);
            else
                ++it;
        }
    }

    void RevokeMalformedProtectedBlockQos_(
            Connection& conn, const std::string& exact_block_hash = {}) {
        if (!IsLiveConfiguredOutboundAnchor_(conn)) return;
        bool has_live_lease = false;
        {
            std::lock_guard<std::mutex> lk(ingest_mtx_);
            const uint64_t now = MonotonicSeconds();
            PruneProtectedBlockPolicyLocked_(now);
            auto lease = protected_block_requests_.find(conn.Identity());
            has_live_lease = lease != protected_block_requests_.end() &&
                (exact_block_hash.empty() ||
                 lease->second.block_hash == exact_block_hash);
        }
        if (!has_live_lease) return;
        PendingBlockIngest rejected;
        rejected.sender_source = conn.RemoteAddr();
        rejected.sender_connection_id = conn.Identity();
        rejected.protected_request = true;
        RevokeProtectedBlockQos_(rejected);
    }

    static bool IsHardBlockReject_(const std::string& tag) {
        return tag == "pow_verify_failed" ||
               tag == "intra_block_double_spend" ||
               tag == "consensus_tx_sig_or_value_invalid" ||
               tag == "consensus_tx_sig_or_value_invalid_v2" ||
               tag == "signature_verify_fail" ||
               tag == "merkle_mismatch" ||
               tag == "block_known_body_mismatch" ||
               tag == "block_too_large" ||
               tag == "too_many_txs" ||
               tag == "empty_transactions" ||
               tag == "tx0_not_coinbase" ||
               tag == "extra_coinbase" ||
               tag == "coinbase_basic_invalid" ||
               tag == "transaction_basic_invalid" ||
               tag == "duplicate_txid_in_block" ||
               tag == "supply_cap_overflow_pre_pow" ||
               tag == "checkpoint_mismatch" ||
               tag == "foreign_genesis" ||
               tag == "stake_lock_amount_out_of_range" ||
               tag == "stake_lock_sum_overflow" ||
               tag == "stake_lock_bad_address";
    }

    static bool IsHeaderHashCacheableBlockReject_(const std::string& tag) {
        // AddBlockDirect checks transaction presence/count/basic structure,
        // complete wire size, and only then validates the Merkle commitment.
        // A peer can freely vary all pre-Merkle body fields under an honest
        // header, so NONE of those early tags may poison this header-keyed
        // cache. Keep this header-keyed optimization deliberately narrower
        // than the set of hard rejects: only failures evaluated solely from
        // the header and local chain position are admitted. Body-derived
        // failures remain retryable and cannot gain consensus significance
        // through this non-consensus cache.
        return tag == "pow_verify_failed" ||
               tag == "checkpoint_mismatch" ||
               tag == "foreign_genesis";
    }

    void CacheHeaderAuthenticatedBlockReject_(
            const std::string& tag, const std::string& hash_hex) {
        if (!IsHeaderHashCacheableBlockReject_(tag)) return;
        std::lock_guard<std::mutex> rl(rejected_mutex_);
        RejectedBlockInsertLocked_(hash_hex);
    }

    void HandleHardBlockReject_(const PendingBlockIngest& job,
                                const std::string& tag) {
        // Credit the stored source even if it disconnected while VeldHash ran.
#ifdef VELD_TEST_HOOKS
        test_block_ingest_penalty_calls_.fetch_add(
            1, std::memory_order_acq_rel);
#endif
        RecordViolation(job.sender_source, 15, tag.c_str());
        RevokeProtectedBlockQos_(job);
    }

    std::shared_ptr<mining::ExpensivePowBudget> PowBudgetForSource_(
            const std::string& source) {
        if (source.empty() || source.size() > 255) return {};
        const uint64_t now = MonotonicSeconds();
        std::lock_guard<std::mutex> lk(source_pow_budget_mtx_);
        for (auto it = source_pow_budgets_.begin();
             it != source_pow_budgets_.end();) {
            const bool idle = it->second.budget.use_count() == 1;
            const bool stale = now >= it->second.last_seen &&
                now - it->second.last_seen >= SOURCE_POW_BUDGET_TTL_SECONDS;
            if (idle && stale) it = source_pow_budgets_.erase(it);
            else ++it;
        }
        auto found = source_pow_budgets_.find(source);
        if (found != source_pow_budgets_.end()) {
            found->second.last_seen = now;
            return found->second.budget;
        }
        if (source_pow_budgets_.size() >= SOURCE_POW_BUDGET_CAP) return {};
        auto budget = std::make_shared<mining::ExpensivePowBudget>(
            1, 8, std::chrono::minutes(1));
        source_pow_budgets_.emplace(
            source, SourcePowBudgetEntry{budget, now});
        return budget;
    }

    IngestEnqueueResult EnqueueBlockIngest(
                             Block&& blk,
                             size_t wire_bytes,
                             const std::string& sender_key,
                             std::shared_ptr<Connection> sender_conn) {
        if (wire_bytes == 0 || wire_bytes > MAX_BLOCK_SIZE)
            return IngestEnqueueResult::Full;
        const std::string block_hash = HashToHex(blk.GetHash());
        const std::string source = IngestSource_(sender_key, sender_conn);
        auto source_pow_budget = PowBudgetForSource_(source);
        if (!source_pow_budget) return IngestEnqueueResult::Full;
        if (IsBanned(source)) {
            if (sender_conn) sender_conn->Close();
            return IngestEnqueueResult::Full;
        }
        bool anchor_outbound = sender_conn &&
            IsLiveConfiguredOutboundAnchor_(*sender_conn);
        Hash256 current_tip{};
        bool have_current_tip = false;
        if (anchor_outbound && !chain_.IsEmpty()) {
            current_tip = chain_.TipCopy().GetHash();
            have_current_tip = true;
        }
        bool queued = false;
        {
            std::lock_guard<std::mutex> lk(ingest_mtx_);
            const uint64_t now = MonotonicSeconds();
            PruneProtectedBlockPolicyLocked_(now);
            const uint64_t connection_id = sender_conn
                ? sender_conn->Identity() : 0;
            bool protected_request = false;
            auto lease = protected_block_requests_.find(connection_id);
            auto revoked = protected_block_qos_revoked_until_.find(source);
            if (connection_id != 0 && anchor_outbound && have_current_tip &&
                lease != protected_block_requests_.end() &&
                now <= lease->second.expires_at &&
                lease->second.block_hash == block_hash &&
                lease->second.expected_prev == blk.header.prev_block_hash &&
                lease->second.expected_prev == current_tip &&
                (revoked == protected_block_qos_revoked_until_.end() ||
                 now >= revoked->second)) {
                protected_request = true;
            }

            // Same-class duplicates remain O(1). A protected exact response is
            // deliberately allowed alongside a normal same-header front-run;
            // the protected lane runs first and the later normal job takes the
            // worker's known-body fast path without a second VeldHash.
            if (protected_request) {
                if (ingest_protected_lane_.pending_hashes.count(block_hash)) {
                    protected_block_requests_.erase(connection_id);
                    return IngestEnqueueResult::Duplicate;
                }
            } else if (ingest_normal_lane_.pending_hashes.count(block_hash) ||
                       ingest_protected_lane_.pending_hashes.count(block_hash)) {
                return IngestEnqueueResult::Duplicate;
            }

            PendingBlockIngest e;
            e.new_block   = std::move(blk);
            e.sender_key  = sender_key;
            e.sender_source = source;
            e.block_hash = block_hash;
            e.wire_bytes = wire_bytes;
            e.sender_connection_id = connection_id;
            e.protected_request = protected_request;
            e.sender_conn = std::weak_ptr<Connection>(sender_conn);
            e.source_pow_budget = std::move(source_pow_budget);
            if (protected_request) {
                const bool lane_was_idle =
                    ingest_protected_lane_.pending_jobs == 0;
                queued = QueueBlockInLaneLocked_(
                    ingest_protected_lane_, std::move(e),
                    LAYER_C_BLOCK_INGEST_PROTECTED_CAP,
                    LAYER_C_BLOCK_INGEST_PROTECTED_MAX_BYTES,
                    LAYER_C_BLOCK_INGEST_PROTECTED_PER_SOURCE_MAX_BYTES);
                if (queued) {
                    protected_block_requests_.erase(connection_id);
                    if (lane_was_idle) ingest_protected_preempt_ = true;
                }
            } else {
                queued = QueueBlockInLaneLocked_(
                    ingest_normal_lane_, std::move(e),
                    LAYER_C_BLOCK_INGEST_NORMAL_CAP,
                    LAYER_C_BLOCK_INGEST_NORMAL_MAX_BYTES,
                    LAYER_C_BLOCK_INGEST_NORMAL_PER_SOURCE_MAX_BYTES);
            }
        }
        if (!queued) return IngestEnqueueResult::Full;
        ingest_cv_.notify_one();
        return IngestEnqueueResult::Queued;
    }

    bool ShouldInjectEventLoopException_(int stage) {
#ifdef VELD_TEST_HOOKS
        int expected = stage;
        return test_event_loop_exception_stage_.compare_exchange_strong(
            expected, 0, std::memory_order_acq_rel);
#else
        (void)stage;
        return false;
#endif
    }

    void NoteContainedNetworkException_() noexcept {
#ifdef VELD_TEST_HOOKS
        test_contained_network_exceptions_.fetch_add(
            1, std::memory_order_acq_rel);
#endif
    }

    static void LogNetworkThreadException_(const char* entry,
                                           const char* detail) noexcept {
        try {
            std::cerr << "  [p2p-boundary] contained exception in "
                      << (entry ? entry : "network worker");
            if (detail && detail[0] != '\0') std::cerr << ": " << detail;
            std::cerr << "\n";
            std::cerr.flush();
        } catch (...) {
            // A diagnostic failure must never turn containment into terminate.
        }
    }

    void FinalizePeerConnectionNoThrow_(
            const std::string& key,
            const std::shared_ptr<Connection>& conn,
            const char* phase) noexcept {
        try {
            if (ShouldInjectEventLoopException_(4))
                throw std::runtime_error("injected peer-cleanup exception");
            (void)FinalizePeerConnection_(key, conn);
            return;
        } catch (const std::exception& e) {
            NoteContainedNetworkException_();
            LogNetworkThreadException_(phase, e.what());
        } catch (...) {
            NoteContainedNetworkException_();
            LogNetworkThreadException_(phase, "unknown exception");
        }

        // Retry the exact-object/idempotent cleanup once. If an allocation or
        // platform exception repeats, close the socket at minimum; the normal
        // Stop path owns the remaining registry destruction.
        try {
            (void)FinalizePeerConnection_(key, conn);
        } catch (...) {
            try {
                if (conn) conn->Close();
            } catch (...) {
            }
        }
    }

    void RetireEventLoopPeerNoThrow_(
            EventLoopWorker* w,
            const std::string& key,
            const std::shared_ptr<Connection>& conn,
            const char* phase) noexcept {
        try {
            if (w) {
                auto it = w->peer_states.find(key);
                if (it != w->peer_states.end() && it->second.conn == conn)
                    w->peer_states.erase(it);
            }
        } catch (...) {
            NoteContainedNetworkException_();
            LogNetworkThreadException_("event-loop peer-state cleanup",
                                       "container exception");
        }
        FinalizePeerConnectionNoThrow_(key, conn, phase);
    }

    void RetireEventLoopWorkerStateNoThrow_(EventLoopWorker* w) noexcept {
        if (!w) return;
        try {
            while (!w->peer_states.empty()) {
                auto node = w->peer_states.extract(w->peer_states.begin());
                FinalizePeerConnectionNoThrow_(
                    node.key(), node.mapped().conn,
                    "event-loop shard recovery");
            }
        } catch (...) {
            NoteContainedNetworkException_();
            LogNetworkThreadException_("event-loop shard recovery",
                                       "peer-state cleanup exception");
        }

        try {
            std::deque<EventLoopWorker::PendingNewPeer> pending;
            {
                std::lock_guard<std::mutex> lk(w->incoming_mtx);
                pending.swap(w->incoming);
            }
            while (!pending.empty()) {
                auto np = std::move(pending.front());
                pending.pop_front();
                FinalizePeerConnectionNoThrow_(
                    np.key, np.conn, "event-loop handoff recovery");
            }
        } catch (...) {
            NoteContainedNetworkException_();
            LogNetworkThreadException_("event-loop handoff recovery",
                                       "pending-peer cleanup exception");
        }
    }

    void EventLoopWorkerThreadEntry_(EventLoopWorker* w) noexcept {
        while (w && w->running.load(std::memory_order_acquire) &&
               running_.load(std::memory_order_acquire)) {
            try {
                EventLoopWorkerLoop(w);
                return;
            } catch (const std::exception& e) {
                NoteContainedNetworkException_();
                LogNetworkThreadException_("event-loop worker", e.what());
            } catch (...) {
                NoteContainedNetworkException_();
                LogNetworkThreadException_("event-loop worker",
                                           "unknown exception");
            }
            RetireEventLoopWorkerStateNoThrow_(w);
            if (w->running.load(std::memory_order_acquire) &&
                running_.load(std::memory_order_acquire))
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        RetireEventLoopWorkerStateNoThrow_(w);
    }

    void AcceptThreadEntry_() noexcept {
        while (running_.load(std::memory_order_acquire)) {
            try {
                AcceptThreadLoop();
                return;
            } catch (const std::exception& e) {
                NoteContainedNetworkException_();
                LogNetworkThreadException_("event-loop acceptor", e.what());
            } catch (...) {
                NoteContainedNetworkException_();
                LogNetworkThreadException_("event-loop acceptor",
                                           "unknown exception");
            }
            if (running_.load(std::memory_order_acquire))
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    void LegacyAcceptThreadEntry_() noexcept {
        while (running_.load(std::memory_order_acquire)) {
            try {
                AcceptLoop();
                return;
            } catch (const std::exception& e) {
                NoteContainedNetworkException_();
                LogNetworkThreadException_("legacy acceptor", e.what());
            } catch (...) {
                NoteContainedNetworkException_();
                LogNetworkThreadException_("legacy acceptor",
                                           "unknown exception");
            }
            if (running_.load(std::memory_order_acquire))
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    void BlockIngestThreadEntry_() noexcept {
        while (ingest_running_.load(std::memory_order_acquire)) {
            try {
                BlockIngestWorker();
                return;
            } catch (const std::exception& e) {
                NoteContainedNetworkException_();
                LogNetworkThreadException_("block-ingest worker", e.what());
            } catch (...) {
                NoteContainedNetworkException_();
                LogNetworkThreadException_("block-ingest worker",
                                           "unknown exception");
            }
            if (ingest_running_.load(std::memory_order_acquire))
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    void AcceptThreadLoop() {
        while (running_) {
#ifdef _WIN32
            WSAPOLLFD pfd{(SOCKET)listen_fd_, POLLIN, 0};
            int pr = ::WSAPoll(&pfd, 1, 100);
#else
            struct pollfd pfd{listen_fd_, POLLIN, 0};
            int pr = ::poll(&pfd, 1, 100);
#endif
            if (pr <= 0) continue;
            if ((pfd.revents & POLLIN) == 0) continue;

            struct sockaddr_in client_addr{};
            socklen_t addr_len = sizeof(client_addr);
            SocketHandle client_fd = ::accept(listen_fd_,
                (struct sockaddr*)&client_addr, &addr_len);
            if (!veld::compat::IsValidSocket(client_fd)) continue;

            std::string remote_addr;
            std::string key;
            auto conn = AdmitInboundConnection(client_fd, client_addr,
                                                key, remote_addr);
            if (!conn) continue;

            // Send our tiny VERSION directly from the accept thread.  Deferring
            // this to a busy event-loop worker made the handshake depend on the
            // same CPU pool that may be verifying an IBD burst.
            PeerManager pm(magic_, chain_.Height(),
                           local_services_.load(std::memory_order_acquire));
            if (!conn->Send(pm.BuildVersionMessage(chain_.Height(), self_nonce_))) {
                FinalizePeerConnection_(key, conn);
                continue;
            }
            auto ps = std::make_shared<PeerState>();
            if (!HandOffNewPeerToWorker(key, conn, ps, false)) {
                FinalizePeerConnection_(key, conn);
            }
        }
    }

    void EventLoopWorkerLoop(EventLoopWorker* w) {
        struct PeerFdEntry {
            SocketHandle                   fd;
            std::shared_ptr<Connection>    conn;
            std::string                    key;
            PeerStatePtr                   ps;
        };

        while (w->running.load(std::memory_order_acquire) && running_) {
            if (ShouldInjectEventLoopException_(1))
                throw std::bad_alloc();
            PeerManager pm(magic_, chain_.Height(),
                           local_services_.load(std::memory_order_acquire));

            {
                std::vector<EventLoopWorker::PendingNewPeer> drained;
                {
                    std::lock_guard<std::mutex> lk(w->incoming_mtx);
                    constexpr size_t MAX_NEW_PEERS_PER_TICK = 128;
                    const size_t count = std::min(
                        MAX_NEW_PEERS_PER_TICK, w->incoming.size());
                    drained.reserve(count);
                    for (size_t i = 0; i < count; ++i) {
                        drained.push_back(std::move(w->incoming.front()));
                        w->incoming.pop_front();
                    }
                }
                for (auto& np : drained) {
                    try {
                    bool still_registered = false;
                    {
                        std::lock_guard<std::mutex> lk(peers_mutex_);
                        auto it = peer_connections_.find(np.key);
                        still_registered =
                            it != peer_connections_.end() &&
                            it->second == np.conn;
                    }
                    if (!still_registered) {
                        RetireEventLoopPeerNoThrow_(
                            w, np.key, np.conn,
                            "event-loop stale handoff");
                        continue;
                    }
                    if (np.needs_initial_version_send && np.conn) {
                        if (!np.conn->TrySend(pm.BuildVersionMessage(
                                chain_.Height(), self_nonce_))) {
                            // A newer same-key dial may already own the map.
                            // Retire only the socket whose handoff failed.
                            RetireEventLoopPeerNoThrow_(
                                w, np.key, np.conn,
                                "event-loop VERSION handoff");
                            continue;
                        }
                    }
                    w->peer_states[np.key] = {np.conn, np.ps};
                    } catch (const std::exception& e) {
                        NoteContainedNetworkException_();
                        LogNetworkThreadException_(
                            "event-loop peer handoff", e.what());
                        RetireEventLoopPeerNoThrow_(
                            w, np.key, np.conn,
                            "event-loop handoff cleanup");
                    } catch (...) {
                        NoteContainedNetworkException_();
                        LogNetworkThreadException_(
                            "event-loop peer handoff", "unknown exception");
                        RetireEventLoopPeerNoThrow_(
                            w, np.key, np.conn,
                            "event-loop handoff cleanup");
                    }
                }
            }

            {
                std::vector<std::pair<std::string,
                                      std::shared_ptr<Connection>>> stale;
                {
                    std::lock_guard<std::mutex> lk(peers_mutex_);
                    for (const auto& [k, bound] : w->peer_states) {
                        auto it = peer_connections_.find(k);
                        if (it == peer_connections_.end() || !it->second ||
                            it->second != bound.conn ||
                            !bound.conn || !bound.conn->IsConnected()) {
                            stale.push_back({k, bound.conn});
                        }
                    }
                }
                for (const auto& [k, stale_conn] : stale) {
                    RetireEventLoopPeerNoThrow_(
                        w, k, stale_conn, "event-loop stale peer");
                }
            }

            std::vector<PeerFdEntry> peer_fds;
            peer_fds.reserve(w->peer_states.size());
            {
                std::lock_guard<std::mutex> lk(peers_mutex_);
                for (const auto& [k, bound] : w->peer_states) {
                    auto it = peer_connections_.find(k);
                    if (it == peer_connections_.end() ||
                        it->second != bound.conn) continue;
                    auto& c = bound.conn;
                    if (!c || !c->IsConnected()) continue;
                    SocketHandle f = c->Fd();
                    if (!veld::compat::IsValidSocket(f)) continue;
                    peer_fds.push_back({f, c, k, bound.state});
                }
            }
            std::sort(peer_fds.begin(), peer_fds.end(),
                [](const PeerFdEntry& a, const PeerFdEntry& b) {
                    return a.key < b.key;
                });

#ifdef _WIN32
            std::vector<WSAPOLLFD> pfds;
            pfds.reserve(peer_fds.size());
            for (const auto& e : peer_fds) {
                const short events = static_cast<short>(
                    POLLIN | (e.conn->HasPendingEventLoopSend() ? POLLOUT : 0));
                pfds.push_back({(SOCKET)e.fd, events, 0});
            }
            int pr = pfds.empty() ? 0
                : ::WSAPoll(pfds.data(), (ULONG)pfds.size(), 50);
#else
            std::vector<struct pollfd> pfds;
            pfds.reserve(peer_fds.size());
            for (const auto& e : peer_fds) {
                const short events = static_cast<short>(
                    POLLIN | (e.conn->HasPendingEventLoopSend() ? POLLOUT : 0));
                pfds.push_back({e.fd, events, 0});
            }
            int pr = pfds.empty() ? 0
                : ::poll(pfds.data(), pfds.size(), 50);
#endif
            if (pfds.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            if (pr < 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            std::vector<std::shared_ptr<Connection>> died;
            std::vector<std::string> died_keys;
            std::vector<bool> peer_done(pfds.size(), false);
            const size_t io_start = pfds.empty()
                ? 0 : (w->io_cursor % pfds.size());
            if (!pfds.empty()) w->io_cursor = (io_start + 1) % pfds.size();

            // Writes are globally and per-peer bounded per poll turn.  A slow
            // reader therefore retains only its bounded queue and cannot make
            // unrelated peers wait behind a blocking send or one giant flush.
            constexpr size_t MAX_WRITE_BYTES_PER_TICK = 4 * 1024 * 1024;
            constexpr size_t MAX_WRITE_BYTES_PER_PEER = 256 * 1024;
            size_t write_budget = MAX_WRITE_BYTES_PER_TICK;
            for (size_t off = 0; off < pfds.size(); ++off) {
                const size_t i = (io_start + off) % pfds.size();
                short rev = pfds[i].revents;
                auto& entry = peer_fds[i];
                if (rev & (POLLERR | POLLHUP | POLLNVAL)) {
                    died.push_back(entry.conn);
                    died_keys.push_back(entry.key);
                    peer_done[i] = true;
                    continue;
                }
                if ((rev & POLLOUT) && write_budget > 0 &&
                    entry.conn->HasPendingEventLoopSend()) {
                    try {
                    const size_t allowance = std::min(
                        write_budget, MAX_WRITE_BYTES_PER_PEER);
                    const size_t before = entry.conn->QueuedSendBytes();
                    if (!entry.conn->FlushEventLoopSend(allowance)) {
                        died.push_back(entry.conn);
                        died_keys.push_back(entry.key);
                        peer_done[i] = true;
                        continue;
                    }
                    const size_t after = entry.conn->QueuedSendBytes();
                    const size_t wrote = before >= after ? before - after : 0;
                    write_budget -= std::min(write_budget, wrote);
                    } catch (const std::exception& e) {
                        NoteContainedNetworkException_();
                        LogNetworkThreadException_(
                            "event-loop peer write", e.what());
                        RetireEventLoopPeerNoThrow_(
                            w, entry.key, entry.conn,
                            "event-loop write cleanup");
                        peer_done[i] = true;
                        continue;
                    } catch (...) {
                        NoteContainedNetworkException_();
                        LogNetworkThreadException_(
                            "event-loop peer write", "unknown exception");
                        RetireEventLoopPeerNoThrow_(
                            w, entry.key, entry.conn,
                            "event-loop write cleanup");
                        peer_done[i] = true;
                        continue;
                    }
                }
                if (!(rev & POLLIN)) peer_done[i] = true;
            }
            constexpr int MAX_DRAIN_PASSES = 256;
            constexpr size_t MAX_RECV_CALLS_PER_TICK = 256;
            constexpr size_t MAX_MESSAGES_PER_TICK = 128;
            constexpr size_t MAX_RECV_BYTES_PER_TICK = 4 * 1024 * 1024;
            size_t recv_calls = 0;
            size_t messages = 0;
            size_t recv_bytes = 0;
            for (int pass = 0;
                 pass < MAX_DRAIN_PASSES &&
                 recv_calls < MAX_RECV_CALLS_PER_TICK &&
                 messages < MAX_MESSAGES_PER_TICK &&
                 recv_bytes < MAX_RECV_BYTES_PER_TICK;
                 ++pass) {
                bool any_progress = false;
                for (size_t off = 0;
                     off < pfds.size() &&
                     recv_calls < MAX_RECV_CALLS_PER_TICK &&
                     messages < MAX_MESSAGES_PER_TICK &&
                     recv_bytes < MAX_RECV_BYTES_PER_TICK;
                     ++off) {
                    const size_t i = (io_start + off) % pfds.size();
                    if (peer_done[i]) continue;
                    auto& entry = peer_fds[i];
                    try {
                    const uint64_t before_recv = entry.conn->BytesRecv();
                    auto rr = entry.conn->TryRecvMessage(magic_);
                    ++recv_calls;
                    const uint64_t after_recv = entry.conn->BytesRecv();
                    if (after_recv >= before_recv) {
                        const uint64_t delta = after_recv - before_recv;
                        recv_bytes += static_cast<size_t>(std::min<uint64_t>(
                            delta, MAX_RECV_BYTES_PER_TICK - recv_bytes));
                    }
                    if (rr.status == Connection::TryRecvStatus::WouldBlock) {
                        peer_done[i] = true;
                        continue;
                    }
                    if (rr.status == Connection::TryRecvStatus::Error) {
                        died.push_back(entry.conn);
                        died_keys.push_back(entry.key);
                        peer_done[i] = true;
                        continue;
                    }
                    any_progress = true;
                    ++messages;
                    auto rl = CheckRateLimit(*entry.conn);
                    if (!rl.allow) continue;
                    if (!entry.ps->their_version &&
                        rr.msg.command != MessageType::VERSION &&
                        rr.msg.command != MessageType::VERACK) {
                        RecordViolation(entry.conn->RemoteAddr(), 0, "pre_handshake");
                        continue;
                    }
                    if (ShouldInjectEventLoopException_(2))
                        throw std::runtime_error(
                            "injected peer-dispatch exception");
                    auto sr = PeerProtocolStep(*entry.ps, *entry.conn, pm,
                                               rr.msg, entry.key,
                                               entry.conn->IsInbound());
                    if (sr == StepResult::DropPeer) {
                        died.push_back(entry.conn);
                        died_keys.push_back(entry.key);
                        peer_done[i] = true;
                        continue;
                    }
                    } catch (const std::exception& e) {
                        NoteContainedNetworkException_();
                        LogNetworkThreadException_(
                            "event-loop peer dispatch", e.what());
                        RetireEventLoopPeerNoThrow_(
                            w, entry.key, entry.conn,
                            "event-loop dispatch cleanup");
                        peer_done[i] = true;
                        continue;
                    } catch (...) {
                        NoteContainedNetworkException_();
                        LogNetworkThreadException_(
                            "event-loop peer dispatch", "unknown exception");
                        RetireEventLoopPeerNoThrow_(
                            w, entry.key, entry.conn,
                            "event-loop dispatch cleanup");
                        peer_done[i] = true;
                        continue;
                    }
                }
                if (!any_progress) break;
            }

            if (!died.empty()) {
                for (size_t i = 0; i < died_keys.size(); ++i) {
                    RetireEventLoopPeerNoThrow_(
                        w, died_keys[i], died[i],
                        "event-loop peer retirement");
                }
            }

            {
                std::vector<PeerFdEntry> alive_fds;
                alive_fds.reserve(w->peer_states.size());
                {
                    std::lock_guard<std::mutex> lk(peers_mutex_);
                    for (const auto& [k, bound] : w->peer_states) {
                        auto it = peer_connections_.find(k);
                        if (it == peer_connections_.end() ||
                            it->second != bound.conn) continue;
                        auto& c = bound.conn;
                        if (!c || !c->IsConnected()) continue;
                        alive_fds.push_back(
                            {c->Fd(), c, k, bound.state});
                    }
                }
                std::sort(alive_fds.begin(), alive_fds.end(),
                    [](const PeerFdEntry& a, const PeerFdEntry& b) {
                        return a.key < b.key;
                    });
                std::vector<std::shared_ptr<Connection>> timer_died;
                std::vector<std::string> timer_died_keys;
                constexpr size_t MAX_TIMERS_PER_TICK = 128;
                const size_t timer_count = std::min(
                    MAX_TIMERS_PER_TICK, alive_fds.size());
                const size_t timer_start = alive_fds.empty()
                    ? 0 : (w->timer_cursor % alive_fds.size());
                if (!alive_fds.empty()) {
                    w->timer_cursor = (timer_start + timer_count) %
                                      alive_fds.size();
                }
                for (size_t off = 0; off < timer_count; ++off) {
                    auto& e = alive_fds[(timer_start + off) % alive_fds.size()];
                    try {
                        if (ShouldInjectEventLoopException_(3))
                            throw std::runtime_error(
                                "injected peer-timer exception");
                        if (RunPeerTimers(*e.ps, *e.conn, pm)) {
                            timer_died.push_back(e.conn);
                            timer_died_keys.push_back(e.key);
                        }
                    } catch (const std::exception& ex) {
                        NoteContainedNetworkException_();
                        LogNetworkThreadException_(
                            "event-loop peer timer", ex.what());
                        RetireEventLoopPeerNoThrow_(
                            w, e.key, e.conn,
                            "event-loop timer cleanup");
                    } catch (...) {
                        NoteContainedNetworkException_();
                        LogNetworkThreadException_(
                            "event-loop peer timer", "unknown exception");
                        RetireEventLoopPeerNoThrow_(
                            w, e.key, e.conn,
                            "event-loop timer cleanup");
                    }
                }
                if (!timer_died.empty()) {
                    for (size_t i = 0; i < timer_died_keys.size(); ++i) {
                        RetireEventLoopPeerNoThrow_(
                            w, timer_died_keys[i], timer_died[i],
                            "event-loop timer retirement");
                    }
                }
            }
        }
        w->peer_states.clear();
    }

    void ProcessBlockIngestJob_(PendingBlockIngest& job) {
        // A prior item from this source may have crossed the ban threshold
        // while later items were already queued. Never run another
        // memory-hard consensus validation for that source.
        if (IsBanned(job.sender_source)) {
            if (auto sc = job.sender_conn.lock()) sc->Close();
            return;
        }

        // A protected response may intentionally coexist with a normal
        // same-header front-run. Whichever validates first makes the other a
        // cheap exact-body check, never a second memory-hard proof verify.
        auto already_known = chain_.GetBlockByHash(job.new_block.GetHash());
        if (already_known.has_value()) {
            if (already_known->Serialize() != job.new_block.Serialize()) {
                HandleHardBlockReject_(job, "block_known_body_mismatch");
                return;
            }
            if (chain_.IsCanonicalBlock(job.new_block.GetHash()) ||
                !chain_.IsVolatileSideBlock(job.new_block.GetHash())) return;
            // Only volatile quarantine entries fall through: a transient local
            // work deferral may be retried without another ingress hash.
        }

#ifdef VELD_TEST_HOOKS
        test_block_ingest_consensus_calls_.fetch_add(
            1, std::memory_order_acq_rel);
#endif
        if (!job.source_pow_budget) return;
        const auto admission = chain_.AddBlockDirect(
            job.new_block, false, true, false,
            mining::PowAdmissionContext::Peer(
                job.sender_source, job.source_pow_budget));
        if (admission.IsAccepted()) {
            // The queued wire block carried height=0. AddBlockDirect has now
            // replaced it with the locally parent-derived height; only at this
            // point may the sender influence height/tip evidence.
            if (auto sc = job.sender_conn.lock()) {
                const std::string peer_ip = sc->RemoteAddr();
                RecordVerifiedPeerHeight_(peer_ip, job.new_block.GetHash());
                int64_t now_s = (int64_t)std::chrono::duration_cast<
                    std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                RecordPeerTip(*sc, job.new_block.GetHash(),
                              job.new_block.height, now_s);
            }
            // Post-accept INV broadcast — sender NOT excluded so its INV
            // handler fires on_block_ack_ for layer-1 quorum tracking.
            if (ibd_complete_flag_.load()) {
#ifdef VELD_TEST_HOOKS
                test_block_ingest_relay_calls_.fetch_add(
                    1, std::memory_order_acq_rel);
#endif
                PeerManager pm(magic_, chain_.Height());
                BroadcastMessage(
                    pm.BuildInvMessage({InvItem(InvType::BLOCK,
                                                job.new_block.GetHash())}),
                    "");
            }
            if (on_block_) on_block_(job.new_block, job.sender_key);

            if (auto sc = job.sender_conn.lock()) {
                PeerManager pm2(magic_, chain_.Height());
                ProcessOrphanChain(job.new_block.GetHash(), pm2,
                                   *sc, job.sender_key);
            }
            return;
        }

        // The tag is per-thread and belongs to this exact AddBlockDirect call.
        // Cache only a header-authenticated permanent failure. In particular,
        // no body failure reached before the Merkle check is cacheable.
        const std::string rt = chain_.GetLastRejectTag();
        if (IsHardBlockReject_(rt)) {
            HandleHardBlockReject_(job, rt);
            CacheHeaderAuthenticatedBlockReject_(rt, job.block_hash);
        }
    }

    // Block-ingest worker. A single thread drains the queue and serializes commit
    // work via AddBlockDirect under chain unique_lock. Event-loop
    // workers never hold chain unique_lock; they only enqueue here.
    //
    // Why single thread: chain_mutex_ is unique_lock during commit, so
    // multiple ingest workers couldn't parallelize anyway. One thread
    // keeps queue ordering deterministic and avoids needless context
    // switches.
    //
    // Post-accept INV broadcast: after a successful AddBlockDirect we
    // call BroadcastMessage(INV) which iterates the shared
    // peer_connections_ — sender NOT excluded so the sender's INV
    // handler fires on_block_ack_ on receipt, satisfying the layer-1
    // ACK quorum (preserved from original PeerProtocolStep BLOCK
    // handler at tcp.h:4741-4745).
    void BlockIngestWorker() {
#ifdef _WIN32
        // Independent snapshot validation is deliberately subordinate to the
        // foreground node. Windows background mode lowers both CPU scheduling
        // and I/O priority for this consensus-heavy worker without changing
        // validation order or weakening any block check.
        if (background_sync_mode_)
            ::SetThreadPriority(::GetCurrentThread(),
                                THREAD_MODE_BACKGROUND_BEGIN);
#endif
        while (ingest_running_.load(std::memory_order_acquire)) {
            PendingBlockIngest job;
            {
                std::unique_lock<std::mutex> lk(ingest_mtx_);
                ingest_cv_.wait_for(lk, std::chrono::milliseconds(200), [this]{
                    return LaneHasQueued_(ingest_protected_lane_) ||
                           LaneHasQueued_(ingest_normal_lane_) ||
                           !ingest_running_.load(std::memory_order_acquire);
                });
                if (!ingest_running_.load(std::memory_order_acquire)) break;
                if (!TakeNextBlockIngestLocked_(job)) continue;
            }

            struct PendingAccountingGuard {
                std::function<void()> release;
                ~PendingAccountingGuard() { if (release) release(); }
            } accounting_guard{
                [this, &job] { ReleasePendingBlockAccounting_(job); }};

            try {
                ProcessBlockIngestJob_(job);
            } catch (const std::exception& e) {
                std::cerr << "  [block-ingest] consensus worker exception for "
                          << job.block_hash.substr(0, 16) << "...: "
                          << e.what() << " — item released, worker continues\n";
                std::cerr.flush();
            } catch (...) {
                std::cerr << "  [block-ingest] unknown consensus worker exception for "
                          << job.block_hash.substr(0, 16)
                          << "... — item released, worker continues\n";
                std::cerr.flush();
            }
            if (background_sync_mode_) std::this_thread::yield();
        }
    }
    void AcceptLoopEventDriven() {

        struct PeerFdEntry {
            SocketHandle fd;
            std::shared_ptr<Connection> conn;
            std::string key;
            PeerStatePtr ps;
        };

        while (running_) {
            PeerManager pm(magic_, chain_.Height());

            std::vector<PeerFdEntry> peer_fds;
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                peer_fds.reserve(peer_connections_.size());
                for (const auto& [k, c] : peer_connections_) {
                    if (!c || !c->IsConnected()) continue;
                    SocketHandle f = c->Fd();
                    if (!veld::compat::IsValidSocket(f)) continue;
                    auto sit = peer_states_.find(k);
                    if (sit == peer_states_.end() ||
                        sit->second.conn != c) continue;
                    peer_fds.push_back({f, c, k, sit->second.state});
                }
            }

#ifdef _WIN32
            std::vector<WSAPOLLFD> pfds;
            pfds.reserve(peer_fds.size() + 1);
            pfds.push_back({(SOCKET)listen_fd_, POLLIN, 0});
            for (const auto& e : peer_fds) {
                pfds.push_back({(SOCKET)e.fd, POLLIN, 0});
            }
            int pr = ::WSAPoll(pfds.data(), (ULONG)pfds.size(), 50);
#else
            std::vector<struct pollfd> pfds;
            pfds.reserve(peer_fds.size() + 1);
            pfds.push_back({listen_fd_, POLLIN, 0});
            for (const auto& e : peer_fds) {
                pfds.push_back({e.fd, POLLIN, 0});
            }
            int pr = ::poll(pfds.data(), pfds.size(), 50);
#endif
            if (pr < 0) {
                if (running_) std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            std::vector<std::shared_ptr<Connection>> died;
            std::vector<std::string> died_keys;
            for (size_t i = 1; i < pfds.size(); ++i) {
                short rev = pfds[i].revents;
                auto& entry = peer_fds[i - 1];
                if (rev & POLLERR) {
                    died.push_back(entry.conn);
                    died_keys.push_back(entry.key);
                    continue;
                }
                if (!(rev & POLLIN)) continue;
                for (int draindrop = 0; draindrop < 256; ++draindrop) {
                    auto rr = entry.conn->TryRecvMessage(magic_);
                    if (rr.status == Connection::TryRecvStatus::WouldBlock) break;
                    if (rr.status == Connection::TryRecvStatus::Error) {
                        died.push_back(entry.conn);
                        died_keys.push_back(entry.key);
                        break;
                    }
                    auto rl = CheckRateLimit(*entry.conn);
                    if (!rl.allow) continue;
                    if (!entry.ps->their_version &&
                        rr.msg.command != MessageType::VERSION &&
                        rr.msg.command != MessageType::VERACK) {
                        RecordViolation(entry.conn->RemoteAddr(), 0, "pre_handshake");
                        continue;
                    }
                    auto sr = PeerProtocolStep(*entry.ps, *entry.conn, pm,
                                               rr.msg, entry.key,
                                               entry.conn->IsInbound());
                    if (sr == StepResult::DropPeer) {
                        died.push_back(entry.conn);
                        died_keys.push_back(entry.key);
                        break;
                    }
                }
            }

            if (!died.empty()) {
                static std::atomic<uint64_t> el_died_total{0};
                uint64_t total = el_died_total.fetch_add(died.size()) + died.size();
                if (total / 100 != (total - died.size()) / 100) {
                    std::cerr << "  [event-loop] dropped " << died.size()
                              << " peer(s) this tick (cumulative=" << total << ")\n";
                    std::cerr.flush();
                }
                for (size_t i = 0; i < died_keys.size(); ++i) {
                    auto sit = peer_states_.find(died_keys[i]);
                    if (sit != peer_states_.end() &&
                        sit->second.conn == died[i]) {
                        peer_states_.erase(sit);
                    }
                    FinalizePeerConnection_(died_keys[i], died[i]);
                }
            }

            {
                std::vector<PeerFdEntry> alive_fds;
                {
                    std::lock_guard<std::mutex> lock(peers_mutex_);
                    alive_fds.reserve(peer_connections_.size());
                    for (const auto& [k, c] : peer_connections_) {
                        if (!c || !c->IsConnected()) continue;
                        auto sit = peer_states_.find(k);
                        if (sit == peer_states_.end() ||
                            sit->second.conn != c) continue;
                        alive_fds.push_back(
                            {c->Fd(), c, k, sit->second.state});
                    }
                }
                std::vector<std::shared_ptr<Connection>> timer_died;
                std::vector<std::string> timer_died_keys;
                for (auto& e : alive_fds) {
                    if (RunPeerTimers(*e.ps, *e.conn, pm)) {
                        timer_died.push_back(e.conn);
                        timer_died_keys.push_back(e.key);
                    }
                }
                if (!timer_died.empty()) {
                    for (size_t i = 0; i < timer_died_keys.size(); ++i) {
                        auto sit = peer_states_.find(timer_died_keys[i]);
                        if (sit != peer_states_.end() &&
                            sit->second.conn == timer_died[i]) {
                            peer_states_.erase(sit);
                        }
                        FinalizePeerConnection_(timer_died_keys[i],
                                                timer_died[i]);
                    }
                }
            }

            if (pfds[0].revents & POLLIN) {
                AcceptOnePeerEventDriven(pm);
            }
        }

        // Shared registry ownership belongs to Stop(), after the driver exits.
        // Clearing peer_connections_ here used to bypass direction accounting.
        peer_states_.clear();
    }

    std::shared_ptr<Connection>
    AdmitInboundConnection(SocketHandle client_fd,
                           const sockaddr_in& client_addr,
                           std::string& out_key,
                           std::string& out_remote_addr) {
        {
            char ip_early[INET_ADDRSTRLEN];
            ::inet_ntop(AF_INET, &client_addr.sin_addr, ip_early, sizeof(ip_early));
            std::string ip_str(ip_early);
            bool is_trusted_early = false;
            {
                std::lock_guard<std::mutex> lock(ban_mutex_);
                is_trusted_early = trusted_ips_.count(ip_str) > 0;
            }
            if (!is_trusted_early) {
                constexpr uint32_t ACCEPT_PER_IP_PER_60S = 30;
                if (!TakeIpRateToken(accept_rate_per_ip_, ip_str, ACCEPT_PER_IP_PER_60S)) {
                    VELD_CLOSE_SOCKET(client_fd);
                    const bool emit = TakeKeyCooldown(
                        accept_drop_log_at_, ip_str, 60, 600, 4096);
                    if (emit) {
                        std::cerr << "  [accept-rate-limit] dropping fresh conn from "
                                  << ip_str << " — over " << ACCEPT_PER_IP_PER_60S
                                  << " accepts/60s\n";
                        std::cerr.flush();
                    }
                    return nullptr;
                }
            }
        }

        {
            // The shared listener is non-blocking to avoid accept thundering-
            // herd stalls.  Normalize accepted sockets back to blocking for the
            // synchronous VERSION send; event-loop handoff switches them to its
            // own non-blocking queue semantics afterward.
#ifdef _WIN32
            u_long accepted_blocking = 0;
            if (::ioctlsocket((SOCKET)client_fd, FIONBIO,
                              &accepted_blocking) != 0) {
                VELD_CLOSE_SOCKET(client_fd);
                return nullptr;
            }
#else
            const int accepted_flags = ::fcntl(client_fd, F_GETFL, 0);
            if (accepted_flags == -1 ||
                ::fcntl(client_fd, F_SETFL,
                        accepted_flags & ~O_NONBLOCK) == -1) {
                VELD_CLOSE_SOCKET(client_fd);
                return nullptr;
            }
#endif
            int ka = 1;
            ::setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&ka, sizeof(ka));
#ifdef TCP_KEEPIDLE
            int keepidle = 10, keepintvl = 5, keepcnt = 3;
            ::setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE,  (const char*)&keepidle,  sizeof(keepidle));
            ::setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPINTVL, (const char*)&keepintvl, sizeof(keepintvl));
            ::setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPCNT,   (const char*)&keepcnt,   sizeof(keepcnt));
#endif
#ifdef _WIN32
            struct tcp_keepalive_vals_in {
                u_long onoff;
                u_long keepalivetime;
                u_long keepaliveinterval;
            } kav = { 1, 10000, 5000 };
            DWORD bytes_returned = 0;
            ::WSAIoctl(client_fd, 0x98000004 ,
                       &kav, sizeof(kav), nullptr, 0,
                       &bytes_returned, nullptr, nullptr);
#endif
        }

        char ip[INET_ADDRSTRLEN];
        ::inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        std::string remote_addr = ip;
        uint16_t remote_port = ntohs(client_addr.sin_port);
        std::string key = remote_addr + ":" + std::to_string(remote_port);

        if (IsBanned(remote_addr)) {
            VELD_CLOSE_SOCKET(client_fd);
            return nullptr;
        }
        constexpr size_t PER_IP_CAP     = 25;
        constexpr size_t PER_SUBNET_CAP = 75;
        auto conn = std::make_shared<Connection>(client_fd, remote_addr, remote_port, true);
        std::shared_ptr<Connection> superseded_same_key;
        std::vector<std::shared_ptr<Connection>> eviction_victims;
        size_t observed_same_ip = 0;
        bool admitted = false;

        bool ip_is_trusted = false;
        {
            std::lock_guard<std::mutex> blk(ban_mutex_);
            ip_is_trusted = trusted_ips_.count(remote_addr) > 0;
        }
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            size_t same_ip_count = 0;
            size_t same_ip_pre_version = 0;
            const auto subnet_24 = [](const std::string& ipx) -> std::string {
                auto p = ipx.find_last_of('.');
                return (p == std::string::npos) ? ipx : ipx.substr(0, p);
            };
            const std::string my_subnet = subnet_24(remote_addr);
            size_t same_subnet_count = 0;
            for (const auto& [k, c] : peer_connections_) {
                if (k == key) continue;
                if (!c) continue;
                if (subnet_24(c->RemoteAddr()) == my_subnet)
                    ++same_subnet_count;
                if (c->RemoteAddr() == remote_addr) {
                    ++same_ip_count;
                    if (c->IsInbound() && c->IsConnected() &&
                        !c->VersionReceived()) {
                        ++same_ip_pre_version;
                    }
                }
            }
            observed_same_ip = same_ip_count;

            auto same_key_it = peer_connections_.find(key);
            const uint32_t replaced_inbound =
                (same_key_it != peer_connections_.end() &&
                 same_key_it->second && same_key_it->second->IsInbound()) ? 1u : 0u;
            const uint32_t current_inbound =
                inbound_count_.load(std::memory_order_acquire);

            bool reject = !running_.load(std::memory_order_acquire) ||
                current_inbound - std::min(current_inbound, replaced_inbound) + 1u >
                    max_inbound_connections_;
            if (!ip_is_trusted &&
                same_ip_pre_version >= PRE_VERSION_PER_IP_CAP) {
                reject = true;
            }

            if (!reject && !ip_is_trusted && same_ip_count >= PER_IP_CAP) {
                std::vector<std::pair<int64_t, std::string>> closable;
                closable.reserve(same_ip_count);
                for (const auto& [k, c] : peer_connections_) {
                    if (k == key) continue;
                    if (!c || c->RemoteAddr() != remote_addr) continue;
                    int64_t sort_key = c->IsConnected()
                        ? static_cast<int64_t>(c->BytesRecv())
                        : -1;
                    closable.emplace_back(sort_key, k);
                }
                std::sort(closable.begin(), closable.end());
                size_t need_to_close = (same_ip_count + 1) - PER_IP_CAP;
                for (const auto& [_sort, k] : closable) {
                    if (eviction_victims.size() >= need_to_close) break;
                    auto it = peer_connections_.find(k);
                    if (it != peer_connections_.end() && it->second)
                        eviction_victims.push_back(it->second);
                }
            }

            if (!ip_is_trusted) {
                const size_t projected_ip =
                    same_ip_count - std::min(same_ip_count,
                                              eviction_victims.size());
                const size_t projected_subnet =
                    same_subnet_count - std::min(same_subnet_count,
                                                  eviction_victims.size());
                if (projected_ip >= PER_IP_CAP ||
                    projected_subnet >= PER_SUBNET_CAP) reject = true;
            }

            if (!reject) {
                for (const auto& victim : eviction_victims) {
                    for (auto it = peer_connections_.begin();
                         it != peer_connections_.end(); ++it) {
                        if (it->second != victim) continue;
                        DecrConnCount_(it->second);
                        peer_connections_.erase(it);
                        break;
                    }
                }
                admitted = RegisterAdmittedConnectionLocked_(
                    key, conn, superseded_same_key);
            }
        }
        for (const auto& victim : eviction_victims)
            RetireDetachedConnection_(victim);
        if (superseded_same_key)
            RetireDetachedConnection_(superseded_same_key);
        if (!admitted) {
            RetireDetachedConnection_(conn);
            return nullptr;
        }
        if (!eviction_victims.empty()) {
            std::cerr << "  [per-ip-cap] " << remote_addr
                      << " was at " << observed_same_ip
                      << " connections; closed " << eviction_victims.size()
                      << " (dead+oldest) to make room for new\n";
            std::cerr.flush();
        }
        // Cache an inbound address only in this server's transport namespace.
        // Hard-coding final-mainnet 8333 here poisoned a testnet peers.dat
        // with cross-role endpoints even though the listener itself was 19333.
        AddKnownPeer(remote_addr, InboundPeerCachePort_());

        out_key = key;
        out_remote_addr = remote_addr;
        return conn;
    }

    uint16_t InboundPeerCachePort_() const noexcept {
        return port_;
    }

    void AcceptOnePeerEventDriven(PeerManager& ) {
        struct sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        SocketHandle client_fd = ::accept(listen_fd_, (struct sockaddr*)&client_addr, &addr_len);
        if (!veld::compat::IsValidSocket(client_fd)) return;

        std::string key, remote_addr;
        auto conn = AdmitInboundConnection(client_fd, client_addr, key, remote_addr);
        if (!conn) return;

        auto ps = std::make_shared<PeerState>();
        PeerManager local_pm(magic_, chain_.Height(),
                             local_services_.load(std::memory_order_acquire));
        if (!conn->Send(local_pm.BuildVersionMessage(
                chain_.Height(), self_nonce_))) {
            FinalizePeerConnection_(key, conn);
            return;
        }

        bool still_registered = false;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            auto it = peer_connections_.find(key);
            if (it != peer_connections_.end() && it->second == conn) {
                peer_states_[key] = {conn, ps};
                still_registered = true;
            }
        }
        if (!still_registered) FinalizePeerConnection_(key, conn);
    }

    void HandlePeer(std::shared_ptr<Connection> conn,
                    const std::string& key, bool inbound,
                    bool initial_version_sent = false) {
        PeerManager pm(magic_, chain_.Height(),
                       local_services_.load(std::memory_order_acquire));

        if (!initial_version_sent &&
            !conn->Send(pm.BuildVersionMessage(chain_.Height(), self_nonce_))) {
            FinalizePeerConnection_(key, conn);
            return;
        }

        PeerState ps;
        // Aliases so the rest of HandlePeer reads naturally and the
        // diff stays small. References, NOT copies — writes propagate
        // back into ps. Compiler will optimize these away.
        bool& version_sent              = ps.version_sent;
        bool& version_acked             = ps.version_acked;
        bool& their_version             = ps.their_version;
        bool& handshake_done            = ps.handshake_done;
        bool& getaddr_sent              = ps.getaddr_sent;
        uint64_t& their_start_height    = ps.their_start_height;
        auto& last_ping                 = ps.last_ping;
        auto& last_getblocks            = ps.last_getblocks;
        auto& conn_started              = ps.conn_started;
        auto& last_mempool_req          = ps.last_mempool_req;
        (void)version_sent; (void)version_acked; (void)their_version;
        (void)handshake_done; (void)getaddr_sent; (void)their_start_height;
        (void)last_ping; (void)last_getblocks;
        (void)conn_started; (void)last_mempool_req;
        while (conn->IsConnected() && running_) {
            if (RunPeerTimers(ps, *conn, pm)) break;
            auto msg_opt = conn->RecvMessage(magic_);
            if (!msg_opt) break;
            const auto& msg = *msg_opt;
            if (msg.command.empty()) continue;

            // Drop messages that exceed the per-peer rate limit.
            //
            // Rate-limit violations do not count toward BAN_THRESHOLD. Over-cap messages
            // are still dropped (DoS protection preserved), but a peer
            // sending faster than MAX_MSG_PER_SECOND is NOT an attacker —
            // it's a high-hashrate miner bursting BLOCK + INV + NMS
            // through a tight loop after winning a race, or a peer
            // doing legitimate IBD catch-up. Banning them for 1 hour
            // costs the network a productive contributor and forces an
            // unnecessary snapshot-bootstrap cycle. Concrete
            // bad-actor signals — bad signatures, malformed handshakes,
            // oversized payloads, genesis mismatch, fee-too-low spam —
            // already have their own RecordViolation tags with
            // appropriate weights, and those still drive bans correctly.
            // The over-cap drop alone, with no ban credit, is the right
            // primitive for "you're sending faster than I can process."
            {
                auto rl = CheckRateLimit(*conn);
                if (!rl.allow) continue;
            }

            if (!their_version &&
                msg.command != MessageType::VERSION &&
                msg.command != MessageType::VERACK) {
                RecordViolation(conn->RemoteAddr(), 0, "pre_handshake");
                continue;
            }

            {
                auto sr = PeerProtocolStep(ps, *conn, pm, msg, key, inbound);
                if (sr == StepResult::DropPeer)  break;
                if (sr == StepResult::Handled)   continue;
            }

        }

        // Registry removal owns the direction-counter decrement.  Reapers and
        // same-key supersession may have removed this exact socket already; in
        // that case finalization closes only the stale handler's socket and must
        // not erase/decrement the replacement.
        FinalizePeerConnection_(key, conn);
    }

    static constexpr size_t MAX_GETBLOCKS_RESPONSE =
        IBD_GETBLOCKS_BATCH_BLOCKS;
    static constexpr size_t MAX_GETBLOCKS_RESPONSE_BYTES = 64 * 1024 * 1024;
};

}
}
