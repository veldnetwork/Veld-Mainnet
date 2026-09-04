#include "../include/network/explorer.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <new>
#include <string>
#include <thread>
#include <vector>

#if defined(VELD_PUBLIC_RELEASE)
#if !defined(VELD_PUBLIC_MAINNET) || !defined(VELD_MAINNET_POW)
#error "the public fixture requires the exact public-mainnet profile"
#endif
#elif !defined(VELD_TEST_HOOKS)
#error "build either the exact public profile or the non-public counter profile"
#endif

namespace allocation_probe {
std::atomic<bool> enabled{false};
std::atomic<size_t> calls{0};
std::atomic<size_t> bytes{0};
std::atomic<size_t> maximum{0};

void Record(size_t size) noexcept {
    if (!enabled.load(std::memory_order_relaxed)) return;
    calls.fetch_add(1, std::memory_order_relaxed);
    bytes.fetch_add(size, std::memory_order_relaxed);
    size_t observed = maximum.load(std::memory_order_relaxed);
    while (observed < size &&
           !maximum.compare_exchange_weak(
               observed, size, std::memory_order_relaxed)) {}
}
}  // namespace allocation_probe

void* operator new(std::size_t size) {
    if (size == 0) size = 1;
    if (void* ptr = std::malloc(size)) {
        allocation_probe::Record(size);
        return ptr;
    }
    throw std::bad_alloc();
}

void* operator new[](std::size_t size) {
    return ::operator new(size);
}

void operator delete(void* ptr) noexcept { std::free(ptr); }
void operator delete[](void* ptr) noexcept { std::free(ptr); }
void operator delete(void* ptr, std::size_t) noexcept { std::free(ptr); }
void operator delete[](void* ptr, std::size_t) noexcept { std::free(ptr); }

namespace {

size_t checks = 0;
size_t failures = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << label << "\n";
    }
}

veld::Block ExactMaximumBlock(veld::Blockchain& chain) {
    using namespace veld;
    Block block;
    block.height = 1;
    block.header.version = PROTOCOL_VERSION;
    block.header.prev_block_hash = chain.TipCopy().GetHash();
    block.header.timestamp = chain.TipCopy().header.timestamp + 1;
    block.header.bits = chain.ComputeNextBits();
    block.header.nonce = 1;

    Transaction coinbase;
    coinbase.inputs.push_back(TxInput::Coinbase("H"));
    coinbase.outputs.reserve(123);
    const std::vector<uint8_t> maximum_script(
        MAX_OP_RETURN_SCRIPT_PUBKEY_BYTES, 0x6a);
    for (size_t i = 0; i < 122; ++i)
        coinbase.outputs.emplace_back(0, maximum_script);
    coinbase.outputs.emplace_back(0, std::vector<uint8_t>(3'233, 0x6a));
    block.transactions.push_back(std::move(coinbase));
    block.UpdateMerkleRoot();
    return block;
}

}  // namespace

int main() {
    using namespace veld;
    using namespace veld::explorer;

    Blockchain chain;
    auto genesis = CreateGenesisBlock();
    Check(chain.AddBlockDirect(
              genesis, true, false, false,
              mining::PowAdmissionContext::Internal()).IsAccepted(),
          "trusted genesis fixture accepted");

    Block maximum = ExactMaximumBlock(chain);
    const std::vector<uint8_t> raw = maximum.Serialize();
    Check(raw.size() == MAX_BLOCK_SIZE,
          "fixture is exactly the canonical 8,000,000-byte maximum");
    Check(maximum.SerializedSize() == MAX_BLOCK_SIZE,
          "serialized-size helper agrees with exact maximum fixture");

    Block parsed;
    const size_t consumed = Block::Deserialize(raw, 0, parsed);
    parsed.height = 1;
    Check(consumed == raw.size(),
          "exact maximum fixture fully deserializes");
    Check(parsed.Serialize() == raw,
          "exact maximum fixture round-trips byte-for-byte");
    Check(chain.AddBlockDirect(
              parsed, true, true, false,
              mining::PowAdmissionContext::Internal()).IsAccepted(),
          "exact maximum fixture is resident in the canonical chain");
    Check(chain.Height() == 1 &&
              chain.GetBlock(1).SerializedSize() == MAX_BLOCK_SIZE,
          "resident canonical body remains exactly 8,000,000 bytes");

    std::atomic<uint64_t> loader_calls{0};
    chain.SetHistoricalBlockLoader(
        [&](const Hash256&) -> std::optional<std::vector<uint8_t>> {
            loader_calls.fetch_add(1, std::memory_order_relaxed);
            return raw;
        });
#ifdef VELD_TEST_HOOKS
    chain.TestResetBlockBodyLookupCount();
#endif

    const auto suffix = std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    const std::filesystem::path storage_path =
        std::filesystem::temp_directory_path() /
        ("veld-daybreak-public-history-max-block-" + suffix);
    {
        Mempool mempool;
        StorageEngine storage(storage_path.string(), MAINNET_MAGIC);
        RpcServer rpc(chain, mempool, storage);
        BlockExplorer explorer(chain, mempool, 0);

        std::atomic<size_t> indexed_calls{0};
        const auto bounded_history =
            [&](const std::string&, size_t limit, const std::string&) {
                indexed_calls.fetch_add(1, std::memory_order_relaxed);
                Check(limit <= 50,
                      "indexed callback receives only a bounded page limit");
                return std::string(
                    "{\"entries\":[{\"txid\":\"") +
                    std::string(64, '1') +
                    "\",\"block_height\":1,\"net_veld\":1.0,"
                    "\"fee_veld\":0.0,\"type\":\"received\"}],"
                    "\"has_more\":false,\"next_cursor\":\"\"}";
            };
        rpc.SetAddressHistoryFn(bounded_history);
        explorer.SetAddressHistoryFn(bounded_history);

        const std::string indexed_request =
            R"({"jsonrpc":"2.0","method":"getaddresshistory","params":["address",50],"id":3})";
        const std::string indexed_response = rpc.Handle(indexed_request);
        Check(indexed_response.find("\"type\":\"received\"") !=
                  std::string::npos,
              "legitimate bounded indexed RPC request remains available");
        const auto indexed_http = explorer.Route(HttpRequest::Parse(
            "GET /api/v1/addresshistory/address/50 HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n\r\n"));
        Check(indexed_http.status_code == 200 &&
                  indexed_http.body.find("\"has_more\":false") !=
                      std::string::npos,
              "legitimate bounded explorer history request remains available");
        Check(loader_calls.load(std::memory_order_relaxed) == 0,
              "legitimate indexed requests never invoke the block loader");

        const std::string history_request =
            R"({"jsonrpc":"2.0","method":"gettxhistory","params":["address",0,5001,8000000],"id":1})";
        const std::string earnings_request =
            R"({"jsonrpc":"2.0","method":"getearnings","params":["address",0,5001],"id":2})";
        const std::vector<std::string> removed_routes{
            "/api/txhistory?start=0&end=5001",
            "/api/v1/txhistory/address",
            "/txhistory",
        };

        std::atomic<size_t> worker_failures{0};
        std::atomic<size_t> response_bytes{0};
        std::vector<std::thread> workers;
        workers.reserve(16);
        allocation_probe::calls.store(0, std::memory_order_relaxed);
        allocation_probe::bytes.store(0, std::memory_order_relaxed);
        allocation_probe::maximum.store(0, std::memory_order_relaxed);
        allocation_probe::enabled.store(true, std::memory_order_release);
        for (size_t i = 0; i < 16; ++i) {
            workers.emplace_back([&, i]() {
                const std::string first = rpc.Handle(history_request);
                const std::string second = rpc.Handle(earnings_request);
                response_bytes.fetch_add(first.size() + second.size(),
                                         std::memory_order_relaxed);
                if (first.find("\"code\":-32601") == std::string::npos ||
                    second.find("\"code\":-32601") == std::string::npos ||
                    first.size() > 4'096 || second.size() > 4'096) {
                    worker_failures.fetch_add(1, std::memory_order_relaxed);
                }
                const auto request = HttpRequest::Parse(
                    "GET " + removed_routes[i % removed_routes.size()] +
                    " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
                const auto response = explorer.Route(request);
                response_bytes.fetch_add(response.body.size(),
                                         std::memory_order_relaxed);
                if (response.status_code != 404 ||
                    response.body.size() > 4'096) {
                    worker_failures.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }
        for (auto& worker : workers) worker.join();
        allocation_probe::enabled.store(false, std::memory_order_release);

        Check(worker_failures.load(std::memory_order_relaxed) == 0,
              "concurrent removed RPC methods and explorer routes fail closed");
        Check(response_bytes.load(std::memory_order_relaxed) < 256'000,
              "removed surfaces retain a strictly small aggregate response");
        Check(allocation_probe::maximum.load(std::memory_order_relaxed) <
                  MAX_BLOCK_SIZE / 64,
              "no request allocates a block-sized or material response buffer");
        Check(allocation_probe::bytes.load(std::memory_order_relaxed) <
                  MAX_BLOCK_SIZE / 2,
              "concurrent removed-surface allocation work stays bounded");
        Check(allocation_probe::calls.load(std::memory_order_relaxed) < 20'000,
              "concurrent removed-surface allocation count stays bounded");

        std::mutex history_gate_mutex;
        std::condition_variable history_gate_cv;
        size_t history_gate_entered = 0;
        bool release_history_gate = false;
        rpc.SetAddressHistoryFn(
            [&](const std::string&, size_t, const std::string&) {
                std::unique_lock<std::mutex> lock(history_gate_mutex);
                ++history_gate_entered;
                history_gate_cv.notify_all();
                history_gate_cv.wait(lock,
                    [&] { return release_history_gate; });
                return std::string(
                    "{\"entries\":[],\"has_more\":false,"
                    "\"next_cursor\":\"\"}");
            });
        std::vector<std::thread> held_queries;
        for (size_t i = 0; i < 4; ++i)
            held_queries.emplace_back([&] { (void)rpc.Handle(indexed_request); });
        {
            std::unique_lock<std::mutex> lock(history_gate_mutex);
            history_gate_cv.wait(lock,
                [&] { return history_gate_entered == 4; });
        }
        const std::string busy_response = rpc.Handle(indexed_request);
        Check(busy_response.find("address history is busy") !=
                  std::string::npos,
              "fifth concurrent indexed request fails at the method cap");
        {
            std::lock_guard<std::mutex> lock(history_gate_mutex);
            release_history_gate = true;
        }
        history_gate_cv.notify_all();
        for (auto& worker : held_queries) worker.join();
    }

    Check(loader_calls.load(std::memory_order_relaxed) == 0,
          "removed history surfaces never invoke the durable body loader");
#ifdef VELD_TEST_HOOKS
    Check(chain.TestBlockBodyLookupCount() == 0,
          "removed history surfaces never enter resident or durable body lookup");
#endif

    std::error_code cleanup_error;
    std::filesystem::remove_all(storage_path, cleanup_error);
    Check(!cleanup_error && !std::filesystem::exists(storage_path),
          "temporary storage fixture cleaned up");

    std::cout << (failures == 0 ? "PASS " : "FAIL ")
              << "daybreak_public_history_disabled_max_block_tests checks="
              << checks << " fixture_bytes=" << raw.size()
              << " loader_calls=" << loader_calls.load()
              << " allocation_calls=" << allocation_probe::calls.load()
              << " allocation_bytes=" << allocation_probe::bytes.load()
              << " maximum_allocation=" << allocation_probe::maximum.load()
#ifdef VELD_TEST_HOOKS
              << " block_body_lookups=" << chain.TestBlockBodyLookupCount()
#endif
              << "\n";
    return failures == 0 ? 0 : 1;
}
