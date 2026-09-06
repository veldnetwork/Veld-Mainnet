#include "core/script.h"
#include "network/explorer_prevouts.h"
#include "network/recent_lookup_progress.h"
#include "network/receipt_source_slots.h"
#include "wallet/secure_channel_file.h"
#include <cassert>
#include <iostream>

// Small, ordinary fixtures only: no listeners, peers, chain workloads or keys.
int main(int argc, char** argv) {
    using namespace veld;
    Transaction tx;
    tx.version = 2;
    tx.locktime = 7;
    tx.inputs.resize(2);
    tx.inputs[0].sequence = 3;
    tx.inputs[1].sequence = 4;
    tx.outputs.emplace_back(25, std::vector<uint8_t>{0x51});
    TransactionScriptHashes hashes(tx);
    const auto first = hashes.TemplateHash(0);
    const auto second = hashes.TemplateHash(1);
    assert(first != second);
    assert(&hashes.TemplateHash(0) == &hashes.TemplateHash(0));
    assert(hashes.TemplateHash(0) == first);
    // Independent fixed preimage, including LE32 sequence and input suffix.
    auto expected = [&](uint32_t index) {
        std::vector<uint8_t> pre{2,0,0,0,7,0,0,0,2,0,0,0};
        const auto seq = Hash256d(std::vector<uint8_t>{3,0,0,0,4,0,0,0});
        const auto out = Hash256d(std::vector<uint8_t>{25,0,0,0,0,0,0,0,1,0x51});
        pre.insert(pre.end(), seq.begin(), seq.end());
        pre.insert(pre.end(), {1,0,0,0});
        pre.insert(pre.end(), out.begin(), out.end());
        pre.insert(pre.end(), {static_cast<uint8_t>(index),0,0,0});
        return Hash256d(pre);
    };
    assert(first == expected(0) && second == expected(1));
    ScriptInterpreter interpreter;
    ScriptContext context;
    context.covenants_active = true;
    std::vector<uint8_t> script{32};
    script.insert(script.end(), first.begin(), first.end());
    script.insert(script.end(), {0xb3, 0x75, 0x51});
    assert(interpreter.Execute({}, script, tx, 0, context, &hashes));
    assert(interpreter.Execute({}, script, tx, 0, context));
    assert(!interpreter.Execute({}, script, tx, 0));
    Transaction other = tx;
    assert(!interpreter.Execute({}, script, other, 0, context, &hashes));
    other.locktime = 8;
    TransactionScriptHashes next_hashes(other);
    assert(next_hashes.TemplateHash(0) != first);

    explorer::PrevoutProjection projection;
    Transaction spend;
    spend.inputs.resize(2);
    {
        Transaction previous;
        previous.inputs.push_back(TxInput::Coinbase("ordinary fixture"));
        previous.outputs.emplace_back(100, std::vector<uint8_t>{0x51});
        spend.inputs[0].prev_tx_hash = previous.GetTxID();
        spend.inputs[1].prev_tx_hash = previous.GetTxID();
        spend.inputs[1].prev_out_index = 1;
        assert(projection.AddInputs(spend));
        assert(projection.Remaining() == 2);
        projection.Observe(previous);
        assert(projection.Remaining() == 1);
        projection.Observe(previous);
        assert(projection.Remaining() == 1);
    }
    assert(projection.Find(spend.inputs[0])->units == 100);
    assert(projection.Find(spend.inputs[1]) == nullptr);

    rpc_detail::RecentLookupProgress progress;
    progress.ObserveTip(10, "ordinary-tip", false);
    for (uint64_t h = 10; h >= 3; --h) progress.MarkExamined(h);
    assert(progress.Next() == 2);
    progress.ObserveTip(11, "ordinary-extension", true);
    assert(progress.Next() == 11);
    progress.MarkExamined(11);
    assert(progress.Next() == 2);
    progress.MarkExamined(2);
    progress.MarkExamined(1);
    progress.MarkExamined(0);
    assert(!progress.Next());
    progress.ObserveTip(11, "replacement-anchor", false);
    assert(progress.Next() == 11);
    explorer::ReceiptSourceSlots receipt;
    for (size_t i = 0; i < explorer::ReceiptSourceSlots::PER_SOURCE; ++i)
        assert(receipt.Take("ordinary-source-a"));
    assert(!receipt.Take("ordinary-source-a"));
    assert(receipt.Take("ordinary-source-b"));
    receipt.Release("ordinary-source-a");
    assert(receipt.Take("ordinary-source-a"));

    if (argc == 2) {
        namespace sf = channel::secure_file;
        std::string error;
        if (!sf::EnsurePrivateDirectory(argv[1], &error)) {
            std::cerr << "Private fixture setup failed: " << error << '\n';
            return 2;
        }
        const auto path = (std::filesystem::path(argv[1]) / "ordinary-data.bin").string();
        std::vector<uint8_t> before{1,2,3}, after{4,5,6}, read;
        assert(sf::AtomicWriteNew(path, before, &error, true));
        assert(sf::AtomicWrite(path, after, &error, true));
        assert(sf::Read(path, read, &error, 16, true) == sf::ReadResult::Ok);
        assert(read == after);
        // Remove only the exact ordinary fixture created above.
        assert(std::filesystem::remove(path));
    }
    std::cout << "PASS: template compatibility, fresh contexts, bounded prevout ownership, private atomic replacement\n";
}
