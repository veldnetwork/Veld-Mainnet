#pragma once
// Internal adapter shared by guarded public entrypoints and isolated full-native qualification.
#include "node/node.h"
#include <cstdio>
#include "node/appchain_parent_transaction.h"

namespace veld {
// Private pipe adapter around the complete native node. It exposes no signing
// or network listener. Exact signed settlement relay belongs to the operator's
// local follower; read-only public endpoints expose only status/body responses.
class AppchainParentFeedCore {
    VeldNode& node_;
    std::function<app::Bytes()> network_status_;
    std::function<void(const Block&)> relay_;
    std::function<void(const Transaction&)> relay_transaction_;

    void RequireValidated_() const {
        app::need(node_.ChainFullyValidated() && !node_.FailStopRequired() &&
                      !node_.GetChain().IsEmpty(),
                  "public parent is not fully validated and durable");
    }

    app::Bytes Status_() const {
        const auto& chain = node_.GetChain();
        const auto tip = chain.TipCopy();
        app::Writer out;
        out.raw(CreateGenesisBlock().GetHash());
        // Status identity is (height, hash). Same-height reorganizations and
        // rollback remain observable without a process-local revision counter.
        out.n(tip.height, 8);
        out.n(tip.height, 8);
        out.raw(tip.GetHash());
        out.n(tip.height + 1, 8);
        return out.b;
    }

  public:
    explicit AppchainParentFeedCore(VeldNode& node, std::function<app::Bytes()> network_status = {},
                                    std::function<void(const Block&)> relay = {},
                                    std::function<void(const Transaction&)> relay_transaction = {})
        : node_(node), network_status_(std::move(network_status)), relay_(std::move(relay)),
          relay_transaction_(std::move(relay_transaction)) {
        RequireValidated_();
        app::need(node_.GetChain().GetBlock(0).GetHash() == CreateGenesisBlock().GetHash(),
                  "public parent genesis mismatch");
    }

    static bool FrameSizeAllowed(uint8_t op, uint64_t size) {
        return ((op == 0 || op == 3 || op == 4) && size == 0) || (op == 2 && size == 40) ||
               ((op == 1 || op == 5) && size >= 40 + 92 && size <= 40 + MAX_BLOCK_SIZE) ||
               (op == 6 && size > AppchainParentTransaction::PREFIX_BYTES &&
                size <= AppchainParentTransaction::PREFIX_BYTES + Mempool::MAX_RELAY_TX_BYTES);
    }

    app::Bytes Request(uint8_t op, const app::Bytes& body) {
        app::need(FrameSizeAllowed(op, body.size()), "public parent request shape");
        auto& chain = node_.GetChainMut();
        // AddBlockDirect acquires this non-recursive sequencer itself. Keep
        // read operations under it, and acquire it after a private import.
        std::optional<Blockchain::ConsensusTransitionGuard> transition;
        if (op != 1 && op != 5)
            transition.emplace(chain.AcquireConsensusTransitionGuard());
        RequireValidated_();
        app::Reader in{body};
        if (op == 0)
            return Status_();
        if (op == 4) {
            app::need(bool(network_status_), "parent acquisition is not running");
            return network_status_();
        }
        if (op == 3) {
            app::Writer out;
            out.n(1, 1); // Public-mainnet feed protocol version.
            out.raw(CreateGenesisBlock().GetHash());
            out.n(APPCHAIN_BRIDGE_ENABLED, 1);
            out.n(APPCHAIN_BRIDGE_ACTIVATION_HEIGHT, 8);
            out.raw(APPCHAIN_BRIDGE_DESCRIPTOR);
            return out.b;
        }
        if (op == 6) {
            app::need(bool(network_status_) && bool(relay_transaction_),
                      "networked settlement relay required");
            const auto request = AppchainParentTransaction::Decode(body);
            const auto health = network_status_();
            app::Reader network{health};
            app::need(network.raw(5) == app::Bytes({'V', 'P', 'N', 'H', 1}) &&
                          network.raw(32) ==
                              app::Bytes(request.genesis.begin(), request.genesis.end()) &&
                          app::bridge::Anchor::read(network) == request.parent &&
                          network.n(1) == 1 && network.n(1) == 1 && network.n(2) >= 2,
                      "current ready outbound parent network required");
            const auto verified = network.n(8), sync = network.n(8), valid = network.n(8);
            network.end();
            app::need(verified >= request.parent.height && sync <= request.parent.height &&
                          valid > 5000 && valid < UINT64_MAX,
                      "fresh outbound parent observations required");
            const auto admitted =
                AdmitAppchainParentTransaction(*transition, chain, node_.GetMempoolMut(), request);
            bool relayed = false;
            // Admission may already have occurred when connectivity fails.
            // Report that outcome rather than implying a side-effect-free refusal.
            try {
                relay_transaction_(admitted.transaction);
                relayed = true;
            } catch (const app::Invalid&) {
            }
            if (node_.FailStopRequired())
                throw std::runtime_error("parent durability failed after settlement admission");
            app::Writer out;
            out.raw(app::Bytes{'V', 'P', 'R', 'T', 1});
            out.raw(request.genesis);
            request.parent.write(out);
            out.raw(request.descriptor);
            out.raw(request.bridge);
            out.raw(admitted.transaction.GetTxID());
            out.n(request.fee, 8);
            out.n(1, 1);
            out.n(relayed, 1);
            out.n(admitted.duplicate, 1);
            return out.b;
        }
        const uint64_t height = in.n(8);
        Hash256 expected{};
        const auto hash = in.raw(32);
        std::copy(hash.begin(), hash.end(), expected.begin());
        app::need(height < UINT64_MAX, "public parent height overflow");
        if (op == 2) {
            in.end();
            app::need(height <= chain.Height() &&
                          chain.HasBlockAtHeight(height, HashToHex(expected)),
                      "public parent body is not canonical");
            const auto block = chain.GetBlock(height);
            app::need(block.GetHash() == expected, "public parent body identity changed");
            const auto bytes = block.Serialize();
            app::need(bytes.size() <= MAX_BLOCK_SIZE, "public parent response bound");
            return bytes;
        }

        const auto bytes = in.raw(body.size() - in.pos);
        in.end();
        Block block;
        app::need(Block::Deserialize(bytes, 0, block) == bytes.size() &&
                      block.Serialize() == bytes && block.GetHash() == expected,
                  "public parent block encoding or identity");
        app::need(height > 0, "genesis cannot be imported");
        const auto parent = chain.GetBlockByHash(block.header.prev_block_hash);
        app::need(parent && parent->height == height - 1,
                  "public parent block height does not match validated ancestry");
        if (op == 5) {
#ifdef VELD_FLEET_NO_MINE
            throw app::Invalid("fleet appchain mining relay is disabled");
#else
            app::need(bool(relay_) && AppchainBridgeActive(height),
                      "active local mining relay required");
            auto permit = chain.AcquireConsensusTransitionGuard();
            block.height = height;
            if (chain.HasBlockAtHeight(height, HashToHex(expected))) {
                app::need(chain.GetBlock(height).Serialize() == bytes,
                          "retained mined block differs");
                relay_(block);
                return Status_();
            }
            const auto carrier = chain.AppAuxiliaryCarrierIndex(block);
            app::need(carrier.has_value() &&
                          chain.AppAuxiliaryTemplateUnderTransition(block, *carrier),
                      "mined parent is not the validated current auxiliary template");
#endif
        }
        // Never supply a skip-validation or historical-PoW bypass argument.
        const auto admission = chain.AddBlockDirect(block, false, true, false,
                                                    mining::PowAdmissionContext::Internal());
        app::need(admission.IsAccepted(), "public parent block admission refused");
        transition.emplace(chain.AcquireConsensusTransitionGuard());
        RequireValidated_();
        if (op == 5)
            relay_(block);
        return Status_();
    }
};

// The public process and isolated tests share exact bounded pipe framing.
inline void ServeAppchainParentFeed(FILE* input, FILE* output, VeldNode& node,
                                    AppchainParentFeedCore& feed) {
    for (;;) {
        uint8_t size_bytes[4];
        const size_t got = fread(size_bytes, 1, 4, input);
        if (!got)
            break;
        app::need(got == 4, "truncated public parent frame");
        app::Reader size{std::span(size_bytes, 4)};
        const uint64_t count = size.n(4);
        app::need(count > 0 && count <= 41ULL + veld::MAX_BLOCK_SIZE, "public parent frame bound");
        uint8_t op = 0;
        app::need(fread(&op, 1, 1, input) == 1 &&
                      veld::AppchainParentFeedCore::FrameSizeAllowed(op, count - 1),
                  "public parent frame shape");
        app::Bytes body(count - 1);
        app::need(fread(body.data(), 1, body.size(), input) == body.size(),
                  "truncated public parent body");
        app::Writer answer;
        try {
            const auto result = feed.Request(op, body);
            answer.n(0, 1);
            answer.raw(result);
        } catch (const app::Invalid&) {
            if (node.FailStopRequired())
                throw;
            answer.n(4, 1);
        }
        app::Writer frame;
        frame.n(answer.b.size(), 4);
        frame.raw(answer.b);
        app::need(fwrite(frame.b.data(), 1, frame.b.size(), output) == frame.b.size() &&
                      fflush(output) == 0,
                  "public parent response write failed");
    }
}
} // namespace veld
