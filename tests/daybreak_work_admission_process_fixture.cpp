#ifndef VELD_TEST_HOOKS
#error "Finding-4 process fixture requires VELD_TEST_HOOKS"
#endif
#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET)
#error "Finding-4 process fixture must never compile in a public profile"
#endif

#include <atomic>
#include <cstdint>
#include <vector>

#if !defined(VELD_PUBLIC_TESTNET)
#define VELD_TEST_DATASET_BYTES (1024u * 1024u)
#include "daybreak_regtest_profile.h"
#include "../include/crypto/veld_signing.h"

namespace validator_value_bound_test {

inline std::atomic<uint64_t> build_script_sig_calls{0};

inline veld::SignedInput CountedBuildScriptSig(
        const veld::Secp256k1PrivKey& private_key,
        const veld::Secp256k1PubKey& public_key,
        const veld::Transaction& transaction,
        uint32_t input_index,
        const std::vector<uint8_t>& previous_script) {
    build_script_sig_calls.fetch_add(1, std::memory_order_acq_rel);
    return veld::BuildScriptSig(private_key, public_key, transaction,
                                input_index, previous_script);
}

}  // namespace validator_value_bound_test

#define BuildScriptSig validator_value_bound_test::CountedBuildScriptSig
#define main veld_embedded_validator_main
#include "../src/veld-validator.cpp"
#undef main
#undef BuildScriptSig
#endif

#include "../include/node/node.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

using namespace veld;

namespace {

static_assert(std::string_view(DEPLOYMENT_PROFILE_ID) !=
                  "veld-public-mainnet-v2",
              "qualification fixture is non-public-mainnet only");

size_t checks = 0;

void Check(bool condition, const std::string& label) {
    ++checks;
    if (!condition) throw std::runtime_error("FAIL: " + label);
}

std::string JsonEscape(const std::string& value) {
    std::string out;
    for (char c : value) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }
    return out;
}

std::string RpcRequest(const std::string& method,
                       const std::vector<std::string>& params = {}) {
    std::ostringstream out;
    out << "{\"jsonrpc\":\"2.0\",\"method\":\"" << method
        << "\",\"params\":[";
    for (size_t i = 0; i < params.size(); ++i) {
        if (i) out << ',';
        out << '"' << JsonEscape(params[i]) << '"';
    }
    out << "],\"id\":1}";
    return out.str();
}

std::string Hex(const std::vector<uint8_t>& bytes) {
    return BytesToHex(bytes);
}

std::string EncodeSubmitBindingForBlock(
        const work_admission::Binding& issued,
        const Block& candidate) {
    auto bound = issued;
    bound.subject.target_hash =
        candidate.header.GetTemplateWorkIdentity();
    return work_admission::EncodeBinding(bound);
}

struct PublishedBlockTemplate {
    Block block;
    std::string binding;
    std::string token;
};

std::optional<PublishedBlockTemplate> ParsePublishedBlockTemplate(
        const std::string& response) {
    btc_buy::JsonValue root;
    std::string error;
    btc_buy::StrictJsonParser parser(
        response, 4u * 1024u * 1024u, true);
    if (!parser.Parse(root, error) ||
        root.kind != btc_buy::JsonValue::Kind::Object)
        return std::nullopt;
    const auto* rpc_error = root.Get("error");
    const auto* result = root.Get("result");
    if (!rpc_error || rpc_error->kind != btc_buy::JsonValue::Kind::Null ||
        !result || result->kind != btc_buy::JsonValue::Kind::Object)
        return std::nullopt;
    const auto* block_hex = result->Get("block_hex");
    const auto* binding = result->Get("work_binding");
    const auto* token = result->Get("work_token");
    if (!block_hex || !binding || !token ||
        block_hex->kind != btc_buy::JsonValue::Kind::String ||
        binding->kind != btc_buy::JsonValue::Kind::String ||
        token->kind != btc_buy::JsonValue::Kind::String ||
        token->text.size() != 64)
        return std::nullopt;
    const auto bytes = HexToBytes(block_hex->text);
    Block block;
    const size_t consumed = Block::Deserialize(bytes, 0, block);
    const auto decoded = work_admission::DecodeBinding(binding->text);
    if (consumed == 0 || consumed != bytes.size() ||
        block.Serialize() != bytes || !decoded ||
        work_admission::EncodeBinding(*decoded) != binding->text)
        return std::nullopt;
    block.height = decoded->subject.height;
    if (decoded->subject.target_hash !=
        block.header.GetTemplateWorkIdentity())
        return std::nullopt;
    return PublishedBlockTemplate{
        std::move(block), binding->text, token->text};
}

void SolvePublishedBlock(Block& block) {
    const Hash256 target = block.header.GetTarget();
    for (uint64_t nonce = 0; nonce < 5'000'000; ++nonce) {
        block.header.nonce = nonce;
        if (mining::VeldHash(block.header.Serialize(), block.height) < target) {
            Check(Blockchain::VerifyBlockPoW(block),
                  "published block has valid authoritative PoW");
            return;
        }
    }
    throw std::runtime_error("published block did not solve within bound");
}

void WaitForTemplateTimestamp(const Blockchain& chain) {
    const uint64_t mtp = chain.MedianTimePast();
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        const std::time_t now = std::time(nullptr);
        if (now >= 0 && static_cast<uint64_t>(now) > mtp) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    throw std::runtime_error(
        "wall clock did not advance beyond template parent MTP");
}

Hash256 CompiledGenesisBytes() {
    return HexToHash(GENESIS_HASH);
}

std::shared_ptr<net::Connection> MakeConnection(
        const std::string& ip, uint16_t port) {
    const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!compat::IsValidSocket(fd)) return {};
    return std::make_shared<net::Connection>(fd, ip, port, false);
}

struct PeerFixture {
    std::shared_ptr<net::Connection> first;
    std::shared_ptr<net::Connection> second;
};

PeerFixture InstallSafePeers(VeldNode& node, uint64_t height,
                             uint16_t port_base) {
    auto& server = node.TestWorkAdmissionProcessServer();
    server.TestSetPeerHeightClock(100);
    PeerFixture peers{
        MakeConnection("10.71.0.1", port_base),
        MakeConnection("10.71.0.2", static_cast<uint16_t>(port_base + 1))};
    Check(peers.first && peers.second, "peer sockets allocated");
    server.TestRecordVersionClaim(peers.first, height);
    server.TestRecordVersionClaim(peers.second, height);
    server.TestMarkPeerHandshakeReady(peers.first);
    server.TestMarkPeerHandshakeReady(peers.second);
    const Hash256 exact_tip = node.GetChain().TipCopy().GetHash();
    server.TestRecordVerifiedPeerHeight("10.71.0.1", exact_tip);
    server.TestRecordVerifiedPeerHeight("10.71.0.2", exact_tip);
    const auto view = server.GetPeerHeightView();
    Check(view.work_sequencer_wired && view.work_view_stable,
          "production peer-view sequencer wired");
    Check(view.distinct_version_ips == 2 &&
              view.distinct_outbound_sync_ips == 2 &&
              view.outbound_sync_height == height,
          "two exact outbound VERSION sources establish safe peer view");
    Check(server.TestVerifiedPeerEvidenceCount() == 2 &&
              view.verified_height == height,
          "two distinct peers publish exact canonical-tip observations");
    return peers;
}

void InstallTrustedChain(Blockchain& chain, Mempool& mempool,
                         const RealKeyPair& miner, uint64_t tip_height) {
    Check(chain.AddBlockDirect(
              CreateGenesisBlock(), true, true, false,
              mining::PowAdmissionContext::Internal()).IsAccepted(),
          "trusted fixture genesis installed");
    for (uint64_t height = 1; height <= tip_height; ++height) {
        auto mined = MineOnly(chain, mempool, miner);
        Check(mined.success && mined.block.height == height,
              "fresh fixture block constructed");
        Check(chain.AddBlockDirect(
                  mined.block, true, true, false,
                  mining::PowAdmissionContext::Internal()).IsAccepted(),
              "trusted fixture block installed");
    }
}

VeldNode::TestWorkAdmissionProcessState ReadyState() {
    return {};
}

VeldNode::TestWorkAdmissionProcessState StateForRow(
        const std::string& row) {
    auto state = ReadyState();
    if (row == "node_running") state.node_running = false;
    else if (row == "startup_replay") state.startup_replay_complete = false;
    else if (row == "independent_validation")
        state.independent_validation_complete = false;
    else if (row == "sync_ibd") state.sync_complete = false;
    else if (row == "snapshot_clean") state.snapshot_state_clean = false;
    else if (row == "durable_state") state.durable_state_proven = false;
    else if (row == "datadir_identity") state.datadir_identity_valid = false;
    else if (row == "checkpoint_anchor") state.checkpoint_anchor_valid = false;
    else if (row == "tip_known") state.canonical_tip_known = false;
    else if (row == "runtime") state.runtime_open = false;
    else if (row == "role_profile") state.role_permitted = false;
    else if (row == "default_unknown") {
        // Model the fail-closed pre-start/default coordinator state without
        // also raising the independently terminal durable-commit fail-stop.
        // Unwiring below supplies the authoritative unknown-state proof; the
        // distinct durable_state row owns the global fail-stop disposition.
        state.node_running = false;
        state.startup_replay_complete = false;
        state.independent_validation_complete = false;
        state.sync_complete = false;
        state.snapshot_state_clean = false;
        state.durable_state_proven = true;
        state.datadir_identity_valid = true;
        state.checkpoint_anchor_valid = false;
        state.canonical_tip_known = false;
        state.runtime_open = false;
        state.role_permitted = false;
    }
    return state;
}

bool IsClosedRow(const std::string& row) {
    return row != "open";
}

bool IsGlobalTerminalSafetyRow(const std::string& row) {
    return row == "durable_state";
}

bool IsStartupListenerUnavailableRow(const std::string& row) {
    return row == "default_unknown" || row == "node_running" ||
           row == "startup_replay" || row == "datadir_identity";
}

struct RowCounters {
    uint64_t internal_mining_admitted{0};
    uint64_t internal_hashes{0};
    uint64_t internal_progress{0};
    uint64_t gbt_templates{0};
    uint64_t submit_add_calls{0};
    uint64_t submit_durable_calls{0};
    uint64_t block_broadcasts{0};
    uint64_t inproc_journals{0};
    uint64_t inproc_signatures{0};
    uint64_t inproc_mempool{0};
    uint64_t inproc_gossip{0};
    uint64_t standalone_journals{0};
    uint64_t standalone_signatures{0};
    uint64_t standalone_mempool{0};
    uint64_t standalone_gossip{0};
    uint64_t finality_journals{0};
    uint64_t finality_signatures{0};
    uint64_t finality_gossip{0};
    uint64_t finality_sink_calls{0};
    uint64_t finality_active_calls{0};
    uint64_t finality_verify_result{UINT8_MAX};
    uint64_t finality_assembler{0};
    uint64_t finality_node_gossip{0};
    uint64_t p2p_add_calls{0};
    uint64_t p2p_durable_calls{0};
    uint64_t p2p_tip_advanced{0};
    uint64_t p2p_global_runtime_closed{0};
    uint64_t p2p_relay_calls{0};
    uint64_t p2p_penalty_calls{0};
    std::string p2p_reject_tag;
};

#if !defined(VELD_PUBLIC_TESTNET)
class LoopbackRpcShim {
public:
    using ResponseFilter = std::function<std::string(
        const std::string&, std::string)>;

    explicit LoopbackRpcShim(VeldNode& node,
                             ResponseFilter response_filter = {})
        : node_(node), response_filter_(std::move(response_filter)) {
        listener_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (!compat::IsValidSocket(listener_))
            throw std::runtime_error("RPC shim socket failed");
        int one = 1;
        ::setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&one), sizeof(one));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (::bind(listener_, reinterpret_cast<sockaddr*>(&address),
                   sizeof(address)) != 0 || ::listen(listener_, 8) != 0)
            throw std::runtime_error("RPC shim bind/listen failed");
        socklen_t length = sizeof(address);
        if (::getsockname(listener_, reinterpret_cast<sockaddr*>(&address),
                          &length) != 0)
            throw std::runtime_error("RPC shim getsockname failed");
        port_ = ntohs(address.sin_port);
        thread_ = std::thread([this] { Run(); });
    }

    ~LoopbackRpcShim() {
        stop_.store(true, std::memory_order_release);
        const auto wake = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (compat::IsValidSocket(wake)) {
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address.sin_port = htons(port_);
            (void)::connect(wake, reinterpret_cast<sockaddr*>(&address),
                            sizeof(address));
            VELD_CLOSE_SOCKET(wake);
        }
        if (thread_.joinable()) thread_.join();
        VELD_CLOSE_SOCKET(listener_);
    }

    uint16_t port() const noexcept { return port_; }

private:
    static bool SendAll(compat::SocketHandle fd, const std::string& bytes) {
        size_t offset = 0;
        while (offset < bytes.size()) {
            const int sent = ::send(fd, bytes.data() + offset,
                                    static_cast<int>(bytes.size() - offset), 0);
            if (sent <= 0) return false;
            offset += static_cast<size_t>(sent);
        }
        return true;
    }

    void Run() noexcept {
        while (!stop_.load(std::memory_order_acquire)) {
            sockaddr_in peer{};
            socklen_t length = sizeof(peer);
            const auto fd = ::accept(
                listener_, reinterpret_cast<sockaddr*>(&peer), &length);
            if (!compat::IsValidSocket(fd)) continue;
            if (stop_.load(std::memory_order_acquire)) {
                VELD_CLOSE_SOCKET(fd);
                break;
            }
            std::string request;
            size_t body_start = std::string::npos;
            size_t content_length = 0;
            char buffer[4096];
            while (request.size() < 2u * 1024u * 1024u) {
                const int got = ::recv(fd, buffer, sizeof(buffer), 0);
                if (got <= 0) break;
                request.append(buffer, static_cast<size_t>(got));
                if (body_start == std::string::npos) {
                    body_start = request.find("\r\n\r\n");
                    if (body_start != std::string::npos) {
                        const auto marker = request.find("Content-Length:");
                        if (marker != std::string::npos) {
                            const auto value = marker + 15;
                            content_length = static_cast<size_t>(
                                std::stoull(request.substr(value)));
                        }
                        body_start += 4;
                    }
                }
                if (body_start != std::string::npos &&
                    request.size() >= body_start + content_length)
                    break;
            }
            std::string response_body;
            try {
                if (body_start == std::string::npos ||
                    request.size() < body_start + content_length)
                    throw std::runtime_error("incomplete HTTP body");
                const std::string request_body =
                    request.substr(body_start, content_length);
                response_body = node_.TestHandleWorkAdmissionRpc(
                    request_body);
                if (response_filter_)
                    response_body = response_filter_(
                        request_body, std::move(response_body));
            } catch (const std::exception& e) {
                response_body = std::string(
                    "{\"jsonrpc\":\"2.0\",\"result\":null,\"error\":{\"code\":-32603,\"message\":\"") +
                    JsonEscape(e.what()) + "\"},\"id\":1}";
            }
            const std::string response =
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
                "Content-Length: " + std::to_string(response_body.size()) +
                "\r\nConnection: close\r\n\r\n" + response_body;
            (void)SendAll(fd, response);
            VELD_CLOSE_SOCKET(fd);
        }
    }

    VeldNode& node_;
    ResponseFilter response_filter_;
    compat::SocketHandle listener_{compat::kInvalidSocket};
    uint16_t port_{0};
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

enum class ValidatorValueAttack {
    RegistrationOutputWrap,
    AuthenticatedInputWrap,
};

struct FakeAuthenticatedParent {
    std::string txid;
    uint64_t value{0};
    std::string raw_hex;
};

struct MaliciousValidatorProposal {
    Transaction transaction;
    std::vector<FakeAuthenticatedParent> parents;
    std::string response;
    uint64_t claimed_total_input{0};
    uint64_t claimed_total_output{0};
    uint64_t claimed_change{0};
};

std::string RpcResultEnvelope(const std::string& result) {
    return "{\"jsonrpc\":\"2.0\",\"result\":" + result +
           ",\"error\":null,\"id\":1}";
}

MaliciousValidatorProposal BuildMaliciousRegistrationProposal(
        const ValidatorKey& validator, const std::string& operation,
        ValidatorValueAttack attack) {
    const std::vector<uint8_t> from_script =
        AddressToScript(validator.address);
    const std::vector<uint8_t> vault_script =
        AddressToScript(STAKE_VAULT_ADDRESS);
    const std::vector<uint8_t> operation_script =
        BuildOpReturnScript(operation);
    Check(!from_script.empty() && !vault_script.empty() &&
              !operation_script.empty(),
          "malicious preparer fixture scripts are canonical");

    MaliciousValidatorProposal proposal;
    auto add_parent = [&](uint64_t value) {
        Transaction parent;
        parent.outputs.emplace_back(value, from_script);
        const std::vector<uint8_t> parent_raw = parent.Serialize();
        const Hash256 parent_hash = parent.GetTxID();
        proposal.parents.push_back(FakeAuthenticatedParent{
            HashToHex(parent_hash), value, Hex(parent_raw)});
        TxInput input;
        input.prev_tx_hash = parent_hash;
        input.prev_out_index = 0;
        proposal.transaction.inputs.push_back(std::move(input));
    };

    proposal.transaction.outputs.emplace_back(
        MIN_VALIDATOR_STAKE, vault_script);
    if (attack == ValidatorValueAttack::RegistrationOutputWrap) {
        // Exact demonstrated exploit vector: S + C wraps the complete output
        // sum to one unit, so a 100001-unit parent appears to pay the exact
        // 100000-unit fee unless C is individually bounded before subtraction.
        const uint64_t malicious_change =
            std::numeric_limits<uint64_t>::max() -
            MIN_VALIDATOR_STAKE + 2U;
        add_parent(MIN_TX_FEE + 1U);
        proposal.transaction.outputs.emplace_back(
            malicious_change, from_script);
        proposal.claimed_total_input = MIN_TX_FEE + 1U;
        proposal.claimed_total_output = 1U;
        proposal.claimed_change = malicious_change;
    } else {
        // The first authenticated parent is supply-bounded.  Adding the second
        // oversized parent wraps the accumulator to S + fee, which used to
        // satisfy the exact-fee check unless each parent was bounded first.
        const uint64_t oversized_parent =
            std::numeric_limits<uint64_t>::max() - MAX_SUPPLY_UNITS + 1U +
            MIN_VALIDATOR_STAKE + MIN_TX_FEE;
        add_parent(MAX_SUPPLY_UNITS);
        add_parent(oversized_parent);
        proposal.claimed_total_input = MIN_VALIDATOR_STAKE + MIN_TX_FEE;
        proposal.claimed_total_output = MIN_VALIDATOR_STAKE;
        proposal.claimed_change = 0;
    }
    proposal.transaction.outputs.emplace_back(0, operation_script);

    const std::string from_script_hex = Hex(from_script);
    std::ostringstream inputs;
    inputs << '[';
    for (uint32_t i = 0; i < proposal.transaction.inputs.size(); ++i) {
        if (i) inputs << ',';
        const Hash256 sighash = ComputeSighash(
            proposal.transaction, i, from_script);
        inputs << "{\"index\":" << i
               << ",\"sighash_hex\":\""
               << bytes_to_hex(sighash.data(), sighash.size())
               << "\",\"prev_script_hex\":\"" << from_script_hex
               << "\"}";
    }
    inputs << ']';

    std::ostringstream result;
    result << "{\"unsigned_tx_hex\":\""
           << Hex(proposal.transaction.Serialize())
           << "\",\"inputs\":" << inputs.str()
           << ",\"total_input\":" << proposal.claimed_total_input
           << ",\"total_output\":" << proposal.claimed_total_output
           << ",\"fee\":" << MIN_TX_FEE
           << ",\"change\":" << proposal.claimed_change << '}';
    proposal.response = RpcResultEnvelope(result.str());
    return proposal;
}

std::string AuthenticatedParentRpcResponse(
        const FakeAuthenticatedParent& parent,
        const std::vector<uint8_t>& from_script, bool transaction) {
    std::ostringstream result;
    if (transaction) {
        result << "{\"raw_hex\":\"" << parent.raw_hex
               << "\",\"txid\":\"" << parent.txid << "\"}";
    } else {
        result << "{\"txid\":\"" << parent.txid
               << "\",\"vout\":0,\"value_units\":" << parent.value
               << ",\"script_pubkey_hex\":\"" << Hex(from_script)
               << "\",\"block_height\":1}";
    }
    return RpcResultEnvelope(result.str());
}

void ExerciseStandaloneValidatorValueBounds(
        VeldNode& node, const ValidatorKey& validator) {
    const std::string host = "127.0.0.1";
    const std::string operation = ValidatorRegistry::BuildRegisterOp(
        validator.pubkey_hex);
    const std::vector<uint8_t> from_script =
        AddressToScript(validator.address);

    for (const ValidatorValueAttack attack : {
             ValidatorValueAttack::RegistrationOutputWrap,
             ValidatorValueAttack::AuthenticatedInputWrap}) {
        const MaliciousValidatorProposal proposal =
            BuildMaliciousRegistrationProposal(
                validator, operation, attack);
        if (attack == ValidatorValueAttack::RegistrationOutputWrap) {
            Check(proposal.parents.size() == 1 &&
                      proposal.parents[0].value == MIN_TX_FEE + 1U &&
                      proposal.transaction.outputs.size() == 3 &&
                      proposal.transaction.outputs[0].value ==
                          MIN_VALIDATOR_STAKE &&
                      proposal.transaction.outputs[1].value ==
                          std::numeric_limits<uint64_t>::max() -
                              MIN_VALIDATOR_STAKE + 2U &&
                      proposal.claimed_total_output == 1U,
                  "registration output-wrap reproducer uses exact demonstrated values");
            uint64_t wrapped_output = 0;
            for (const auto& output : proposal.transaction.outputs)
                wrapped_output += output.value;
            Check(wrapped_output == 1U,
                  "registration malicious outputs wrap to one unit");
        } else {
            Check(proposal.parents.size() == 2 &&
                      proposal.parents[0].value == MAX_SUPPLY_UNITS &&
                      proposal.parents[1].value > MAX_SUPPLY_UNITS,
                  "input-wrap reproducer includes an oversized authenticated parent");
            uint64_t wrapped_input = 0;
            for (const auto& parent : proposal.parents)
                wrapped_input += parent.value;
            Check(wrapped_input == MIN_VALIDATOR_STAKE + MIN_TX_FEE,
                  "malicious authenticated inputs wrap to bond plus exact fee");
        }

        std::atomic<uint64_t> prepare_responses{0};
        std::atomic<uint64_t> gettxout_responses{0};
        std::atomic<uint64_t> gettransaction_responses{0};
        std::atomic<uint64_t> send_requests{0};
        LoopbackRpcShim malicious_rpc(
            node, [&](const std::string& request, std::string response) {
                if (request.find("\"method\":\"prepareregistervalidator\"") !=
                        std::string::npos) {
                    prepare_responses.fetch_add(1, std::memory_order_acq_rel);
                    return proposal.response;
                }
                const bool gettxout =
                    request.find("\"method\":\"gettxout\"") !=
                    std::string::npos;
                const bool gettransaction =
                    request.find("\"method\":\"gettransaction\"") !=
                    std::string::npos;
                for (const auto& parent : proposal.parents) {
                    if (request.find(parent.txid) == std::string::npos)
                        continue;
                    if (gettxout) {
                        gettxout_responses.fetch_add(
                            1, std::memory_order_acq_rel);
                        return AuthenticatedParentRpcResponse(
                            parent, from_script, false);
                    }
                    if (gettransaction) {
                        gettransaction_responses.fetch_add(
                            1, std::memory_order_acq_rel);
                        return AuthenticatedParentRpcResponse(
                            parent, from_script, true);
                    }
                }
                if (request.find("\"method\":\"sendrawtransaction\"") !=
                        std::string::npos)
                    send_requests.fetch_add(1, std::memory_order_acq_rel);
                return response;
            });

        const uint64_t script_sigs_before =
            validator_value_bound_test::build_script_sig_calls.load(
                std::memory_order_acquire);
        const size_t mempool_before = node.GetMempool().Size();
        const uint64_t gossip_before = node.TestWorkTxGossipCalls();
        Check(!broadcast_op_return(
                  host, malicious_rpc.port(), validator.address,
                  operation, validator),
              attack == ValidatorValueAttack::RegistrationOutputWrap
                  ? "standalone validator rejects registration output-wrap values"
                  : "standalone validator rejects oversized authenticated parent");
        Check(prepare_responses.load(std::memory_order_acquire) == 1,
              "malicious preparer supplied exactly one proposal");
        if (attack == ValidatorValueAttack::RegistrationOutputWrap) {
            Check(gettxout_responses.load(std::memory_order_acquire) == 0 &&
                      gettransaction_responses.load(
                          std::memory_order_acquire) == 0,
                  "oversized output is refused before parent lookups");
        } else {
            Check(gettxout_responses.load(std::memory_order_acquire) == 2 &&
                      gettransaction_responses.load(
                          std::memory_order_acquire) == 2,
                  "oversized input is refused after both parents authenticate");
        }
        Check(validator_value_bound_test::build_script_sig_calls.load(
                  std::memory_order_acquire) == script_sigs_before,
              "malicious value proposal reaches no BuildScriptSig invocation");
        Check(send_requests.load(std::memory_order_acquire) == 0,
              "malicious value proposal reaches no sendrawtransaction request");
        Check(node.GetMempool().Size() == mempool_before &&
                  node.TestWorkTxGossipCalls() == gossip_before,
              "malicious value proposal reaches no mempool or gossip artifact");
    }
}

finality::qc::EpochSnapshot MakeSnapshot(
        const dilithium::PublicKey& voter_public) {
    namespace fq = finality::qc;
    fq::EpochSnapshot snapshot;
    snapshot.epoch_id = 0;
    snapshot.snapshot_height = 0;
    std::vector<std::string> keys;
    keys.push_back(BytesToHex(voter_public.data(), voter_public.size()));
    for (char fill : {'1', '2', '3', '4', '5', '6'})
        keys.emplace_back(dilithium::PUBKEY_BYTES * 2, fill);
    for (size_t i = 0; i < keys.size(); ++i) {
        fq::SnapshotEntry entry;
        entry.pubkey_hex = keys[i];
        entry.pubkey_commit = fq::PubkeyCommit(entry.pubkey_hex);
        entry.address = "qualification-validator-" + std::to_string(i);
        entry.registered_height = 1;
        entry.weight = fq::BOND_PER_KEY_UNITS;
        snapshot.entries.push_back(std::move(entry));
    }
    std::sort(snapshot.entries.begin(), snapshot.entries.end(),
              [](const auto& a, const auto& b) {
                  return a.pubkey_commit < b.pubkey_commit;
              });
    snapshot.total_weight = snapshot.entries.size() * fq::BOND_PER_KEY_UNITS;
    snapshot.root = fq::SnapshotRoot(
        snapshot.entries, snapshot.epoch_id, snapshot.snapshot_height,
        snapshot.total_weight);
    Check(fq::SnapshotQualifies(snapshot), "finality snapshot qualifies");
    return snapshot;
}

void AssertFinalityVoteAdmissibleBeforeNodeSink(
        VeldNode& node, const finality::qc::EpochSnapshot& snapshot,
        const finality::qc::SignedVote& vote) {
    namespace fq = finality::qc;
    const uint64_t tip = node.GetChain().Height();
    Check(fq::FinalityEvidenceVoteWellFormed(
              vote, snapshot.epoch_id, snapshot.root, tip),
          "finality vote is structurally admissible at production tip");
    const auto retained = node.GetValidators().ResolveRetainedFinalityMember(
        vote.epoch_id, vote.set_root, vote.pubkey_hex);
    Check(retained.has_value(),
          "finality signer resolves through production retained membership");
    const auto member = std::find_if(
        snapshot.entries.begin(), snapshot.entries.end(),
        [&](const auto& entry) { return entry.pubkey_hex == vote.pubkey_hex; });
    Check(member != snapshot.entries.end(),
          "finality signer exists in exact installed snapshot");
    Check(fq::AuthenticateVoteForMember(
              vote, snapshot.epoch_id, snapshot.root, *member,
              fq::NETWORK_ID, CompiledGenesisBytes()).has_value(),
          "finality vote authenticates under production network/genesis domain");
    fq::CheckpointRef canonical_target{
        vote.target.height,
        node.GetChain().GetBlock(vote.target.height).GetHash()};
    Check(fq::VoteMatchesCanonicalFrame(
              vote, snapshot, tip, canonical_target,
              fq::FinalizedRecord{}),
          "finality vote matches production canonical frame");
}

void ExerciseStandaloneEndorsement(
        VeldNode& node, LoopbackRpcShim& shim, const RealKeyPair& signer,
        const std::filesystem::path& artifact_dir, bool expect_open,
        RowCounters& counters) {
    const Block tip = node.GetChain().TipCopy();
    const std::string host = "127.0.0.1";
    g_rpc_token.assign(64, 'a');
    const auto grant = fetch_work_admission(
        host, shim.port(),
        work_admission::Purpose::ValidatorEndorsement,
        tip.height, tip.GetHash());
    Check(static_cast<bool>(grant) == expect_open,
          "standalone fetch_work_admission follows tuple");
    if (!grant) return;
    WorkGrantCancelGuard release(host, shim.port(), *grant);
    EndorseAntiEquivGuard guard;
    const auto journal = artifact_dir / "standalone-endorse.journal";
    guard.load(journal.string());
    const std::string key = std::to_string(tip.height) + ":" +
        BytesToHex(signer.public_key.data(), signer.public_key.size());
    Check(guard.record(key, HashToHex(tip.GetHash())),
          "standalone actual anti-equivocation record persists");
    ++counters.standalone_journals;
    Check(grant->Live(std::chrono::milliseconds(1000)),
          "standalone signing grant live before signer");
    const std::string signature = sign_block(
        signer.private_key, tip.height, HashToHex(tip.GetHash()));
    Check(!signature.empty(), "standalone actual endorsement signer runs");
    ++counters.standalone_signatures;

    ValidatorKey validator;
    validator.privkey = signer.private_key;
    validator.pubkey = signer.public_key;
    validator.address = signer.address;
    validator.pubkey_hex = to_hex(validator.pubkey);
    Check(validator.HasExactIdentityBinding(),
          "standalone validator identity is locally key-bound");
    ExerciseStandaloneValidatorValueBounds(node, validator);
    const std::string operation = ValidatorRegistry::BuildEndorseOp(
        tip.height, HashToHex(tip.GetHash()), signature);
    const size_t mempool_before = node.GetMempool().Size();
    const uint64_t gossip_before = node.TestWorkTxGossipCalls();
    std::string prep_error;
    btc_buy::JsonValue prep_root;
    const auto* prep_result = strict_rpc_result(
        json_rpc(host, shim.port(), "preparerawop",
                 "[\"" + validator.address + "\",\"" + operation + "\"]"),
        prep_root, prep_error);
    uint64_t prepared_change = 0;
    uint64_t prepared_output_total = 0;
    Check(prep_result &&
              json_u64(*prep_result, "change", prepared_change) &&
              json_u64(*prep_result, "total_output", prepared_output_total) &&
              prepared_change > 0 &&
              prepared_output_total == prepared_change,
          "standalone production proposal has authenticated nonzero change "
          "included in its complete output total");
    Check(broadcast_op_return(host, shim.port(), validator.address,
                              operation, validator, &*grant),
          "standalone endorsement traverses preparerawop/authenticated parents/"
          "sign/sendrawtransaction sink");
    counters.standalone_mempool = static_cast<uint64_t>(
        node.GetMempool().Size() - mempool_before);
    counters.standalone_gossip =
        node.TestWorkTxGossipCalls() - gossip_before;
    Check(counters.standalone_mempool == 1 &&
              counters.standalone_gossip == 1,
          "standalone bound endorsement reaches one real mempool/gossip sink");

    // Regression for the F1/F4 preparer contract: `total_output` is the
    // complete independently recomputed output sum, including nonzero change,
    // not only the zero-valued protocol marker.  A malicious preparer that
    // restores the legacy protocol-only claim must be rejected before any
    // transaction signature, mempool mutation, or gossip.
    std::atomic<uint64_t> altered_total_responses{0};
    LoopbackRpcShim altered_total_rpc(
        node, [&](const std::string& request, std::string response) {
            if (request.find("\"method\":\"preparerawop\"") ==
                    std::string::npos)
                return response;
            const std::string marker = "\"total_output\":";
            const size_t begin = response.find(marker);
            if (begin == std::string::npos) return response;
            const size_t value_begin = begin + marker.size();
            size_t value_end = value_begin;
            while (value_end < response.size() &&
                   response[value_end] >= '0' &&
                   response[value_end] <= '9')
                ++value_end;
            if (value_end == value_begin) return response;
            response.replace(value_begin, value_end - value_begin, "0");
            altered_total_responses.fetch_add(1, std::memory_order_acq_rel);
            return response;
        });
    const auto altered_grant = fetch_work_admission(
        host, altered_total_rpc.port(),
        work_admission::Purpose::ValidatorEndorsement,
        tip.height, tip.GetHash());
    Check(altered_grant.has_value(),
          "altered-total regression obtains a fresh one-use grant");
    WorkGrantCancelGuard altered_release(
        host, altered_total_rpc.port(), *altered_grant);
    const size_t altered_mempool_before = node.GetMempool().Size();
    const uint64_t altered_gossip_before = node.TestWorkTxGossipCalls();
    Check(!broadcast_op_return(
              host, altered_total_rpc.port(), validator.address,
              operation, validator, &*altered_grant),
          "standalone signer rejects altered complete-output claim");
    Check(altered_total_responses.load(std::memory_order_acquire) == 1,
          "altered-total fixture changed exactly one production response");
    Check(node.GetMempool().Size() == altered_mempool_before &&
              node.TestWorkTxGossipCalls() == altered_gossip_before,
          "altered total reaches no mempool or gossip sink");
}

void ExerciseFinalityDaemon(
        VeldNode& node, LoopbackRpcShim& shim,
        const std::filesystem::path& artifact_dir, bool expect_open,
        RowCounters& counters) {
    namespace fq = finality::qc;
    const auto keypair = dilithium::Generate();
    const auto snapshot = MakeSnapshot(keypair.public_key);
    for (const auto& member : snapshot.entries) {
        node.GetValidators().TestInjectValidatorBond(
            member.pubkey_hex, member.address, member.weight);
    }
    Check(node.TestInstallFinalityEvidenceSnapshot(snapshot),
          "finality production verifier retains exact epoch membership");
    const std::string pubkey =
        BytesToHex(keypair.public_key.data(), keypair.public_key.size());
    fq::DaemonHooks hooks;
    hooks.fetch_snapshot = [snapshot](uint64_t epoch)
        -> std::optional<fq::EpochSnapshot> {
        return epoch == snapshot.epoch_id
            ? std::optional<fq::EpochSnapshot>(snapshot) : std::nullopt;
    };
    hooks.fetch_tip_height = [&] { return node.GetChain().Height(); };
    hooks.fetch_block_hash = [&](uint64_t height)
        -> std::optional<Hash256> {
        if (height > node.GetChain().Height()) return std::nullopt;
        return node.GetChain().GetBlock(height).GetHash();
    };
    hooks.authorize_work = [&](const fq::CheckpointRef& target)
        -> std::optional<fq::DaemonWorkGrant> {
        auto grant = fetch_work_admission(
            "127.0.0.1", shim.port(),
            work_admission::Purpose::FinalityVote,
            target.height, target.hash);
        if (!grant) return std::nullopt;
        return fq::DaemonWorkGrant{
            grant->binding, grant->token, grant->deadline};
    };
    hooks.cancel_work = [&](const fq::DaemonWorkGrant& grant) {
        (void)cancel_work_signing("127.0.0.1", shim.port(), grant.token);
    };
    hooks.gossip_vote = [&](const fq::SignedVote& vote,
                            const fq::DaemonWorkGrant& grant) {
        AssertFinalityVoteAdmissibleBeforeNodeSink(node, snapshot, vote);
        WorkAdmissionGrant transport{
            grant.binding, grant.token, grant.deadline};
        Check(finality::qc::EncodeSignedVoteWire(vote).size() ==
                  finality::qc::SIGNED_VOTE_WIRE_BYTES,
              "finality transport uses exact canonical FVT1 wire");
        Check(transport.Live(),
              "finality transport grant remains live at submission");
        Check(validate_work_binding(
                  transport.binding, work_admission::Purpose::FinalityVote,
                  vote.target.height, vote.target.hash),
              "finality transport binding matches exact signed target");
        const bool submitted = submit_finality_vote(
            "127.0.0.1", shim.port(), vote, transport);
        if (submitted) ++counters.finality_gossip;
        return submitted;
    };
    hooks.persist_journal = [&](const fq::DaemonJournal&) {
        ++counters.finality_journals;
        std::ofstream out(artifact_dir / "finality-vote.journal",
                          std::ios::binary | std::ios::trunc);
        out << "F4-FINALITY-JOURNAL\n";
        out.flush();
        return out.good();
    };
    hooks.load_journal = []() -> std::optional<fq::DaemonJournal> {
        return std::nullopt;
    };
    hooks.fetch_finalized = []()
        -> std::optional<fq::FinalizedRecord> { return std::nullopt; };
    hooks.fetch_prevote_qc = [](const fq::EpochSnapshot&)
        -> std::optional<fq::DecodedQc> { return std::nullopt; };
    hooks.authorize_target = [](const fq::CheckpointRef&) { return true; };

    fq::FinalityVoter::TestResetSignatureCount();
    fq::FinalityDaemon daemon(
        pubkey, keypair.secret_key, fq::NETWORK_ID,
        CompiledGenesisBytes(), std::move(hooks));
    const bool acted = daemon.Tick();
    counters.finality_signatures = fq::FinalityVoter::TestSignatureCount();
    counters.finality_sink_calls = node.TestWorkFinalitySinkCalls();
    counters.finality_active_calls = node.TestWorkFinalityActiveCalls();
    counters.finality_verify_result = node.TestWorkFinalityVerifyResult();
    counters.finality_assembler = node.TestFinalityAssemblerCount();
    counters.finality_node_gossip = node.TestWorkFinalityGossipCalls();
    Check(acted == expect_open,
          "FinalityDaemon Tick follows tuple (sink=" +
              std::to_string(counters.finality_sink_calls) +
              ", active=" +
              std::to_string(counters.finality_active_calls) +
              ", verify=" +
              std::to_string(counters.finality_verify_result) + ")");
    Check(counters.finality_assembler == (expect_open ? 1u : 0u) &&
              counters.finality_node_gossip == (expect_open ? 1u : 0u),
          "FinalityDaemon traverses real node verify/assembler/gossip sink");
}
#endif

Transaction MakeEndorsementTransaction(
        VeldNode& node, const RealKeyPair& signer,
        uint64_t target_height, const Hash256& target_hash) {
    UTXO funding;
    funding.tx_hash = Hash256d(
        std::string("F4-INPROC-FUNDING-") + HashToHex(target_hash));
    funding.output_index = 0;
    funding.value = MIN_TX_FEE + 5'000;
    funding.script_pubkey = signer.GetP2PKHScript();
    funding.block_height = 1;
    funding.is_coinbase = false;
    node.GetChainMut().TestInjectUTXO(funding);

    const Hash256 message = ValidatorRegistry::BuildEndorseMessage(
        target_height, target_hash);
    const auto signature = Sign(signer.private_key, message);
    const std::string marker = ValidatorRegistry::BuildEndorseOp(
        target_height, HashToHex(target_hash), BytesToHex(signature));

    Transaction tx;
    TxInput input;
    input.prev_tx_hash = funding.tx_hash;
    input.prev_out_index = funding.output_index;
    tx.inputs.push_back(input);
    tx.outputs.emplace_back(5'000, signer.GetP2PKHScript());
    tx.outputs.emplace_back(0, BuildOpReturnScript(marker));
    tx.inputs[0].script_sig =
        signer.SignInput(tx, 0, funding.script_pubkey).script_sig;
    return tx;
}

void ExerciseInProcessEndorsement(
        VeldNode& node, const RealKeyPair& signer,
        const std::filesystem::path& artifact_dir, bool expect_open,
        RowCounters& counters) {
    const Block tip = node.GetChain().TipCopy();
    work_admission::Subject subject;
    subject.purpose = work_admission::Purpose::ValidatorEndorsement;
    subject.height = tip.height;
    subject.target_hash = tip.GetHash();
    subject.parent_height = tip.height;
    subject.parent_hash = tip.GetHash();
    auto permit = node.AcquireLocalValidatorEndorsementPermit(subject);
    Check(static_cast<bool>(permit) == expect_open,
          "in-process pre-journal permit follows tuple");
    if (!permit) return;

    EndorseAntiEquivGuard guard;
    const auto journal = artifact_dir / "inproc-endorse.journal";
    guard.load(journal.string());
    const std::string pubkey =
        BytesToHex(signer.public_key.data(), signer.public_key.size());
    Check(guard.record(std::to_string(tip.height) + ":" + pubkey,
                       HashToHex(tip.GetHash())),
          "in-process actual anti-equivocation record persists");
    ++counters.inproc_journals;
    const Transaction tx = MakeEndorsementTransaction(
        node, signer, tip.height, tip.GetHash());
    ++counters.inproc_signatures;
    const size_t before = node.GetMempool().Size();
    const auto result = node.SubmitLocalValidatorEndorsement(
        tx, MIN_TX_FEE, std::move(*permit));
    Check(result.accepted, "in-process endorsement reaches real mempool sink");
    counters.inproc_mempool =
        static_cast<uint64_t>(node.GetMempool().Size() - before);
    counters.inproc_gossip = node.TestWorkTxGossipCalls();
}

void AssertNoRetainedWork(VeldNode& node, bool allow_mempool) {
    const auto snapshot = node.TestWorkAdmissionCoordinatorSnapshot();
    Check(snapshot.active_leases == 0 &&
              snapshot.pending_remote_tokens == 0,
          "no coordinator lease or pending bearer retained");
    Check(node.TestActiveRemoteSigningLeaseCount() == 0,
          "no active remote signing lease retained");
    Check(node.TestPendingBroadcastCount() == 0,
          "no pending block broadcast retained");
    Check(node.TestCachedTemplateCount() == 0,
          "no pending block-template authorization retained");
    if (!allow_mempool)
        Check(node.GetMempool().IsEmpty(), "closed row retains no mempool work");
}

bool WaitForCoordinatorClosing(VeldNode& node,
                               std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (node.TestWorkAdmissionCoordinatorSnapshot().phase ==
            work_admission::AdmissionCoordinator::Phase::Closing)
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}

void RethrowThreadFailure(const std::exception_ptr& failure,
                          const char* label) {
    if (!failure) return;
    try {
        std::rethrow_exception(failure);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string(label) + ": " + e.what());
    } catch (...) {
        throw std::runtime_error(std::string(label) + ": unknown exception");
    }
}

void RunSubmitRaceRow(const std::string& row,
                      const std::filesystem::path& artifact_dir) {
#if defined(VELD_PUBLIC_TESTNET)
    (void)row; (void)artifact_dir;
    throw std::runtime_error("submit race row built with public-testnet profile");
#else
    const bool acquired_first = row == "race_submit_acquired_first";
    Check(acquired_first || row == "race_submit_close_first",
          "recognized submit race row");
    const RealKeyPair miner = GenerateKeyPair(false);
    VeldNode node(MainnetConfig(), (artifact_dir / "submit-node").string());
    node.TestWireDBForDurableCommit();
    InstallTrustedChain(node.GetChainMut(), node.GetMempoolMut(), miner, 1);
    node.TestInstallWorkAdmissionProcessServer();
    auto peers = InstallSafePeers(node, node.GetChain().Height(), 37401);
    const uint64_t peer_generation_before =
        node.TestWorkAdmissionProcessServer().GetPeerHeightView().
            work_generation;
    node.TestConfigureWorkAdmissionProcess(ReadyState());
    const auto subject = node.TestCurrentBlockProductionSubject();
    Check(subject.has_value(), "submit race canonical subject exists");
    const auto decision = node.TestEvaluateWorkAdmission(
        work_admission::Path::SubmitBlock, *subject);
    Check(decision.allowed && decision.binding,
          "submit race issues real bound work decision");
    WaitForTemplateTimestamp(node.GetChain());
    auto candidate = ParsePublishedBlockTemplate(
        node.TestHandleWorkAdmissionRpc(
            RpcRequest("getblocktemplate", {miner.address})));
    Check(candidate.has_value(),
          "submit race obtains a server-authorized real template");
    SolvePublishedBlock(candidate->block);
    const std::string request = RpcRequest(
        "submitblock", {Hex(candidate->block.Serialize()),
                        candidate->binding, candidate->token});

    node.TestResetWorkAdmissionProcessCounters();
    Blockchain::TestResetAddBlockDirectCalls();
    std::atomic<uint64_t> barrier_calls{0};
    std::atomic<bool> close_done{false};
    std::atomic<bool> submit_done{false};
    std::exception_ptr submit_failure;
    std::exception_ptr close_failure;
    std::string response;
    bool close_blocked_before_release = false;

    if (!acquired_first) {
        (void)node.TestWorkAdmissionProcessServer().TestFinalizePeerConnection(
            "unused", peers.first);
        Check(node.TestWorkAdmissionCoordinatorSnapshot().phase ==
                  work_admission::AdmissionCoordinator::Phase::Closed,
              "submit close-first peer transition closes coordinator");
        node.GetChainMut().TestSetLocalWorkPreCommitBarrier([&] {
            barrier_calls.fetch_add(1, std::memory_order_acq_rel);
        });
        response = node.TestHandleWorkAdmissionRpc(request);
        submit_done.store(true, std::memory_order_release);
    } else {
        std::promise<void> entered_promise;
        auto entered = entered_promise.get_future();
        std::promise<void> release_promise;
        auto release = release_promise.get_future().share();
        node.GetChainMut().TestSetLocalWorkPreCommitBarrier([&] {
            barrier_calls.fetch_add(1, std::memory_order_acq_rel);
            entered_promise.set_value();
            release.wait();
        });
        std::thread submit_thread([&] {
            try {
                response = node.TestHandleWorkAdmissionRpc(request);
                submit_done.store(true, std::memory_order_release);
            } catch (...) {
                submit_failure = std::current_exception();
            }
        });
        if (entered.wait_for(std::chrono::seconds(3)) !=
            std::future_status::ready) {
            release_promise.set_value();
            submit_thread.join();
            throw std::runtime_error(
                "submit acquired-first never reached real pre-commit barrier");
        }
        Check(node.TestWorkAdmissionCoordinatorSnapshot().active_leases == 1,
              "submit acquired-first owns one claimed coordinator lease");
        std::thread close_thread([&] {
            try {
                (void)node.TestWorkAdmissionProcessServer().
                    TestFinalizePeerConnection("unused", peers.first);
                close_done.store(true, std::memory_order_release);
            } catch (...) {
                close_failure = std::current_exception();
            }
        });
        Check(WaitForCoordinatorClosing(node, std::chrono::seconds(2)),
              "submit acquired-first close reaches Closing phase");
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        close_blocked_before_release =
            !close_done.load(std::memory_order_acquire);
        Check(close_blocked_before_release &&
                  !submit_done.load(std::memory_order_acquire),
              "submit acquired-first close cannot linearize across live sink");
        release_promise.set_value();
        submit_thread.join();
        close_thread.join();
        RethrowThreadFailure(submit_failure, "submit race thread");
        RethrowThreadFailure(close_failure, "submit close thread");
    }
    node.GetChainMut().TestSetLocalWorkPreCommitBarrier({});

    const auto published_peer_view =
        node.TestWorkAdmissionProcessServer().GetPeerHeightView();
    Check(published_peer_view.work_generation != peer_generation_before &&
              published_peer_view.distinct_version_ips == 1 &&
              node.TestWorkAdmissionProcessServer().
                      TestVerifiedPeerEvidenceCount() == 1,
          acquired_first
              ? "acquired-first commit completes before exact peer disconnect publication"
              : "close-first exact peer disconnect publishes before submit refusal");

    const uint64_t add_calls = Blockchain::TestAddBlockDirectCalls();
    const uint64_t durable_calls = node.TestWorkDurableWriterCalls();
    const uint64_t broadcasts = node.TestWorkBlockBroadcastCalls();
    if (acquired_first) {
        Check(barrier_calls.load(std::memory_order_acquire) == 1 &&
                  submit_done.load(std::memory_order_acquire) &&
                  close_done.load(std::memory_order_acquire),
              "submit acquired-first completes both bounded participants once");
        Check(add_calls == 1 && durable_calls == 1 && broadcasts == 1,
              "submit acquired-first emits exactly one bounded sink");
        Check(response.find("error\":null") != std::string::npos,
              "submit acquired-first RPC returns success");
    } else {
        Check(barrier_calls.load(std::memory_order_acquire) == 0 &&
                  add_calls == 0 && durable_calls == 0 && broadcasts == 0,
              "submit close-first emits zero precommit/durable/publication effects");
        Check(response.find("error\":null") == std::string::npos,
              "submit close-first RPC refuses work");
    }
    AssertNoRetainedWork(node, false);
    const auto snapshot = node.TestWorkAdmissionCoordinatorSnapshot();
    std::cout << "F4_ROW_JSON {\"row\":\"" << JsonEscape(row)
              << "\",\"race\":\"submitblock\",\"linearization\":\""
              << (acquired_first ? "acquired_first" : "close_first")
              << "\",\"closed\":true,\"checks\":" << checks
              << ",\"barrier_calls\":" << barrier_calls.load()
              << ",\"close_blocked_before_release\":"
              << (close_blocked_before_release ? 1 : 0)
              << ",\"submit_add_calls\":" << add_calls
              << ",\"submit_durable_calls\":" << durable_calls
              << ",\"block_broadcasts\":" << broadcasts
              << ",\"journal_calls\":0,\"signature_calls\":0,"
                 "\"gossip_calls\":0,\"cached_templates\":0,"
              << "\"pending_tokens\":" << snapshot.pending_remote_tokens
              << ",\"active_leases\":" << snapshot.active_leases
              << ",\"active_remote_leases\":"
              << node.TestActiveRemoteSigningLeaseCount()
              << ",\"pending_broadcasts\":"
              << node.TestPendingBroadcastCount() << "}" << std::endl;
#endif
}

void RunFinalityRaceRow(const std::string& row,
                        const std::filesystem::path& artifact_dir) {
#if defined(VELD_PUBLIC_TESTNET)
    (void)row; (void)artifact_dir;
    throw std::runtime_error("finality race row built with public-testnet profile");
#else
    namespace fq = finality::qc;
    const bool acquired_first = row == "race_finality_acquired_first";
    Check(acquired_first || row == "race_finality_close_first",
          "recognized finality race row");
    const RealKeyPair miner = GenerateKeyPair(false);
    VeldNode node(MainnetConfig(), (artifact_dir / "finality-node").string());
    InstallTrustedChain(node.GetChainMut(), node.GetMempoolMut(), miner, 21);
    node.TestInstallWorkAdmissionProcessServer();
    auto peers = InstallSafePeers(node, node.GetChain().Height(), 37501);
    node.TestConfigureWorkAdmissionProcess(ReadyState());
    node.TestResetWorkAdmissionProcessCounters();
    LoopbackRpcShim rpc(node);
    g_rpc_token.assign(64, 'a');

    const auto keypair = dilithium::Generate();
    const auto snapshot = MakeSnapshot(keypair.public_key);
    for (const auto& member : snapshot.entries) {
        node.GetValidators().TestInjectValidatorBond(
            member.pubkey_hex, member.address, member.weight);
    }
    Check(node.TestInstallFinalityEvidenceSnapshot(snapshot),
          "finality race installs exact membership in production verifier");
    const std::string pubkey =
        BytesToHex(keypair.public_key.data(), keypair.public_key.size());
    std::atomic<uint64_t> authorize_calls{0};
    std::atomic<uint64_t> active_observed{0};
    std::atomic<uint64_t> journal_calls{0};
    std::atomic<uint64_t> gossip_calls{0};
    std::atomic<bool> tick_done{false};
    std::atomic<bool> tick_acted{false};
    std::atomic<bool> close_done{false};
    std::exception_ptr tick_failure;
    std::exception_ptr close_failure;
    bool close_blocked_before_release = false;
    std::promise<void> entered_promise;
    auto entered = entered_promise.get_future();
    std::promise<void> release_promise;
    auto release = release_promise.get_future().share();

    fq::DaemonHooks hooks;
    hooks.fetch_snapshot = [snapshot](uint64_t epoch)
        -> std::optional<fq::EpochSnapshot> {
        return epoch == snapshot.epoch_id
            ? std::optional<fq::EpochSnapshot>(snapshot) : std::nullopt;
    };
    hooks.fetch_tip_height = [&] { return node.GetChain().Height(); };
    hooks.fetch_block_hash = [&](uint64_t height)
        -> std::optional<Hash256> {
        if (height > node.GetChain().Height()) return std::nullopt;
        return node.GetChain().GetBlock(height).GetHash();
    };
    hooks.authorize_work = [&](const fq::CheckpointRef& target)
        -> std::optional<fq::DaemonWorkGrant> {
        authorize_calls.fetch_add(1, std::memory_order_acq_rel);
        auto grant = fetch_work_admission(
            "127.0.0.1", rpc.port(),
            work_admission::Purpose::FinalityVote,
            target.height, target.hash);
        if (!grant) return std::nullopt;
        active_observed.store(
            node.TestActiveRemoteSigningLeaseCount(),
            std::memory_order_release);
        if (acquired_first) {
            entered_promise.set_value();
            release.wait();
        }
        return fq::DaemonWorkGrant{
            grant->binding, grant->token, grant->deadline};
    };
    hooks.cancel_work = [&](const fq::DaemonWorkGrant& grant) {
        (void)cancel_work_signing("127.0.0.1", rpc.port(), grant.token);
    };
    hooks.gossip_vote = [&](const fq::SignedVote& vote,
                            const fq::DaemonWorkGrant& grant) {
        AssertFinalityVoteAdmissibleBeforeNodeSink(node, snapshot, vote);
        WorkAdmissionGrant transport{
            grant.binding, grant.token, grant.deadline};
        Check(finality::qc::EncodeSignedVoteWire(vote).size() ==
                  finality::qc::SIGNED_VOTE_WIRE_BYTES,
              "finality race transport uses exact canonical FVT1 wire");
        Check(transport.Live(),
              "finality race transport grant remains live at submission");
        Check(validate_work_binding(
                  transport.binding, work_admission::Purpose::FinalityVote,
                  vote.target.height, vote.target.hash),
              "finality race binding matches exact signed target");
        const bool submitted = submit_finality_vote(
            "127.0.0.1", rpc.port(), vote, transport);
        if (submitted)
            gossip_calls.fetch_add(1, std::memory_order_acq_rel);
        return submitted;
    };
    hooks.persist_journal = [&](const fq::DaemonJournal&) {
        journal_calls.fetch_add(1, std::memory_order_acq_rel);
        std::ofstream out(artifact_dir / "finality-race.journal",
                          std::ios::binary | std::ios::trunc);
        out << "F4-FINALITY-RACE-JOURNAL\n";
        out.flush();
        return out.good();
    };
    hooks.load_journal = []() -> std::optional<fq::DaemonJournal> {
        return std::nullopt;
    };
    hooks.fetch_finalized = []()
        -> std::optional<fq::FinalizedRecord> { return std::nullopt; };
    hooks.fetch_prevote_qc = [](const fq::EpochSnapshot&)
        -> std::optional<fq::DecodedQc> { return std::nullopt; };
    hooks.authorize_target = [](const fq::CheckpointRef&) { return true; };

    fq::FinalityVoter::TestResetSignatureCount();
    fq::FinalityDaemon daemon(
        pubkey, keypair.secret_key, fq::NETWORK_ID,
        CompiledGenesisBytes(), std::move(hooks));

    if (!acquired_first) {
        (void)node.TestWorkAdmissionProcessServer().TestFinalizePeerConnection(
            "unused", peers.first);
        Check(node.TestWorkAdmissionCoordinatorSnapshot().phase ==
                  work_admission::AdmissionCoordinator::Phase::Closed,
              "finality close-first peer transition closes coordinator");
        tick_acted.store(daemon.Tick(), std::memory_order_release);
        tick_done.store(true, std::memory_order_release);
    } else {
        std::thread tick_thread([&] {
            try {
                tick_acted.store(daemon.Tick(), std::memory_order_release);
                tick_done.store(true, std::memory_order_release);
            } catch (...) {
                tick_failure = std::current_exception();
            }
        });
        if (entered.wait_for(std::chrono::seconds(3)) !=
            std::future_status::ready) {
            release_promise.set_value();
            tick_thread.join();
            throw std::runtime_error(
                "finality acquired-first never reached active-lease barrier");
        }
        Check(active_observed.load(std::memory_order_acquire) == 1 &&
                  node.TestActiveRemoteSigningLeaseCount() == 1,
              "finality acquired-first barrier owns one active remote lease");
        Check(journal_calls.load(std::memory_order_acquire) == 0 &&
                  fq::FinalityVoter::TestSignatureCount() == 0 &&
                  gossip_calls.load(std::memory_order_acquire) == 0,
              "finality active-lease barrier precedes journal/sign/gossip");
        std::thread close_thread([&] {
            try {
                (void)node.TestWorkAdmissionProcessServer().
                    TestFinalizePeerConnection("unused", peers.first);
                close_done.store(true, std::memory_order_release);
            } catch (...) {
                close_failure = std::current_exception();
            }
        });
        Check(WaitForCoordinatorClosing(node, std::chrono::seconds(2)),
              "finality acquired-first close reaches Closing phase");
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        close_blocked_before_release =
            !close_done.load(std::memory_order_acquire);
        Check(close_blocked_before_release &&
                  !tick_done.load(std::memory_order_acquire),
              "finality acquired-first close cannot linearize across active signer");
        release_promise.set_value();
        tick_thread.join();
        close_thread.join();
        RethrowThreadFailure(tick_failure, "finality Tick thread");
        RethrowThreadFailure(close_failure, "finality close thread");
    }

    const uint64_t signatures = fq::FinalityVoter::TestSignatureCount();
    const uint64_t sink_calls = node.TestWorkFinalitySinkCalls();
    const uint64_t active_calls = node.TestWorkFinalityActiveCalls();
    const uint64_t verify_result = node.TestWorkFinalityVerifyResult();
    const uint64_t node_gossip = node.TestWorkFinalityGossipCalls();
    const uint64_t assembler = node.TestFinalityAssemblerCount();
    if (acquired_first) {
        Check(tick_done.load(std::memory_order_acquire),
              "finality acquired-first Tick completes boundedly");
        Check(close_done.load(std::memory_order_acquire),
              "finality acquired-first close completes boundedly");
        Check(tick_acted.load(std::memory_order_acquire),
              "finality acquired-first real vote sink accepts");
        Check(authorize_calls.load() == 1 && journal_calls.load() == 1 &&
                  signatures == 1 && gossip_calls.load() == 1 &&
                  sink_calls == 1 && active_calls == 1 &&
                  verify_result == static_cast<uint8_t>(
                      net::NodeServer::FinalityVoteVerifyResult::AcceptedNew) &&
                  node_gossip == 1 && assembler == 1,
              "finality acquired-first emits exactly one journal/sign/"
              "verify/assembler/gossip sink");
    } else {
        Check(!tick_acted.load(std::memory_order_acquire) &&
                  authorize_calls.load() == 1 &&
                  active_observed.load() == 0 && journal_calls.load() == 0 &&
                  signatures == 0 && gossip_calls.load() == 0 &&
                  sink_calls == 0 && active_calls == 0 &&
                  verify_result == UINT8_MAX &&
                  node_gossip == 0 && assembler == 0,
              "finality close-first emits zero active/journal/sign/gossip effects");
        Check(!std::filesystem::exists(artifact_dir / "finality-race.journal"),
              "finality close-first emits no journal artifact");
    }
    AssertNoRetainedWork(node, false);
    const auto coordinator = node.TestWorkAdmissionCoordinatorSnapshot();
    std::cout << "F4_ROW_JSON {\"row\":\"" << JsonEscape(row)
              << "\",\"race\":\"finality\",\"linearization\":\""
              << (acquired_first ? "acquired_first" : "close_first")
              << "\",\"closed\":true,\"checks\":" << checks
              << ",\"barrier_calls\":" << active_observed.load()
              << ",\"close_blocked_before_release\":"
              << (close_blocked_before_release ? 1 : 0)
              << ",\"submit_add_calls\":0,\"submit_durable_calls\":0,"
                 "\"block_broadcasts\":0,\"journal_calls\":"
              << journal_calls.load() << ",\"signature_calls\":"
              << signatures << ",\"gossip_calls\":" << gossip_calls.load()
              << ",\"sink_calls\":" << sink_calls
              << ",\"active_calls\":" << active_calls
              << ",\"verify_result\":" << verify_result
              << ",\"node_gossip_calls\":" << node_gossip
              << ",\"assembler_calls\":" << assembler
              << ",\"cached_templates\":0,\"pending_tokens\":"
              << coordinator.pending_remote_tokens
              << ",\"active_leases\":" << coordinator.active_leases
              << ",\"active_remote_leases\":"
              << node.TestActiveRemoteSigningLeaseCount()
              << ",\"pending_broadcasts\":"
              << node.TestPendingBroadcastCount() << "}" << std::endl;
#endif
}

void RunGenericRow(const std::string& row,
                   const std::filesystem::path& artifact_dir) {
#if defined(VELD_PUBLIC_TESTNET)
    (void)row; (void)artifact_dir;
    throw std::runtime_error("generic row built with public-testnet profile");
#else
    const bool closed = IsClosedRow(row);
    const bool expect_open = !closed;
    RowCounters counters;
    const RealKeyPair miner = GenerateKeyPair(false);

    VeldNode node(MainnetConfig(), (artifact_dir / "node").string());
    node.TestWireDBForDurableCommit();
    // The standalone production transaction preparer authenticates complete
    // raw parent transactions.  Four fixed-difficulty blocks leave the first
    // fixture coinbase beyond the regtest profile's exact maturity boundary.
    InstallTrustedChain(node.GetChainMut(), node.GetMempoolMut(), miner, 4);
    node.TestInstallWorkAdmissionProcessServer();
    auto peers = InstallSafePeers(node, node.GetChain().Height(), 37101);

    VeldNode finality_node(
        MainnetConfig(), (artifact_dir / "finality-node").string());
    InstallTrustedChain(finality_node.GetChainMut(),
                        finality_node.GetMempoolMut(), miner, 21);
    finality_node.TestInstallWorkAdmissionProcessServer();
    auto finality_peers = InstallSafePeers(
        finality_node, finality_node.GetChain().Height(), 37201);

    node.TestConfigureWorkAdmissionProcess(ReadyState());
    finality_node.TestConfigureWorkAdmissionProcess(ReadyState());
    const auto subject = node.TestCurrentBlockProductionSubject();
    Check(subject.has_value(), "canonical block subject available");
    auto stale_submit = node.TestEvaluateWorkAdmission(
        work_admission::Path::SubmitBlock, *subject);
    Check(stale_submit.allowed && stale_submit.binding,
          "open setup issues real submit binding");
    auto candidate = MineOnly(
        node.GetChainMut(), node.GetMempoolMut(), miner);
    Check(candidate.success, "P2P/submit candidate mined before row closes");

    auto state = StateForRow(row);
    node.TestConfigureWorkAdmissionProcess(state);
    finality_node.TestConfigureWorkAdmissionProcess(state);
    if (row == "default_unknown") {
        node.TestUnwireAuthoritativeWorkAdmission();
        finality_node.TestUnwireAuthoritativeWorkAdmission();
    }
    if (row == "peer_view" || row == "peer_version_loss") {
        (void)node.TestWorkAdmissionProcessServer().TestFinalizePeerConnection(
            "unused", peers.first);
        (void)finality_node.TestWorkAdmissionProcessServer().
            TestFinalizePeerConnection("unused", finality_peers.first);
    }
    if (row == "peer_version_expiry") {
        const uint64_t expired = 100 +
            net::NodeServer::TestVersionHeightHintTtlSeconds() + 1;
        node.TestWorkAdmissionProcessServer().TestSetPeerHeightClock(expired);
        finality_node.TestWorkAdmissionProcessServer().
            TestSetPeerHeightClock(expired);
    }

    std::string binding = EncodeSubmitBindingForBlock(
        *stale_submit.binding, candidate.block);
    std::string submit_hex = Hex(candidate.block.Serialize());
    std::string submit_token(64, 'a');
    if (expect_open) {
        const auto current = node.TestEvaluateWorkAdmission(
            work_admission::Path::SubmitBlock, *subject);
        Check(current.allowed && current.binding,
              "open row reissues current submit binding");
        binding = EncodeSubmitBindingForBlock(
            *current.binding, candidate.block);
    }

    node.TestResetWorkAdmissionProcessCounters();
    finality_node.TestResetWorkAdmissionProcessCounters();
    node.TestEnableWorkAdmissionMiningBarrier(true);
    const uint64_t hashes_before = node.GetTotalHashes();
    const uint64_t progress_before = node.GetMiningProgressCounter();
    node.StartMining(miner);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    node.StopMining();
    counters.internal_mining_admitted =
        node.TestWorkMiningAdmittedCalls();
    counters.internal_hashes = node.GetTotalHashes() - hashes_before;
    counters.internal_progress =
        node.GetMiningProgressCounter() - progress_before;
    Check((counters.internal_mining_admitted > 0) == expect_open,
          "internal miner authoritative pre-hash barrier follows tuple");
    Check(counters.internal_hashes == 0 && counters.internal_progress == 0,
          "internal miner performs zero hash/progress work at barrier");

    if (expect_open) WaitForTemplateTimestamp(node.GetChain());
    const std::string gbt = node.TestHandleWorkAdmissionRpc(
        RpcRequest("getblocktemplate", {miner.address}));
    counters.gbt_templates =
        gbt.find("\\\"block_hex\\\"") != std::string::npos ||
        gbt.find("\"block_hex\"") != std::string::npos;
    Check((counters.gbt_templates == 1) == expect_open,
          "real getblocktemplate follows tuple");
    if (expect_open) {
        auto published = ParsePublishedBlockTemplate(gbt);
        Check(published.has_value(),
              "open row receives a server-issued template capability");
        SolvePublishedBlock(published->block);
        submit_hex = Hex(published->block.Serialize());
        binding = published->binding;
        submit_token = published->token;
    }

    Blockchain::TestResetAddBlockDirectCalls();
    const uint64_t durable_before = node.TestWorkDurableWriterCalls();
    const std::string submit = node.TestHandleWorkAdmissionRpc(
        RpcRequest("submitblock", {submit_hex, binding, submit_token}));
    (void)submit;
    counters.submit_add_calls = Blockchain::TestAddBlockDirectCalls();
    counters.submit_durable_calls =
        node.TestWorkDurableWriterCalls() - durable_before;
    counters.block_broadcasts = node.TestWorkBlockBroadcastCalls();
    Check((counters.submit_add_calls == 1) == expect_open,
          "submitblock reaches AddBlockDirect only for open tuple");
    Check((counters.submit_durable_calls == 1) == expect_open,
          "submitblock durable writer follows tuple");
    Check((counters.block_broadcasts == 1) == expect_open,
          "submitblock publication follows tuple");

    LoopbackRpcShim validator_rpc(node);
    LoopbackRpcShim finality_rpc(finality_node);
    ExerciseInProcessEndorsement(
        node, miner, artifact_dir, expect_open, counters);
    ExerciseStandaloneEndorsement(
        node, validator_rpc, miner, artifact_dir, expect_open, counters);
    ExerciseFinalityDaemon(
        finality_node, finality_rpc, artifact_dir, expect_open, counters);

    if (closed) {
        Check(counters.inproc_journals == 0 &&
                  counters.inproc_signatures == 0 &&
                  counters.inproc_mempool == 0 &&
                  counters.inproc_gossip == 0 &&
                  counters.standalone_journals == 0 &&
                  counters.standalone_signatures == 0 &&
                  counters.standalone_mempool == 0 &&
                  counters.standalone_gossip == 0 &&
                  counters.finality_journals == 0 &&
                  counters.finality_signatures == 0 &&
                  counters.finality_gossip == 0 &&
                  counters.finality_sink_calls == 0 &&
                  counters.finality_active_calls == 0 &&
                  counters.finality_verify_result == UINT8_MAX &&
                  counters.finality_assembler == 0 &&
                  counters.finality_node_gossip == 0,
              "closed tuple emits zero journal/sign/mempool/gossip effects");

        // The F4 predicate controls only locally produced/signed work.
        // Every false-prerequisite child independently proves ordinary inbound
        // synchronization still traverses the real bounded P2P ingest path.
        {
            Blockchain::TestResetAddBlockDirectCalls();
            const uint64_t p2p_durable_before =
                node.TestWorkDurableWriterCalls();
            const uint64_t p2p_height_before = node.GetChain().Height();
            auto& server = node.TestWorkAdmissionProcessServer();
            server.TestResetBlockIngestOutcomeCounters();
            // Make the relay sink observable. An accepted boundary probe emits
            // exactly one post-accept relay attempt; a terminal safety refusal
            // must not reach it.
            server.SetIBDComplete(true);
            server.TestUseQueuedBlockIngest(true);
            const auto queued = server.TestEnqueueBlockIngest(
                candidate.block, candidate.block.SerializedSize(),
                "198.51.100.7");
            Check(queued == net::NodeServer::IngestEnqueueResult::Queued,
                  "P2P candidate enters real bounded ingest queue");
            Check(server.TestProcessOnePendingBlockIngest(),
                  "P2P candidate traverses production ingest worker routine");
            counters.p2p_add_calls = Blockchain::TestAddBlockDirectCalls();
            counters.p2p_durable_calls =
                node.TestWorkDurableWriterCalls() - p2p_durable_before;
            counters.p2p_tip_advanced =
                node.GetChain().Height() == p2p_height_before + 1;
            counters.p2p_relay_calls = server.TestBlockIngestRelayCount();
            counters.p2p_penalty_calls = server.TestBlockIngestPenaltyCount();
            counters.p2p_reject_tag = node.GetChain().GetLastRejectTag();
            if (IsGlobalTerminalSafetyRow(row)) {
                Check(counters.p2p_add_calls == 1,
                      "terminal P2P probe reaches real consensus admission boundary");
                Check(counters.p2p_durable_calls == 0 &&
                          counters.p2p_tip_advanced == 0 &&
                          counters.p2p_relay_calls == 0 &&
                          counters.p2p_penalty_calls == 0,
                      "terminal safety refusal precedes durable/tip/relay/penalty sinks");
                Check(counters.p2p_reject_tag == "anchor_conflict" &&
                          !server.TestIsBlockRejected(candidate.block.GetHash()),
                      "durable fail-stop is exact non-penalizing anchor safety refusal");
            } else {
                Check(counters.p2p_add_calls == 1 &&
                          counters.p2p_durable_calls == 1 &&
                          counters.p2p_tip_advanced == 1 &&
                          counters.p2p_relay_calls == 1 &&
                          counters.p2p_penalty_calls == 0,
                      "ordinary inbound P2P sync remains functional while local gate closed");
            }
        }
    } else {
        Check(counters.inproc_journals == 1 &&
                  counters.inproc_signatures == 1 &&
                  counters.inproc_mempool == 1 &&
                  counters.inproc_gossip == 1 &&
                  counters.standalone_journals == 1 &&
                  counters.standalone_signatures == 1 &&
                  counters.standalone_mempool == 1 &&
                  counters.standalone_gossip == 1 &&
                  counters.finality_journals == 1 &&
                  counters.finality_signatures == 1 &&
                  counters.finality_gossip == 1 &&
                  counters.finality_sink_calls == 1 &&
                  counters.finality_active_calls == 1 &&
                  counters.finality_verify_result == static_cast<uint8_t>(
                      net::NodeServer::FinalityVoteVerifyResult::AcceptedNew) &&
                  counters.finality_assembler == 1 &&
                  counters.finality_node_gossip == 1,
              "all validator/finality paths open together exactly once");
    }

    AssertNoRetainedWork(node, expect_open);
    AssertNoRetainedWork(finality_node, false);
    std::cout << "F4_ROW_JSON {\"row\":\"" << JsonEscape(row)
              << "\",\"closed\":" << (closed ? "true" : "false")
              << ",\"checks\":" << checks
              << ",\"internal_mining_admitted\":" << counters.internal_mining_admitted
              << ",\"internal_hashes\":" << counters.internal_hashes
              << ",\"internal_progress\":" << counters.internal_progress
              << ",\"gbt_templates\":" << counters.gbt_templates
              << ",\"submit_add_calls\":" << counters.submit_add_calls
              << ",\"submit_durable_calls\":" << counters.submit_durable_calls
              << ",\"block_broadcasts\":" << counters.block_broadcasts
              << ",\"inproc_journals\":" << counters.inproc_journals
              << ",\"inproc_signatures\":" << counters.inproc_signatures
              << ",\"inproc_mempool\":" << counters.inproc_mempool
              << ",\"inproc_gossip\":" << counters.inproc_gossip
              << ",\"standalone_journals\":" << counters.standalone_journals
              << ",\"standalone_signatures\":" << counters.standalone_signatures
              << ",\"standalone_mempool\":" << counters.standalone_mempool
              << ",\"standalone_gossip\":" << counters.standalone_gossip
              << ",\"finality_journals\":" << counters.finality_journals
              << ",\"finality_signatures\":" << counters.finality_signatures
              << ",\"finality_gossip\":" << counters.finality_gossip
              << ",\"finality_sink_calls\":" << counters.finality_sink_calls
              << ",\"finality_active_calls\":" << counters.finality_active_calls
              << ",\"finality_verify_result\":" << counters.finality_verify_result
              << ",\"finality_assembler\":" << counters.finality_assembler
              << ",\"finality_node_gossip\":" << counters.finality_node_gossip
              << ",\"p2p_add_calls\":" << counters.p2p_add_calls
              << ",\"p2p_durable_calls\":" << counters.p2p_durable_calls
              << ",\"p2p_tip_advanced\":" << counters.p2p_tip_advanced
              << ",\"p2p_global_runtime_closed\":"
              << counters.p2p_global_runtime_closed
              << ",\"p2p_relay_calls\":" << counters.p2p_relay_calls
              << ",\"p2p_penalty_calls\":" << counters.p2p_penalty_calls
              << ",\"p2p_reject_tag\":\""
              << JsonEscape(counters.p2p_reject_tag) << "\""
              << ",\"p2p_disposition\":\""
              << (IsGlobalTerminalSafetyRow(row)
                      ? "terminal_global_safety_refusal"
                      : "advanced_local_gate_independent") << "\""
              << ",\"listener_lifecycle\":\""
              << (IsStartupListenerUnavailableRow(row)
                      ? "production_listener_not_open_until_startup_complete"
                      : "listener_operational") << "\""
              << ",\"cached_templates\":0,\"pending_tokens\":0,"
                 "\"active_leases\":0,\"pending_broadcasts\":0}"
              << std::endl;
#endif
}

void RunPublicTestnetExpiryRow(
        const std::filesystem::path& artifact_dir) {
#if !defined(VELD_PUBLIC_TESTNET)
    (void)artifact_dir;
    throw std::runtime_error("public-testnet row requires that profile");
#else
    RowCounters counters;
    const int64_t now = public_testnet::CurrentUnixTime();
    public_testnet::RuntimeLimits limits;
    std::string lease_error;
    Check(!public_testnet::CompiledRuntimeLimits(now, limits, &lease_error),
          "expired compiled public-testnet lease refuses startup authority");
    Check(now >= 1788112800,
          "wall clock is beyond immutable public-testnet expiry");

    const RealKeyPair miner = GenerateKeyPair(true);
    VeldNode node(MainnetConfig(), (artifact_dir / "publictest-node").string());
    node.TestWireDBForDurableCommit();
    InstallTrustedChain(node.GetChainMut(), node.GetMempoolMut(), miner, 1);
    node.TestInstallWorkAdmissionProcessServer();
    auto peers = InstallSafePeers(node, node.GetChain().Height(), 37301);
    (void)peers;
    node.TestConfigureWorkAdmissionProcess(ReadyState());
    node.TestResetWorkAdmissionProcessCounters();
    node.TestEnableWorkAdmissionMiningBarrier(true);
    const uint64_t hash_before = node.GetTotalHashes();
    node.StartMining(miner);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    node.StopMining();
    counters.internal_mining_admitted = node.TestWorkMiningAdmittedCalls();
    counters.internal_hashes = node.GetTotalHashes() - hash_before;
    Check(counters.internal_mining_admitted == 0 &&
              counters.internal_hashes == 0,
          "expired public-testnet emits no internal mining work");
    const std::string gbt = node.TestHandleWorkAdmissionRpc(
        RpcRequest("getblocktemplate", {miner.address}));
    Check(gbt.find("block_hex") == std::string::npos,
          "expired public-testnet emits no GBT template");
    auto candidate = MineOnly(node.GetChainMut(), node.GetMempoolMut(), miner);
    Check(candidate.success, "expired-profile submit candidate constructed");
    work_admission::Binding prior;
    prior.subject = *node.TestCurrentBlockProductionSubject();
    prior.subject.target_hash =
        candidate.block.header.GetTemplateWorkIdentity();
    prior.validation_generation = 1;
    prior.network_magic = MainnetConfig().magic;
    prior.genesis_hash = CompiledGenesisBytes();
    prior.profile_digest = Hash256d(std::string(DEPLOYMENT_PROFILE_ID));
    Blockchain::TestResetAddBlockDirectCalls();
    (void)node.TestHandleWorkAdmissionRpc(RpcRequest(
        "submitblock", {Hex(candidate.block.Serialize()),
                        work_admission::EncodeBinding(prior),
                        std::string(64, 'a')}));
    Check(Blockchain::TestAddBlockDirectCalls() == 0 &&
              node.TestWorkDurableWriterCalls() == 0,
          "expired public-testnet submit reaches no chain/durable sink");
    AssertNoRetainedWork(node, false);
    std::cout << "F4_ROW_JSON {\"row\":\"public_testnet_expiry\","
                 "\"closed\":true,\"checks\":" << checks
              << ",\"internal_mining_admitted\":0,\"internal_hashes\":0,"
                 "\"internal_progress\":0,\"gbt_templates\":0,"
                 "\"submit_add_calls\":0,\"submit_durable_calls\":0,"
                 "\"block_broadcasts\":0,\"inproc_journals\":0,"
                 "\"inproc_signatures\":0,\"inproc_mempool\":0,"
                 "\"inproc_gossip\":0,\"standalone_journals\":0,"
                 "\"standalone_signatures\":0,\"standalone_mempool\":0,"
                 "\"standalone_gossip\":0,\"finality_journals\":0,"
                 "\"finality_signatures\":0,\"finality_gossip\":0,"
                 "\"finality_sink_calls\":0,\"finality_active_calls\":0,"
                 "\"finality_verify_result\":255,"
                 "\"finality_assembler\":0,\"finality_node_gossip\":0,"
                 "\"p2p_add_calls\":0,\"p2p_durable_calls\":0,"
                 "\"p2p_tip_advanced\":0,\"cached_templates\":0,"
                 "\"pending_tokens\":0,\"active_leases\":0,"
                 "\"pending_broadcasts\":0}"
              << std::endl;
#endif
}

}  // namespace

int main(int argc, char** argv) {
    try {
        compat::InitNetwork();
        if (argc != 3)
            throw std::runtime_error("usage: fixture <row> <artifact-dir>");
        const std::string row = argv[1];
        const std::filesystem::path artifact_dir = argv[2];
        std::filesystem::create_directories(artifact_dir);
        if (row == "public_testnet_expiry")
            RunPublicTestnetExpiryRow(artifact_dir);
        else if (row == "race_submit_close_first" ||
                 row == "race_submit_acquired_first")
            RunSubmitRaceRow(row, artifact_dir);
        else if (row == "race_finality_close_first" ||
                 row == "race_finality_acquired_first")
            RunFinalityRaceRow(row, artifact_dir);
        else
            RunGenericRow(row, artifact_dir);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
