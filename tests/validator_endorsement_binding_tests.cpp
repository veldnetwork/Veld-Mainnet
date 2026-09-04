#include "network/rpc.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

using namespace veld;

namespace {

size_t checks = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition) {
        std::cerr << "FAIL: " << label << "\n";
        std::exit(1);
    }
}

Hash256 Filled(uint8_t value) {
    Hash256 hash{};
    hash.fill(value);
    return hash;
}

Transaction EndorsementTx(const std::string& payload) {
    Transaction tx;
    TxInput input;
    input.prev_tx_hash = Filled(0x44);
    input.prev_out_index = 3;
    input.script_sig = {0x01};
    tx.inputs.push_back(input);
    tx.outputs.emplace_back(0, BuildOpReturnScript(payload));
    return tx;
}

std::string Request(const Transaction& tx, const std::optional<std::string>& binding,
                    const std::optional<std::string>& token = std::nullopt) {
    std::string json = "{\"jsonrpc\":\"2.0\",\"method\":\"sendrawtransaction\","
                       "\"params\":[\"" +
                       BytesToHex(tx.Serialize()) + "\"";
    if (binding)
        json += ",\"" + *binding + "\"";
    if (token)
        json += ",\"" + *token + "\"";
    return json + "],\"id\":1}";
}

std::string MakeRpcRequest(const std::string& method, const std::vector<std::string>& params) {
    std::string json = "{\"jsonrpc\":\"2.0\",\"method\":\"" + method + "\",\"params\":[";
    for (size_t i = 0; i < params.size(); ++i) {
        if (i)
            json += ',';
        json += "\"" + params[i] + "\"";
    }
    return json + "],\"id\":2}";
}

} // namespace

int main() {
    const std::string hash_text(64, '2');
    const std::string signature_text(128, '3');
    const std::string payload = "VELD_VALIDATOR|ENDORSE|7|" + hash_text + "|" + signature_text;
    const Transaction canonical = EndorsementTx(payload);

    std::optional<rpc_detail::ValidatorEndorsementTarget> target;
    Check(rpc_detail::ExtractValidatorEndorsementTarget(canonical, target) && target &&
              target->height == 7 && HashToHex(target->hash) == hash_text,
          "canonical endorsement target extracted");

    Transaction ordinary = canonical;
    ordinary.outputs[0].script_pubkey = BuildOpReturnScript("ordinary metadata");
    target.reset();
    Check(rpc_detail::ExtractValidatorEndorsementTarget(ordinary, target) && !target,
          "ordinary transaction remains unbound");

    Transaction leading_zero =
        EndorsementTx("VELD_VALIDATOR|ENDORSE|07|" + hash_text + "|" + signature_text);
    Check(!rpc_detail::ExtractValidatorEndorsementTarget(leading_zero, target),
          "noncanonical height rejected");

    Transaction uppercase_hash =
        EndorsementTx("VELD_VALIDATOR|ENDORSE|7|" + std::string(64, 'A') + "|" + signature_text);
    Check(!rpc_detail::ExtractValidatorEndorsementTarget(uppercase_hash, target),
          "uppercase target hash rejected");

    Transaction duplicate = canonical;
    duplicate.outputs.push_back(canonical.outputs.front());
    Check(!rpc_detail::ExtractValidatorEndorsementTarget(duplicate, target),
          "multiple endorsement markers rejected");

    Transaction valued = canonical;
    valued.outputs.front().value = 1;
    Check(!rpc_detail::ExtractValidatorEndorsementTarget(valued, target),
          "valued endorsement marker rejected");

    Transaction noncanonical_push = canonical;
    const std::vector<uint8_t> payload_bytes(payload.begin(), payload.end());
    noncanonical_push.outputs.front().script_pubkey.clear();
    noncanonical_push.outputs.front().script_pubkey.push_back(0x6a);
    noncanonical_push.outputs.front().script_pubkey.push_back(0x4d);
    noncanonical_push.outputs.front().script_pubkey.push_back(
        static_cast<uint8_t>(payload_bytes.size()));
    noncanonical_push.outputs.front().script_pubkey.push_back(0);
    noncanonical_push.outputs.front().script_pubkey.insert(
        noncanonical_push.outputs.front().script_pubkey.end(), payload_bytes.begin(),
        payload_bytes.end());
    Check(!rpc_detail::ExtractValidatorEndorsementTarget(noncanonical_push, target),
          "nonminimal endorsement push rejected");

    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const std::filesystem::path storage_path = std::filesystem::temp_directory_path() /
                                               ("veld-security-test-endorsement-binding-" + suffix);
    {
        Blockchain chain;
        Check(chain.AddBlockDirect(CreateGenesisBlock(), true, true, false,
                                   mining::PowAdmissionContext::Internal()),
              "fixture genesis installed");
        Mempool mempool;
        StorageEngine storage(storage_path.string(), MAINNET_MAGIC);
        RpcServer rpc(chain, mempool, storage);

        const std::string missing = rpc.Handle(Request(canonical, std::nullopt));
        Check(missing.find("requires its work binding") != std::string::npos && mempool.IsEmpty(),
              "missing binding refused before mempool admission");

        work_admission::Binding binding;
        binding.subject.purpose = work_admission::Purpose::ValidatorEndorsement;
        binding.subject.height = 7;
        binding.subject.target_hash = HexToHash(hash_text);
        binding.subject.parent_height = 0;
        binding.subject.parent_hash = CreateGenesisBlock().GetHash();
        binding.validation_generation = 1;
        binding.network_magic = MAINNET_MAGIC;
        binding.genesis_hash = Filled(0x55);
        binding.profile_digest = Filled(0x66);
        const std::string encoded = work_admission::EncodeBinding(binding);

        const std::string token(64, 'a');
        const std::string unwired = rpc.Handle(Request(canonical, encoded, token));
        Check(unwired.find("work admission refused") != std::string::npos && mempool.IsEmpty(),
              "unwired endorsement sink fails closed");

        size_t closed_calls = 0;
        rpc.SetWorkAdmissionFn(
            [&](work_admission::Path path, const work_admission::Subject& subject,
                const std::optional<work_admission::Binding>& prior, bool require_prior) {
                ++closed_calls;
                Check(path == work_admission::Path::ValidatorEndorsement && subject.height == 7 &&
                          subject.target_hash == HexToHash(hash_text) && prior &&
                          *prior == binding && require_prior,
                      "sink passes exact subject and prior binding");
                return work_admission::Decision{false, work_admission::Refusal::RuntimeClosed,
                                                std::nullopt};
            });
        const std::string closed = rpc.Handle(Request(canonical, encoded, token));
        Check(closed_calls == 1 && closed.find("work admission refused") != std::string::npos &&
                  mempool.IsEmpty(),
              "closed predicate emits no cached artifact");

        const std::string ordinary_extra = rpc.Handle(Request(ordinary, encoded, token));
        Check(ordinary_extra.find("Usage: sendrawtransaction") != std::string::npos,
              "ordinary transaction cannot smuggle a work binding");

        const std::string begin_unwired = rpc.Handle(
            MakeRpcRequest("beginworksigning", {"validator_endorsement", encoded, token}));
        Check(begin_unwired.find("activation unavailable") != std::string::npos,
              "remote signing start fails closed when unwired");

        size_t begin_calls = 0;
        rpc.SetBeginRemoteSigningFn([&](work_admission::Path path, const std::string& got_binding,
                                        const std::string& got_token) {
            ++begin_calls;
            Check(path == work_admission::Path::ValidatorEndorsement && got_binding == encoded &&
                      got_token == token,
                  "remote signing start preserves exact capability");
            RpcServer::RemoteSigningActivationResult result;
            result.started = begin_calls == 1;
            result.ttl_ms = result.started ? 7000 : 0;
            result.reason = result.started ? "" : "token_consumed";
            return result;
        });
        const std::string begun = rpc.Handle(
            MakeRpcRequest("beginworksigning", {"validator_endorsement", encoded, token}));
        Check(begun.find("\"started\":true") != std::string::npos &&
                  begun.find("\"ttl_ms\":7000") != std::string::npos,
              "pending grant activates before remote signing");
        const std::string replay = rpc.Handle(
            MakeRpcRequest("beginworksigning", {"validator_endorsement", encoded, token}));
        Check(begin_calls == 2 && replay.find("token_consumed") != std::string::npos,
              "remote sign-start replay fails closed");

        size_t cancel_calls = 0;
        rpc.SetCancelRemoteSigningFn([&](const std::string& got_token) {
            ++cancel_calls;
            return got_token == token;
        });
        const std::string cancelled = rpc.Handle(MakeRpcRequest("cancelworksigning", {token}));
        Check(cancel_calls == 1 && cancelled.find("\"released\":true") != std::string::npos,
              "remote exception cancellation reaches authoritative sink");
    }
    std::error_code cleanup_error;
    std::filesystem::remove_all(storage_path, cleanup_error);
    Check(!cleanup_error && !std::filesystem::exists(storage_path), "fixture storage removed");

    std::cout << "PASS validator_endorsement_binding_tests checks=" << checks << "\n";
    return 0;
}
