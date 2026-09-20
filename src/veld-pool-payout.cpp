// Private payout construction helper. The payment service must authorize the
// exact entitlement/input manifest and journal signed bytes before broadcasting.
// There is no raw signing, RPC, network, stake, or arbitrary-operation interface.
#include "crypto/veld_signing.h"
#include "core/script.h"
#include "network/strict_json.h"
#include "wallet/secure_channel_file.h"
#include <charconv>
#include <iostream>
#include <set>

#include "pool/signing_policy.h"
#include "pool/build_identity.h"
using namespace veld::pool_signing;

int main(int argc, char** argv) {
    using namespace veld;
    try {
        if(pool::PrintBuildIdentity(argc,argv,"pool-payout-signer",true))return 0;
        if (argc==2 && std::string(argv[1])=="--policy") {
            auto genesis=HexToBytes(GENESIS_HASH);std::reverse(genesis.begin(),genesis.end());
            std::cout << "{\"chain\":\"" << BytesToHex(genesis)
                      << "\",\"minimum_fee_units\":\"" << MIN_TX_FEE
                      << "\",\"dust_threshold_units\":\"" << DUST_THRESHOLD_UNITS << "\"}\n";
            return 0;
        }
        Require(argc == 3, "requires private pool and operator-fee seed paths");
        // Bounded framing before any key access.
        std::array<char, 65538> frame{};
        Require(bool(std::cin.getline(frame.data(),frame.size())), "bounded request frame");
        Json intent;std::string error;
        Require(btc_buy::StrictJsonParser(frame.data(),65536,true).Parse(intent,error), "request JSON");
        Fields(intent,{"chain","pool_script","fee_script","inputs","recipients","fee_units"});
        auto genesis=HexToBytes(GENESIS_HASH);std::reverse(genesis.begin(),genesis.end());
        Require(Text(*intent.Get("chain")) == BytesToHex(genesis), "wrong chain");
        const auto& inputs=*intent.Get("inputs");const auto& recipients=*intent.Get("recipients");
        Require(inputs.kind==Json::Kind::Array && inputs.array.size()>=2 && inputs.array.size()<=64, "input bound");
        Require(recipients.kind==Json::Kind::Array && !recipients.array.empty() && recipients.array.size()<=128, "recipient bound");
        const uint64_t fee=Amount(*intent.Get("fee_units"));
        Require(fee==MIN_TX_FEE, "fixed candidate network fee");
        const auto pool=Key(argv[1]), fees=Key(argv[2]);
        const auto pool_script=pool.GetP2PKHScript(), fee_script=fees.GetP2PKHScript();
        Require(pool_script!=fee_script, "fee funds require a distinct key");
        Require(Text(*intent.Get("pool_script"))==BytesToHex(pool_script) &&
                Text(*intent.Get("fee_script"))==BytesToHex(fee_script), "key identity mismatch");
        Transaction tx;
        uint64_t pool_in=0, fee_in=0, paid=0;
        std::vector<bool> fee_input;
        std::set<std::pair<std::string,uint32_t>> used;
        for (const auto& input:inputs.array) {
            Fields(input,{"txid","vout","units","role"});
            const auto txid=Text(*input.Get("txid"));
            Require(txid.size()==64 && txid.find_first_not_of("0123456789abcdef")==std::string::npos, "txid encoding");
            const auto index=static_cast<uint32_t>(Amount(*input.Get("vout"),UINT32_MAX-1));
            const auto amount=Amount(*input.Get("units"));
            Require(amount>0 && used.emplace(txid,index).second, "duplicate or empty funding");
            const auto role=Text(*input.Get("role"));
            Require(role=="pool" || role=="fees", "funding role");
            if (role=="fees") fee_in=Add(fee_in,amount);else pool_in=Add(pool_in,amount);
            fee_input.push_back(role=="fees");
            TxInput in;in.prev_tx_hash=HexToHash(txid);in.prev_out_index=index;tx.inputs.push_back(in);
        }
        std::set<std::string> destinations;
        for (const auto& recipient:recipients.array) {
            Fields(recipient,{"address","units"});
            const auto address=Text(*recipient.Get("address"));
            const auto script=AddressToScript(address);
            const auto amount=Amount(*recipient.Get("units"));
            Require((script.size()==25 || IsSha384KeyScript(script)) && script!=pool_script && script!=fee_script &&
                    destinations.insert(address).second && amount>0, "recipient policy");
            paid=Add(paid,amount);tx.outputs.emplace_back(amount,script);
        }
        Require(pool_in>=paid && fee_in>=fee, "separate funding insufficient");
        if (pool_in>paid) tx.outputs.emplace_back(pool_in-paid,pool_script);
        if (fee_in>fee) tx.outputs.emplace_back(fee_in-fee,fee_script);
        Require(!tx.HasDustOutput(DUST_THRESHOLD_UNITS), "payout or change below native dust limit");
        // All signatures bind the same complete unsigned transaction.
        std::vector<std::vector<uint8_t>> signatures;
        for (size_t i=0;i<tx.inputs.size();++i) {
            const auto& key=fee_input[i]?fees:pool;
            signatures.push_back(key.SignInput(tx,static_cast<uint32_t>(i),key.GetP2PKHScript()).script_sig);
        }
        for (size_t i=0;i<signatures.size();++i) tx.inputs[i].script_sig=std::move(signatures[i]);
        tx.InvalidateTxIDCache();
        for (size_t i=0;i<tx.inputs.size();++i) {
            ScriptInterpreter verifier;
            Require(verifier.Execute(tx.inputs[i].script_sig,fee_input[i]?fee_script:pool_script,
                                     tx,static_cast<uint32_t>(i)), "signature self verification");
        }
        const auto bytes=tx.Serialize();
        Require(bytes.size()<=1024*1024 && tx.IsValid(), "signed transaction bounds");
        std::cout << HashToHex(tx.GetTxID()) << ' ' << BytesToHex(bytes) << '\n';
    } catch (const std::exception& error) {
        std::cerr << "payout refused: " << error.what() << '\n';return 1;
    }
}
