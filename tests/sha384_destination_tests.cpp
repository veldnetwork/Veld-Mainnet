#include "core/blockchain.h"
#include "wallet/wallet.h"
#include "wallet/cli.h"
#include <iostream>
#include <stdexcept>

int main() {
    using namespace veld;
    unsigned checks = 0;
    auto require = [&](bool value) { ++checks; if (!value) throw std::runtime_error("SHA-384 destination assertion " + std::to_string(checks)); };
    require(SHA384_DESTINATION_ACTIVATION_HEIGHT == 9500);
    require(!Sha384DestinationsActive(8999) && !Sha384DestinationsActive(9000) && !Sha384DestinationsActive(9001));
    require(!Sha384DestinationsActive(9499) && Sha384DestinationsActive(9500) && Sha384DestinationsActive(9501));
    Secp256k1PubKey vector_key{};
    for (size_t i=0;i<vector_key.size();++i) vector_key[i]=static_cast<uint8_t>(i);
    // Independent Python hashlib oracle: exact fixed domain, NUL, network=0,
    // compiled genesis ASCII, uint32 little-endian 1952 and bytes(i mod 256).
    const auto vector_digest=PublicKeyCommitment384(vector_key);
    require(BytesToHex(vector_digest.data(),vector_digest.size())=="4e3a555217be2451fc322b97489f6c0ae5a37047b0f0dadb88d1efc7330893e529973bee308ee97b54988dc108864a1d");
    auto key = GenerateKeyPair();
    const auto legacy = key.GetP2PKHScript();
    const auto legacy_address = key.address;
    const auto digest = PublicKeyCommitment384(key.public_key);
    const auto script = BuildSha384KeyScript(digest);
    const auto address = PubKeyToSha384Address(key.public_key);
    require(script.size() == 51 && digest.size() == 48);
    require(address != legacy_address && IsValidVeldAddress(address));
    require(AddressToScript(address) == script && ScriptToAddress(script) == address);
    require(PublicKeyOwnsAddress(key.public_key, legacy_address) && PublicKeyOwnsAddress(key.public_key, address));
    require(PublicKeyCommitment384(key.public_key, true) != digest);
    require(!IsValidVeldAddress(address, true));
    Transaction tx;
    TxInput input; input.prev_tx_hash[0] = 17; input.prev_out_index = 2; tx.inputs.push_back(input);
    tx.outputs.emplace_back(100000000, legacy);
    tx.inputs[0].script_sig = BuildScriptSig(key.private_key,key.public_key,tx,0,script).script_sig;
    ScriptInterpreter interpreter;
    for (uint64_t height : {9499,9500,9501,9499,9500}) {
        ScriptContext context; context.block_height = height;
        require(interpreter.Execute(tx.inputs[0].script_sig,script,tx,0,context) == (height >= 9500));
        require(Blockchain::VerifyInputAgainstScript(tx,0,script,height) == (height >= 9500));
        require(IsCanonicalKeyScriptAtHeight(script,height) == (height >= 9500));
    }
    ScriptContext active; active.block_height = 9500;
    require(!interpreter.Execute(tx.inputs[0].script_sig,script,tx,0));
    for (size_t i = 3; i < script.size(); ++i) {
        auto altered = script; altered[i] ^= 1;
        require(!interpreter.Execute(tx.inputs[0].script_sig,altered,tx,0,active));
    }
    auto wrong_key=key.public_key; wrong_key.back() ^= 1;
    require(!MatchesSha384Key(script,wrong_key));
    for (size_t length : {0u,1u,2u,3u,23u,25u,50u,52u}) {
        auto bad=script;bad.resize(length);
        require(!IsSha384KeyScript(bad));
        // Empty scripts have separate historical semantics; they do not
        // identify the versioned destination opcode and are not changed here.
        if (!bad.empty()) require(!interpreter.Execute(tx.inputs[0].script_sig,bad,tx,0,active));
    }
    for (uint8_t version : {0,2,255}) {
        auto bad=script;bad[1]=version;
        require(!interpreter.Execute(tx.inputs[0].script_sig,bad,tx,0,active));
        require(ScriptToAddress(bad).empty());
    }
    auto changed = tx; changed.outputs[0].value++;
    require(!Blockchain::VerifyInputAgainstScript(changed,0,script,9500));
    changed=tx;changed.inputs[0].script_sig.push_back(0);
    require(!Blockchain::VerifyInputAgainstScript(changed,0,script,9500));
    changed=tx;changed.inputs[0].script_sig[4]^=1;
    require(!Blockchain::VerifyInputAgainstScript(changed,0,script,9500));
    require(!Blockchain::VerifyInputAgainstScript(tx,1,script,9500));
    tx.inputs[0].script_sig=BuildScriptSig(key.private_key,key.public_key,tx,0,legacy).script_sig;
    for (uint64_t height : {9499,9500,9501}) require(Blockchain::VerifyInputAgainstScript(tx,0,legacy,height));
    require(AddressToScript(legacy_address)==legacy && ScriptToAddress(legacy)==legacy_address);
    key.address=address;require(key.GetP2PKHScript()==script);
    auto recovered=key;require(recovered.GetP2PKHScript()==script);
    auto moved=std::move(recovered);require(moved.GetP2PKHScript()==script);
    cli::WalletFile file;file.keys.push_back(key);
    auto plaintext=file.Serialize();
    auto loaded=cli::WalletFile::ParsePlaintext(plaintext);
    require(loaded.has_value()&&loaded->keys.size()==1&&loaded->keys[0].address==address&&loaded->keys[0].GetP2PKHScript()==script);
    auto other=GenerateKeyPair();
    auto substituted=plaintext;substituted.replace(substituted.find(address),address.size(),Sha384KeyAddress(other.public_key));
    require(!cli::WalletFile::ParsePlaintext(substituted));
    auto encrypted=wallet_crypto::EncryptWallet(plaintext,"disposable SHA384 boundary test passphrase");
    auto decrypted=wallet_crypto::DecryptWallet(encrypted,"disposable SHA384 boundary test passphrase");
    loaded=cli::WalletFile::ParsePlaintext(decrypted);
    require(loaded.has_value()&&loaded->keys[0].address==address);
    WipeString(plaintext);WipeString(substituted);WipeString(decrypted);
    std::cout << "PASS " << checks << " native SHA-384 destination and real ML-DSA-65 boundary assertions\n";
}
