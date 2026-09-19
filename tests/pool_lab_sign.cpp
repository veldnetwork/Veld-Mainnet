// Disposable qualification keys only. This deliberately permits adversarial
// transaction fixtures and MUST NOT be installed as a pool signer.
#if !defined(VELD_TEST_CHAIN_BUILD) || !defined(VELD_TEST_HOOKS) || defined(VELD_PUBLIC_RELEASE)
#error "pool lab signer is forbidden outside the isolated qualification profile"
#endif
#include "pool/signing_policy.h"
#include "consensus/validators.h"
#include "consensus/finality_codec.h"
#include <iostream>

int main(int argc,char** argv) {
    using namespace veld;
    using namespace veld::pool_signing;
    try {
        Require(argc==3,"protected disposable seed and operation required");
        auto key=Key(argv[1]);
        key.address=ScriptToAddress(key.GetP2PKHScript());
        const std::string action=argv[2];
        if(action=="identity") {
            std::cout<<key.address<<' '<<BytesToHex(key.public_key.data(),key.public_key.size())<<' '<<BytesToHex(key.GetP2PKHScript())<<'\n';
            return 0;
        }
        std::vector<char> frame(2*1024*1024+2);
        Require(bool(std::cin.getline(frame.data(),frame.size())),"bounded lab request");
        Json request;std::string error;
        Require(btc_buy::StrictJsonParser(frame.data(),2*1024*1024,true).Parse(request,error),"lab request JSON");
        if(action=="endorse") {
            Fields(request,{"height","block"});
            const auto height=Amount(*request.Get("height"),UINT64_MAX-1);
            const auto hash=Text(*request.Get("block"));
            Require(hash.size()==64 && hash.find_first_not_of("0123456789abcdef")==std::string::npos,"block hash");
            const auto message=ValidatorRegistry::BuildEndorseMessage(height,HexToHash(hash));
            const auto signature=Sign(key.private_key,message);
            std::cout<<ValidatorRegistry::BuildEndorseOp(height,hash,BytesToHex(signature),key.address,height+1)<<'\n';
            return 0;
        }
        if(action=="finality") {
            namespace fq=veld::finality::qc;
            Fields(request,{"epoch","set_root","phase","target_height","target_hash","source_height","source_hash"});
            auto hash=[&](const char* field) {
                const auto value=Text(*request.Get(field));
                Require(value.size()==64 && value.find_first_not_of("0123456789abcdef")==std::string::npos,"canonical finality hash");
                return HexToHash(value);
            };
            fq::SignedVote vote;
            vote.epoch_id=Amount(*request.Get("epoch"),UINT64_MAX-1);
            vote.set_root=hash("set_root");
            const auto phase=Amount(*request.Get("phase"),2);Require(phase>=1,"finality phase");
            vote.phase=static_cast<fq::Phase>(phase);
            vote.target={Amount(*request.Get("target_height"),UINT64_MAX-1),hash("target_hash")};
            vote.source={Amount(*request.Get("source_height"),UINT64_MAX-1),hash("source_hash")};
            vote.round=fq::CheckpointRound(vote.target.height);
            Require(fq::IsScheduledCheckpoint(vote.target.height) && fq::EpochOf(vote.target.height)==vote.epoch_id &&
                    fq::SourceRefWellFormed(vote.source,vote.target),"finality checkpoint context");
            vote.pubkey_hex=BytesToHex(key.public_key.data(),key.public_key.size());
            const auto genesis_bytes=HexToBytes(GENESIS_HASH);Hash256 genesis{};
            Require(genesis_bytes.size()==genesis.size(),"compiled genesis");
            std::copy(genesis_bytes.begin(),genesis_bytes.end(),genesis.begin());
            dilithium::SecretKey secret{};
            struct Wipe { dilithium::SecretKey& value; ~Wipe(){compat::SecureZero(value.data(),value.size());} } wipe{secret};
            dilithium::PublicKey derived{};
            Require(veld_mldsa65_keypair_from_seed(key.private_key.data(),derived.data(),secret.data())==0 &&
                    derived==key.public_key,"disposable seed expansion");
            vote.signature=dilithium::Sign(secret,fq::VotePreimage(fq::NETWORK_ID,genesis,vote.epoch_id,vote.set_root,
                vote.phase,vote.round,vote.source,vote.target));
            const auto wire=fq::EncodeSignedVoteWire(vote);Require(!wire.empty(),"canonical finality wire");
            std::cout<<BytesToHex(wire)<<'\n';return 0;
        }
        Require(action=="transaction","lab operation");
        Fields(request,{"unsigned_tx_hex","bond_units","reduce_change_units"});
        const auto encoded=Text(*request.Get("unsigned_tx_hex"));
        Require(encoded.size()%2==0 && encoded.find_first_not_of("0123456789abcdef")==std::string::npos,"transaction encoding");
        const auto unsigned_bytes=HexToBytes(encoded);Transaction tx;
        Require(Transaction::Deserialize(unsigned_bytes,0,tx)==unsigned_bytes.size(),"native transaction decoding");
        Require(!tx.inputs.empty() && tx.inputs.size()<=128,"qualification input bound");
        const auto bond=Text(*request.Get("bond_units"));
        if(!bond.empty()) {
            const auto amount=Amount(*request.Get("bond_units"));
            Require(tx.outputs.size()==3 && tx.outputs[0].script_pubkey==AddressToScript(STAKE_VAULT_ADDRESS) &&
                    tx.outputs[1].script_pubkey==key.GetP2PKHScript() && amount<=tx.outputs[0].value,"adversarial bond fixture shape");
            tx.outputs[1].value+=tx.outputs[0].value-amount;tx.outputs[0].value=amount;
        }
        const auto reduce=Amount(*request.Get("reduce_change_units"));
        if(reduce) {
            Require(tx.outputs.size()==3 && tx.outputs[1].script_pubkey==key.GetP2PKHScript() &&
                    tx.outputs[1].value>reduce,"adversarial spent-input fixture shape");
            tx.outputs[1].value-=reduce;
        }
        std::vector<std::vector<uint8_t>> signatures;
        for(uint32_t i=0;i<tx.inputs.size();++i)signatures.push_back(key.SignInput(tx,i,key.GetP2PKHScript()).script_sig);
        for(size_t i=0;i<signatures.size();++i)tx.inputs[i].script_sig=std::move(signatures[i]);
        tx.InvalidateTxIDCache();
        const auto raw=tx.Serialize();Require(raw.size()<=1024*1024,"native transaction size bound");
        std::cout<<HashToHex(tx.GetTxID())<<' '<<BytesToHex(raw)<<'\n';
    } catch(const std::exception& error) {
        std::cerr<<"disposable qualification signer refused: "<<error.what()<<'\n';return 1;
    }
}
