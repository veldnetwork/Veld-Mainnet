#ifdef VELD_FIRST_ACTIVATION_NETWORK
#include "security_first_activation_profile.h"
#else
#include "security_state_migration_profile.h"
#endif
#include "node/node.h"
#include "network/rpc_http.h"
#include "network/public_testnet_json.h"
#include "compat/endorse_guard.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

using namespace veld;
using Value = public_testnet::runtime_json::Value;
namespace {
Value Json(const std::string& text) {
    Value out; std::string error;
    public_testnet::runtime_json::Parser parser(text, 4 * 1024 * 1024);
    if (!parser.Parse(out,error)) throw std::runtime_error("test JSON: "+error);
    return out;
}
const Value& Field(const Value& value,const std::string& name) {
    const auto* out=value.Get(name);
    if(!out) throw std::runtime_error("test missing field: "+name);
    return *out;
}
uint64_t Number(const Value& value) {
    uint64_t out=0;
    if(!ParseCanonicalUint64Text(value.text,out)) throw std::runtime_error("test integer");
    return out;
}
std::string Call(VeldNode& node,const std::string& method,const std::vector<std::string>& params={}) {
    std::vector<std::string> args;
    for(const auto& value:params) args.push_back(JsonBuilder::String(value));
    const std::string wire=JsonBuilder::Object({
        {"jsonrpc",JsonBuilder::String("2.0")},
        {"method",JsonBuilder::String(method)},
        {"params",JsonBuilder::Array(args)},{"id","1"}});
    const std::string response=node.GetRPC().Handle(wire);
    const auto parsed=Json(response);
    if(parsed.Get("error") && parsed.Get("error")->kind != Value::Kind::Null)
        throw std::runtime_error("test RPC "+method+": "+response);
    return response;
}
Value Result(VeldNode& node,const std::string& method,const std::vector<std::string>& params={}) {
    return Field(Json(Call(node,method,params)),"result");
}
std::string SignAndSend(VeldNode& node,const RealKeyPair& key,const std::string& method,const std::vector<std::string>& params,
                        const std::vector<std::string>& submission_fields={}) {
    const auto prepared=Result(node,method,params);
    const auto raw=HexToBytes(Field(prepared,"unsigned_tx_hex").text);
    Transaction tx;
    if(Transaction::Deserialize(raw,0,tx)!=raw.size() || tx.Serialize()!=raw)
        throw std::runtime_error("noncanonical prepared transaction");
    const auto own=key.GetP2PKHScript();
    std::vector<std::vector<uint8_t>> signatures;
    for(uint32_t i=0;i<tx.inputs.size();++i) {
        const auto prev=node.GetChain().GetUTXO(tx.inputs[i].prev_tx_hash,tx.inputs[i].prev_out_index);
#ifdef VELD_FIRST_ACTIVATION_NETWORK
        const auto pool=node.GetAmm().GetPool("VELD:btcVELD");
        const bool pool_method=method=="prepareammadd" || method=="prepareammswap" || method=="prepareammremove";
        if(pool_method && i==0 && prev && pool.utxo_valid &&
           tx.inputs[i].prev_tx_hash==pool.pool_txid && tx.inputs[i].prev_out_index==pool.pool_vout &&
           prev->script_pubkey==PoolVeldScript("VELD:btcVELD")) {
            signatures.push_back({});
            continue;
        }
#endif
        if(!prev || prev->script_pubkey!=own)
            throw std::runtime_error("prepared input is not disposable wallet's");
        signatures.push_back(BuildScriptSig(key.private_key,key.public_key,tx,i,own).script_sig);
    }
    for(size_t i=0;i<signatures.size();++i) tx.inputs[i].script_sig=signatures[i];
    tx.InvalidateTxIDCache();
    std::vector<std::string> submission{BytesToHex(tx.Serialize())};
    submission.insert(submission.end(),submission_fields.begin(),submission_fields.end());
    return Call(node,"sendrawtransaction",submission);
}
std::string Digest(VeldNode& node) {
    return HashToHex(node.ConsensusStateDigest());
}
}
#ifdef VELD_FIRST_ACTIVATION_NETWORK
#include "security_first_activation_support.h"
#endif
int main(int argc,char** argv) {
    try {
        compat::InitNetwork();
        if(argc!=4) throw std::runtime_error("use DATA_DIR P2P_PORT RPC_PORT");
        const auto directory=std::filesystem::absolute(argv[1]);
        std::string error;
        if(!channel::secure_file::EnsurePrivateDirectory(directory.string(),&error))
            throw std::runtime_error("test directory: "+error);
        const uint16_t p2p=uint16_t(std::stoul(argv[2])), rpc_port=uint16_t(std::stoul(argv[3]));
        if(p2p<20000 || rpc_port<20000 || p2p==rpc_port) throw std::runtime_error("test ports");
        NetworkConfig config=RegtestConfig(); config.port=p2p; config.rpc_port=rpc_port;
        VeldNode node(config,directory.string()); node.SetQuietBoot(true); node.SetP2PPort(p2p);
        node.Start();
        std::vector<RealKeyPair> wallets;
#ifdef VELD_FIRST_ACTIVATION_NETWORK
#ifdef VELD_RELEASE_INTEGRATION_NETWORK
        constexpr size_t wallet_count=11;
#else
        constexpr size_t wallet_count=8;
#endif
#else
        constexpr size_t wallet_count=6;
#endif
        for(size_t i=0;i<wallet_count;++i) {
#ifdef VELD_FIRST_ACTIVATION_NETWORK
            const auto seed_path=directory.parent_path()/"disposable-identities"/("wallet-"+std::to_string(i)+".seed");
            if(std::filesystem::file_size(seed_path)!=32) throw std::runtime_error("disposable wallet seed length");
            RealKeyPair wallet;
            std::ifstream seed(seed_path,std::ios::binary);
            seed.read(reinterpret_cast<char*>(wallet.private_key.data()),32);
            if(!seed) throw std::runtime_error("disposable wallet unavailable");
            wallet.public_key=DerivePublicKey(wallet.private_key);
            wallet.address=PubKeyToAddress(wallet.public_key,false);
            if(i==0 && wallet.address!=BTCVELD_ISSUER_ADDRESS) throw std::runtime_error("disposable launch authority mismatch");
            wallets.push_back(std::move(wallet));
#else
            wallets.push_back(GenerateKeyPair(false));
#endif
        }
#ifdef VELD_FIRST_ACTIVATION_NETWORK
        FirstActivationSupport first_activation(node,wallets,directory);
#endif
        RealKeyPair miner;
        miner.private_key=wallets[0].private_key; miner.public_key=wallets[0].public_key;
        miner.testnet=true; miner.address=PubKeyToAddress(miner.public_key,true);
        // Regtest transport uses the test-network miner identity. The compiled
        // consensus modules keep their own canonical address spelling; both
        // encodings resolve to this same disposable P2PKH script.
        if(miner.GetP2PKHScript()!=wallets[0].GetP2PKHScript())
            throw std::runtime_error("test miner payout script mismatch");
        if(!node.BindGenerationIdentity(miner,&error)) throw std::runtime_error("test miner: "+error);
        EndorseAntiEquivGuard endorsement_journal;
        endorsement_journal.load((directory/"test-endorsements.dat").string());
        std::array<uint8_t,32> token_bytes{};
        if(!compat::SecureRandom(token_bytes.data(),token_bytes.size())) throw std::runtime_error("test randomness");
        const std::string token=BytesToHex(token_bytes);
        const auto token_path=directory/"test-rpc-token";
        if(!channel::secure_file::AtomicWriteText(token_path.string(),token,&error,true))
            throw std::runtime_error("test RPC token file");
        RpcHttpServer http(node.GetRPC(),rpc_port,"",token);
        if(!http.Start()) throw std::runtime_error("test RPC listener unavailable");
        std::vector<std::string> addresses;
        for(const auto& w:wallets) addresses.push_back(JsonBuilder::String(w.address));
        std::cout<<"TEST_READY "<<JsonBuilder::Object({
            {"height",JsonBuilder::Number(node.GetChain().Height())},
            {"digest",JsonBuilder::String(Digest(node))},
            {"addresses",JsonBuilder::Array(addresses)},
            {"explorer_port",JsonBuilder::Number(uint64_t(node.TestLocalExplorerPort()))}
        })<<std::endl;
        std::string line;
        while(std::getline(std::cin,line)) {
            try {
                const Value command=Json(line);
                const std::string op=Field(command,"command").text;
                if(op=="stop") break;
                const auto* id_field=command.Get("wallet");
                const size_t index=id_field?size_t(Number(*id_field)):0;
                if(index>=wallets.size()) throw std::runtime_error("test wallet index");
                const auto& key=wallets[index];
                std::string response;
#ifdef VELD_FIRST_ACTIVATION_NETWORK
                if(op.rfind("fa_",0)==0) response=first_activation.Handle(op,command);
                else
#endif
                if(op=="status") {
                    const auto peer_view=node.GetPeerHeightView();
                    const auto tip=node.GetChain().TipCopy();
                    work_admission::Subject subject;
                    subject.purpose=work_admission::Purpose::BlockProduction;
                    subject.height=tip.height+1; subject.parent_height=tip.height;
                    subject.parent_hash=tip.GetHash();
                    const auto admission=node.EvaluateWorkAdmission(work_admission::Path::SynchronousGeneration,subject);
                    response=JsonBuilder::Object({
                        {"height",JsonBuilder::Number(node.GetChain().Height())},
                        {"digest",JsonBuilder::String(Digest(node))},
                        {"tip",JsonBuilder::String(HashToHex(node.GetChain().TipCopy().GetHash()))},
                        {"active_validators",JsonBuilder::Number(uint64_t(node.GetValidators().GetActiveValidatorCount()))},
                        {"ready_peer_ips",JsonBuilder::Number(uint64_t(peer_view.distinct_version_ips))},
                        {"admission",JsonBuilder::String(work_admission::RefusalName(admission.refusal))},
                        {"admission_allowed",JsonBuilder::Bool(admission.allowed)},
                        {"admission_generation",JsonBuilder::Number(admission.binding?admission.binding->validation_generation:0)}});
                } else if(op=="synchronize") {
                    const auto peer_view=node.GetPeerHeightView();
                    const bool at_tip=IsInitialDownloadAtTip(true,node.GetChain().Height(),node.GetChain().IsEmpty(),
                        peer_view.distinct_version_ips,peer_view.verified_height,
                        peer_view.distinct_outbound_sync_ips,peer_view.outbound_sync_height);
                    if(!at_tip || !node.ChainFullyValidated()) throw std::runtime_error("test chain has not synchronized");
                    node.SetIBDComplete(true); node.SyncTCPIBDFlag();
                    if(!node.IsIBDComplete()) throw std::runtime_error("node refused synchronized state");
                    response="{\"synchronized\":true}";
                } else if(op=="connect") {
                    node.ConnectTo("127.0.0.1",uint16_t(Number(Field(command,"port"))));
                    response="{\"connected_requested\":true}";
                } else if(op=="maintain") {
                    // Drive the production main-loop maintenance entry points.
                    // Their internal pacing and peer admission rules remain in force.
                    node.BroadcastSupervisorTick();
                    node.TriggerTipReconcile();
                    node.ReapStuckHandshakes();
                    response="{\"maintenance_driven\":true}";
                } else if(op=="export_history" || op=="import_history") {
                    const std::string name=Field(command,"name").text;
                    if(name!="prefix-history.bin" && name!="final-history.bin")
                        throw std::runtime_error("test history filename is not allowlisted");
                    const auto path=directory.parent_path()/name;
                    if(op=="export_history") {
                        if(std::filesystem::exists(path)) throw std::runtime_error("test history already exists");
                        auto transition=node.GetChain().AcquireConsensusTransitionGuard();
                        const auto tip=node.GetChain().Height();
                        std::ofstream out(path,std::ios::binary);
                        out.write("VLDMIG01",8);
                        for(uint64_t h=0;h<=tip;++h) {
                            const auto raw=node.GetChain().GetBlock(h).Serialize();
                            if(raw.size()>MAX_BLOCK_SIZE) throw std::runtime_error("test history block size");
                            const uint32_t length=static_cast<uint32_t>(raw.size());
                            for(unsigned i=0;i<4;++i) out.put(char(length>>(i*8)));
                            out.write(reinterpret_cast<const char*>(raw.data()),raw.size());
                            if(!out) throw std::runtime_error("test history write failed");
                        }
                        out.flush(); if(!out) throw std::runtime_error("test history flush failed");
                        response=JsonBuilder::Object({{"exported_height",JsonBuilder::Number(tip)}});
                    } else {
                        std::ifstream in(path,std::ios::binary);
                        char magic[8]{}; in.read(magic,8);
                        if(!in || std::string(magic,8)!="VLDMIG01") throw std::runtime_error("test history header");
                        uint64_t height=0;
                        while(in.peek()!=std::char_traits<char>::eof()) {
                            if(height>4096) throw std::runtime_error("test history height bound");
                            uint32_t length=0;
                            for(unsigned i=0;i<4;++i) { const int b=in.get(); if(b<0) throw std::runtime_error("test history length"); length|=uint32_t(b)<<(i*8); }
                            if(length==0 || length>MAX_BLOCK_SIZE) throw std::runtime_error("test history body bound");
                            std::vector<uint8_t> raw(length);
                            in.read(reinterpret_cast<char*>(raw.data()),length);
                            Block block;
                            if(!in || Block::Deserialize(raw,0,block)!=raw.size() || block.Serialize()!=raw)
                                throw std::runtime_error("test history block encoding");
                            if(height<=node.GetChain().Height()) {
                                if(node.GetChain().GetBlock(height).Serialize()!=raw) throw std::runtime_error("test history prefix mismatch");
                            } else {
                                // Local historical replay: every new body still passes
                                // ordinary PoW, transaction, and all-module validation.
                                // No peer quota or validation switch is changed.
                                const auto result=node.GetChainMut().AddBlockDirect(block,false,false,false,mining::PowAdmissionContext::Internal());
                                if(!result.IsAccepted()) throw std::runtime_error("test local history replay refused at "+std::to_string(height));
                            }
                            ++height;
                        }
                        response=JsonBuilder::Object({{"imported_height",JsonBuilder::Number(node.GetChain().Height())},{"digest",JsonBuilder::String(Digest(node))}});
                    }
                } else if(op=="fund") {
                    const size_t to=size_t(Number(Field(command,"to")));
                    if(to>=wallets.size()) throw std::runtime_error("test recipient index");
                    response=SignAndSend(node,key,"preparerawtransaction",{key.address,wallets[to].address,Field(command,"amount").text});
                } else if(op=="register") {
                    response=SignAndSend(node,key,"prepareregistervalidator",{key.address,BytesToHex(key.public_key.data(),key.public_key.size())});
                } else if(op=="stake") {
                    response=SignAndSend(node,key,"preparestake",{key.address,Field(command,"amount").text});
                } else if(op=="propose") {
                    const auto height=node.GetChain().Height();
                    const std::string title=Field(command,"title").text;
                    const std::string description=Field(command,"description").text;
                    const bool framed=SecurityStateMigrationActive(NextInclusionHeight(height));
                    const auto* type_field=command.Get("type");
                    const std::string type_name=type_field?type_field->text:"general";
                    ProposalType type;
                    if(type_name=="general") type=ProposalType::GENERAL;
                    else if(type_name=="protocol_upgrade") type=ProposalType::PROTOCOL_UPGRADE;
                    else throw std::runtime_error("unsupported test proposal type");
                    const auto challenge=GovernanceEngine::BuildProposalChallenge(type,key.address,title,description,height,true,framed);
                    const auto signature=BytesToHex(Sign(key.private_key,Hash256d(challenge)));
                    response=SignAndSend(node,key,"preparegovproposal",{key.address,type_name,title,description,BytesToHex(key.public_key.data(),key.public_key.size()),signature,std::to_string(height)});
                } else if(op=="vote") {
                    const auto proposal=Number(Field(command,"proposal"));
                    const auto height=node.GetChain().Height();
                    const std::string identity=Field(command,"identity").text;
                    const auto challenge=GovernanceEngine::BuildVoteChallenge(proposal,VoteChoice::YES,height,identity);
                    const auto signature=BytesToHex(Sign(key.private_key,Hash256d(challenge)));
                    std::vector<std::string> params{key.address,std::to_string(proposal),"yes",BytesToHex(key.public_key.data(),key.public_key.size()),signature,std::to_string(height)};
                    if(!identity.empty()) params.push_back(identity);
                    response=SignAndSend(node,key,"preparegovvote",params);
                } else if(op=="endorse") {
                    const uint64_t height=Number(Field(command,"height"));
                    const std::string hash=node.GetChain().GetBlockHashAtHeight(height);
                    const std::string public_key=BytesToHex(key.public_key.data(),key.public_key.size());
                    const std::string journal_key=std::to_string(height)+":"+public_key;
                    if(endorsement_journal.would_equivocate(journal_key,hash))
                        throw std::runtime_error("test refuses conflicting endorsement");
                    const auto grant=Result(node,"getworkadmission",{"validator_endorsement",std::to_string(height),hash});
                    const std::string binding=Field(grant,"binding").text;
                    const std::string signing_token=Field(grant,"signing_token").text;
                    try {
                        (void)Result(node,"beginworksigning",{"validator_endorsement",binding,signing_token});
                        if(!endorsement_journal.record(journal_key,hash))
                            throw std::runtime_error("test endorsement journal write failed");
                        const auto message=ValidatorRegistry::BuildEndorseMessage(height,HexToHash(hash));
                        const auto signature=BytesToHex(Sign(key.private_key,message));
                        const auto wire=ValidatorRegistry::BuildEndorseOp(height,hash,signature,key.address,NextInclusionHeight(node.GetChain().Height()));
                        const auto* sponsor_field=command.Get("sponsor");
                        const size_t sponsor=sponsor_field?size_t(Number(*sponsor_field)):index;
                        if(sponsor>=wallets.size()) throw std::runtime_error("test sponsor index");
                        response=SignAndSend(node,wallets[sponsor],"preparerawop",{wallets[sponsor].address,wire},{binding,signing_token});
                    } catch(...) {
                        try { (void)Result(node,"cancelworksigning",{signing_token}); } catch(...) {}
                        throw;
                    }
                } else {
                    throw std::runtime_error("unknown test command");
                }
                std::cout<<"TEST_RESULT "<<response<<std::endl;
            } catch(const std::exception& e) {
                std::cout<<"TEST_RESULT "<<JsonBuilder::Object({{"test_error",JsonBuilder::String(e.what())}})<<std::endl;
            }
        }
        http.Stop(); node.Stop();
        std::filesystem::remove(token_path);
        std::cout<<"TEST_STOPPED"<<std::endl;
        return 0;
    } catch(const std::exception& e) {
        std::cerr<<"TEST_FATAL "<<e.what()<<std::endl;
        return 1;
    }
}
