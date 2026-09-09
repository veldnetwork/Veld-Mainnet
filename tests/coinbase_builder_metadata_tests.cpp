// Real builder/handler and ML-DSA certificate verification; isolated parent fixtures.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_ASERT_TESTCHAIN 1
#define VELD_TEST_BRANCH_CONTEXT 1
#define VELD_TEST_STAKE_OUTPOINT_BACKING 1
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3360
#define VELD_LIGHT_VERIFY 1
#include "coinbase_admission_test_support.h"
using namespace coinbase_test;
namespace fq=veld::finality::qc;
namespace {
std::string Request(const std::string& method,const std::string& address) {
    return "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\""+method+"\",\"params\":[\""+address+"\"]}";
}
struct RpcContext {
    VeldNode& node;
    std::vector<std::shared_ptr<net::Connection>> peers;
    explicit RpcContext(VeldNode& n):node(n) {
        compat::InitNetwork();node.TestInstallWorkAdmissionProcessServer();
        node.TestWorkAdmissionProcessServer().TestSetPeerHeightClock(100);
        for(const std::string ip:{"10.82.0.1","10.82.0.2"}) {
            const auto fd=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
            Check(compat::IsValidSocket(fd),"fixture socket");
            // Unconnected sockets: no connect(), listener or network traffic.
            peers.push_back(std::make_shared<net::Connection>(fd,ip,38201,false));
        }
        Refresh();node.TestConfigureWorkAdmissionProcess({});
    }
    void Refresh() {
        auto& server=node.TestWorkAdmissionProcessServer();
        for(const auto& p:peers) {
            server.TestRecordVersionClaim(p,node.GetChain().Height());
            server.TestMarkPeerHandshakeReady(p);
            auto ip=p->RemoteAddr();
            const auto port=ip.find_last_of(':');
            if(port!=std::string::npos)ip.resize(port);
            server.TestRecordVerifiedPeerHeight(ip,node.GetChain().TipCopy().GetHash());
        }
    }
    std::optional<Block> Template(const RealKeyPair& owner) {
        Refresh();asert_qualification::candidate_time.store(node.GetChain().TipCopy().header.timestamp+180);
        const auto response=node.TestHandleWorkAdmissionRpc(Request("getblocktemplate",PubKeyToAddress(owner.public_key,false)));
        btc_buy::JsonValue parsed;std::string error;
        btc_buy::StrictJsonParser parser(response,4*1024*1024,true);
        Check(parser.Parse(parsed,error),"RPC response malformed");
        const auto* e=parsed.Get("error");Check(e!=nullptr,"RPC missing error field");
        if(e->kind!=btc_buy::JsonValue::Kind::Null) {
            Check(IsProtocolSettlementHeight(node.GetChain().Height()+1) &&
                response.find("mandatory protocol settlement")!=std::string::npos,"unexpected template refusal: "+response);
            return std::nullopt;
        }
        const auto* result=parsed.Get("result");Check(result!=nullptr,"RPC missing result");
        const auto* wire=result->Get("block_hex");Check(wire!=nullptr,"RPC missing block bytes");
        const auto bytes=HexToBytes(wire->text);Block block;
        Check(Block::Deserialize(bytes,0,block)==bytes.size(),"RPC block encoding");
        block.height=node.GetChain().Height()+1;
        Check(node.GetChain().ValidateMiningCoinbase(block),"RPC canonical policy refused");
        return block;
    }
};
struct CertificateParent {
    fq::EpochSnapshot snapshot;
    std::map<std::string,dilithium::KeyPair> keys;
    explicit CertificateParent(size_t members=7) {
        Check(members>=7 && members*fq::BOND_PER_KEY_UNITS<=MAX_SUPPLY_UNITS,"unrepresentable certificate membership");
        snapshot.epoch_id=7;snapshot.snapshot_height=3359;
        for(size_t i=0;i<members;++i) {
            auto key=dilithium::Generate();auto hex=BytesToHex(key.public_key.data(),key.public_key.size());
            fq::SnapshotEntry member;member.pubkey_hex=hex;member.pubkey_commit=fq::PubkeyCommit(hex);
            member.address="private-certificate-member-"+std::to_string(i);
            member.registered_height=1;member.weight=fq::BOND_PER_KEY_UNITS;
            snapshot.entries.push_back(member);keys.emplace(hex,std::move(key));
        }
        std::sort(snapshot.entries.begin(),snapshot.entries.end(),[](const auto& a,const auto& b){return a.pubkey_commit<b.pubkey_commit;});
        snapshot.total_weight=members*fq::BOND_PER_KEY_UNITS;
        snapshot.root=fq::SnapshotRoot(snapshot.entries,snapshot.epoch_id,snapshot.snapshot_height,snapshot.total_weight);
        Check(fq::SnapshotQualifies(snapshot),"certificate snapshot invalid");
    }
    void Install(VeldNode& node) {
        auto state=node.TestReadAnchorFinalityStatus().finality;
        state.snapshots[7]=snapshot;state.consecutive_qualified_epochs=3;state.finality_ever_active=true;
        state.record.epoch_id=7;state.record.round=fq::CheckpointRound(3360);
        state.record.target={3360,node.GetChain().GetBlock(3360).GetHash()};
        state.record.carrier={3361,node.GetChain().GetBlock(3361).GetHash()};
        state.record.cert_commit=Hash256d("assumed-private-finality-parent");
        for(const auto& member:snapshot.entries)
            node.GetValidators().TestInjectValidatorBond(member.pubkey_hex,member.address,member.weight);
        Check(node.TestInstallAnchorFinalityParent(state),"certificate parent refused");
        Check(node.TestCaptureAnchorFinalityCheckpoint(),"certificate parent checkpoint");
    }
    std::vector<std::vector<uint8_t>> Metadata(VeldNode& node,unsigned variant) const {
        fq::QuorumCert qc;qc.epoch_id=7;qc.set_root=snapshot.root;qc.phase=fq::Phase::PRECOMMIT;
        qc.round=fq::CheckpointRound(3380);qc.source={3360,node.GetChain().GetBlock(3360).GetHash()};
        qc.target={3380,node.GetChain().GetBlock(3380).GetHash()};
        size_t signers=snapshot.entries.size()==7 ? 5 : snapshot.entries.size();
        if(variant==3)signers=snapshot.entries.size()*2/3;
        if(variant==4)signers=snapshot.entries.size()*2/3+1;
        qc.bitmap.assign((snapshot.entries.size()+7)/8,0);
        for(size_t i=0;i<signers;++i)qc.bitmap[i>>3]|=uint8_t(1u<<(i&7));
        qc.weight=signers*fq::BOND_PER_KEY_UNITS;
        auto genesis=HexToHash(GENESIS_HASH);if(variant==2)genesis[0]^=1;
        const auto preimage=fq::VotePreimage(fq::NETWORK_ID,genesis,7,snapshot.root,qc.phase,qc.round,qc.source,qc.target);
        std::vector<std::vector<uint8_t>> signatures;
        for(size_t i=0;i<signers;++i)signatures.push_back(dilithium::Sign(keys.at(snapshot.entries[i].pubkey_hex).secret_key,preimage));
        if(variant==1)signatures[0][0]^=1;
        const auto encoded=fq::EncodeQc(qc,signatures);
        Check(!encoded.empty(),"QC encoding failed");
        const auto payloads=fq::EncodeFinalityCarrierPayloads(encoded);
        std::vector<std::vector<uint8_t>> scripts;for(const auto& value:payloads)scripts.push_back(BuildOpReturnScript(value));
        Check(!scripts.empty() && scripts.size()<=MAX_FINALITY_MARKER_OUTPUTS,"metadata size bound");
        return scripts;
    }
};
Block WithCertificate(VeldNode& node,const RealKeyPair& owner,const CertificateParent& parent,unsigned variant) {
    auto block=Build(node,owner,950000+variant);
    block.transactions[0]=Blockchain::BuildCanonicalCoinbase(block.height,MAX_SUPPLY_UNITS,0,owner.GetP2PKHScript(),parent.Metadata(node,variant));
    block.UpdateMerkleRoot();
    Check(block.transactions[0].TotalOutput()==0,"certificate minted value");
    for(const auto& out:block.transactions[0].outputs)Check(Blockchain::IsFinalityCoinbaseMetadata(out),"zero marker mixed with metadata");
    Check(node.GetChain().ValidateMiningCoinbase(block),"metadata shape preflight rejected");
    auto parsed=fq::ParseFinalityBlock(block,[](const auto& script){return ParseOpReturn(script);});
    Check(parsed.status==fq::FinParseStatus::VALID,"certificate parser rejected fixture");
    const bool verified=fq::VerifyDecodedQc(parsed.decoded,parent.snapshot,fq::NETWORK_ID,HexToHash(GENESIS_HASH));
    Check(verified==(variant==0 || variant==4),"certificate authentication control differs");
    Check(block.SerializedSize()<=MAX_BLOCK_SIZE,"certificate exceeds block size");
    return block;
}
}
int main(int argc,char** argv) {
    try {
        Check(argc>=2 && argc<=4,"fresh fixture root, optional member count and legacy control required");
        const size_t members=argc>=3 ? std::stoull(argv[2]) : 7;
        const bool legacy_control=argc==4 && std::string(argv[3])=="--expect-legacy-output-limit";
        Check(argc<4 || legacy_control,"unknown control");
        const fs::path root=fs::absolute(argv[1]);
        Check(!fs::exists(root),"preserve existing fixture");fs::create_directories(root);
        auto owner=GenerateKeyPair(true);auto normal=Fresh(root/"normal");std::vector<Block> prefix{CreateGenesisBlock()};
        for(uint64_t h=1;h<=3399;++h){auto b=Build(*normal,owner,h);Admit(*normal,b);prefix.push_back(b);}
        RpcContext normal_rpc(*normal);
        Check(!normal_rpc.Template(owner),"external settlement template unexpectedly emitted");
        auto refused=MineAndCommit(normal->GetChainMut(),normal->GetMempoolMut(),owner);
        Check(!refused.success && refused.error.find("settlement height")!=std::string::npos && refused.hashes_tried==0,"standalone settlement refusal");
        Admit(*normal,Build(*normal,owner,959999));
        Fee(*normal,owner,30*BLOCK_REWARD_UNITS+1);
        auto emitted=normal_rpc.Template(owner);Check(emitted.has_value(),"ordinary template absent");
        auto expected=Build(*normal,owner,960000);
        Check(emitted->transactions[0].Serialize()==expected.transactions[0].Serialize(),"RPC and node coinbase differ");
        auto mined=MineAndCommit(normal->GetChainMut(),normal->GetMempoolMut(),owner);
        Check(mined.success && mined.hashes_tried>0,"MineAndCommit failed: "+mined.error);
        Check(mined.block.transactions[0].Serialize()==emitted->transactions[0].Serialize(),"standalone and RPC coinbase differ");
        Coherent(*normal,normal->GetChain().TotalSupplyUnits());
        std::cout<<"PASS RPC template and standalone mining callers, including settlement refusal"<<std::endl;
        CertificateParent certificates(members);
        const auto parent=[&](const char* name){auto n=Fresh(root/name);for(size_t h=1;h<prefix.size();++h)Admit(*n,prefix[h]);Seed(*n,0);certificates.Install(*n);return n;};
        if(legacy_control) {
            Check(members==2000,"legacy control requires representable large membership");
            auto baseline=parent("legacy-control");
            auto large=WithCertificate(*baseline,owner,certificates,0);
            Check(large.transactions[0].outputs.size()==207,"large certificate fragment count");
            Check(!baseline->TestIngestDStateQualificationFrame(large.Serialize(),large.height) &&
                Blockchain::GetLastRejectTag()=="coinbase_too_many_outputs","legacy ingress disagreement not reproduced");
            auto smaller=WithCertificate(*baseline,owner,certificates,4);
            Check(smaller.transactions[0].outputs.size()<200,"smaller quorum control still oversized");
            Admit(*baseline,smaller);Coherent(*baseline,MAX_SUPPLY_UNITS);
            std::ofstream(root/"result.json")<<"{\"status\":\"reproduced\",\"valid_signatures\":2000,\"metadata_outputs\":207,\"smaller_quorum_accepted\":true}\n";
            std::cout<<"REPRODUCED authenticated 207-output preflight/ingress mismatch; smaller quorum accepted"<<std::endl;
            return 0;
        }
        auto direct=parent("direct"),branch=parent("branch"),replay=parent("independent");
        Equal(*direct,*branch);Equal(*branch,*replay);
        const auto before=branch->ConsensusStateDigest();
        for(unsigned variant=1;variant<=3;++variant) {
            auto bad=WithCertificate(*branch,owner,certificates,variant);
            Check(!branch->TestIngestDStateQualificationFrame(bad.Serialize(),bad.height),"unauthenticated or nonquorum certificate accepted");
            Check(branch->ConsensusStateDigest()==before,"bad certificate mutated state");
        }
        Admit(*direct,Build(*direct,owner,970000));
        auto valid=WithCertificate(*branch,owner,certificates,0);
        if(members==2000)Check(valid.transactions[0].outputs.size()==207,"large certificate fragment count");
        Admit(*branch,valid);Admit(*replay,valid);Admit(*direct,valid);
        uint64_t reorg_applied=0;
        if(direct->GetChain().TipCopy().GetHash()==valid.GetHash()) {
            reorg_applied=direct->GetChain().LastReorgApplyCount();
            Check(direct->GetChain().LastReorgDisconnectCount()==1 && reorg_applied==1,
                "certificate tie-break reorganization counts");
        }
        Check(branch->TestReadAnchorFinalityStatus().finality.FinalizedHeight()==3380,"valid QC not applied");
        auto child=Build(*branch,owner,970001);Admit(*branch,child);Admit(*replay,child);Admit(*direct,child);
        if(reorg_applied==0) {
            reorg_applied=direct->GetChain().LastReorgApplyCount();
            Check(direct->GetChain().LastReorgDisconnectCount()==1 && reorg_applied==2,
                "certificate greater-work reorganization counts");
        }
        std::cout<<"REORG disconnected=1 applied="<<reorg_applied<<std::endl;
        Equal(*direct,*branch);Equal(*branch,*replay);
        RpcContext cap_rpc(*branch);Fee(*branch,owner,MIN_TX_FEE+1);
        auto fee_template=cap_rpc.Template(owner);Check(fee_template.has_value(),"cap template absent");
        auto fee_mined=MineAndCommit(branch->GetChainMut(),branch->GetMempoolMut(),owner);
        Check(fee_mined.success && fee_mined.hashes_tried>0,"fee-only standalone mining failed: "+fee_mined.error);
        Check(fee_template->transactions[0].Serialize()==fee_mined.block.transactions[0].Serialize(),"cap builder callers differ");
        Admit(*direct,fee_mined.block);Admit(*replay,fee_mined.block);Equal(*direct,*branch);Equal(*branch,*replay);
        std::ofstream receipt(root/"result.json");receipt<<"{\"status\":\"passed\",\"checks\":"<<checks<<",\"members\":"<<members<<",\"metadata_outputs\":"<<valid.transactions[0].outputs.size()<<",\"synthetic_supply_and_finality_parent\":true,\"authenticated_mldsa_certificate\":true,\"rpc_dispatch_only\":true,\"listeners_started\":false}\n";
        std::cout<<"PASS authenticated metadata, wrong-signature/domain/quorum refusal, reorg and builder equality checks="<<checks<<std::endl;
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<std::endl;return 1;}
}
