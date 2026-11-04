#include "node/appchain_parent_network.h"
#include <fstream>
#include <iostream>

namespace fs=std::filesystem;
using namespace veld;
static void require(bool ok,const char* label){if(!ok)throw std::runtime_error(label);std::cout<<"PASS "<<label<<std::endl;}
template<class F>static void await(F f,const char* label){
    const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(180);
    while(!f()){if(std::chrono::steady_clock::now()>until)throw std::runtime_error(label);std::this_thread::sleep_for(std::chrono::milliseconds(50));}
    require(true,label);
}
static Block block(const fs::path& root,unsigned h){
    std::ifstream in(root/(std::to_string(h)+".block"),std::ios::binary);
    std::vector<uint8_t> raw{std::istreambuf_iterator<char>(in),{}};Block b;
    require(Block::Deserialize(raw,0,b)==raw.size()&&b.Serialize()==raw,"canonical source block");return b;
}
static void seed(const fs::path& root,const std::string& name,unsigned last){
    const auto path=root/name;require(fs::create_directory(path),"fresh node directory");
    fs::copy_file(root/"network.identity",path/"network.identity");
    db::VeldDB out((path/"db").string());uint64_t supply=0;
    for(unsigned h=0;h<=last;++h){const auto b=block(root,h);const auto hash=b.GetHash();
        require(out.WriteBlock(hash,b.Serialize())&&out.WriteBlockIndex(HashToHex(hash),h,b.header.bits),"historical body stored");
        for(const auto& output:b.transactions.front().outputs)supply+=output.value;
        if(h==last)require(out.WriteChainTip(hash,h,supply),"historical tip stored");}
}
int main(int argc,char** argv){try{
    require(argc==2,"disposable root supplied");const auto root=fs::canonical(argv[1]);
    std::ifstream marker(root/".qualification-only");std::string line;std::getline(marker,line);
    require(line=="parent-acquisition","isolated qualification marker");
    require(!APPCHAIN_BRIDGE_ENABLED,"public bridge remains inactive");
    for(const auto& text:{"0.0.0.0:1","224.0.0.1:1","127.0.0.1:01","localhost:1"}){
        bool rejected=false;try{AppchainParentNetwork::Endpoint(text);}catch(const app::Invalid&){rejected=true;}
        require(rejected,"ambiguous endpoint refused");}
    seed(root,"first",10);seed(root,"second",10);seed(root,"receiver",8);
    vendored_crypto::vendored_crypto_selftest();
    VeldNode first(MainnetConfig(),(root/"first").string()),second(MainnetConfig(),(root/"second").string());
    first.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);second.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
    const auto last=block(root,10),base=block(root,8);
    first.ValidateStoredChainOnly(10,HashToHex(last.GetHash()),true);second.ValidateStoredChainOnly(10,HashToHex(last.GetHash()),true);
    auto donor=[&](VeldNode& n,unsigned port,const std::string& name){
        auto s=std::make_unique<net::NodeServer>(port,MainnetConfig().magic,n.GetChainMut(),n.GetMempoolMut());
        s->SetBanFilePath((root/name/"bans").string());s->SetPeerCachePath((root/name/"peers").string());s->SetAnchorsPath((root/name/"anchors").string());
        require(s->Start(),"isolated donor listener started");return s;};
    auto a=donor(first,58471,"first"),b=donor(second,58472,"second");
    Hash256 digest{};
    {
        VeldNode receiver(MainnetConfig(),(root/"receiver").string());receiver.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
        receiver.ValidateStoredChainOnly(8,HashToHex(base.GetHash()),true);
        AppchainParentNetwork network(receiver,root/"receiver",{"127.0.0.2:58471","127.0.0.3:58472"});
        AppchainPublicParentFeed feed(receiver,[&]{return network.Status();});
        await([&]{return receiver.GetChain().TipCopy().GetHash()==last.GetHash();},"actual outbound peers deliver fully validated blocks");
        await([&]{const auto health=feed.Request(4,{});return health.size()==105&&health[78]==1;},"two peer work observations open readiness");
        const auto health=feed.Request(4,{});require(health[79]==2&&health[80]==0,"two distinct outbound addresses reported");
        app::Writer request;request.n(10,8);request.raw(last.GetHash());
        require(feed.Request(2,request.b)==last.Serialize(),"acquired canonical body exported unchanged");
        digest=receiver.ConsensusStateDigest();
        auto retained=receiver.GetChain().GetBlock(10);
        {auto guard=receiver.GetChainMut().AcquireConsensusTransitionGuard();network.RelayValidated(retained);}
        auto changed=retained;changed.transactions.back().outputs.back().value^=1;
        bool refused=false;try{auto guard=receiver.GetChainMut().AcquireConsensusTransitionGuard();network.RelayValidated(changed);}
        catch(const app::Invalid&){refused=true;}
        require(refused,"relay refuses changed bytes even when header hash matches a retained block");
        require(receiver.ConsensusStateDigest()==digest,"validated relay leaves canonical state unchanged");
        b->Stop();await([&]{return feed.Request(4,{})[78]==0;},"loss of one peer closes readiness");
        a->Stop();await([&]{const auto h=feed.Request(4,{});return h[79]==0&&h[80]==0&&h[78]==0;},"disconnect closes all peer evidence");
        require(receiver.GetChain().TipCopy().GetHash()==last.GetHash()&&receiver.ConsensusStateDigest()==digest,"disconnect preserves validated chain state");
        require(!receiver.IsMiningReady(),"parent reader never opens mining admission");
    }
    VeldNode restarted(MainnetConfig(),(root/"receiver").string());restarted.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
    restarted.ValidateStoredChainOnly(10,HashToHex(last.GetHash()),true);
    require(restarted.ConsensusStateDigest()==digest,"cold full validation preserves acquired state");
    std::cout<<"PASS_PUBLIC_PARENT_ACQUISITION"<<std::endl;return 0;
}catch(const std::exception& e){std::cerr<<"FAIL_PUBLIC_PARENT_ACQUISITION "<<e.what()<<std::endl;return 1;}}
