#include "../include/node/snapshot_recovery.h"
#include <iostream>

#ifndef VELD_USE_LEVELDB
#error "Snapshot recovery qualification requires the disk-backed LevelDB implementation"
#endif

using namespace veld;
namespace sr = snapshot_recovery;
namespace fs = std::filesystem;
unsigned checks = 0;
void Check(bool value, const char* name) {
    if (!value) throw std::runtime_error(name);
    ++checks;
}
template<class F> void Refuses(F&& f, const char* name) {
    bool refused=false;
    try { f(); } catch (const std::exception&) { refused=true; }
    Check(refused,name);
}
Hash256 Hash(unsigned char value) { Hash256 h{};h.fill(value);return h; }
constexpr uint32_t magic=0x74736574;
const Hash256 genesis=Hash(1);

btcanchor::floor_store::Record Floor(uint64_t target,unsigned char id) {
    btcanchor::AnchorSet::PermanentCheckpoint p;
    p.target_height=target;
    auto& e=p.entry;
    e.veld_block_hash=Hash(id);e.carrying_veld_height=target+1;
    e.carrying_veld_hash=Hash(id+1);e.btc_block_hash=Hash(id+2);e.btc_txid=Hash(id+3);
    auto& f=p.authorization_record;
    f.target.height=((target+1)/finality::qc::CHECKPOINT_INTERVAL+1)*finality::qc::CHECKPOINT_INTERVAL;
    f.target.hash=Hash(id+4);f.epoch_id=finality::qc::EpochOf(f.target.height);
    f.round=finality::qc::CheckpointRound(f.target.height);f.phase=finality::qc::Phase::PRECOMMIT;
    f.set_root=Hash(id+5);f.cert_commit=Hash(id+6);f.carrier.height=f.target.height+1;
    f.carrier.hash=Hash(id+7);f.retention_floor=f.target.height;
    e.authorization_veld_height=f.carrier.height;e.authorization_veld_hash=f.carrier.hash;
    e.authorization_finality_digest=finality::qc::RecordDigest(f);
    std::string error;
    const auto record=btcanchor::floor_store::Make(magic,genesis,p,&error);
    sr::Require(record.has_value(),error);return *record;
}
fs::path New(const fs::path& base,const std::string& name) {
    const auto root=base/name;
    Check(!fs::exists(root),"fixture must be new");
    std::string error;
    Check(channel::secure_file::EnsurePrivateDirectory(root.string(),&error),"private fixture root");
    { db::VeldDB store((root/"db").string()); }
    return root;
}
void PutIndex(const fs::path& root,const std::string& key,const std::string& value) {
    db::LevelDBStore store((root/"db/index").string(),false);Check(store.Put(key,value),"durable fixture key");
}
void PutDbFloor(const fs::path& root,const btcanchor::floor_store::Record& record) {
    const auto wire=btcanchor::floor_store::Encode(record);Check(bool(wire),"floor encoding");
    PutIndex(root,db::VeldDB::ANCHOR_SECURITY_FLOOR_KEY,{wire->begin(),wire->end()});
}
void PutExternalFloor(const fs::path& root,const btcanchor::floor_store::Record& record) {
    std::string error;
    Check(channel::secure_file::EnsurePrivateDirectory((root/"security").string(),&error),"private security dir");
    const auto wire=btcanchor::floor_store::Encode(record);Check(bool(wire),"floor encoding");
    sr::Write(root/"security/anchor-floor.vlf1",*wire);
}
int main(int argc,char** argv) {
    try {
        Check(argc==2,"explicit disposable root required");
        const auto base=fs::absolute(argv[1]);
        Check(!fs::exists(base),"do not reuse a fixture root");
        fs::create_directories(base);
        {
            const auto fresh=base/"bootstrap-policy";
            std::string directory_error;
            Check(channel::secure_file::EnsurePrivateDirectory(fresh.string(),&directory_error),"private bootstrap fixture");
            Check(channel::secure_file::EnsurePrivateDirectory((fresh/"db").string(),&directory_error),"private empty storage directory");
            Check(!sr::HasLocalChainState(fresh),"empty datadir permits first bootstrap");
            // Each surviving storage member or validation obligation must
            // prevent automatic replacement, including partial local state.
            for (const auto* name : {"db/blocks", "db/utxo", "db/index",
                    "db/.snapshot-consensus-replay-required", ".snapshot-handoff",
                    ".background-chainstate-required", "background-ibd",
                    "background-chainstate", sr::REQUEST, sr::REVOKED,
                    sr::JOURNAL, sr::IMPORT}) {
                const auto path=fresh/name;
                sr::Write(path,"retained local state\n");
                Check(sr::HasLocalChainState(fresh),"existing state blocks another snapshot import");
                Check(sr::Read(path,64)==std::optional<std::vector<uint8_t>>(
                    std::vector<uint8_t>{'r','e','t','a','i','n','e','d',' ','l','o','c','a','l',' ','s','t','a','t','e','\n'}),
                    "bootstrap decision preserves local bytes");
                sr::Remove(path);
            }
        }
        const auto lower=Floor(480,10),higher=Floor(520,30);
        for (unsigned sources=0;sources<5;++sources) {
            const auto root=New(base,"floor-"+std::to_string(sources));
            if (sources==1 || sources>=3) PutExternalFloor(root,lower);
            if (sources==2 || sources==3) PutDbFloor(root,lower);
            if (sources==4) PutDbFloor(root,higher);
            sr::Write(root/"network.identity","disposable network identity\n");
            sr::Write(root/"miner.key","disposable fixture bytes\n");
            sr::Request(root,"independent-tip-mismatch");
            Check(sr::RejectionExitCode(root)==75,"durable rejection requests automatic restart");
            Check(sr::Prepare(root,magic,genesis),"recovery starts");
            const auto t=sr::Load(root);Check(t && t->phase=="ibd","fresh IBD journal");
            const auto rejected=root/(".snapshot-rejected-"+t->id);
            Check(fs::is_directory(rejected/"db") && !fs::exists(root/"db"),"rejected database quarantined");
            const auto floors=sr::ReadFloors(root,magic,genesis);
            Check(floors.size()==(sources==0?0:sources==4?2:1),"all distinct floor copies survive");
            Check(sr::Read(root/"miner.key",128).has_value() && sr::Read(root/"network.identity",128).has_value(),"role identity preserved");
            {db::VeldDB fresh((root/"db").string());}
            PutIndex(root,"fixture:new-progress","17");
            Check(sr::Prepare(root,magic,genesis),"second recovery startup");
            {db::LevelDBStore fresh((root/"db/index").string(),false);Check(fresh.Get("fixture:new-progress")=="17","fresh progress retained");}
            Check(sr::Load(root)->id==t->id,"one quarantine generation");
            Refuses([&]{sr::Complete(root,"full-ibd.receipt");},"missing receipt cannot clear recovery");
            Check(sr::Pending(root),"failed completion preserves barrier");
        }
        for (const auto* key : {db::VeldDB::DURABLE_PUBLICATION_PENDING_KEY,
                db::VeldDB::REORG_UTXO_PENDING_KEY,"reorg:utxo:rebuilding","pending:commit"}) {
            const auto root=New(base,"repair-"+std::to_string(checks));
            PutIndex(root,key,"retained local obligation");sr::Request(root,"independent-tip-mismatch");
            Refuses([&]{sr::Prepare(root,magic,genesis);},"local repair blocks replacement");
            Check(fs::is_directory(root/"db") && !sr::Exists(root/sr::JOURNAL),"repair source remains in place");
            db::LevelDBStore store((root/"db/index").string(),false);
            Check(store.Get(key)=="retained local obligation","repair identity unchanged");
        }
        {
            const auto root=New(base,"conflicting-floors");PutExternalFloor(root,lower);
            auto other=lower;other.checkpoint.authorization_record.cert_commit=Hash(88);
            other.checkpoint.entry.authorization_finality_digest=finality::qc::RecordDigest(other.checkpoint.authorization_record);
            other.floor_digest=btcanchor::floor_store::ComputeFloorDigest(other);
            PutDbFloor(root,other);sr::Request(root,"independent-tip-mismatch");
            Refuses([&]{sr::Prepare(root,magic,genesis);},"same target metadata conflict refuses replacement");
            Check(fs::is_directory(root/"db"),"conflicting evidence retained");
        }
        for (const auto* marker : {sr::REQUEST,sr::REVOKED}) {
            const auto root=New(base,"legacy-"+std::to_string(checks));
            sr::Write(root/marker,"schema=1\nreason=independent-tip-mismatch\n");
            Check(sr::Prepare(root,magic,genesis),"single legacy sentinel enters recovery");
        }
        for (const auto* body : {"", "schema=1\nreason=bad reason\n", "schema=1\nreason=ok\nextra=1\n"}) {
            const auto root=New(base,"malformed-"+std::to_string(checks));sr::Write(root/sr::REQUEST,body);
            Refuses([&]{sr::Prepare(root,magic,genesis);},"malformed intent fails closed");
            Check(sr::RejectionExitCode(root)==76,"malformed intent requires inspection");
            Check(fs::is_directory(root/"db"),"malformed request does not mutate chain namespace");
        }
        {
            const auto root=New(base,"uncertain-floor");PutExternalFloor(root,lower);
            sr::Write(root/"security/anchor-floor.uncertain","VLF1-UNCERTAIN\n");sr::Request(root,"independent-tip-mismatch");
            Refuses([&]{sr::Prepare(root,magic,genesis);},"uncertain floor cannot be erased by recovery");
        }
        {
            const auto root=New(base,"healthy");PutIndex(root,"fixture:healthy","unchanged");
            Check(!sr::Prepare(root,magic,genesis),"healthy startup does not enter recovery");
            Check(sr::RejectionExitCode(root)==76,"absent rejection cannot authorize recovery restart");
            db::LevelDBStore store((root/"db/index").string(),false);
            Check(store.Get("fixture:healthy")=="unchanged","healthy chain preserved");
        }
        std::cout<<"PASS "<<checks<<" disk-backed recovery checks\n";return 0;
    } catch (const std::exception& e) {std::cerr<<"FAIL after "<<checks<<" checks: "<<e.what()<<"\n";return 1;}
}
