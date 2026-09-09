// Disk-backed recovery with real signed evidence and isolated membership fixtures.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_ASERT_TESTCHAIN 1
#define VELD_TEST_STAKE_OUTPOINT_BACKING 1
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3360
#define VELD_ENABLE_SNAPSHOT_BOOTSTRAP 1
#define VELD_LIGHT_VERIFY 1
#include "node/node.h"
#include <filesystem>
#include <iostream>

using namespace veld;
namespace fs=std::filesystem;
namespace fq=veld::finality::qc;
namespace sr=veld::snapshot_recovery;
size_t checks=0;
void Check(bool ok,const char* what){++checks;if(!ok)throw std::runtime_error(what);}
void Mine(VeldNode& node,const RealKeyPair& key) {
    std::string error;Check(node.BindGenerationIdentity(key,&error),"generation identity");
    for(unsigned n=0;n<20;++n){
        asert_qualification::candidate_time.store(node.GetChain().TipCopy().header.timestamp+180);
        Check(node.GenerateBlocksForRpc(1,0).generated==1,"real private PoW block");
    }
}
void Install(VeldNode& node,const fq::EpochSnapshot& snapshot) {
    auto state=node.GetValidators().SnapshotState();
    ValidatorRecord record;record.pubkey_hex=snapshot.entries[0].pubkey_hex;
    state.validators[record.pubkey_hex]=record;node.GetValidators().RestoreState(state);
    Check(node.TestInstallFinalityEvidenceSnapshot(snapshot),"retained membership fixture");
}
int main(int argc,char**argv){
 try{
    Check(argc==2,"explicit disposable directory required");const auto root=fs::absolute(argv[1]);
    Check(!fs::exists(root),"preserve previous fixtures");
    auto config=RegtestConfig();config.port=31141;
    auto key=GenerateKeyPair(true);key.address=PubKeyToAddress(key.public_key,false);
    key.script_override=AddressToScript(key.address);
    const auto signer=dilithium::Generate();
    fq::SnapshotEntry member;member.pubkey_hex=BytesToHex(signer.public_key.data(),signer.public_key.size());
    member.pubkey_commit=fq::PubkeyCommit(member.pubkey_hex);member.address=key.address;
    member.weight=fq::BOND_PER_KEY_UNITS;
    fq::EpochSnapshot snapshot;snapshot.epoch_id=0;snapshot.snapshot_height=0;
    snapshot.entries={member};snapshot.total_weight=member.weight;
    snapshot.root=fq::SnapshotRoot(snapshot.entries,0,0,snapshot.total_weight);
    Hash256 genesis{};const auto genesis_wire=HexToBytes(GENESIS_HASH);
    Check(genesis_wire.size()==genesis.size(),"compiled finality domain genesis");
    std::copy(genesis_wire.begin(),genesis_wire.end(),genesis.begin());
    fq::SignedVote a;a.epoch_id=0;a.set_root=snapshot.root;a.phase=fq::Phase::PREVOTE;
    a.round=fq::CheckpointRound(20);a.target.height=20;a.target.hash.fill(0x31);
    a.pubkey_hex=member.pubkey_hex;auto b=a;b.target.hash.fill(0x32);
    const auto sign=[&](fq::SignedVote& vote){vote.signature=dilithium::Sign(signer.secret_key,
        fq::VotePreimage(fq::NETWORK_ID,genesis,vote.epoch_id,vote.set_root,
                         vote.phase,vote.round,vote.source,vote.target));};
    sign(a);sign(b);
    const auto evidence=fq::ValidateEquivocationPairForRetainedMember(
        a,b,0,snapshot.root,member,20,fq::NETWORK_ID,genesis);
    Check(evidence.has_value(),"both real signatures and canonical pair authenticate");
    fq::FinalityEquivocationCollector original;
    Check(original.Offer(*evidence)==fq::FinalityEquivocationCollector::OfferResult::INSERTED,"completed evidence retained");
    const auto wire=original.Encode();
    {
        VeldNode before(config,root.string());before.SetQuietBoot(true);before.Start();
        Mine(before,key);Install(before,snapshot);
        sr::Write(root/"finality-equivocation.evj",wire);before.TestLoadFinalityEvidence();
        Check(before.TestFinalityEvidenceCount()==1,"legitimate nonempty journal loads before recovery");
        before.RejectIndependentBackgroundValidation("independent-tip-mismatch");
        Check(sr::RejectionExitCode(root)==75,"background rejection requests recovery restart");
        before.Stop();
    }
    {
        VeldNode recovered(config,root.string());recovered.SetQuietBoot(true);
        recovered.SetFullIbd(true);recovered.Start();
        Check(recovered.GetChain().Height()==0 && recovered.IsRunning(),"fresh sync can start without later validator history");
        Check(recovered.TestFinalityEvidenceCount()==0,"unverified old evidence is not active");
        const auto t=sr::Load(root);Check(t.has_value(),"recovery journal retained");
        const auto saved=root/(".snapshot-rejected-"+t->id)/"finality-equivocation.evj";
        Check(sr::Read(saved,wire.size())==wire,"original signed evidence preserved byte for byte");
        recovered.SetIBDComplete(true);
        Check(!recovered.IsIBDComplete(),"unreconstructed evidence prevents premature promotion");
        Mine(recovered,key);Install(recovered,snapshot);
        recovered.SetIBDComplete(true);
        Check(recovered.IsIBDComplete(),"restored membership permits completion");
        Check(recovered.TestFinalityEvidenceCount()==1,"evidence restored after authentication");
        Check(sr::Read(root/"finality-equivocation.evj",wire.size())==wire,"restored evidence durably published");
        std::string error;Check(channel::secure_file::AtomicWriteText((root/"miner.key").string(),
            "disposable receipt binding\n",&error,true),"role binding");
        Check(snapshot_bootstrap::WriteFullIbdReceipt(root.string(),key,20,
            HashToHex(recovered.GetChain().TipCopy().GetHash()),&error),"real signed recovery receipt");
        snapshot_bootstrap::FullIbdReceipt parsed_receipt;
        Check(!snapshot_bootstrap::VerifyFullIbdReceipt(root.string(),key.public_key,parsed_receipt,&error),
              "default receipt verification cannot bypass revocation");
        Check(snapshot_bootstrap::VerifyFullIbdReceipt(root.string(),key.public_key,parsed_receipt,&error,true),
              "recovery mode still authenticates the signed receipt");
        const auto receipt_path=root/snapshot_bootstrap::RECEIPT_FILENAME;
        const auto valid_receipt=sr::Read(receipt_path,24*1024);
        Check(valid_receipt.has_value(),"receipt bytes preserved for mutation controls");
        auto refused_completion=[&](const Secp256k1PubKey& identity){
            bool refused=false;
            try{recovered.CompleteSnapshotRecovery(snapshot_bootstrap::RECEIPT_FILENAME,identity);}
            catch(const std::runtime_error&){refused=true;}
            Check(refused && sr::Pending(root),"invalid receipt cannot retire recovery barriers");
        };
        auto other_identity=key.public_key;other_identity[0]^=1;
        refused_completion(other_identity);
        sr::Write(receipt_path,"truncated receipt\n");refused_completion(key.public_key);
        Check(snapshot_bootstrap::WriteFullIbdReceipt(root.string(),key,19,
            HashToHex(recovered.GetChain().TipCopy().GetHash()),&error),"signed wrong-height fixture");
        refused_completion(key.public_key);
        sr::Write(receipt_path,*valid_receipt);
        snapshot_bootstrap::FullIbdReceipt retry_receipt;
#ifdef _WIN32
        // Deny the first namespace removal after the completion journal is
        // committed. This is an actual Windows sharing failure, not a skip.
        HANDLE blocked = ::CreateFileW((root/sr::REQUEST).c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        Check(blocked!=INVALID_HANDLE_VALUE,"cleanup sharing fault armed");
        Check(!recovered.PersistFullIbdReceiptAtTip(key,false,retry_receipt,&error),
              "cleanup failure did not remain visible");
        Check(sr::Load(root)->phase=="complete","receipt-bound completion was not committed before cleanup failure");
#else
        // Restore the exact durable post-commit/pre-cleanup state, as after a
        // crash at that boundary; a read-only directory forces retry failure.
        auto committed=*sr::Load(root); committed.phase="complete";
        committed.receipt=snapshot_bootstrap::RECEIPT_FILENAME;
        committed.receipt_hash=HashToHex(Hash256d(*valid_receipt));
        sr::Write(root/sr::JOURNAL,sr::Body(committed));
        fs::permissions(root,fs::perms::owner_read|fs::perms::owner_exec);
#endif
        const auto committed_receipt=sr::Read(receipt_path,24*1024);
        Check(committed_receipt.has_value(),"committed receipt disappeared");
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        Check(!recovered.PersistFullIbdReceiptAtTip(key,false,retry_receipt,&error),
              "blocked completion retry reported success");
        Check(sr::Read(receipt_path,24*1024)==committed_receipt,
              "retry overwrote the hash-bound completion receipt");
#ifdef _WIN32
        ::CloseHandle(blocked);
#else
        fs::permissions(root,fs::perms::owner_all);
#endif
        Check(recovered.PersistFullIbdReceiptAtTip(key,false,retry_receipt,&error),
              "completion could not resume after cleanup failure");
        Check(sr::Read(receipt_path,24*1024)==committed_receipt,
              "successful cleanup rewrote committed receipt bytes");
        Check(!sr::Pending(root),"recovery completes only after evidence and receipt persistence");
        Check(sr::Read(saved,wire.size())==wire,"completion retains original evidence");
        recovered.TestLoadFinalityEvidence();
        Check(recovered.TestFinalityEvidenceCount()==1,"restored journal authenticates on reload");
        recovered.Stop();
    }
    std::cout<<"PASS "<<checks<<" recovery and finality checks\n";return 0;
 }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<"\n";return 1;}
}
