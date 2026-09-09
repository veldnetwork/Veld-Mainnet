#include "security_state_migration_profile.h"
#include "consensus/governance.h"
#include "consensus/btcveld_signer_bond.h"
#include "core/leveldb.h"
#include "network/rpc.h"
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <map>
#include <numeric>
#include <random>
#include <stdexcept>

using namespace veld;
using namespace veld::btcveld;
namespace {
size_t checks = 0;
void Check(bool value, const char* label) {
    ++checks;
    if (!value) throw std::runtime_error(label);
}
template<class F> void Refuses(F fn, const char* label) {
    bool refused = false;
    try { fn(); } catch (const std::exception&) { refused = true; }
    Check(refused, label);
}
Hash256 Tag(unsigned value) { return Hash256d(std::to_string(value)); }
std::string Hex(const auto& bytes) { return BytesToHex(std::vector<uint8_t>(bytes.begin(), bytes.end())); }
std::string Sig(const RealKeyPair& key, const std::string& text) {
    return Hex(Sign(key.private_key, Hash256d(text)));
}
struct MemoryArchive {
    std::map<std::string, std::string> rows;
    bool fail = false;
    size_t reads = 0, max_batch = 0;
    RedeemArchive::Read Read() {
        return [this](const std::string& key) -> std::optional<std::string> {
            ++reads;
            const auto it = rows.find(key);
            return it == rows.end() ? std::nullopt : std::optional<std::string>(it->second);
        };
    }
    RedeemArchive::Write Write() {
        return [this](const RedeemArchive::Records& records) {
            max_batch = std::max(max_batch, records.size());
            if (fail) return false;
            for (const auto& [key, value] : records) rows[key] = value;
            return true;
        };
    }
    void Wire(SignerBondCovenant& covenant) { covenant.SetArchiveBackend(Read(), Write()); }
    void Wire(RedeemArchive& archive) { archive.SetBackend(Read(), Write()); }
};
RedeemRequest Request(unsigned id) {
    RedeemRequest r;
    r.request_id = Tag(id); r.amount_sats = 20; r.dest_spk = {0x51};
    r.request_height = 2870; r.deadline_height = 2885;
    r.veld_recipient = "ordinary-recipient"; r.status = ReqStatus::LOCKED_IN;
    r.request_commitment = SignerBondCovenant::RequestCommitment(r);
    return r;
}
Block Carrier(uint64_t height, const std::string& marker) {
    Block block; block.height = height;
    Transaction tx;
    tx.outputs.emplace_back(0, BuildOpReturnScript(marker));
    block.transactions.push_back(tx);
    return block;
}
void ArchiveChecks(const std::filesystem::path& directory) {
    MemoryArchive memory;
    RedeemArchive archive; memory.Wire(archive);
    RedeemArchive::Root root;
    std::vector<unsigned> order(192); std::iota(order.begin(), order.end(), 1);
    for (unsigned i : order) Check(archive.Insert(root, Tag(i), std::to_string(i)), "archive insert");
    const auto first = root;
    Check(root.count == order.size(), "archive count");
    std::shuffle(order.begin(), order.end(), std::mt19937(17));
    RedeemArchive::Root second;
    for (unsigned i : order) archive.Insert(second, Tag(i), std::to_string(i));
    Check(second == first, "archive root independent of insertion order");
    for (unsigned i : order) {
        memory.reads = 0;
        Check(archive.Get(root, Tag(i)) == std::to_string(i), "archive membership value");
        Check(memory.reads <= 257, "archive lookup depth bound");
    }
    Check(!archive.Get(root, Tag(1000)), "archive authenticated absence");
    Check(!archive.Insert(root, Tag(1), "1"), "archive exact insertion idempotent");
    Refuses([&] { archive.Insert(root, Tag(1), "changed"); }, "archive immutable identity");
    memory.fail = true;
    Refuses([&] { archive.Insert(root, Tag(1000), "ordinary"); }, "archive storage failure");
    Check(root == first, "failed archive write preserves root");
    memory.fail = false;
    auto fork = root;
    archive.Insert(fork, Tag(1000), "fork");
    Check(!archive.Get(root, Tag(1000)) && archive.Get(fork, Tag(1000)) == "fork", "archive fork isolation");
    Check(memory.max_batch <= 258, "archive write working-set bound");
    const std::string root_key = HashToHex(root.hash);
    const auto saved = memory.rows.at(root_key);
    memory.rows.erase(root_key);
    Refuses([&] { archive.Get(root, Tag(1)); }, "missing archive is not absence");
    memory.rows[root_key] = "incomplete";
    Refuses([&] { archive.Get(root, Tag(1)); }, "corrupt archive is not absence");
    memory.rows[root_key] = saved;

    RedeemArchive::Root persisted;
    std::filesystem::create_directories(directory);
    {
        db::LevelDBStore store(directory.string());
        RedeemArchive disk;
        disk.SetBackend([&](const std::string& h) { return store.Get(h); },
            [&](const RedeemArchive::Records& records) {
                db::WriteBatch batch;
                for (const auto& [h, value] : records) batch.Put(h, value);
                return store.Write(batch);
            });
        for (unsigned i : order) disk.Insert(persisted, Tag(i), std::to_string(i));
        Check(persisted == first, "disk and memory roots agree");
    }
    {
        db::LevelDBStore store(directory.string(), false);
        RedeemArchive disk;
        disk.SetBackend([&](const std::string& h) { return store.Get(h); },
            [](const auto&) { return false; });
        for (unsigned i : order) Check(disk.Get(persisted, Tag(i)) == std::to_string(i), "archive reopen");
    }
}
void CovenantChecks() {
    constexpr uint64_t H = SECURITY_STATE_MIGRATION_HEIGHT;
    static_assert(H == 2880 && CONSENSUS_SECURITY_UPGRADE_HEIGHT == 2880);
    MemoryArchive memory;
    SignerBondCovenant cov; memory.Wire(cov);
    Check(cov.Register("ordinary-signer", 100) && cov.Activate("ordinary-signer"), "legacy signer control");
    auto open = Request(1), paid = Request(2), defaulted = Request(3);
    cov.AddRequest(open); // keep settlement-only locks
    cov.AddRequest(paid, true);
    cov.AddRequest(defaulted, true);
    Check(cov.MarkAuthorizedReservePayout(paid.request_id, Tag(102), paid.amount_sats, paid.dest_spk), "ordinary fulfilled request");
    cov.SetStatus(defaulted.request_id, ReqStatus::DEFAULTED);
    Check(cov.ConsumeFraudSpend(Tag(103)), "ordinary consumed evidence identity");
    const auto parent = cov.SnapshotState();
    const Hash256 old_digest = cov.Digest();
    cov.BeginBlock(H-1);
    Check(cov.Digest() == old_digest, "preheight digest unchanged");
    memory.fail = true;
    Refuses([&] { cov.BeginBlock(H); }, "migration durable storage failure");
    Check(cov.Digest() == old_digest, "migration failure retains complete parent");
    memory.fail = false;
    cov.BeginBlock(H);
    Check(cov.TotalActiveBond() == 0 && cov.ActiveCount() == 0, "legacy authority retired");
    Check(!cov.Register("new-signer", 1) && !cov.Activate("ordinary-signer"), "legacy registration retired");
    Check(cov.GetCopy(paid.request_id)->status == ReqStatus::FULFILLED, "archived paid lookup");
    Check(cov.GetCopy(defaulted.request_id)->status == ReqStatus::DEFAULTED, "archived default lookup");
    Check(cov.GetCopy(open.request_id)->request_commitment == open.request_commitment, "open commitment preserved");
    Check(cov.SnapshotState().requests.size() == 1 && cov.SnapshotState().consumed_payouts.empty(), "terminal history leaves hot state");
    Check(cov.IsConsumedPayout(Tag(102)) && cov.IsConsumedFraudSpend(Tag(103)), "consumed identities retained");
    Check(!cov.ConsumeFraudSpend(Tag(103)), "consumed evidence stays consumed");
    Refuses([&] { cov.AddRequest(paid, true); }, "archived paid identifier never admitted");
    const auto migrated = cov.SnapshotState();
    const Hash256 migrated_digest = cov.Digest();
    const auto verdict = cov.EvalNonPayment(open.request_id, 2886);
    Check(verdict.slash && verdict.compensate_sats == open.amount_sats, "unpaid principal independent of retired bond");
    cov.ApplySlash(verdict);
    cov.SetStatus(open.request_id, ReqStatus::DEFAULTED);
    cov.FinishBlock();
    Check(cov.SnapshotState().signers.empty() && cov.SnapshotState().requests.empty(), "settlement-only locks released");
    Check(cov.GetCopy(open.request_id)->status == ReqStatus::DEFAULTED, "settled legacy lock archived");
    const Hash256 settled_digest = cov.Digest();
    cov.RestoreState(migrated);
    Check(cov.Digest() == migrated_digest && cov.GetCopy(open.request_id)->status == ReqStatus::LOCKED_IN, "candidate rollback restores open liability");
    cov.SetStatus(open.request_id, ReqStatus::DEFAULTED); cov.FinishBlock();
    Check(cov.Digest() == settled_digest, "settlement reapplication deterministic");
    cov.RestoreState(parent); cov.BeginBlock(H);
    Check(cov.Digest() == migrated_digest, "reorganization across migration");
    cov.BeginBlock(H+1);
    Check(cov.Digest() == migrated_digest, "migration only once");
}
void GovernanceAndEndorsements() {
    constexpr uint64_t H = SECURITY_STATE_MIGRATION_HEIGHT;
    std::vector<RealKeyPair> keys;
    for (int i=0;i<5;++i) keys.push_back(GenerateKeyPair(false));
    ValidatorRegistry registry;
    ValidatorRegistry::StateSnapshot vs;
    Blockchain chain; StakingLedger staking;
    GovernanceEngine gov(chain, staking); gov.SetValidators(&registry);
    Check(!gov.GovernanceBondGateOpen(), "governance locked at zero validators");
    for (size_t i=0;i<keys.size();++i) {
        const auto& key=keys[i]; const std::string pk=Hex(key.public_key);
        ValidatorRecord r; r.pubkey_hex=pk; r.address=key.address; r.active=true;
        r.bond_custodial=true; r.bond_units=MIN_VALIDATOR_STAKE;
        r.registered_height=1;
        vs.validators[pk]=r; vs.address_to_pubkey[r.address]=pk;
        registry.RestoreState(vs);
        Check(gov.GovernanceBondGateOpen() == (i==4), "five distinct full bonds required");
    }
    const auto& key=keys.front();
    const std::string title="Budget caf\xc3\xa9 | phase:2";
    const std::string description="Ordinary UTF-8 proposal.";
    const auto type=ProposalType::GENERAL;
    const std::string challenge=GovernanceEngine::BuildProposalChallenge(type,key.address,title,description,H-1,true,true);
    const std::string signature=Sig(key,challenge);
    const std::string marker=GovernanceEngine::BuildFramedProposalOp(type,key.address,title,description,H-1,Hex(key.public_key),signature);
    const auto before=gov.SnapshotState();
    gov.ProcessBlock(Carrier(H-1,marker),H-1,false);
    Check(gov.SnapshotState().proposals.empty(), "future format does not apply before H");
    gov.ProcessBlock(Carrier(H,marker),H,false);
    auto state=gov.SnapshotState();
    Check(state.proposals.size()==1, "framed proposal applies at H");
    const Proposal proposal=state.proposals.begin()->second;
    Check(proposal.title==title && proposal.description==description, "proposal UTF-8 fields preserved");
    const auto identity=GovernanceEngine::VoteIdentity(proposal);
    const std::string vote_challenge=GovernanceEngine::BuildVoteChallenge(proposal.id,VoteChoice::YES,H,identity);
    const auto vote_signature=Sig(key,vote_challenge);
    const std::string vote=GovernanceEngine::BuildVoteOp(proposal.id,key.address,VoteChoice::YES,H,Hex(key.public_key),vote_signature,identity);
    gov.ProcessBlock(Carrier(H+1,vote),H+1,false);
    state=gov.SnapshotState();
    Check(state.proposals.at(proposal.id).votes_yes==1, "bound vote applies after new proposal");
    const auto expiry=state.proposals.at(proposal.id).expires_at;
    const auto voted_digest=gov.GovernanceDigest();
    gov.RestoreState(state); gov.ProcessBlock(Carrier(H+2,"ordinary"),H+2,false);
    Check(gov.SnapshotState().proposals.at(proposal.id).expires_at==expiry, "new migration does not restart expiry");
    Check(gov.SnapshotState().proposals.at(proposal.id).votes_yes==1, "new migration preserves votes");
    gov.RestoreState(before); gov.ProcessBlock(Carrier(H,marker),H,false);
    gov.ProcessBlock(Carrier(H+1,vote),H+1,false);
    Check(gov.GovernanceDigest()==voted_digest, "proposal/vote replay digest");
    Check(GovernanceEngine::BuildProposalChallenge(type,key.address,"A|B","C",H,true,true) !=
          GovernanceEngine::BuildProposalChallenge(type,key.address,"A","B|C",H,true,true), "field framing is unambiguous");

    const Hash256 target=Tag(888);
    const std::string endorse_sig=Hex(Sign(key.private_key,ValidatorRegistry::BuildEndorseMessage(H-1,target)));
    const std::string current=ValidatorRegistry::BuildEndorseOp(H-1,HashToHex(target),endorse_sig,key.address,H);
    EndorsementWire wire;
    Check(ParseEndorsementWire(current,wire) && wire.attributed && wire.address==key.address, "new endorsement producer/parser agreement");
    Block endorsed=Carrier(H,current);
    registry.RestoreState(vs);
    Check(registry.ProcessBlock(endorsed,[](const auto&){return uint64_t{0};}), "attributed endorsement process");
    Check(registry.HasAcceptedEndorsement(key.address,H-1,HashToHex(target),endorse_sig), "ordinary attributed endorsement accepted");
    std::optional<rpc_detail::ValidatorEndorsementTarget> extracted;
    Check(rpc_detail::ExtractValidatorEndorsementTarget(endorsed.transactions[0],extracted) &&
          extracted && extracted->height==H-1 && extracted->hash==target, "RPC work admission target remains bound");
    const auto endorsed_state=registry.SnapshotState();
    const auto endorsed_digest=registry.ValidatorsDigest();
    const ValidatorRegistry copied(registry);
    Check(copied.SnapshotState().state_migration_active &&
          copied.ValidatorsDigest()==endorsed_digest, "registry copy preserves migration state");
    registry.RestoreState(vs);
    const auto legacy=ValidatorRegistry::BuildEndorseOp(H-1,HashToHex(target),endorse_sig);
    registry.ProcessBlock(Carrier(H,legacy),[](const auto&){return uint64_t{0};});
    Check(!registry.HasAcceptedEndorsement(key.address,H-1,HashToHex(target),endorse_sig), "legacy format inactive at H");
    registry.RestoreState(vs);
    registry.ProcessBlock(Carrier(H-1,legacy),[](const auto&){return uint64_t{0};});
    Check(registry.HasAcceptedEndorsement(key.address,H-1,HashToHex(target),endorse_sig), "historical endorsement replay");
    registry.RestoreState(endorsed_state);
    Check(registry.ValidatorsDigest()==endorsed_digest, "endorsement rollback digest");
    Block bounded;
    bounded.height=H;
    for(size_t i=0;i<ValidatorRegistry::MAX_ENDORSEMENT_VERIFICATIONS_PER_BLOCK;++i)
        bounded.transactions.push_back(endorsed.transactions[0]);
    Check(ValidatorRegistry::HasValidRegisterMultiplicity(bounded), "declared endorsement work bound");
    bounded.transactions.push_back(endorsed.transactions[0]);
    Check(!ValidatorRegistry::HasValidRegisterMultiplicity(bounded), "excess work rejected before processing");
}

void DefaultCompensationChecks() {
    // Trusted module-state fixture for an already-open, fully backed request.
    // This exercises the real token/covenant settlement methods, not Bitcoin SPV.
    constexpr uint64_t H=SECURITY_STATE_MIGRATION_HEIGHT;
    const auto recipient=GenerateKeyPair(false);
    OnChainTokenLedger tokens;
    auto token_parent=tokens.SnapshotState();
    token_parent.tokens[BTCVELD_TOKEN_ID]={BTCVELD_TOKEN_ID,"btcVELD",recipient.address,8,"BTC"};
    token_parent.supply[BTCVELD_TOKEN_ID]=40000;
    token_parent.balances[std::string(BTCVELD_TOKEN_ID)+":"+recipient.address]=40000;
    auto& reserve=token_parent.reserve_state;
    reserve.status=btcveld::reserve::Status::ACTIVE;
    reserve.reserve_txid=Tag(901); reserve.reserve_vout=0;
    reserve.reserve_value_sats=50000; reserve.reserve_bitcoin_block=Tag(902);
    reserve.open_redemption_principal=10000;
    Check(reserve.AccountingHolds(40000), "backed compensation parent accounting");
    tokens.RestoreState(token_parent);
    MemoryArchive memory;
    SignerBondCovenant covenant; memory.Wire(covenant);
    tokens.SetBtcVeldRedeemCovenant(&covenant);
    auto request=Request(903); request.amount_sats=10000;
    request.veld_recipient=recipient.address; request.dest_spk=recipient.GetP2PKHScript();
    request.deadline_height=H+2;
    request.request_commitment=SignerBondCovenant::RequestCommitment(request);
    covenant.AddRequest(request,true); covenant.BeginBlock(H);
    const auto covenant_parent=covenant.SnapshotState();
    const auto token_digest=tokens.Digest();
    const auto covenant_digest=covenant.Digest();
    auto settle=[&]() {
        const auto verdict=covenant.EvalNonPayment(request.request_id,H+3);
        Check(verdict.slash && verdict.compensate_sats==10000, "full default liability survives authority retirement");
        covenant.ApplySlash(verdict);
        Check(tokens.CompensateMint(verdict.compensate_to,verdict.compensate_sats,H+3,"migration-default-fixture"), "real token compensation credit");
        covenant.SetStatus(request.request_id,ReqStatus::DEFAULTED); covenant.FinishBlock();
    };
    settle();
    Check(tokens.GetSupply(BTCVELD_TOKEN_ID)==50000 &&
          tokens.GetBalance(BTCVELD_TOKEN_ID,recipient.address)==50000, "exact owed principal credited");
    Check(tokens.GetBtcVeldReserveState().AccountingHolds(50000) &&
          tokens.GetBtcVeldReserveState().open_redemption_principal==0, "settlement preserves reserve accounting");
    Check(covenant.SnapshotState().requests.empty() &&
          covenant.GetCopy(request.request_id)->status==ReqStatus::DEFAULTED, "settled compensation archived");
    Check(!tokens.CompensateMint(recipient.address,10000,H+4,"already-settled"), "closed principal cannot compensate twice");
    const auto settled_token=tokens.Digest(), settled_covenant=covenant.Digest();
    tokens.RestoreState(token_parent); covenant.RestoreState(covenant_parent);
    Check(tokens.Digest()==token_digest && covenant.Digest()==covenant_digest, "combined token and covenant rollback");
    settle();
    Check(tokens.Digest()==settled_token && covenant.Digest()==settled_covenant, "combined compensation replay");
}
}
int main(int argc,char** argv) {
    try {
        if(argc!=2) throw std::runtime_error("supply a fresh fixture directory");
        const auto path=std::filesystem::absolute(argv[1]);
        if(std::filesystem::exists(path)) throw std::runtime_error("fixture directory must be fresh");
        ArchiveChecks(path);
        CovenantChecks();
        GovernanceAndEndorsements();
        DefaultCompensationChecks();
        std::cout<<"PASS security_state_migration_tests checks="<<checks<<" activation=2880\n";
        return 0;
    } catch(const std::exception& e) {
        std::cerr<<"FAIL security_state_migration_tests: "<<e.what()<<"\n";
        return 1;
    }
}
