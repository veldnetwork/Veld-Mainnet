#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_ASERT_TESTCHAIN 1
#include "consensus/finality_equivocation.h"
#include <iostream>
#include <stdexcept>

namespace fq = veld::finality::qc;
using namespace veld;
unsigned checks = 0;
void Check(bool value, const char* message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}
std::vector<uint8_t> Journal(const std::vector<fq::SignedVote>& votes) {
    std::vector<uint8_t> out{'V','E','J','1'};
    state_digest::put_u32_le(out, static_cast<uint32_t>(votes.size()/2));
    for (const auto& vote : votes) {
        const auto wire = fq::EncodeSignedVoteWire(vote);
        out.insert(out.end(), wire.begin(), wire.end());
    }
    const auto checksum = state_digest::sha256_domain(
        fq::DOMAIN_EQUIVOCATION_JOURNAL, out);
    out.insert(out.end(), checksum.begin(), checksum.end());
    return out;
}
int main() {
    try {
        const auto key = dilithium::Generate();
        Hash256 genesis{};
        const auto bytes = HexToBytes(GENESIS_HASH);
        std::copy(bytes.begin(), bytes.end(), genesis.begin());
        fq::SnapshotEntry member;
        member.pubkey_hex = BytesToHex(key.public_key.data(), key.public_key.size());
        member.pubkey_commit = fq::PubkeyCommit(member.pubkey_hex);
        fq::SignedVote a;
        a.epoch_id = 0; a.set_root.fill(0x11); a.phase = fq::Phase::PREVOTE;
        a.round = fq::CheckpointRound(20); a.target.height = 20;
        a.target.hash.fill(0x31); a.pubkey_hex = member.pubkey_hex;
        auto b = a; b.target.hash.fill(0x32);
        const auto sign = [&](fq::SignedVote& vote) {
            vote.signature = dilithium::Sign(key.secret_key, fq::VotePreimage(
                fq::NETWORK_ID, genesis, vote.epoch_id, vote.set_root, vote.phase,
                vote.round, vote.source, vote.target));
        };
        sign(a); sign(b);
        const auto wire = Journal({a,b});
        fq::FinalityEquivocationCollector collector;
        unsigned membership_checks = 0;
        const auto absent = [&](const fq::SignedVote&, const fq::SignedVote&)
                -> std::optional<fq::ValidatedEquivocationEvidence> {
            ++membership_checks; return std::nullopt;
        };
        const auto member_present = [&](const fq::SignedVote& x, const fq::SignedVote& y) {
            ++membership_checks;
            return fq::ValidateEquivocationPairForRetainedMember(x,y,0,a.set_root,
                member,20,fq::NETWORK_ID,genesis);
        };
        const uint64_t boundary = 20 + fq::FINALITY_EQUIV_EVIDENCE_WINDOW;
        const auto restore = [&](const std::vector<uint8_t>& input,
                const fq::FinalityEquivocationCollector::PairValidator& validator,
                uint64_t tip, uint32_t network = fq::NETWORK_ID) {
#ifdef VELD_JOURNAL_EXPIRY_BASELINE
            (void)tip; (void)network;
            return collector.Restore(input, validator);
#else
            return collector.RestoreJournalAtTip(input, validator, tip, network, genesis);
#endif
        };
        Check(restore(wire, member_present, 20), "ordinary authenticated journal rejected");
        Check(collector.PairCount()==1, "live evidence missing");
        Check(!restore(wire, absent, boundary), "actionable boundary lost membership check");
        Check(collector.PairCount()==1, "failed restore changed live collector");
        const unsigned before = membership_checks;
        Check(restore(wire, absent, boundary+1), "expired signed journal blocks recovery after membership ages out");
        Check(membership_checks==before && collector.PairCount()==0,
              "expired row became a membership capability");
        Check(collector.Encode()==Journal({}), "expired storage charge or bytes retained");
        Check(!restore(wire, absent, boundary+1, fq::NETWORK_ID^1), "wrong chain signature accepted");
        auto bad = a; bad.signature[0] ^= 1;
        Check(!restore(Journal({bad,b}), absent, boundary+1), "bad expired signature skipped");
        bad = a; bad.round += 1; sign(bad);
        Check(!restore(Journal({bad,b}), absent, boundary+1), "malformed expired round skipped");
        bad = b; bad.target.height += 20; sign(bad);
        Check(!restore(Journal({a,bad}), absent, boundary+1), "different target heights skipped");
        Check(!restore(Journal({b,a}), absent, boundary+1), "noncanonical pair ordering skipped");
        Check(!restore(Journal({a,b,a,b}), absent, boundary+1), "duplicate expired rows skipped");
        auto corrupt = wire; corrupt.back() ^= 1;
        Check(!restore(corrupt, absent, boundary+1), "bad journal checksum skipped");
        corrupt = wire; corrupt.push_back(0);
        Check(!restore(corrupt, absent, boundary+1), "trailing journal bytes skipped");
        Check(!collector.Restore(wire, absent), "strict Restore contract relaxed");
        Check(restore(wire, member_present, boundary), "live boundary control rejected");
        Check(collector.PairCount()==1, "live boundary control disappeared");
        std::cout << "PASS finality journal expiry checks=" << checks << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n'; return 1;
    }
}
