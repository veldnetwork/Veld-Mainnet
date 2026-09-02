#include "node/node.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

using namespace veld;

namespace {

size_t checks = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition) {
        std::cerr << "FAIL: " << label << "\n";
        std::exit(1);
    }
}

Hash256 Filled(uint8_t value) {
    Hash256 hash{};
    hash.fill(value);
    return hash;
}

work_admission::AdmissionCoordinator::Configuration OpenConfiguration(
        const work_admission::AdmissionCoordinator& coordinator) {
    const uint64_t close_epoch_before = coordinator.ObserveCloseEpoch();
    work_admission::AdmissionCoordinator::Configuration configuration;
    auto& p = configuration.prerequisites;
    p.role_permitted = true;
    p.node_running = true;
    p.startup_replay_complete = true;
    p.independent_validation_complete = true;
    p.sync_complete = true;
    p.snapshot_state_clean = true;
    p.durable_state_proven = true;
    p.datadir_identity_valid = true;
    p.checkpoint_anchor_valid = true;
    p.canonical_tip_known = true;
    p.runtime_open = true;
    p.peer_view_safe = true;
    p.validation_generation = 7;
    p.network_magic = MAINNET_MAGIC;
    p.genesis_hash = Filled(0x11);
    p.profile_digest = Filled(0x22);
    configuration.permitted_paths.fill(true);
    work_admission::AdmissionCoordinator::BindCloseEpochSnapshot(
        configuration, close_epoch_before, coordinator.ObserveCloseEpoch());
    return configuration;
}

work_admission::Subject FinalitySubject() {
    work_admission::Subject subject;
    subject.purpose = work_admission::Purpose::FinalityVote;
    subject.height = finality::qc::CHECKPOINT_INTERVAL;
    subject.target_hash = Filled(0x33);
    subject.parent_height = 120;
    subject.parent_hash = Filled(0x44);
    return subject;
}

}  // namespace

int main() {
    namespace fq = ::veld::finality::qc;
    using Coordinator = work_admission::AdmissionCoordinator;

    // This is a canonical standalone-validator wire frame: exact FVT1 binary
    // length, scheduled checkpoint, canonical phase/round, exact key and
    // signature widths.  It is intentionally not registered in this empty
    // fixture, so the verifier returns RejectedState after entering the state
    // gate.  Before the fix it deadlocked trying to acquire that gate twice.
    fq::SignedVote vote;
    vote.epoch_id = fq::EpochOf(fq::CHECKPOINT_INTERVAL);
    vote.set_root = Filled(0x55);
    vote.phase = fq::Phase::PREVOTE;
    vote.round = fq::CheckpointRound(fq::CHECKPOINT_INTERVAL);
    vote.target.height = fq::CHECKPOINT_INTERVAL;
    vote.target.hash = Filled(0x66);
    vote.pubkey_hex.assign(dilithium::PUBKEY_BYTES * 2, '0');
    vote.signature.assign(dilithium::SIG_MAX_BYTES, 0);
    const auto wire = fq::EncodeSignedVoteWire(vote);
    Check(wire.size() == fq::SIGNED_VOTE_WIRE_BYTES,
          "canonical standalone finality wire encoded");

    const auto suffix = std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    const auto datadir = std::filesystem::temp_directory_path() /
        ("veld-finality-work-lock-" + suffix);
    {
        VeldNode node(MainnetConfig(), datadir.string());
        const auto started = std::chrono::steady_clock::now();
        const auto result =
            node.TestVerifyFinalityVoteWireWithHeldTransition(wire);
        const auto elapsed = std::chrono::steady_clock::now() - started;
        Check(result == net::NodeServer::FinalityVoteVerifyResult::RejectedState,
              "caller-held verifier reaches deterministic state result");
        Check(elapsed < std::chrono::seconds(2),
              "caller-held verifier does not recursively deadlock");
    }
    std::error_code cleanup_error;
    std::filesystem::remove_all(datadir, cleanup_error);
    Check(!cleanup_error && !std::filesystem::exists(datadir),
          "fixture datadir removed");

    uint8_t next_token = 1;
    Coordinator coordinator(
        Coordinator::Limits{std::chrono::milliseconds(500),
                            std::chrono::milliseconds(1200), 4, 8},
        [&](Coordinator::TokenBytes& token) {
            token.fill(next_token++);
            return true;
        });
    const auto configuration = OpenConfiguration(coordinator);
    Check(coordinator.Open(configuration).opened,
          "finality coordinator opens explicitly");
    const auto subject = FinalitySubject();
    auto issued = coordinator.IssueRemoteSigningLease(
        work_admission::Path::FinalityVote, subject, std::nullopt,
        false, std::chrono::milliseconds(1000));
    Check(issued && issued.grant,
          "remote finality capability issued before close");
    const auto closing = coordinator.BeginClose(
        work_admission::Refusal::BindingMismatch);
    Check(!closing.fully_closed && coordinator.GetSnapshot().phase ==
              Coordinator::Phase::Closing,
          "acquired-first finality capability holds bounded closing phase");
    auto consumed = coordinator.ConsumeRemoteSigningLease(
        issued.grant->token, work_admission::Path::FinalityVote, subject,
        issued.grant->binding);
    Check(consumed && consumed.lease,
          "acquired-first finality capability consumes while closing");
    Check(consumed.lease->ClaimForSink(),
          "acquired-first finality sink claims exactly once");
    Check(!consumed.lease->ClaimForSink(),
          "claimed finality sink cannot be replayed");
    consumed.lease.reset();
    Check(coordinator.GetSnapshot().phase == Coordinator::Phase::Closed,
          "finality close completes after acquired-first sink releases");

    const auto close_wins = coordinator.IssueRemoteSigningLease(
        work_admission::Path::FinalityVote, subject, issued.grant->binding,
        false, std::chrono::milliseconds(1000));
    Check(!close_wins &&
              close_wins.error == Coordinator::Error::Closed,
          "close-first finality acquisition emits no capability");

    std::cout << "PASS daybreak_finality_work_admission_lock_tests checks="
              << checks << "\n";
    return 0;
}
