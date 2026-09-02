#include "../include/node/work_admission.h"

#include <cstdlib>
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

using namespace veld;
using namespace veld::work_admission;

namespace {

int checks = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition) {
        std::cerr << "FAIL: " << label << "\n";
        std::exit(1);
    }
}

Hash256 Filled(uint8_t byte) {
    Hash256 value{};
    value.fill(byte);
    return value;
}

Prerequisites OpenPrerequisites() {
    Prerequisites p;
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
    p.validation_generation = 9;
    p.network_magic = 0x56454c44u;
    p.genesis_hash = Filled(0x11);
    p.profile_digest = Filled(0x22);
    return p;
}

Subject BlockSubject() {
    Subject subject;
    subject.purpose = Purpose::BlockProduction;
    subject.height = 43;
    subject.parent_height = 42;
    subject.parent_hash = Filled(0x33);
    return subject;
}

}  // namespace

int main() {
    const Prerequisites open = OpenPrerequisites();
    const Subject block = BlockSubject();

    Check(!Evaluate(block, Prerequisites{}).allowed,
          "all-default unknown state fails closed");

    using Mutator = std::function<void(Prerequisites&)>;
    const std::vector<std::pair<Refusal, Mutator>> false_prerequisites{
        {Refusal::RoleDenied, [](auto& p) { p.role_permitted = false; }},
        {Refusal::NodeNotRunning, [](auto& p) { p.node_running = false; }},
        {Refusal::StartupReplayIncomplete,
         [](auto& p) { p.startup_replay_complete = false; }},
        {Refusal::IndependentValidationIncomplete,
         [](auto& p) { p.independent_validation_complete = false; }},
        {Refusal::SyncIncomplete, [](auto& p) { p.sync_complete = false; }},
        {Refusal::SnapshotStateUntrusted,
         [](auto& p) { p.snapshot_state_clean = false; }},
        {Refusal::DurableStateUnproven,
         [](auto& p) { p.durable_state_proven = false; }},
        {Refusal::DatadirIdentityUnproven,
         [](auto& p) { p.datadir_identity_valid = false; }},
        {Refusal::CheckpointAnchorUnproven,
         [](auto& p) { p.checkpoint_anchor_valid = false; }},
        {Refusal::TipUnknown,
         [](auto& p) { p.canonical_tip_known = false; }},
        {Refusal::RuntimeClosed, [](auto& p) { p.runtime_open = false; }},
        {Refusal::PeerViewUnsafe, [](auto& p) { p.peer_view_safe = false; }},
    };
    for (const auto& [expected, mutate] : false_prerequisites) {
        Prerequisites p = open;
        mutate(p);
        const auto decision = Evaluate(block, p);
        Check(!decision.allowed && decision.refusal == expected,
              RefusalName(expected));
    }

    const auto issued = Evaluate(block, open);
    Check(issued.allowed && issued.binding.has_value(),
          "all prerequisites open together");
    Check(Evaluate(block, open, issued.binding, true).allowed,
          "exact binding recheck succeeds");
    Check(Evaluate(block, open, std::nullopt, true).refusal ==
              Refusal::BindingMissing,
          "missing prior binding rejected");

    const std::string encoded = EncodeBinding(*issued.binding);
    const auto decoded = DecodeBinding(encoded);
    Check(decoded && *decoded == *issued.binding,
          "binding canonical round trip");
    std::string uppercase = encoded;
    uppercase.back() = 'A';
    Check(!DecodeBinding(uppercase), "uppercase binding rejected");
    Check(!DecodeBinding(encoded + "00"), "oversize binding rejected");

    auto RejectTamper = [&](const std::function<void(Binding&)>& mutate,
                            const char* label) {
        Binding changed = *issued.binding;
        mutate(changed);
        Check(Evaluate(block, open, changed, true).refusal ==
                  Refusal::BindingMismatch,
              label);
    };
    RejectTamper([](auto& b) { b.subject.purpose = Purpose::FinalityVote; },
                 "purpose tamper rejected");
    RejectTamper([](auto& b) { ++b.subject.height; },
                 "height tamper rejected");
    RejectTamper([](auto& b) { b.subject.target_hash = Filled(0x44); },
                 "target tamper rejected");
    RejectTamper([](auto& b) { ++b.subject.parent_height; },
                 "parent height tamper rejected");
    RejectTamper([](auto& b) { b.subject.parent_hash = Filled(0x55); },
                 "parent hash tamper rejected");
    RejectTamper([](auto& b) { ++b.validation_generation; },
                 "validation generation tamper rejected");
    RejectTamper([](auto& b) { ++b.network_magic; },
                 "network magic tamper rejected");
    RejectTamper([](auto& b) { b.genesis_hash = Filled(0x66); },
                 "genesis tamper rejected");
    RejectTamper([](auto& b) { b.profile_digest = Filled(0x77); },
                 "profile tamper rejected");

    Subject finality = block;
    finality.purpose = Purpose::FinalityVote;
    finality.height = 20;
    finality.target_hash = Filled(0x88);
    Check(Evaluate(finality, open).allowed,
          "historical canonical finality target shape accepted");
    finality.target_hash.fill(0);
    Check(Evaluate(finality, open).refusal == Refusal::SubjectNotCanonical,
          "zero finality target rejected");

    Subject malformed = block;
    malformed.height = malformed.parent_height + 2;
    Check(Evaluate(malformed, open).refusal == Refusal::SubjectNotCanonical,
          "non-next block work rejected");
    malformed = block;
    malformed.target_hash = Filled(0x99);
    Check(Evaluate(malformed, open).refusal == Refusal::SubjectNotCanonical,
          "block work target must be unresolved zero");

    std::cout << "PASS checks=" << checks << "\n";
    return 0;
}
