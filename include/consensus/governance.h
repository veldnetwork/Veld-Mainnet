#pragma once

#include "../core/constants.h"
#include "../core/canonical_numeric.h"
#include "../core/blockchain.h"
#include "../core/json_escape.h"
#include "../consensus/staking.h"
#include "../consensus/validators.h"
#include "../wallet/wallet.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <functional>
#include <cmath>
#include <algorithm>
#include <optional>
#include <limits>

namespace veld {

constexpr uint32_t GOV_VOTE_DURATION_DAYS    = 14;

constexpr uint32_t GOV_QUORUM_GENERAL        = 7;
constexpr uint32_t GOV_QUORUM_PROTOCOL       = 10;

constexpr uint32_t GOV_PASS_PCT_GENERAL      = 51;
constexpr uint32_t GOV_PASS_PCT_PROTOCOL     = 67;

constexpr uint32_t GOV_PROTOCOL_TIMELOCK     = 7 * BLOCKS_PER_DAY;      // 7 days

constexpr uint64_t GOV_ACTIVE_WINDOW         = 7ULL * BLOCKS_PER_DAY;   // 7 days
static_assert(TARGET_BLOCK_TIME != 60 ||
              (GOV_PROTOCOL_TIMELOCK == 10080 && GOV_ACTIVE_WINDOW == 10080),
              "wall-clock re-expression must preserve the legacy 60s profile");

// DISPLAY-ONLY (explorer/RPC headline). NOT a consensus gate. The real
// participation floor is the per-type quorum enforced in GetMinVotesRequired /
// GetDynamicMinVotes: PROTOCOL_UPGRADE needs >= GOV_QUORUM_PROTOCOL with no
// sub-quorum collapse, while GENERAL keeps the softer GOV_QUORUM_GENERAL floor
// so signalling remains usable at the mainnet governance-activation point. Kept
// (== GOV_QUORUM_PROTOCOL) only so the UI can show one "validators needed"
// number; do not read it in any consensus path.
constexpr uint32_t GOV_MIN_ACTIVE_VALIDATORS = 10;

constexpr uint32_t GOV_PASS_PCT              = GOV_PASS_PCT_GENERAL;
constexpr uint32_t GOV_MIN_VOTES_PASS        = GOV_QUORUM_GENERAL;

enum class ProposalStatus { OPEN, PASSED, REJECTED, EXPIRED, TIMELOCKED };
enum class VoteChoice     { YES, NO, ABSTAIN };
enum class ProposalType   { GENERAL, PROTOCOL_UPGRADE };

struct Proposal {
    uint64_t    id            = 0;
    ProposalType type         = ProposalType::GENERAL;
    std::string title;
    std::string description;
    std::string proposer;
    std::time_t created_at    = 0;
    std::time_t expires_at    = 0;
    ProposalStatus status     = ProposalStatus::OPEN;
    uint32_t    votes_yes     = 0;
    uint32_t    votes_no      = 0;
    uint32_t    votes_abstain = 0;
    std::unordered_map<std::string, VoteChoice> votes;

    uint64_t    timelock_until        = 0;
};

struct GovernanceEligibility {
    bool   can_vote;
    bool   can_propose;
    uint64_t blocks_mined;
    double   staked_veld;
    double   held_veld;
    std::string reason;
};

class GovernanceEngine {
public:
    GovernanceEngine(const Blockchain& chain, const StakingLedger& staking)
        : chain_(chain), staking_(staking), validators_(nullptr), next_id_(1) {}

    void SetValidators(const ValidatorRegistry* v) { validators_ = v; }

    // MAINNET governance-activation gate. Open once validators have bonded
    // >= GOVERNANCE_ACTIVATION_BONDED_UNITS (each bond capped at MIN_VALIDATOR_STAKE
    // ⇒ >= 5 validators × 10k = 50,000 VELD on mainnet). On the test chain
    // (GOVERNANCE_BOND_GATE_ACTIVE=false) it is ALWAYS open — governance stays
    // always-active for testing. Pure fn of the replayed validator set + the
    // compile-time constants; consulted by every apply-path entry below so the
    // whole system is dormant on mainnet until the bonded quorum exists.
    bool GovernanceBondGateOpen() const {
        if (!GOVERNANCE_BOND_GATE_ACTIVE) return true;
        return validators_ &&
               validators_->GetGovernanceBondedTotal() >= GOVERNANCE_ACTIVATION_BONDED_UNITS;
    }

    using KVPut  = std::function<void(const std::string& key, const std::string& val)>;
    using KVDel  = std::function<void(const std::string& key)>;
    using KVScan = std::function<void(const std::string& prefix,
                                       std::function<bool(const std::string&, const std::string&)>)>;

    void SetPersistence(KVPut put, KVDel del, KVScan scan) {
        kv_put_  = put;
        kv_del_  = del;
        kv_scan_ = scan;
    }

    void LoadFromKV() {
        if (!kv_scan_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        proposals_.clear();
        next_id_ = 1;
        uint64_t loaded_max_id = 0;
        kv_scan_("gov:prop:", [&](const std::string& key,
                                  const std::string& val) -> bool {
            static constexpr size_t PREFIX_LEN = 9;
            if (key.size() <= PREFIX_LEN ||
                key.compare(0, PREFIX_LEN, "gov:prop:") != 0) return true;
            uint64_t key_id = 0;
            if (!ParseCanonicalUint64Text(
                    std::string_view(key).substr(PREFIX_LEN), key_id) ||
                key_id == 0 || key_id == UINT64_MAX) return true;
            Proposal p;
            if (DeserializeProposal(val, p) && p.id == key_id) {
                proposals_[key_id] = std::move(p);
                if (key_id > loaded_max_id) loaded_max_id = key_id;
            }
            return true;
        });
        auto next_id_cb = [&](const std::string& key,
                              const std::string& val) -> bool {
            if (key != "gov:next_id") return true;
            uint64_t parsed = 0;
            if (ParseCanonicalUint64Text(val, parsed) && parsed > 0)
                next_id_ = parsed;
            return false;
        };
        kv_scan_("gov:next_id", next_id_cb);
        if (next_id_ <= loaded_max_id) next_id_ = loaded_max_id + 1;
    }

    void PersistAll() {
        std::lock_guard<std::mutex> lock(mutex_);
        PersistAllLocked();
    }

    void PruneOrphanedKV() {
        std::lock_guard<std::mutex> lock(mutex_);
        PruneOrphanedKVLocked();
    }

    void PruneOrphanedKVLocked() {
        if (!kv_scan_ || !kv_del_) return;
        std::vector<std::string> to_delete;
        kv_scan_("gov:prop:", [&](const std::string& key, const std::string& ) -> bool {
            uint64_t id = 0;
            if (key.size() <= 9 ||
                key.compare(0, 9, "gov:prop:") != 0 ||
                !ParseCanonicalUint64Text(
                    std::string_view(key).substr(9), id) ||
                id == 0 || proposals_.find(id) == proposals_.end()) {
                to_delete.push_back(key);
            }
            return true;
        });
        for (const auto& k : to_delete) kv_del_(k);
    }

    void PersistAllLocked() {
        if (!kv_put_) return;
        kv_put_("gov:next_id", std::to_string(next_id_));
        for (const auto& [id, p] : proposals_)
            kv_put_("gov:prop:" + std::to_string(id), SerializeProposal(p));
    }

    void Reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        proposals_.clear();
        last_proposal_block_.clear();
        last_vote_block_.clear();
        // Replay assigns proposal identifiers deterministically in chain order.
        // The persisted counter is informational and is not restored here.
        next_id_ = 1;
        PruneOrphanedKVLocked();
    }

    // Atomic block-state snapshot and restore. Captures exactly
    // the block-mutable state Reset() clears — next_id_ + the three maps — so the
    // block-connect path can roll governance back verbatim on an all-or-nothing
    // block reject (never the mutex, cond-var, KV callbacks, or gov_debug_).
    struct StateSnapshot {
        uint64_t                                   next_id = 1;
        std::unordered_map<uint64_t, Proposal>     proposals;
        std::unordered_map<std::string, uint64_t>  last_proposal_block;
        std::unordered_map<std::string, uint64_t>  last_vote_block;
    };
    StateSnapshot SnapshotState() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return StateSnapshot{ next_id_, proposals_, last_proposal_block_,
                              last_vote_block_ };
    }
    void RestoreState(const StateSnapshot& s) {
        std::lock_guard<std::mutex> lock(mutex_);
        next_id_              = s.next_id;
        proposals_            = s.proposals;
        last_proposal_block_  = s.last_proposal_block;
        last_vote_block_      = s.last_vote_block;
    }

    Hash256 GovernanceDigest() const {
        std::lock_guard<std::mutex> lock(mutex_);
        namespace sd = ::veld::state_digest;
        std::vector<uint8_t> body;
        sd::put_u64_le(body, next_id_);
        std::vector<uint64_t> ids;
        ids.reserve(proposals_.size());
        for (const auto& [k, _] : proposals_) ids.push_back(k);
        std::sort(ids.begin(), ids.end());
        sd::put_u32_le(body, (uint32_t)ids.size());
        for (uint64_t id : ids) {
            const auto& p = proposals_.at(id);
            sd::put_u64_le(body, p.id);
            sd::put_u8(body, (uint8_t)p.type);
            sd::put_u8(body, (uint8_t)p.status);
            sd::put_len_prefixed(body, p.title);
            sd::put_len_prefixed(body, p.description);
            sd::put_len_prefixed(body, p.proposer);
            sd::put_u64_le(body, (uint64_t)p.created_at);
            sd::put_u64_le(body, (uint64_t)p.expires_at);
            sd::put_u32_le(body, p.votes_yes);
            sd::put_u32_le(body, p.votes_no);
            sd::put_u32_le(body, p.votes_abstain);
            std::vector<std::pair<std::string, VoteChoice>> votes_sorted;
            votes_sorted.reserve(p.votes.size());
            for (const auto& [v, c] : p.votes) votes_sorted.emplace_back(v, c);
            std::sort(votes_sorted.begin(), votes_sorted.end(),
                      [](const auto& a, const auto& b) { return a.first < b.first; });
            sd::put_u32_le(body, (uint32_t)votes_sorted.size());
            for (const auto& [v, c] : votes_sorted) {
                sd::put_len_prefixed(body, v);
                sd::put_u8(body, (uint8_t)c);
            }
            sd::put_u64_le(body, p.timelock_until);
        }
        std::vector<std::pair<std::string, uint64_t>> lpb_sorted;
        lpb_sorted.reserve(last_proposal_block_.size());
        for (const auto& [k, v] : last_proposal_block_) lpb_sorted.emplace_back(k, v);
        std::sort(lpb_sorted.begin(), lpb_sorted.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        sd::put_u32_le(body, (uint32_t)lpb_sorted.size());
        for (const auto& [k, v] : lpb_sorted) {
            sd::put_len_prefixed(body, k);
            sd::put_u64_le(body, v);
        }
        std::vector<std::pair<std::string, uint64_t>> lvb_sorted;
        lvb_sorted.reserve(last_vote_block_.size());
        for (const auto& [k, v] : last_vote_block_) lvb_sorted.emplace_back(k, v);
        std::sort(lvb_sorted.begin(), lvb_sorted.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        sd::put_u32_le(body, (uint32_t)lvb_sorted.size());
        for (const auto& [k, v] : lvb_sorted) {
            sd::put_len_prefixed(body, k);
            sd::put_u64_le(body, v);
        }
        return sd::sha256_domain(sd::tags::GOVERNANCE, body);
    }

    void PruneExpired(uint64_t current_height) {
        std::lock_guard<std::mutex> lock(mutex_);
        (void)PruneExpiredLocked_(current_height, /*persist_deletes=*/true);
    }

    static std::string SerializeProposal(const Proposal& p) {
        std::ostringstream j;
        j << std::fixed << std::setprecision(4);
        j << "{"
          << "\"id\":" << p.id
          << ",\"type\":" << (int)p.type
          << ",\"title\":\"" << JsonEscape(p.title) << "\""
          << ",\"description\":\"" << JsonEscape(p.description) << "\""
          << ",\"proposer\":\"" << JsonEscape(p.proposer) << "\""
          << ",\"created_at\":" << (uint64_t)p.created_at
          << ",\"expires_at\":" << (uint64_t)p.expires_at
          << ",\"status\":" << (int)p.status
          << ",\"votes_yes\":" << p.votes_yes
          << ",\"votes_no\":" << p.votes_no
          << ",\"votes_abstain\":" << p.votes_abstain
          << ",\"timelock_until\":" << p.timelock_until
          << ",\"votes\":[";
        bool first = true;
        for (const auto& [addr, ch] : p.votes) {
            if (!first) j << ",";
            first = false;
            j << "{\"a\":\"" << JsonEscape(addr) << "\",\"c\":" << (int)ch << "}";
        }
        j << "]}";
        return j.str();
    }

    // Minimal JSON extraction — only used here, so we handwrite rather
    // than drag in a parser dep.
    //
    // Field lookup is string-aware. A naive substring search would let an attacker-
    // controlled title/description contain an escaped `":"` sequence
    // that masqueraded as a field boundary. A malicious validator could
    // craft a proposal title that alters deserialized vote counts or status.
    // findField ignores anything inside double-quoted values and only
    // matches field keys at the top object level (depth == 1).
    static bool DeserializeProposal(const std::string& blob, Proposal& out) {
        out = Proposal{};
        if (blob.size() < 2 || blob.size() > 64 * 1024 ||
            blob.front() != '{' || blob.back() != '}') return false;
        auto findField = [&blob](const std::string& name) -> size_t {
            std::string needle = "\"" + name + "\":";
            bool in_string = false;
            int depth = 0;
            for (size_t i = 0; i < blob.size(); ++i) {
                char c = blob[i];
                if (in_string) {
                    if (c == '\\' && i + 1 < blob.size()) { i += 1; continue; }
                    if (c == '"') in_string = false;
                    continue;
                }
                if (c == '"') {
                    if (depth == 1 && i + needle.size() <= blob.size()
                        && blob.compare(i, needle.size(), needle) == 0) {
                        return i;
                    }
                    in_string = true;
                    continue;
                }
                if (c == '{' || c == '[') ++depth;
                else if (c == '}' || c == ']') --depth;
            }
            return std::string::npos;
        };
        auto readU64 = [&](const std::string& name, uint64_t& out_v) -> bool {
            size_t p = findField(name); if (p == std::string::npos) return false;
            p += name.size() + 3;
            size_t end = p;
            while (end < blob.size() && blob[end] >= '0' && blob[end] <= '9')
                ++end;
            if (end == p || end >= blob.size() ||
                (blob[end] != ',' && blob[end] != '}' && blob[end] != ']'))
                return false;
            return ParseCanonicalUint64Text(
                std::string_view(blob).substr(p, end - p), out_v);
        };
        auto readI32 = [&](const std::string& name, int& out_v) -> bool {
            uint64_t v = 0;
            if (!readU64(name, v) ||
                v > static_cast<uint64_t>(std::numeric_limits<int>::max()))
                return false;
            out_v = (int)v;
            return true;
        };
        auto readU32 = [&](const std::string& name, uint32_t& out_v) -> bool {
            uint64_t v = 0;
            if (!readU64(name, v) || v > UINT32_MAX) return false;
            out_v = (uint32_t)v;
            return true;
        };
        auto readStr = [&](const std::string& name, std::string& out_v) -> bool {
            size_t p = findField(name); if (p == std::string::npos) return false;
            p += name.size() + 3;
            if (p >= blob.size() || blob[p] != '"') return false;
            ++p;
            std::string s;
            while (p < blob.size() && blob[p] != '"') {
                if (blob[p] == '\\' && p + 1 < blob.size()) {
                    char c = blob[p+1];
                    switch (c) {
                        case 'n': s += '\n'; break;
                        case 't': s += '\t'; break;
                        case 'r': s += '\r'; break;
                        case '"': s += '"';  break;
                        case '\\': s += '\\'; break;
                        case '/': s += '/'; break;
                        default: return false;
                    }
                    p += 2;
                } else {
                    s += blob[p++];
                }
            }
            if (p >= blob.size() || blob[p] != '"') return false;
            out_v = std::move(s);
            return true;
        };

        uint64_t u64_tmp = 0;
        uint32_t u32_tmp = 0;
        int i32_tmp = 0;
        if (!readU64("id", u64_tmp) || u64_tmp == 0 ||
            u64_tmp == UINT64_MAX) return false;
        out.id = u64_tmp;
        if (!readI32("type", i32_tmp) || i32_tmp < 0 || i32_tmp > 1)
            return false;
        out.type = (ProposalType)i32_tmp;
        if (!readStr("title", out.title) ||
            !readStr("description", out.description) ||
            !readStr("proposer", out.proposer)) return false;
        if (!readU64("created_at", u64_tmp) ||
            u64_tmp > static_cast<uint64_t>(
                std::numeric_limits<std::time_t>::max())) return false;
        out.created_at = (std::time_t)u64_tmp;
        if (!readU64("expires_at", u64_tmp) ||
            u64_tmp > static_cast<uint64_t>(
                std::numeric_limits<std::time_t>::max())) return false;
        out.expires_at = (std::time_t)u64_tmp;
        if (!readI32("status", i32_tmp) || i32_tmp < 0 || i32_tmp > 4)
            return false;
        out.status = (ProposalStatus)i32_tmp;
        if (!readU32("votes_yes", u32_tmp)) return false;
        out.votes_yes = u32_tmp;
        if (!readU32("votes_no", u32_tmp)) return false;
        out.votes_no = u32_tmp;
        if (!readU32("votes_abstain", u32_tmp)) return false;
        out.votes_abstain = u32_tmp;
        if (!readU64("timelock_until", u64_tmp)) return false;
        out.timelock_until = u64_tmp;

        size_t vp = findField("votes");
        if (vp == std::string::npos) return false;
        {
            vp = blob.find('[', vp);
            if (vp == std::string::npos) return false;
            {
                size_t end = blob.find(']', vp);
                if (end == std::string::npos) return false;
                if (end + 2 != blob.size() || blob[end + 1] != '}')
                    return false;
                {
                    std::string arr = blob.substr(vp + 1, end - vp - 1);
                    size_t cursor = 0;
                    while (cursor < arr.size()) {
                        if (cursor > 0) {
                            if (arr[cursor] != ',') return false;
                            ++cursor;
                        }
                        if (cursor >= arr.size() || arr[cursor] != '{')
                            return false;
                        size_t obj_start = cursor;
                        size_t obj_end = arr.find('}', obj_start);
                        if (obj_end == std::string::npos) return false;
                        std::string obj = arr.substr(obj_start, obj_end - obj_start + 1);
                        static constexpr std::string_view VOTE_PREFIX =
                            "{\"a\":\"";
                        if (obj.compare(0, VOTE_PREFIX.size(), VOTE_PREFIX) != 0)
                            return false;
                        const size_t ap = VOTE_PREFIX.size();
                        const size_t ae = obj.find('"', ap);
                        if (ae == std::string::npos || ae == ap) return false;
                        const std::string addr = obj.substr(ap, ae - ap);
                        static constexpr std::string_view CHOICE_SEP =
                            "\",\"c\":";
                        if (obj.compare(ae, CHOICE_SEP.size(), CHOICE_SEP) != 0 ||
                            obj.back() != '}') return false;
                        const size_t cp = ae + CHOICE_SEP.size();
                        uint64_t choice = 0;
                        if (!ParseCanonicalUint64Text(
                                std::string_view(obj).substr(
                                    cp, obj.size() - cp - 1), choice) ||
                            choice > 2 || out.votes.count(addr) != 0)
                            return false;
                        out.votes.emplace(addr, (VoteChoice)choice);
                        cursor = obj_end + 1;
                    }
                }
            }
        }
        {
            uint32_t real_yes = 0, real_no = 0, real_abs = 0;
            for (const auto& [addr, ch] : out.votes) {
                (void)addr;
                if (ch == VoteChoice::YES)     ++real_yes;
                else if (ch == VoteChoice::NO) ++real_no;
                else if (ch == VoteChoice::ABSTAIN) ++real_abs;
            }
            if (real_yes != out.votes_yes ||
                real_no  != out.votes_no  ||
                real_abs != out.votes_abstain) {
                out.votes_yes     = real_yes;
                out.votes_no      = real_no;
                out.votes_abstain = real_abs;
            }
        }
        return true;
    }

    // Protocol upgrades require a HARD quorum (no sub-quorum collapse), so
    // they cannot pass until the active validator set reaches
    // GOV_QUORUM_PROTOCOL. GENERAL/signalling keeps the soft floor (usable at
    // the 5-validator governance activation point). Both overloads must stay
    // identical.
    uint32_t GetMinVotesRequired(ProposalType type = ProposalType::GENERAL) const {
        if (!validators_) return GOV_QUORUM_GENERAL;
        if (type == ProposalType::PROTOCOL_UPGRADE)
            return validators_->GetDynamicMinVotes(chain_.Height(), GOV_PASS_PCT_PROTOCOL, GOV_QUORUM_PROTOCOL, /*hard_quorum*/true);
        return validators_->GetDynamicMinVotes(chain_.Height(), GOV_PASS_PCT_GENERAL, GOV_QUORUM_GENERAL, /*hard_quorum*/false);
    }

    uint32_t GetMinVotesRequired(uint64_t block_height,
                                 ProposalType type = ProposalType::GENERAL) const {
        if (!validators_) return GOV_QUORUM_GENERAL;
        if (type == ProposalType::PROTOCOL_UPGRADE)
            return validators_->GetDynamicMinVotes(block_height, GOV_PASS_PCT_PROTOCOL, GOV_QUORUM_PROTOCOL, /*hard_quorum*/true);
        return validators_->GetDynamicMinVotes(block_height, GOV_PASS_PCT_GENERAL, GOV_QUORUM_GENERAL, /*hard_quorum*/false);
    }

    static uint32_t GetPassPct(ProposalType type) {
        if (type == ProposalType::PROTOCOL_UPGRADE) return GOV_PASS_PCT_PROTOCOL;
        return GOV_PASS_PCT_GENERAL;
    }

    void SetGovDebug(bool on) { gov_debug_ = on; }

    uint64_t GetParseFailureCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return parse_failure_count_;
    }

    GovernanceEligibility CheckEligibility(
        const std::string& address,
        const std::string& script_hex
    ) const {
        GovernanceEligibility e{};
        e.blocks_mined = chain_.GetBlocksMined(script_hex);
        e.held_veld    = GetWalletBalance(address);

        e.staked_veld = (double)staking_.GetStake(address) / VELD_UNITS;

        bool is_validator = validators_ && validators_->IsValidatorByAddress(address);
        if (!is_validator) {
            e.reason = "Must be a registered validator";
            return e;
        }
        // MAINNET UX early-reject (the on-chain apply path is the authoritative
        // gate). On the test chain GovernanceBondGateOpen() is always true.
        if (!GovernanceBondGateOpen()) {
            e.reason = "Governance is not active yet — it unlocks once validators "
                       "have bonded 50,000 VELD (5 validators \xC3\x97 10k) to the custody vault";
            return e;   // can_vote / can_propose stay false
        }

        e.can_vote    = true;
        e.can_propose = true;
        return e;
    }

    std::string SubmitProposal(
        const std::string& proposer,
        const std::string& script_hex,
        const std::string& title,
        const std::string& description
    ) {
        constexpr size_t GOV_TITLE_MAX_BYTES       = 200;
        constexpr size_t GOV_DESCRIPTION_MAX_BYTES = 4096;
        if (title.empty() || title.size() > GOV_TITLE_MAX_BYTES)
            return "error:title must be 1–" + std::to_string(GOV_TITLE_MAX_BYTES) + " bytes";
        if (description.size() > GOV_DESCRIPTION_MAX_BYTES)
            return "error:description must be ≤ " + std::to_string(GOV_DESCRIPTION_MAX_BYTES) + " bytes";

        auto elig = CheckEligibility(proposer, script_hex);
        if (!elig.can_propose) return "error:not_eligible:" + elig.reason;

        static const std::vector<std::string> blocked_keywords = {
            "MAX_SUPPLY", "BLOCK_REWARD_UNITS", "VAULT_ADDRESS",
            "MAX_SUPPLY_UNITS", "VELD_UNITS", "BLOCKS_PER_YEAR",
            "ANNUAL_EMISSION", "MINING_EMISSION",
            "change supply", "modify reward", "change vault address",
            "change block reward", "modify supply cap",
        };
        auto to_lower = [](std::string s) {
            for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            return s;
        };
        auto is_word_ch = [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '_';
        };
        std::string combined_l = to_lower(title + " " + description);
        for (auto& kw : blocked_keywords) {
            std::string kw_l = to_lower(kw);
            size_t pos = 0;
            while ((pos = combined_l.find(kw_l, pos)) != std::string::npos) {
                bool left_ok  = (pos == 0) ||
                                !is_word_ch((unsigned char)combined_l[pos - 1]);
                size_t end_idx = pos + kw_l.size();
                bool right_ok = (end_idx >= combined_l.size()) ||
                                !is_word_ch((unsigned char)combined_l[end_idx]);
                if (left_ok && right_ok) {
                    return "error:general proposals cannot reference protocol constants (" +
                           kw + "). These are immutable and not subject to governance.";
                }
                pos += kw_l.size();
            }
        }

        std::lock_guard<std::mutex> lock(mutex_);
        const uint64_t cur_h = chain_.Height();
        {
            auto it = last_proposal_block_.find(proposer);
            if (it != last_proposal_block_.end() &&
                cur_h < it->second + GOV_SUBMIT_COOLDOWN_BLOCKS) {
                uint64_t remaining = (it->second + GOV_SUBMIT_COOLDOWN_BLOCKS) - cur_h;
                return "error:submit cooldown active — wait " +
                       std::to_string(remaining) + " blocks before another proposal";
            }
        }
        Proposal p;
        p.id           = next_id_++;
        p.type         = ProposalType::GENERAL;
        p.title        = title;
        p.description  = description;
        p.proposer     = proposer;
        p.created_at   = std::time(nullptr);
        p.expires_at   = p.created_at + (GOV_VOTE_DURATION_DAYS * 86400);
        p.status       = ProposalStatus::OPEN;
        p.votes_yes    = 0;
        p.votes_no     = 0;
        p.votes_abstain= 0;
        proposals_[p.id] = p;
        last_proposal_block_[proposer] = cur_h;
        PersistAllLocked();
        return std::to_string(p.id);
    }

    std::string Vote(
        const std::string& voter,
        const std::string& script_hex,
        uint64_t proposal_id,
        VoteChoice choice,
        bool voter_is_validator = false
    ) {
        auto elig = CheckEligibility(voter, script_hex);
        if (!elig.can_vote) return "error:not_eligible:" + elig.reason;

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = proposals_.find(proposal_id);
        if (it == proposals_.end()) return "error:proposal_not_found";
        auto& p = it->second;

        if (p.status != ProposalStatus::OPEN) return "error:proposal_closed";
        if ((uint64_t)p.expires_at < 1'000'000'000ULL) {
            return "error:use_on_chain_gov_path";
        }
        if (std::time(nullptr) > p.expires_at) {
            FinalizeProposal(chain_.Height(), p);
            //  SECURITY: also persist the status flip triggered
            // by expiry, otherwise a restart rehydrates the proposal as
            // OPEN and a stale Vote() call could keep finalizing/re-
            // persisting in a loop.
            PersistAllLocked();
            return "error:proposal_expired";
        }
        const bool is_revote = (p.votes.count(voter) > 0);
        if (is_revote) {
            // Enforce a per-voter, per-proposal vote-change cooldown. Without it,
            // a voter can flip YES↔NO↔YES every block,
            // thrashing the KV persistence layer and the vote-tally mid-
            // flight. First-time vote is NOT rate-limited (no dedup key yet
            // and a legitimate voter should be able to cast their initial
            // vote immediately after proposal creation). Only subsequent
            // changes are throttled.
            const uint64_t cur_h = chain_.Height();
            std::string key = voter + ":" + std::to_string(proposal_id);
            auto vit = last_vote_block_.find(key);
            if (vit != last_vote_block_.end() &&
                cur_h < vit->second + GOV_VOTE_CHANGE_COOLDOWN_BLOCKS) {
                uint64_t remaining = (vit->second + GOV_VOTE_CHANGE_COOLDOWN_BLOCKS) - cur_h;
                return "error:vote change cooldown active — wait " +
                       std::to_string(remaining) + " blocks before changing your vote";
            }
            auto old = p.votes[voter];
            if (old == VoteChoice::YES)     --p.votes_yes;
            if (old == VoteChoice::NO)      --p.votes_no;
            if (old == VoteChoice::ABSTAIN) --p.votes_abstain;
        }
        p.votes[voter] = choice;
        if (choice == VoteChoice::YES)     ++p.votes_yes;
        if (choice == VoteChoice::NO)      ++p.votes_no;
        if (choice == VoteChoice::ABSTAIN) ++p.votes_abstain;
        last_vote_block_[voter + ":" + std::to_string(proposal_id)] = chain_.Height();
        CheckAndFinalize(chain_.Height(), p);
        PersistAllLocked();
        return "ok";
    }

    static std::string JsonEscape(const std::string& s) {
        return json::EscapeStringBytes(s);
    }

    std::string ProposalToJSON(const Proposal& p) const {
        uint32_t yes_count = 0, no_count = 0, abs_count = 0;
        for (const auto& [_addr, ch] : p.votes) {
            (void)_addr;
            if (ch == VoteChoice::YES)          ++yes_count;
            else if (ch == VoteChoice::NO)      ++no_count;
            else if (ch == VoteChoice::ABSTAIN) ++abs_count;
        }
        uint32_t total = yes_count + no_count + abs_count;
        double yes_pct = total > 0 ? (100.0 * yes_count / total) : 0.0;
        std::string status_str;
        switch (p.status) {
            case ProposalStatus::OPEN:       status_str = "open";       break;
            case ProposalStatus::PASSED:     status_str = "passed";     break;
            case ProposalStatus::REJECTED:   status_str = "rejected";   break;
            case ProposalStatus::EXPIRED:    status_str = "expired";    break;
            case ProposalStatus::TIMELOCKED: status_str = "timelocked"; break;
        }
        std::string type_str = ProposalTypeName(p.type);
        std::ostringstream j;
        j << std::fixed << std::setprecision(4);
        j << "{"
          << "\"id\":" << p.id << ","
          << "\"type\":\"" << type_str << "\","
          << "\"title\":\"" << JsonEscape(p.title) << "\","
          << "\"description\":\"" << JsonEscape(p.description) << "\","
          << "\"proposer\":\"" << JsonEscape(p.proposer) << "\","
          << "\"created_at\":" << (uint64_t)p.created_at << ","
          << "\"expires_at\":" << (uint64_t)p.expires_at << ","
          << "\"status\":\"" << status_str << "\","
          << "\"votes_yes\":" << yes_count << ","
          << "\"votes_no\":" << no_count << ","
          << "\"votes_abstain\":" << abs_count << ","
          << "\"total_votes\":" << total << ","
          << "\"yes_pct\":" << std::setprecision(2) << yes_pct << ","
          << "\"votes_needed\":" << GetMinVotesRequired(p.type) << ","
          << "\"threshold_pct\":" << GetPassPct(p.type) << ","
          << "\"timelock_until\":" << p.timelock_until
          << std::setprecision(4);
        j << "}";
        return j.str();
    }

    std::string GetAllProposalsJSON() const {
        return GetAllProposalsJSON("");
    }

    std::string GetAllProposalsJSON(const std::string& requester_address) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string safe_requester;
        if (!requester_address.empty() && requester_address.size() <= 100) {
            bool ok = true;
            for (char c : requester_address) {
                if (c < 0x20 || c > 0x7E) { ok = false; break; }
            }
            if (ok) safe_requester = requester_address;
        }
        std::ostringstream j;
        j << "[";
        bool first = true;
        std::vector<uint64_t> ids;
        for (auto& [id, _] : proposals_) ids.push_back(id);
        std::sort(ids.rbegin(), ids.rend());
        for (auto id : ids) {
            if (!first) j << ",";
            const Proposal& p = proposals_.at(id);
            std::string base = ProposalToJSON(p);
            if (!safe_requester.empty() && !base.empty() && base.back() == '}') {
                auto vit = p.votes.find(safe_requester);
                std::string vote_str = "null";
                if (vit != p.votes.end()) {
                    switch (vit->second) {
                        case VoteChoice::YES:     vote_str = "\"yes\"";     break;
                        case VoteChoice::NO:      vote_str = "\"no\"";      break;
                        case VoteChoice::ABSTAIN: vote_str = "\"abstain\""; break;
                    }
                }
                base.pop_back();
                base += ",\"my_vote\":" + vote_str + "}";
            }
            j << base;
            first = false;
        }
        j << "]";
        return j.str();
    }

    std::string GetEligibilityJSON(const GovernanceEligibility& e) const {
        std::ostringstream j;
        j << std::fixed;
        j << "{"
          << "\"can_vote\":"     << (e.can_vote    ? "true" : "false") << ","
          << "\"can_propose\":"  << (e.can_propose ? "true" : "false") << ","
          << "\"blocks_mined\":" << e.blocks_mined << ","
          << "\"staked_veld\":"  << e.staked_veld << ","
          << "\"held_veld\":"    << e.held_veld << ","
          << "\"reason\":\""     << e.reason << "\","
          << "\"requirements\":{"
          <<   "\"type\":\"validator_only\","
          <<   "\"description\":\"Must be a registered validator\""
          << "}}";
        return j.str();
    }

    static constexpr const char* GOV_PREFIX = "VELD_GOV|";
    static constexpr size_t GOV_PREFIX_LEN = 9;

    static bool DecodeHexExact(const std::string& hex,
                               uint8_t* out, size_t out_len) {
        if (hex.size() != out_len * 2) return false;
        auto nyb = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        for (size_t i = 0; i < out_len; ++i) {
            int hi = nyb(hex[2*i]);
            int lo = nyb(hex[2*i+1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = (uint8_t)((hi << 4) | lo);
        }
        return true;
    }

    static std::string GovChainIdPrefix() {
#ifdef VELD_MAINNET_POW
        return std::string("VELD_GOV|M|") + GENESIS_HASH + "|";
#else
        return std::string("VELD_GOV|T|") + GENESIS_HASH + "|";
#endif
    }

    static bool VerifyGovSig(const std::string& pubkey_hex,
                              const std::string& sig_hex,
                              const std::string& challenge) {
        if (pubkey_hex.size() != 3904) return false;
        if (sig_hex.size() != 6618) return false;
        std::array<uint8_t,1952> pk{};
        if (!DecodeHexExact(pubkey_hex, pk.data(), pk.size())) return false;
        std::vector<uint8_t> sig_bytes(sig_hex.size() / 2);
        if (!DecodeHexExact(sig_hex, sig_bytes.data(), sig_bytes.size())) return false;
        try {
            Hash256 msg_hash = Hash256d(
                (const uint8_t*)challenge.data(), challenge.size());
            return dilithium::Verify(pk, msg_hash, sig_bytes);
        } catch (...) { return false; }
    }

    static std::string PubKeyHexToAddress(const std::string& pubkey_hex) {
        if (pubkey_hex.size() != 3904) return "";
        std::array<uint8_t,1952> pk{};
        if (!DecodeHexExact(pubkey_hex, pk.data(), pk.size())) return "";
        try {
            return PubKeyToAddress(pk, false);
        } catch (...) { return ""; }
    }

    static std::string Base64UrlEncode(const std::string& input) {
        static const char alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string out;
        uint32_t val = 0;
        int valb = -6;
        for (unsigned char c : input) {
            val = (val << 8) | c;
            valb += 8;
            while (valb >= 0) {
                out.push_back(alphabet[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) out.push_back(alphabet[((val << 8) >> (valb + 8)) & 0x3F]);
        return out;
    }
    static std::string Base64UrlDecode(const std::string& input) {
        static const std::array<int, 256> T = []() {
            std::array<int, 256> t{};
            t.fill(-1);
            static const char alphabet[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            for (int i = 0; i < 64; ++i) t[(unsigned char)alphabet[i]] = i;
            return t;
        }();
        std::string out;
        uint32_t val = 0;
        int valb = -8;
        for (unsigned char c : input) {
            if (T[c] == -1) {
                throw std::invalid_argument(
                    "Base64UrlDecode: invalid character in input");
            }
            val = (val << 6) | static_cast<uint32_t>(T[c]);
            valb += 6;
            if (valb >= 0) {
                out.push_back((char)((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        // Unpadded Base64URL has exactly one canonical spelling.  Merely
        // discarding the unused low bits accepted aliases such as Zh for Zg
        // (both decoded to "f"), and a one-character tail decoded to empty.
        // Governance signatures cover the decoded title/description, so those
        // aliases let one signature authorize multiple marker byte strings.
        if (Base64UrlEncode(out) != input) {
            throw std::invalid_argument(
                "Base64UrlDecode: non-canonical input");
        }
        return out;
    }

    static std::string BuildProposalOp(
        const std::string& proposer,
        const std::string& title,
        const std::string& description,
        uint64_t timestamp,
        uint64_t signed_height,
        const std::string& pubkey_hex,
        const std::string& sig_hex) {
        std::ostringstream o;
        o << GOV_PREFIX << "P|" << proposer << "|"
          << Base64UrlEncode(title) << "|"
          << Base64UrlEncode(description) << "|"
          << timestamp << "|"
          << signed_height << "|"
          << pubkey_hex << "|"
          << sig_hex;
        return o.str();
    }
    static std::string ProposalTypeName(ProposalType type) {
        return type == ProposalType::PROTOCOL_UPGRADE
            ? "protocol_upgrade" : "general";
    }
    static bool ParseProposalType(const std::string& name,
                                  ProposalType& type) {
        if (name == "general") {
            type = ProposalType::GENERAL;
            return true;
        }
        if (name == "protocol_upgrade") {
            type = ProposalType::PROTOCOL_UPGRADE;
            return true;
        }
        return false;
    }
    static std::string BuildProposalOp(
        ProposalType type,
        const std::string& proposer,
        const std::string& title,
        const std::string& description,
        uint64_t timestamp,
        uint64_t signed_height,
        const std::string& pubkey_hex,
        const std::string& sig_hex) {
        std::ostringstream o;
        o << GOV_PREFIX << "P|" << ProposalTypeName(type) << "|"
          << proposer << "|"
          << Base64UrlEncode(title) << "|"
          << Base64UrlEncode(description) << "|"
          << timestamp << "|"
          << signed_height << "|"
          << pubkey_hex << "|"
          << sig_hex;
        return o.str();
    }
    static std::string BuildVoteOp(
        uint64_t proposal_id,
        const std::string& voter,
        VoteChoice choice,
        uint64_t signed_height,
        const std::string& pubkey_hex,
        const std::string& sig_hex) {
        std::ostringstream o;
        char c = (choice == VoteChoice::YES) ? 'y' :
                 (choice == VoteChoice::NO)  ? 'n' : 'a';
        o << GOV_PREFIX << "V|" << proposal_id << "|" << voter << "|" << c << "|"
          << signed_height << "|" << pubkey_hex << "|" << sig_hex;
        return o.str();
    }

    // `persist=false` is used by the node's pre-commit module dry-run. The
    // in-memory transition is still executed in full and then restored from a
    // module snapshot, but no governance KV writes may escape a block that has
    // not yet crossed the canonical commit boundary.
    void ProcessBlock(const Block& block, uint64_t block_height,
                      bool persist = true) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool state_mutated = false;
        for (size_t ti = 0; ti < block.transactions.size(); ++ti) {
            const auto& tx = block.transactions[ti];
            for (size_t oi = 0; oi < tx.outputs.size(); ++oi) {
                const auto& out = tx.outputs[oi];
                std::string data = ParseOpReturnPayload(out.script_pubkey);
                if (data.size() < GOV_PREFIX_LEN) continue;
                if (data.compare(0, GOV_PREFIX_LEN, GOV_PREFIX) != 0) continue;
                if (ProcessOpLocked(data, block_height)) state_mutated = true;
            }
        }
        // Quorum finalization is part of the deterministic block transition.
        // The retired implementation queued vote-touched proposals for a
        // background worker. Scheduler timing could then change proposal
        // status, later vote admission, persistence, and the state digest for
        // the same canonical blocks. Apply
        // every operation in transaction/output order, then finalize once at
        // the end of the block so all valid same-block votes are counted.
        for (auto& [_, p] : proposals_) {
            const ProposalStatus before = p.status;
            if (p.status == ProposalStatus::OPEN)
                CheckAndFinalize(block_height, p);
            else if (p.status == ProposalStatus::TIMELOCKED)
                CheckTimelockActivation(block_height, p);
            if (p.status != before) state_mutated = true;
        }
        for (auto& [_, p] : proposals_) {
            if (p.status != ProposalStatus::OPEN) continue;
            uint64_t exp = (uint64_t)p.expires_at;
            if (exp == 0 || exp > 1'000'000'000ULL) continue;
            if (block_height >= exp) {
                FinalizeProposal(block_height, p);
                state_mutated = true;
            }
        }
        // Pruning changes GovernanceDigest() and the cooldown maps consulted by
        // later blocks, so it is a canonical per-block transition, not live-node
        // housekeeping.  The old node-level daily call ran after live commits
        // but never during startup replay, producing different digests for the
        // same chain.  Execute it here on every apply path; preflight passes
        // persist=false and is restored from the surrounding module snapshot.
        if (block_height > 0 && (block_height % BLOCKS_PER_DAY) == 0) {
            if (PruneExpiredLocked_(block_height,
                                    /*persist_deletes=*/persist)) {
                state_mutated = true;
            }
        }
        if (state_mutated && persist) PersistAllLocked();
    }

private:
    bool PruneExpiredLocked_(uint64_t current_height,
                             bool persist_deletes) {
        bool mutated = false;
        const uint64_t prop_cutoff = current_height > GOV_SUBMIT_COOLDOWN_BLOCKS
                                     ? current_height - GOV_SUBMIT_COOLDOWN_BLOCKS : 0;
        for (auto it = last_proposal_block_.begin();
             it != last_proposal_block_.end(); ) {
            if (it->second < prop_cutoff) {
                it = last_proposal_block_.erase(it);
                mutated = true;
            } else {
                ++it;
            }
        }
        const uint64_t vote_cutoff =
            current_height > GOV_VOTE_CHANGE_COOLDOWN_BLOCKS
                ? current_height - GOV_VOTE_CHANGE_COOLDOWN_BLOCKS : 0;
        for (auto it = last_vote_block_.begin();
             it != last_vote_block_.end(); ) {
            if (it->second < vote_cutoff) {
                it = last_vote_block_.erase(it);
                mutated = true;
            } else {
                ++it;
            }
        }
        for (auto it = proposals_.begin(); it != proposals_.end(); ) {
            const auto& p = it->second;
            // A passed GENERAL proposal has no executable payload and no later
            // admission or consensus decision depends on its body/votes.  It
            // must therefore age out under the same deterministic history
            // horizon as rejected/expired proposals.  Retaining every passed
            // proposal forever lets active validators grow every node's
            // consensus map and state-digest cost without bound.  TIMELOCKED
            // remains live until it transitions to PASSED.
            const bool terminal = p.status == ProposalStatus::PASSED ||
                                  p.status == ProposalStatus::EXPIRED ||
                                  p.status == ProposalStatus::REJECTED;
            const uint64_t exp = static_cast<uint64_t>(p.expires_at);
            const bool is_block_height = exp > 0 && exp < 1'000'000'000ULL;
            const bool delay_elapsed =
                exp <= UINT64_MAX - GOV_PRUNE_DELAY_BLOCKS &&
                current_height > exp + GOV_PRUNE_DELAY_BLOCKS;
            if (terminal && is_block_height && delay_elapsed) {
                if (persist_deletes && kv_del_)
                    kv_del_("gov:prop:" + std::to_string(p.id));
                it = proposals_.erase(it);
                mutated = true;
            } else {
                ++it;
            }
        }
        return mutated;
    }

    static std::string ParseOpReturnPayload(const std::vector<uint8_t>& script) {
        if (script.empty() || script[0] != 0x6A) return "";
        if (script.size() < 2) return "";
        size_t i = 1;
        size_t len = 0;
        const uint8_t op = script[i++];
        if (op >= 0x01 && op <= 0x4B) {
            len = op;
        } else if (op == 0x4C) {
            if (i >= script.size()) return "";
            len = script[i++];
            if (len <= 0x4B) return "";  // non-minimal PUSHDATA1 alias
        } else if (op == 0x4D) {
            if (i + 2 > script.size()) return "";
            len = (size_t)script[i] | ((size_t)script[i + 1] << 8);
            i += 2;
            if (len <= 0xFF) return "";  // non-minimal PUSHDATA2 alias
        } else {
            return "";
        }
        // Governance signatures bind the decoded fields, not the containing
        // transaction.  Accepting bytes after the declared push therefore
        // gave one signed action multiple consensus-recognised script
        // spellings.  Require one minimal push consuming the complete script.
        if (i + len != script.size()) return "";
        return std::string(script.begin() + i, script.begin() + i + len);
    }

    static bool ParseCanonicalUint64(const std::string& s,
                                     uint64_t& out) noexcept {
        return ParseCanonicalUint64Text(s, out);
    }

    bool ProcessOpLocked(const std::string& data, uint64_t block_height) {
        try {
            std::vector<std::string> fields;
            {
                size_t pos = 0, pipe;
                while ((pipe = data.find('|', pos)) != std::string::npos) {
                    fields.push_back(data.substr(pos, pipe - pos));
                    pos = pipe + 1;
                }
                fields.push_back(data.substr(pos));
            }
            if (fields.size() < 3) return false;

            const std::string& op = fields[1];
            if (op == "P" && fields.size() == 9) {
                const std::string& proposer      = fields[2];
                const std::string  title         = Base64UrlDecode(fields[3]);
                const std::string  description   = Base64UrlDecode(fields[4]);
                uint64_t timestamp = 0, signed_height = 0;
                if (!ParseCanonicalUint64(fields[5], timestamp) ||
                    !ParseCanonicalUint64(fields[6], signed_height))
                    return false;
                const std::string& pubkey_hex    = fields[7];
                const std::string& sig_hex       = fields[8];
                return ApplyProposalFromChain(
                    block_height, ProposalType::GENERAL,
                    /*typed_marker=*/false, proposer, title, description,
                    timestamp, signed_height, pubkey_hex, sig_hex);
            }
            if (op == "P" && fields.size() == 10) {
                ProposalType type;
                if (!ParseProposalType(fields[2], type)) return false;
                const std::string& proposer      = fields[3];
                const std::string  title         = Base64UrlDecode(fields[4]);
                const std::string  description   = Base64UrlDecode(fields[5]);
                uint64_t timestamp = 0, signed_height = 0;
                if (!ParseCanonicalUint64(fields[6], timestamp) ||
                    !ParseCanonicalUint64(fields[7], signed_height))
                    return false;
                const std::string& pubkey_hex    = fields[8];
                const std::string& sig_hex       = fields[9];
                return ApplyProposalFromChain(
                    block_height, type, /*typed_marker=*/true,
                    proposer, title, description, timestamp, signed_height,
                    pubkey_hex, sig_hex);
            }
            if (op == "V" && fields.size() == 8) {
                uint64_t proposal_id = 0, signed_height = 0;
                if (!ParseCanonicalUint64(fields[2], proposal_id) ||
                    !ParseCanonicalUint64(fields[5], signed_height))
                    return false;
                const std::string& voter         = fields[3];
                const std::string& choice_str    = fields[4];
                const std::string& pubkey_hex    = fields[6];
                const std::string& sig_hex       = fields[7];
                VoteChoice c;
                if (choice_str == "y")      c = VoteChoice::YES;
                else if (choice_str == "n") c = VoteChoice::NO;
                else if (choice_str == "a") c = VoteChoice::ABSTAIN;
                else return false;
                return ApplyVoteFromChain(
                    block_height, proposal_id, voter, c,
                    signed_height, pubkey_hex, sig_hex);
            }
            return false;
        } catch (...) {
            ++parse_failure_count_;
            return false;
        }
    }

    // Apply a proposal from the chain. mutex_ already held.
    // SECURITY: re-verifies the signature AND proposer eligibility — every
    // node does this identically against chain state at `block_height` so
    // all reach the same pass/reject decision.
    //
    // Apply-time validation enforces validator eligibility and rejects votes
    // signed for a future height.
    bool ApplyProposalFromChain(uint64_t block_height,
                                 ProposalType type,
                                 bool typed_marker,
                                 const std::string& proposer,
                                 const std::string& title,
                                 const std::string& description,
                                 uint64_t ,
                                 uint64_t signed_height,
                                 const std::string& pubkey_hex,
                                 const std::string& sig_hex) {
        if (block_height > signed_height + GOV_SIG_REPLAY_WINDOW_BLOCKS) return false;
        if (signed_height > block_height + 1) return false;
        std::string challenge;
        if (signed_height >= BATCH2_HARDENING_HEIGHT) {
            challenge = GovChainIdPrefix()
                      + "GOV_PROPOSAL:"
                      + (typed_marker ? ProposalTypeName(type) + ":" : "")
                      + title + "|" + description
                      + ":@" + std::to_string(signed_height);
        } else {
            challenge = "GOV_PROPOSAL:"
                      + (typed_marker ? ProposalTypeName(type) + ":" : "")
                      + title + "|" + description
                      + ":@" + std::to_string(signed_height);
        }
        if (!VerifyGovSig(pubkey_hex, sig_hex, challenge)) return false;
        if (PubKeyHexToAddress(pubkey_hex) != proposer) return false;
        if (title.size() == 0) return false;
        if (title.size() > 200 || description.size() > 4096) return false;
        auto it_cd = last_proposal_block_.find(proposer);
        if (it_cd != last_proposal_block_.end() &&
            block_height < it_cd->second + GOV_SUBMIT_COOLDOWN_BLOCKS) {
            return false;
        }
        // Enforce validator-only governance at apply time. The
        // RPC-path preparegovproposal currently does NOT enforce this; the
        // OP_RETURN path is the authoritative gate. validators_ state at
        // block_height is already correct here because validators_.ProcessBlock
        // runs BEFORE governance_.ProcessBlock in on_commit_.
        if (!validators_ || !validators_->IsValidatorByAddress(proposer)) return false;
        if (!GovernanceBondGateOpen()) return false;   // mainnet: dormant until 50k bonded
        Proposal p;
        p.id            = next_id_++;
        p.type          = type;
        p.title         = title;
        p.description   = description;
        p.proposer      = proposer;
        p.created_at    = (std::time_t)block_height;
        p.expires_at    = p.created_at + (GOV_VOTE_DURATION_DAYS * BLOCKS_PER_DAY);
        p.status        = ProposalStatus::OPEN;
        p.votes_yes     = 0;
        p.votes_no      = 0;
        p.votes_abstain = 0;
        proposals_[p.id] = p;
        last_proposal_block_[proposer] = block_height;
        return true;
    }

    bool ApplyVoteFromChain(uint64_t block_height,
                             uint64_t proposal_id,
                             const std::string& voter,
                             VoteChoice choice,
                             uint64_t signed_height,
                             const std::string& pubkey_hex,
                             const std::string& sig_hex) {
        if (!GovernanceBondGateOpen()) return false;   // mainnet: dormant until 50k bonded
        if (block_height > signed_height + GOV_SIG_REPLAY_WINDOW_BLOCKS) {
            if (gov_debug_) { std::cerr << "[VOTE-REJ] stale_sig bh=" << block_height << " signed_h=" << signed_height << " id=" << proposal_id << "\n"; std::cerr.flush(); }
            return false;
        }
        if (signed_height > block_height + 1) {
            if (gov_debug_) { std::cerr << "[VOTE-REJ] future_sig bh=" << block_height << " signed_h=" << signed_height << "\n"; std::cerr.flush(); }
            return false;
        }
        std::string choice_str = (choice == VoteChoice::YES) ? "yes" :
                                  (choice == VoteChoice::NO)  ? "no"  : "abstain";
        std::string challenge;
        if (signed_height >= BATCH2_HARDENING_HEIGHT) {
            challenge = GovChainIdPrefix()
                      + "GOV_VOTE:" + std::to_string(proposal_id)
                      + ":" + choice_str
                      + ":@" + std::to_string(signed_height);
        } else {
            challenge = "GOV_VOTE:" + std::to_string(proposal_id)
                      + ":" + choice_str
                      + ":@" + std::to_string(signed_height);
        }
        if (!VerifyGovSig(pubkey_hex, sig_hex, challenge)) {
            if (gov_debug_) { std::cerr << "[VOTE-REJ] sig_verify_failed voter=" << voter << " id=" << proposal_id << " choice=" << choice_str << " signed_h=" << signed_height << "\n"; std::cerr.flush(); }
            return false;
        }
        if (PubKeyHexToAddress(pubkey_hex) != voter) {
            if (gov_debug_) { std::cerr << "[VOTE-REJ] pubkey_addr_mismatch voter=" << voter << " derived=" << PubKeyHexToAddress(pubkey_hex) << "\n"; std::cerr.flush(); }
            return false;
        }
        // Validator-only eligibility is authoritative at chain-apply time,
        // matching ApplyProposalFromChain above. A valid ML-DSA signature
        // proves control of `voter`; it does not confer governance membership.
        // ValidatorRegistry::ProcessBlock runs before this module for the whole
        // block, so same-block registration, deregistration, and slashing are
        // reflected in this active-membership decision deterministically.
        if (!validators_ || !validators_->IsValidatorByAddress(voter)) {
            if (gov_debug_) { std::cerr << "[VOTE-REJ] voter_not_active_validator voter=" << voter << " id=" << proposal_id << "\n"; std::cerr.flush(); }
            return false;
        }
        auto it = proposals_.find(proposal_id);
        if (it == proposals_.end()) {
            if (gov_debug_) { std::cerr << "[VOTE-REJ] proposal_not_found id=" << proposal_id << "\n"; std::cerr.flush(); }
            return false;
        }
        Proposal& p = it->second;
        if (p.status != ProposalStatus::OPEN) {
            if (gov_debug_) { std::cerr << "[VOTE-REJ] proposal_not_open id=" << proposal_id << " status=" << (int)p.status << "\n"; std::cerr.flush(); }
            return false;
        }
        auto prev = p.votes.find(voter);
        if (prev != p.votes.end()) {
            if (prev->second == choice) {
                if (gov_debug_) { std::cerr << "[VOTE-REJ] replay_same_choice id=" << proposal_id << " voter=" << voter << "\n"; std::cerr.flush(); }
                return false;
            }
            std::string key = voter + ":" + std::to_string(proposal_id);
            auto vit = last_vote_block_.find(key);
            if (vit != last_vote_block_.end() &&
                block_height < vit->second + GOV_VOTE_CHANGE_COOLDOWN_BLOCKS) {
                if (gov_debug_) { std::cerr << "[VOTE-REJ] change_cooldown id=" << proposal_id << " voter=" << voter << " last=" << vit->second << " bh=" << block_height << "\n"; std::cerr.flush(); }
                return false;
            }
            if (prev->second == VoteChoice::YES)     --p.votes_yes;
            if (prev->second == VoteChoice::NO)      --p.votes_no;
            if (prev->second == VoteChoice::ABSTAIN) --p.votes_abstain;
        }
        p.votes[voter] = choice;
        if (choice == VoteChoice::YES)     ++p.votes_yes;
        if (choice == VoteChoice::NO)      ++p.votes_no;
        if (choice == VoteChoice::ABSTAIN) ++p.votes_abstain;
        last_vote_block_[voter + ":" + std::to_string(proposal_id)] = block_height;
        return true;
    }

private:
    const Blockchain&      chain_;
    const StakingLedger&   staking_;
    const ValidatorRegistry* validators_;
    mutable std::mutex    mutex_;
    uint64_t              next_id_;
    std::unordered_map<uint64_t, Proposal> proposals_;
    KVPut                 kv_put_;
    KVDel                 kv_del_;
    KVScan                kv_scan_;

    std::unordered_map<std::string, uint64_t>              last_proposal_block_;
    std::unordered_map<std::string, uint64_t>              last_vote_block_;
    bool                                                   gov_debug_ = false;
    uint64_t                                               parse_failure_count_ = 0;

    double GetWalletBalance(const std::string& address) const {
        auto script = AddressToScript(address);
        if (script.empty()) return 0.0;
        auto utxos = chain_.GetUTXOsForScript(script);
        uint64_t total = 0;
        for (auto& u : utxos) total += u.value;
        return (double)total / VELD_UNITS;
    }

    void CheckAndFinalize(uint64_t block_height, Proposal& p) {
        uint32_t total = p.votes_yes + p.votes_no;
        uint32_t min_votes = GetMinVotesRequired(block_height, p.type);
        uint32_t pass_pct = GetPassPct(p.type);
        if (total < min_votes) return;
        if (total == 0) return;
        if ((uint64_t)p.votes_yes * 100 / total >= pass_pct) {
            if (p.type == ProposalType::PROTOCOL_UPGRADE) {
                p.status = ProposalStatus::TIMELOCKED;
                p.timelock_until = block_height + GOV_PROTOCOL_TIMELOCK;
            } else {
                p.status = ProposalStatus::PASSED;
            }
        } else if ((uint64_t)p.votes_no * 100 / total > (100 - pass_pct)) {
            p.status = ProposalStatus::REJECTED;
        }
    }

    void CheckTimelockActivation(uint64_t block_height, Proposal& p) {
        if (p.status != ProposalStatus::TIMELOCKED) return;
        if (block_height >= p.timelock_until) {
            p.status = ProposalStatus::PASSED;
        }
    }

    void FinalizeProposal(uint64_t block_height, Proposal& p) {
        if (p.status == ProposalStatus::TIMELOCKED) {
            CheckTimelockActivation(block_height, p);
            return;
        }
        if (p.status != ProposalStatus::OPEN) return;
        uint32_t total = p.votes_yes + p.votes_no;
        uint32_t min_votes = GetMinVotesRequired(block_height, p.type);
        uint32_t pass_pct = GetPassPct(p.type);
        if (total == 0) { p.status = ProposalStatus::EXPIRED; return; }
        if (total >= min_votes && (uint64_t)p.votes_yes * 100 / total >= pass_pct) {
            if (p.type == ProposalType::PROTOCOL_UPGRADE) {
                p.status = ProposalStatus::TIMELOCKED;
                p.timelock_until = block_height + GOV_PROTOCOL_TIMELOCK;
            } else {
                p.status = ProposalStatus::PASSED;
            }
        } else
            p.status = ProposalStatus::EXPIRED;
    }
};

}
