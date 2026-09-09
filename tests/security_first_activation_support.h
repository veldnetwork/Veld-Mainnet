#pragma once
// First activation support: all mutations use ordinary transaction/RPC paths.
// Bitcoin transaction and header bytes come from the driver's isolated Core wallet.
#include "consensus/finality_daemon.h"
namespace fa_fq = veld::finality::qc;

class FirstActivationSupport {
    VeldNode& node_;
    std::vector<RealKeyPair>& wallets_;
    std::filesystem::path directory_;
    std::vector<std::unique_ptr<fa_fq::FinalityDaemon>> daemons_;
    fa_fq::CheckpointRef bitcoin_checked_target_;
    static std::vector<uint8_t> EncodeJournal(const fa_fq::DaemonJournal& journal);
    static std::optional<fa_fq::DaemonJournal> DecodeJournal(const std::vector<uint8_t>& bytes);

    std::optional<fa_fq::EpochSnapshot> Snapshot(uint64_t epoch) {
        const Value value=Result(node_,"getfinalitysnapshot",{std::to_string(epoch)});
        const auto& s=Field(value,"snapshot");
        if(s.kind==Value::Kind::Null) return std::nullopt;
        fa_fq::EpochSnapshot out;
        out.epoch_id=Number(Field(s,"epoch"));
        out.snapshot_height=Number(Field(s,"snapshot_height"));
        out.root=HexToHash(Field(s,"set_root").text);
        out.total_weight=Number(Field(s,"total_weight"));
        for(const auto& m:Field(s,"members").array) {
            fa_fq::SnapshotEntry entry;
            entry.pubkey_hex=Field(m,"pubkey").text;
            entry.pubkey_commit=HexToHash(Field(m,"commit").text);
            entry.address=Field(m,"address").text;
            entry.registered_height=Number(Field(m,"registered_height"));
            entry.weight=Number(Field(m,"weight"));
            out.entries.push_back(entry);
        }
        if(!fa_fq::SnapshotWellFormed(out)) throw std::runtime_error("noncanonical RPC snapshot");
        return out;
    }
    void StartVoters() {
        if(!daemons_.empty()) return;
        for(size_t index=1;index<wallets_.size();++index) {
            const auto& wallet=wallets_[index];
            const std::string public_key=BytesToHex(wallet.public_key.data(),wallet.public_key.size());
            const auto path=directory_/("finality-"+std::string(GENESIS_HASH).substr(0,16)+"-"+HashToHex(fa_fq::PubkeyCommit(public_key))+".hex");
            fa_fq::DaemonHooks hooks;
            hooks.fetch_snapshot=[this](uint64_t epoch){return Snapshot(epoch);};
            hooks.fetch_tip_height=[this](){return node_.GetChain().Height();};
            hooks.authorize_target=[this](const fa_fq::CheckpointRef& target) {
                return target==bitcoin_checked_target_;
            };
            hooks.fetch_block_hash=[this](uint64_t h)->std::optional<Hash256>{
                if(h>node_.GetChain().Height()) return std::nullopt;
                return node_.GetChain().GetBlock(h).GetHash();
            };
            hooks.authorize_work=[this](const fa_fq::CheckpointRef& target)->std::optional<fa_fq::DaemonWorkGrant>{
                const auto grant=Result(node_,"getworkadmission",{"finality_vote",std::to_string(target.height),HashToHex(target.hash)});
                fa_fq::DaemonWorkGrant out;
                out.binding=Field(grant,"binding").text;
                out.token=Field(grant,"signing_token").text;
                const auto activation=Result(node_,"beginworksigning",{"finality_vote",out.binding,out.token});
                out.deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(Number(Field(activation,"ttl_ms")));
                return out;
            };
            hooks.cancel_work=[this](const fa_fq::DaemonWorkGrant& grant){(void)Result(node_,"cancelworksigning",{grant.token});};
            hooks.gossip_vote=[this](const fa_fq::SignedVote& vote,const fa_fq::DaemonWorkGrant& grant) {
                const auto snapshot=Snapshot(vote.epoch_id);
                if(!snapshot || !fa_fq::VerifyVote(vote,*snapshot,fa_fq::NETWORK_ID,HexToHash(GENESIS_HASH)))
                    throw std::runtime_error("disposable vote does not verify against the node's compiled domain");
                const auto accepted=Result(node_,"submitfinalityvote",{BytesToHex(fa_fq::EncodeSignedVoteWire(vote)),grant.binding,grant.token});
                return Field(accepted,"accepted").boolean;
            };
            hooks.persist_journal=[path](const fa_fq::DaemonJournal& journal) {
                const auto bytes=EncodeJournal(journal);
                if(bytes.empty()) return false;
                std::string error;
                return channel::secure_file::AtomicWriteText(path.string(),BytesToHex(bytes),&error,true);
            };
            hooks.load_journal=[path]()->std::optional<fa_fq::DaemonJournal>{
                if(!std::filesystem::exists(path)) return std::nullopt;
                if(std::filesystem::file_size(path)>100000) throw std::runtime_error("oversized finality journal");
                std::ifstream input(path); std::string hex; input>>hex;
                auto journal=DecodeJournal(HexToBytes(hex));
                if(!input || !journal) throw std::runtime_error("invalid finality journal");
                return journal;
            };
            hooks.fetch_finalized=[this]()->std::optional<fa_fq::FinalizedRecord>{
                const auto value=Result(node_,"getfinalitysnapshot");
                const auto& snapshot=Field(value,"snapshot");
                if(snapshot.kind==Value::Kind::Null) return std::nullopt;
                const auto& record=Field(snapshot,"finalized");
                if(record.kind==Value::Kind::Null) return std::nullopt;
                fa_fq::FinalizedRecord out;
                out.epoch_id=Number(Field(record,"epoch"));
                out.round=uint32_t(Number(Field(record,"round")));
                out.target.height=Number(Field(record,"height"));
                out.target.hash=HexToHash(Field(record,"hash").text);
                return out;
            };
            hooks.fetch_prevote_qc=[this](const fa_fq::EpochSnapshot&)->std::optional<fa_fq::DecodedQc>{
                const auto value=Result(node_,"getfinalityqc",{"1"});
                const auto bytes=HexToBytes(Field(value,"qc_hex").text);
                if(bytes.empty()) return std::nullopt;
                return fa_fq::DecodeQc(std::string(bytes.begin(),bytes.end()));
            };
            dilithium::PublicKey expanded_public{};
            dilithium::SecretKey expanded_secret{};
            if(veld_mldsa65_keypair_from_seed(wallet.private_key.data(),expanded_public.data(),expanded_secret.data())!=0 ||
               !std::equal(expanded_public.begin(),expanded_public.end(),wallet.public_key.begin()))
                throw std::runtime_error("finality identity expansion mismatch");
            daemons_.push_back(std::make_unique<fa_fq::FinalityDaemon>(
                public_key,expanded_secret,fa_fq::NETWORK_ID,HexToHash(GENESIS_HASH),std::move(hooks)));
            compat::SecureZero(expanded_secret.data(),expanded_secret.size());
        }
    }
    btcveld::reserve::Claim Claim(const Value& command) {
        namespace r=btcveld::reserve;
        const auto state=node_.GetTokens().GetBtcVeldReserveState();
        r::Claim claim;
        const auto& operation=Field(command,"operation").text;
        if(operation=="OPEN") claim.operation=r::Operation::OPEN;
        else if(operation=="DEPOSIT") claim.operation=r::Operation::DEPOSIT;
        else if(operation=="PAYOUT") claim.operation=r::Operation::PAYOUT;
        else throw std::runtime_error("unsupported first activation operation");
        claim.network_binding=r::NetworkBinding();
        claim.prior_commitment=state.transition_commitment;
        claim.prior_reserve_txid=state.reserve_txid;
        claim.prior_reserve_vout=state.reserve_vout;
        claim.prior_reserve_value=state.reserve_value_sats;
        claim.prior_transition_count=state.transition_count;
        claim.new_reserve_vout=0;
        claim.new_reserve_value=Number(Field(command,"reserve_value"));
        claim.mint_amount=Number(Field(command,"mint_amount"));
        const auto& recipient=wallets_.at(size_t(Number(Field(command,"wallet")))).address;
        if(operation=="OPEN") claim.exact_commitment=r::detail::OpenDepositCommitment(0,claim.new_reserve_value,recipient);
        if(operation=="DEPOSIT") claim.exact_commitment=r::detail::PendingDepositCommitment(
            HexToHash(Field(command,"pending_txid").text),uint32_t(Number(Field(command,"pending_vout"))),
            Number(Field(command,"pending_value")),recipient);
        if(operation=="PAYOUT") {
            const auto request=node_.TestMainBtcVeldRedeemCovenant().GetCopy(HexToHash(Field(command,"request_id").text));
            if(!request) throw std::runtime_error("unknown on-chain redeem request");
            claim.exact_commitment=request->request_commitment;
            if(claim.new_reserve_value==0) claim.new_reserve_vout=r::NO_VOUT;
        }
        return claim;
    }
public:
    FirstActivationSupport(VeldNode& node,std::vector<RealKeyPair>& wallets,const std::filesystem::path& directory)
        :node_(node),wallets_(wallets),directory_(directory) {}
    std::string Handle(const std::string& op,const Value& command) {
        const auto* index_field=command.Get("wallet");
        const auto& wallet=wallets_.at(index_field?size_t(Number(*index_field)):0);
        if(op=="fa_finality") {
            bitcoin_checked_target_.height=Number(Field(command,"bitcoin_checked_height"));
            bitcoin_checked_target_.hash=HexToHash(Field(command,"bitcoin_checked_hash").text);
            StartVoters();
            unsigned sent=0;
            for(unsigned pass=0;pass<3;++pass) for(auto& daemon:daemons_) if(daemon->Tick()) ++sent;
            const auto qc=Result(node_,"getfinalityqc",{"2"});
            return JsonBuilder::Object({{"votes_sent",JsonBuilder::Number(uint64_t(sent))},
                {"sink_calls",JsonBuilder::Number(node_.TestWorkFinalitySinkCalls())},
                {"active_calls",JsonBuilder::Number(node_.TestWorkFinalityActiveCalls())},
                {"verification_result",JsonBuilder::Number(uint64_t(node_.TestWorkFinalityVerifyResult()))},
                {"precommit_qc_bytes",JsonBuilder::Number(uint64_t(Field(qc,"qc_hex").text.size()/2))}});
        }
        if(op=="fa_anchor") {
            const auto raw=HexToBytes(Field(command,"proof").text);
            if(raw.empty() || raw.size()>12000) throw std::runtime_error("anchor proof fixture size");
            return SignAndSend(node_,wallet,"preparerawop",{wallet.address,"VELD_ANCHOR|"+BytesToHex(raw)});
        }
        if(op=="fa_request") {
            const auto request=node_.TestMainBtcVeldRedeemCovenant().GetCopy(HexToHash(Field(command,"request_id").text));
            if(!request) throw std::runtime_error("request absent from hot and archived state");
            return JsonBuilder::Object({{"status",JsonBuilder::Number(uint64_t(request->status))},
                {"amount_sats",JsonBuilder::Number(request->amount_sats)},
                {"fulfilled_txid",JsonBuilder::String(HashToHex(request->fulfilled_txid))},
                {"commitment",JsonBuilder::String(HashToHex(request->request_commitment))}});
        }
        if(op=="fa_archive_status") {
            const auto state=node_.TestMainBtcVeldRedeemCovenant().SnapshotState();
            return JsonBuilder::Object({
                {"migration_active",JsonBuilder::Bool(state.state_migration_active)},
                {"hot_requests",JsonBuilder::Number(uint64_t(state.requests.size()))},
                {"hot_payout_identities",JsonBuilder::Number(uint64_t(state.consumed_payouts.size()))},
                {"archive_count",JsonBuilder::Number(state.archive_root.count)},
                {"archive_root",JsonBuilder::String(HashToHex(state.archive_root.hash))}});
        }
        if(op=="fa_headers") {
            std::vector<std::array<uint8_t,80>> headers;
            for(const auto& item:Field(command,"headers").array) {
                const auto raw=HexToBytes(item.text);
                if(raw.size()!=80 || headers.size()>=100) throw std::runtime_error("header fixture bound");
                std::array<uint8_t,80> header{}; std::copy(raw.begin(),raw.end(),header.begin()); headers.push_back(header);
            }
            return SignAndSend(node_,wallet,"preparerawop",{wallet.address,"VELD_BHDR|"+BytesToHex(btcspv::EncodeBtcHeaderOp(headers))});
        }
        if(op=="fa_auth" || op=="fa_reserve") {
            namespace r=btcveld::reserve;
            auto claim=Claim(command);
            if(op=="fa_auth") {
                const auto script=claim.operation==r::Operation::OPEN?
                    r::detail::OpenAuthScript(claim.prior_commitment,wallet.address,claim.mint_amount):
                    r::detail::AuthScript(claim.operation,claim.prior_commitment,claim.exact_commitment,claim.mint_amount);
                if(script.empty()) throw std::runtime_error("cannot construct standard reserve authorization");
                return JsonBuilder::Object({{"script",JsonBuilder::String(BytesToHex(script))},
                    {"payload",JsonBuilder::String(BytesToHex(btcspv::ExtractOpReturn(script)))}});
            }
            claim.bitcoin_tx=HexToBytes(Field(command,"rawtx").text);
            claim.bitcoin_txid=HexToHash(Field(command,"txid").text);
            claim.new_reserve_txid=claim.new_reserve_vout==r::NO_VOUT?Hash256{}:claim.bitcoin_txid;
            claim.bitcoin_block=HexToHash(Field(command,"block").text);
            claim.merkle_directions=Number(Field(command,"directions"));
            for(const auto& item:Field(command,"branch").array) claim.merkle_branch.push_back(HexToHash(item.text));
            for(const auto& item:Field(command,"parents").array) claim.direct_parents.push_back(HexToBytes(item.text));
            if(claim.mint_amount) {
                claim.has_nullifier_proof=true;
                if(!btcnull::DecodeProof(HexToBytes(Field(command,"nullifier_proof").text),claim.nullifier_proof))
                    throw std::runtime_error("invalid RPC nullifier witness");
            }
            const auto proof=r::EncodeProof(claim);
            if(proof.empty()) throw std::runtime_error("reserve fixture encoding refused");
            return SignAndSend(node_,wallet,"preparerawop",{wallet.address,"VELD_RSV1|"+BytesToHex(proof)});
        }
        if(op=="fa_transaction") {
            const auto method=Field(command,"method").text;
            const std::set<std::string> allowed={"prepareammseed","prepareammadd","prepareammswap","prepareammremove","preparetokenredeem","preparetokentransfer"};
            if(!allowed.count(method)) throw std::runtime_error("unsupported first activation transaction");
            std::vector<std::string> params{wallet.address};
            for(const auto& p:Field(command,"params").array) params.push_back(p.text);
            return SignAndSend(node_,wallet,method,params);
        }
        throw std::runtime_error("unknown first activation command");
    }
};


inline std::vector<uint8_t> FirstActivationSupport::EncodeJournal(
        const fa_fq::DaemonJournal& journal) {
    std::vector<uint8_t> out{'V','F','J','1'};
    state_digest::put_u32_le(out, journal.version);
    state_digest::put_u8(out, journal.lock.held ? 1 : 0);
    state_digest::put_u64_le(out, journal.lock.epoch_id);
    state_digest::put_u32_le(out, journal.lock.round);
    state_digest::put_u64_le(out, journal.lock.target.height);
    state_digest::put_bytes(out, journal.lock.target.hash.data(), 32);
    state_digest::put_u8(out, journal.last_vote ? 1 : 0);
    if (journal.last_vote) {
        const auto vote = fa_fq::EncodeSignedVoteWire(*journal.last_vote);
        if (vote.size() != fa_fq::SIGNED_VOTE_WIRE_BYTES) return {};
        state_digest::put_bytes(out, vote.data(), vote.size());
    }
    const Hash256 checksum = state_digest::sha256_domain(
        "VELD_FINALITY_DAEMON_JOURNAL_v1|", out);
    state_digest::put_bytes(out, checksum.data(), checksum.size());
    return out;
}

inline std::optional<fa_fq::DaemonJournal> FirstActivationSupport::DecodeJournal(
        const std::vector<uint8_t>& in) {
    constexpr size_t BASE = 4 + 4 + 1 + 8 + 4 + 8 + 32 + 1;
    if (in.size() != BASE + 32 &&
        in.size() != BASE + fa_fq::SIGNED_VOTE_WIRE_BYTES + 32)
        return std::nullopt;
    if (!std::equal(in.begin(), in.begin() + 4,
                    std::array<uint8_t,4>{'V','F','J','1'}.begin()))
        return std::nullopt;
    const size_t checksum_at = in.size() - 32;
    std::vector<uint8_t> body(in.begin(), in.begin() + (ptrdiff_t)checksum_at);
    const Hash256 checksum = state_digest::sha256_domain(
        "VELD_FINALITY_DAEMON_JOURNAL_v1|", body);
    if (!std::equal(checksum.begin(), checksum.end(),
                    in.begin() + (ptrdiff_t)checksum_at)) return std::nullopt;
    size_t p = 4;
    auto u8 = [&]() -> uint8_t { return in[p++]; };
    auto u32 = [&]() { uint32_t v=0; for(int i=0;i<4;++i)v|=(uint32_t)in[p++]<<(8*i); return v; };
    auto u64 = [&]() { uint64_t v=0; for(int i=0;i<8;++i)v|=(uint64_t)in[p++]<<(8*i); return v; };
    fa_fq::DaemonJournal journal;
    journal.version = u32();
    const uint8_t held = u8();
    if (held > 1) return std::nullopt;
    journal.lock.held = held != 0;
    journal.lock.epoch_id = u64();
    journal.lock.round = u32();
    journal.lock.target.height = u64();
    std::copy_n(in.begin() + (ptrdiff_t)p, 32,
                journal.lock.target.hash.begin());
    p += 32;
    const uint8_t has_vote = u8();
    if (has_vote > 1) return std::nullopt;
    if (has_vote) {
        if (p + fa_fq::SIGNED_VOTE_WIRE_BYTES != checksum_at)
            return std::nullopt;
        std::vector<uint8_t> vote(
            in.begin() + (ptrdiff_t)p,
            in.begin() + (ptrdiff_t)(p + fa_fq::SIGNED_VOTE_WIRE_BYTES));
        auto decoded = fa_fq::DecodeSignedVoteWire(vote);
        if (!decoded) return std::nullopt;
        journal.last_vote = std::move(*decoded);
        p += fa_fq::SIGNED_VOTE_WIRE_BYTES;
    }
    if (p != checksum_at) return std::nullopt;
    return journal;
}
