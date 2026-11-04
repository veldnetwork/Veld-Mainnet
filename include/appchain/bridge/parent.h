#pragma once
// Native deposit and withdrawal kernel. Public activation is source-pinned
// separately; development tests use their own genesis.
#include "appchain/auth/checkpoint.h"
#include "core/destination.h"
#include "consensus/appchain_activation.h"
#include "core/marker_composition.h"
#include <functional>
#include <map>
#include <memory>
#include <optional>

namespace veld {
class Blockchain;
}

namespace app::bridge {
inline constexpr uint64_t ACTIVATION = veld::APPCHAIN_BRIDGE_ACTIVATION_HEIGHT, CONFIRMATIONS = 120, DELAY = 480,
                          STALE = 960, CAP = 1000000000000ULL;
inline constexpr std::string_view PREFIX = "VELD_APP1|";
inline bool reserve(const Bytes &s) { return !s.empty() && s[0] == 0xc1; }
inline Bytes reserveScript(const Id &id) {
  need(id != Id{}, "empty reserve identity");
  Bytes s{0xc1, 1, 48};
  s.insert(s.end(), id.begin(), id.end());
  return s;
}
inline bool ordinary(const Bytes &s) {
  return veld::IsSha384KeyScript(s) ||
         (s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 20 &&
          s[23] == 0x88 && s[24] == 0xac);
}
inline Bytes marker(uint8_t op, const Bytes &body) {
  Bytes b(PREFIX.begin(), PREFIX.end());
  b.push_back(op);
  b.insert(b.end(), body.begin(), body.end());
  need(b.size() <= 65531, "bridge marker bound");
  Bytes s{0x6a};
  if (b.size() <= 75)
    s.push_back(b.size());
  else if (b.size() <= 255) {
    s.push_back(0x4c);
    s.push_back(b.size());
  } else {
    s.push_back(0x4d);
    s.push_back(b.size());
    s.push_back(b.size() >> 8);
  }
  s.insert(s.end(), b.begin(), b.end());
  return s;
}
inline bool marked(const veld::Transaction &tx) {
  for (auto &o : tx.outputs)
    if (reserve(o.script_pubkey) ||
        veld::MarkerOpReturnPayload(o.script_pubkey).starts_with(PREFIX))
      return true;
  return false;
}
inline Committee decodeCommittee(std::span<const uint8_t> bytes) {
  Reader r{bytes};
  need(r.raw(5) == Bytes({'V', 'A', 'C', 'D', 1}), "descriptor format");
  Committee c;
  auto g = r.raw(32);
  std::copy(g.begin(), g.end(), c.parentGenesis.begin());
  c.childGenesis = r.id();
  c.bridge = r.id();
  c.version = r.n(4);
  need(r.n(1) == 10 && r.n(1) == 7, "fixed quorum");
  c.developmentReserveCap = r.n(8);
  for (auto &k : c.keys) {
    auto b = r.raw(k.size());
    std::copy(b.begin(), b.end(), k.begin());
  }
  r.end();
  need(c.encode() == Bytes(bytes.begin(), bytes.end()), "canonical descriptor");
  return c;
}
struct Outpoint {
  ParentHash tx{};
  uint32_t index = 0;
  auto operator<=>(const Outpoint &) const = default;
  void write(Writer &w) const {
    w.raw(tx);
    w.n(index, 4);
  }
};
struct Coin {
  uint64_t value = 0, height = 0;
  Bytes script;
  bool coinbase = false;
};
struct Context {
  uint64_t height = 0;
  ParentHash genesis{};
  std::function<ParentHash(uint64_t)> blockHash;
  std::function<std::optional<Coin>(const Outpoint &)> coin;
  std::function<bool(const Bytes &)> ordinaryFunding;
};
struct Leaf {
  Id chain{}, bridge{}, owner{};
  uint32_t version = 1, module = 1;
  uint8_t source = 0;
  uint64_t nonce = 0, gross = 0, maxFee = 0, minimum = 0;
  Bytes recipient;
  Bytes encode() const {
    need(chain != Id{} && bridge != Id{} && owner != Id{} && version == 1 &&
             module == 1 && source <= 2 && nonce <= MAX && gross > 0 &&
             gross <= MAX && maxFee < gross && minimum > 0 &&
             minimum <= gross - maxFee && ordinary(recipient),
         "withdrawal authority/bounds");
    Writer w;
    w.raw(chain);
    w.raw(bridge);
    w.n(version, 4);
    w.n(module, 4);
    w.raw(owner);
    w.n(source, 1);
    w.n(nonce, 8);
    w.n(gross, 8);
    w.n(maxFee, 8);
    w.n(minimum, 8);
    w.str(recipient, 51);
    return w.b;
  }
  Id id() const {
    encode();
    Writer w;
    w.raw(chain);
    w.raw(bridge);
    w.n(version, 4);
    w.n(module, 4);
    w.raw(owner);
    w.n(nonce, 8);
    return hash("VAPP/withdrawal/1", w.b);
  }
  Id digest() const { return hash("VAPP/withdrawal-leaf/1", encode()); }
  static Leaf read(Reader &r) {
    Leaf l;
    l.chain = r.id();
    l.bridge = r.id();
    l.version = r.n(4);
    l.module = r.n(4);
    l.owner = r.id();
    l.source = r.n(1);
    l.nonce = r.n(8);
    l.gross = r.n(8);
    l.maxFee = r.n(8);
    l.minimum = r.n(8);
    l.recipient = r.str(51);
    l.encode();
    return l;
  }
};
inline Id branch(const Id &a, const Id &b) {
  Writer w;
  w.raw(a);
  w.raw(b);
  return hash("VAPP/withdrawal-branch/1", w.b);
}
struct Proof {
  Leaf leaf;
  uint32_t index = 0, count = 0;
  std::vector<Id> siblings;
  void write(Writer &w) const {
    w.raw(leaf.encode());
    w.n(index, 4);
    w.n(count, 4);
    w.n(siblings.size(), 1);
    for (auto &s : siblings)
      w.raw(s);
  }
  static Proof read(Reader &r) {
    Proof p;
    p.leaf = Leaf::read(r);
    p.index = r.n(4);
    p.count = r.n(4);
    auto n = r.n(1);
    need(n <= 20, "withdrawal path bound");
    while (n--)
      p.siblings.push_back(r.id());
    return p;
  }
  Id root() const {
    need(count > 0 && count <= 1048576 && index < count &&
             siblings.size() <= 20,
         "withdrawal tree bound");
    Id h = leaf.digest();
    size_t at = 0;
    uint32_t i = index, n = count;
    while (n > 1) {
      if ((i ^ 1) < n) {
        need(at < siblings.size(), "short withdrawal proof");
        h = (i & 1) ? branch(siblings[at], h) : branch(h, siblings[at]);
        ++at;
      }
      i /= 2;
      n = (n + 1) / 2;
    }
    need(at == siblings.size(), "extra withdrawal proof");
    return h;
  }
};
struct Deposit {
  Id owner{};
  uint64_t trading = 0, fuel = 0, height = 0;
};
struct Final {
  Checkpoint checkpoint;
  uint64_t submitted = 0, finalized = 0;
};
struct Record {
  Committee committee;
  uint64_t registered = 0, deposited = 0, withdrawn = 0, transition = 0;
  bool exitOnly = false;
  Id latest{};
  std::optional<Final> pending;
  std::map<Id, Final> finalized;
  std::map<Outpoint, Deposit> deposits;
  std::map<Outpoint, uint64_t> reserves;
  std::map<Id, std::pair<Outpoint, uint64_t>> paid;
};
struct State {
  std::map<Id, Record> records;
  uint64_t totalReserve = 0;
  bool relevant(const veld::Transaction &tx, const Context &c) const {
    if (marked(tx))
      return true;
    if (!tx.IsCoinbase())
      for (auto &in : tx.inputs) {
        auto u = c.coin({in.prev_tx_hash, in.prev_out_index});
        if (u && reserve(u->script))
          return true;
      }
    return false;
  }
  // Called only on an unpublished copy by the parent plan/commit boundary.
  void apply(const veld::Transaction &tx, const Context &c) {
    if (!veld::AppchainBridgeActive(c.height) || !relevant(tx, c))
      return;
    need(tx.IsValid() && !tx.IsCoinbase(),
         "ordinary bridge transaction required");
    need(!tx.outputs.empty() && tx.outputs[0].value == 0,
         "zero marker output first");
    auto payload = veld::MarkerOpReturnPayload(tx.outputs[0].script_pubkey);
    need(payload.starts_with(PREFIX) &&
             veld::IsCanonicalMarkerOpReturn(tx.outputs[0].script_pubkey,
                                             payload),
         "canonical bridge marker");
    for (size_t i = 1; i < tx.outputs.size(); ++i)
      need(!tx.outputs[i].script_pubkey.empty() &&
               tx.outputs[i].script_pubkey[0] != 0x6a,
           "single-purpose bridge outputs");
    Bytes body(payload.begin() + PREFIX.size(), payload.end());
    Reader r{body};
    auto op = r.n(1);
    need(op <= 5, "unknown bridge operation");
    uint64_t reserveIn = 0, ordinaryIn = 0;
    std::vector<Outpoint> spent;
    std::set<Outpoint> unique;
    for (auto &in : tx.inputs) {
      Outpoint p{in.prev_tx_hash, in.prev_out_index};
      need(unique.insert(p).second, "duplicate bridge input");
      auto u = c.coin(p);
      need(u.has_value(), "canonical bridge funding input");
      need(
          u->height < c.height &&
              (!u->coinbase || c.height - u->height >= veld::COINBASE_MATURITY),
          "mature prior-block funding");
      if (reserve(u->script)) {
        need(op == 5 && in.script_sig.empty(),
             "reserve requires exact payout transition");
        credit(reserveIn, u->value);
        spent.push_back(p);
      } else {
        need(ordinary(u->script) && c.ordinaryFunding(u->script),
             "ordinary external funding only");
        credit(ordinaryIn, u->value);
      }
    }
    need(spent.size() <= 32, "reserve input bound");
    if (op == 0) {
      auto committee = decodeCommittee(r.str(20000));
      r.end();
      need(veld::AppchainBridgeDescriptorAllowed(committee.id()) &&
               committee.parentGenesis == c.genesis && records.size() < 16 &&
               !records.contains(committee.bridge),
           "descriptor registration identity/cap");
      checkOrdinaryOutputs(tx, 1, c);
      Record rec;
      rec.committee = committee;
      rec.registered = c.height;
      records.emplace(committee.bridge, std::move(rec));
      return;
    }
    auto id = r.id();
    auto found = records.find(id);
    need(found != records.end(), "unregistered bridge");
    auto &rec = found->second;
    auto script = reserveScript(id);
    if (op == 1) {
      auto owner = r.id();
      auto trading = r.n(8), fuel = r.n(8);
      r.end();
      auto amount = add(trading, fuel);
      auto last = rec.latest == Id{} ? rec.registered
                                     : rec.finalized.at(rec.latest).finalized;
      need(!rec.exitOnly && c.height - last < STALE, "bridge deposits paused");
      need(owner != Id{} && amount > 0 && amount <= CAP - totalReserve,
           "aggregate reserve cap");
      need(tx.outputs.size() >= 2 && tx.outputs[1].script_pubkey == script &&
               tx.outputs[1].value == amount,
           "exact deposit allocation");
      checkOrdinaryOutputs(tx, 2, c);
      Outpoint p{tx.GetTxID(), 1};
      need(!rec.deposits.contains(p), "deposit replay");
      rec.deposits.emplace(p, Deposit{owner, trading, fuel, c.height});
      rec.reserves.emplace(p, amount);
      credit(rec.deposited, amount);
      credit(totalReserve, amount);
      return;
    }
    if (op == 2) {
      auto cert = Certificate::decode(r.str(35000));
      r.end();
      need(!rec.exitOnly && !rec.pending,
           "checkpoint admission paused/pending");
      auto sequence =
          rec.latest == Id{}
              ? 1
              : add(rec.finalized.at(rec.latest).checkpoint.sequence, 1);
      cert.verify(rec.committee, rec.latest, sequence);
      checkAnchor(cert.checkpoint, c);
      auto &cp = cert.checkpoint;
      uint64_t matured = 0;
      for (auto &[p, d] : rec.deposits)
        if (c.height >= d.height && c.height - d.height + 1 >= CONFIRMATIONS)
          credit(matured, add(d.trading, d.fuel));
      need(cp.depositedTotal <= matured && cp.withdrawnTotal <= rec.withdrawn,
           "unconfirmed/unknown checkpoint accounting");
      if (rec.latest != Id{}) {
        auto &old = rec.finalized.at(rec.latest).checkpoint;
        need(cp.sourceHeight > old.sourceHeight &&
                 greaterWork(cp.sourceWork, old.sourceWork) &&
                 cp.parentAnchorHeight >= old.parentAnchorHeight &&
                 cp.depositedTotal >= old.depositedTotal &&
                 cp.withdrawnTotal >= old.withdrawnTotal,
             "checkpoint regression");
      }
      checkOrdinaryOutputs(tx, 1, c);
      rec.pending = Final{cp, c.height, 0};
      return;
    }
    if (op == 3) {
      auto checkpoint = r.id();
      r.end();
      need(!rec.exitOnly && rec.pending &&
               rec.pending->checkpoint.id() == checkpoint &&
               c.height - rec.pending->submitted >= DELAY,
           "checkpoint finalization delay/state");
      checkAnchor(rec.pending->checkpoint, c);
      checkOrdinaryOutputs(tx, 1, c);
      auto f = *rec.pending;
      f.finalized = c.height;
      rec.finalized.emplace(checkpoint, f);
      rec.latest = checkpoint;
      rec.pending.reset();
      return;
    }
    if (op == 4) {
      auto a = Certificate::decode(r.str(35000)),
           b = Certificate::decode(r.str(35000));
      r.end();
      const auto &ca = a.checkpoint;
      const auto &cb = b.checkpoint;
      need(ca.previous == cb.previous && ca.sequence == cb.sequence &&
               ca.id() != cb.id(),
           "conflict slot");
      uint64_t seq = 1;
      if (ca.previous != Id{}) {
        auto prev = rec.finalized.find(ca.previous);
        need(prev != rec.finalized.end(), "unknown conflict predecessor");
        seq = add(prev->second.checkpoint.sequence, 1);
      }
      a.verify(rec.committee, ca.previous, seq);
      b.verify(rec.committee, ca.previous, seq);
      checkOrdinaryOutputs(tx, 1, c);
      rec.exitOnly = true;
      return;
    }
    auto sequence = r.n(8);
    auto finalized = r.id();
    auto deduction = r.n(8);
    auto count = r.n(1);
    need(sequence == add(rec.transition, 1) && count > 0 && count <= 32,
         "payout sequence/count");
    auto checkpoint = rec.finalized.find(finalized);
    need(checkpoint != rec.finalized.end(),
         "finalized withdrawal root required");
    std::vector<Proof> proofs;
    Id last{};
    uint64_t gross = 0;
    for (unsigned i = 0; i < count; ++i) {
      auto p = Proof::read(r);
      auto wid = p.leaf.id();
      auto &l = p.leaf;
      need((i == 0 || last < wid) && !rec.paid.contains(wid),
           "withdrawal order/replay");
      last = wid;
      need(l.chain == rec.committee.childGenesis && l.bridge == id &&
               l.version == rec.committee.version &&
               p.root() == checkpoint->second.checkpoint.withdrawalsRoot,
           "withdrawal identity/proof");
      auto feePart = deduction / count + (i < deduction % count ? 1 : 0);
      need(feePart <= l.maxFee && l.gross - feePart >= l.minimum &&
               c.ordinaryFunding(l.recipient),
           "signed recipient/fee budget");
      need(tx.outputs.size() > i + 1 &&
               tx.outputs[i + 1].value == l.gross - feePart &&
               tx.outputs[i + 1].script_pubkey == l.recipient,
           "exact withdrawal output");
      credit(gross, l.gross);
      proofs.push_back(std::move(p));
    }
    r.end();
    need(reserveIn >= gross && gross <= rec.deposited - rec.withdrawn,
         "reserve funding");
    for (auto &p : spent) {
      auto u = c.coin(p);
      auto it = rec.reserves.find(p);
      need(it != rec.reserves.end() && u->script == script &&
               u->value == it->second,
           "registered reserve outpoint");
    }
    size_t out = count + 1;
    uint64_t change = reserveIn - gross;
    if (change) {
      need(tx.outputs.size() > out && tx.outputs[out].value == change &&
               tx.outputs[out].script_pubkey == script,
           "exact reserve change");
      ++out;
    }
    checkOrdinaryOutputs(tx, out, c);
    uint64_t sponsorChange = 0;
    for (size_t i = out; i < tx.outputs.size(); ++i)
      credit(sponsorChange, tx.outputs[i].value);
    need(sponsorChange <= ordinaryIn, "sponsor cannot consume backing");
    for (auto &p : spent)
      rec.reserves.erase(p);
    if (change)
      rec.reserves.emplace(Outpoint{tx.GetTxID(), uint32_t(count + 1)}, change);
    for (size_t i = 0; i < proofs.size(); ++i)
      rec.paid.emplace(
          proofs[i].leaf.id(),
          std::make_pair(Outpoint{tx.GetTxID(), uint32_t(i + 1)}, c.height));
    credit(rec.withdrawn, gross);
    debit(totalReserve, gross);
    rec.transition = sequence;
  }
  static void checkOrdinaryOutputs(const veld::Transaction &tx, size_t first,
                                   const Context &c) {
    for (size_t i = first; i < tx.outputs.size(); ++i)
      need(ordinary(tx.outputs[i].script_pubkey) &&
               c.ordinaryFunding(tx.outputs[i].script_pubkey),
           "ordinary change only");
  }
  static bool greaterWork(const std::array<uint8_t, 64> &a,
                          const std::array<uint8_t, 64> &b) {
    return std::lexicographical_compare(b.rbegin(), b.rend(), a.rbegin(),
                                        a.rend());
  }
  static void checkAnchor(const Checkpoint &cp, const Context &c) {
    need(cp.parentAnchorHeight < c.height &&
             c.height - cp.parentAnchorHeight >= CONFIRMATIONS &&
             c.blockHash(cp.parentAnchorHeight) == cp.parentAnchorHash,
         "checkpoint parent anchor depth/hash");
  }
  Id digest() const {
    Writer w;
    w.n(totalReserve, 8);
    w.n(records.size(), 4);
    for (auto &[id, r] : records) {
      w.raw(id);
      w.str(r.committee.encode(), 20000);
      w.n(r.registered, 8);
      w.n(r.deposited, 8);
      w.n(r.withdrawn, 8);
      w.n(r.transition, 8);
      w.n(r.exitOnly, 1);
      w.raw(r.latest);
      w.n(r.pending.has_value(), 1);
      if (r.pending) {
        w.str(r.pending->checkpoint.encode(), 1024);
        w.n(r.pending->submitted, 8);
      }
      w.n(r.finalized.size(), 4);
      for (auto &[key, f] : r.finalized) {
        w.raw(key);
        w.str(f.checkpoint.encode(), 1024);
        w.n(f.submitted, 8);
        w.n(f.finalized, 8);
      }
      w.n(r.deposits.size(), 4);
      for (auto &[p, d] : r.deposits) {
        p.write(w);
        w.raw(d.owner);
        w.n(d.trading, 8);
        w.n(d.fuel, 8);
        w.n(d.height, 8);
      }
      w.n(r.reserves.size(), 4);
      for (auto &[p, v] : r.reserves) {
        p.write(w);
        w.n(v, 8);
      }
      w.n(r.paid.size(), 4);
      for (auto &[id, p] : r.paid) {
        w.raw(id);
        p.first.write(w);
        w.n(p.second, 8);
      }
    }
    return hash("VAPP/parent-bridge-state/1", w.b);
  }
};
struct Anchor {
  uint64_t height = 0;
  ParentHash hash{};
  auto operator<=>(const Anchor &) const = default;
  void write(Writer &w) const {
    w.n(height, 8);
    w.raw(hash);
  }
  static Anchor read(Reader &r) {
    Anchor a;
    a.height = r.n(8);
    auto h = r.raw(32);
    std::copy(h.begin(), h.end(), a.hash.begin());
    return a;
  }
};
// A view can only be issued by the local native parent validator. It is not an
// RPC assertion or a stand-alone proof. Its anchor must still be canonical.
class View {
  friend class veld::Blockchain;
  ParentHash genesis_;
  Anchor anchor_;
  std::shared_ptr<const State> state_;
  View(ParentHash g, Anchor a, std::shared_ptr<const State> s)
      : genesis_(g), anchor_(a), state_(std::move(s)) {}

public:
  const ParentHash &genesis() const { return genesis_; }
  const Anchor &anchor() const { return anchor_; }
  const State &state() const { return *state_; }
};
} // namespace app::bridge
