#pragma once
#if defined(VELD_APPCHAIN_CONTRACT_TESTNET) && (defined(VELD_PUBLIC_MAINNET) || defined(VELD_APPCHAIN_PUBLIC_CHILD))
#error "Experimental contract actions cannot be enabled on mainnet"
#endif
#include "appchain/codec/types.h"
#include <openssl/crypto.h>
extern "C" {
#include "mldsa65/api.h"
}
namespace app {
enum class Action : uint16_t {
  Transfer = 1,
  ToFuel = 2,
  FromFuel = 3,
  Withdraw = 4,
  AssetCreate = 16,
  AssetTransfer = 17,
  ExchangeCreate = 32,
  PoolSeed = 33,
  Swap = 34,
  LpAdd = 35,
  LpRemove = 36,
  CardRegister = 48,
  CardList = 49,
  CardCancel = 50,
  CardBuy = 51,
  CardRedeem = 52,
  CardRedemptionCancel = 53,
  CardHandoff = 54,
  CardReceive = 55,
  CardHold = 56,
  UsdcCredit = 64,
  UsdcBurn = 65,
  UsdcPaid = 66,
  BookCreate = 80,
  BookPlace = 81,
  BookCancel = 82,
  ContractDeploy = 96,
  ContractCall = 97
};
inline bool cardAction(uint16_t n) { return n>=48 && n<=56; }
inline bool usdcAction(uint16_t n) { return n>=64 && n<=66; }
inline bool bookAction(uint16_t n) { return n>=80 && n<=82; }
inline unsigned signatureChecks(Action a) { return (a==Action::UsdcCredit||a==Action::UsdcPaid)?8:a==Action::CardRegister?3:1; }
inline bool supported(uint16_t n) {
#ifdef VELD_APPCHAIN_CONTRACT_TESTNET
  if(n==96||n==97)return true;
#endif
  return (n >= 1 && n <= 4) || (n >= 16 && n <= 17) || (n >= 32 && n <= 36) || cardAction(n) || usdcAction(n) || bookAction(n);
}
struct Key {
  std::array<uint8_t, 1952> pub{};
  std::array<uint8_t, 4032> secret{};
  Key() {
    need(PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pub.data(), secret.data()) ==
             0,
         "MLDSA keygen");
  }
  Key(const Key &) = delete;
  Key &operator=(const Key &) = delete;
  ~Key() { OPENSSL_cleanse(secret.data(), secret.size()); }
};
inline Id owner(const Id &chain, std::span<const uint8_t> pub) {
  need(pub.size() == 1952, "public key length");
  Writer w;
  w.raw(chain);
  w.raw(pub);
  return hash("VAPP/account/1", w.b);
}
struct Tx {
  Id chain{}, bridge{}, sender{}, payer{}, recipient{};
  uint32_t bridgeVersion = 1, moduleVersion = 1;
  uint64_t nonce = 1, expiry = 10, gasLimit = 1000000, gasPricePpm = 1000000,
           maxFee = 1000000;
  Action action = Action::Transfer;
  Bytes payload;
  std::array<uint8_t, 1952> pub{};
  std::array<uint8_t, 3309> sig{};
  Bytes body() const {
    Writer w;
    w.raw(Bytes{'V', 'A', 'P', 'P', 1});
    w.n(1, 2);
    w.raw(chain);
    w.raw(bridge);
    w.n(bridgeVersion, 4);
    w.raw(sender);
    w.raw(payer);
    w.n(nonce, 8);
    w.n(uint16_t(action), 2);
    w.n(moduleVersion, 4);
    w.raw(recipient);
    w.n(expiry, 8);
    w.n(gasLimit, 8);
    w.n(gasPricePpm, 8);
    w.n(maxFee, 8);
    w.str(payload, 60000);
    return w.b;
  }
  Id digest() const { return hash("VAPP/transaction/1", body()); }
  Bytes encode() const {
    Writer w;
    w.raw(body());
    w.raw(pub);
    w.raw(sig);
    need(w.b.size() <= 65536, "transaction bytes");
    return w.b;
  }
  void sign(const Key &key) {
    pub = key.pub;
    sender = owner(chain, pub);
    payer = sender;
    auto h = digest();
    size_t size = 0;
    need(PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
             sig.data(), &size, h.data(), h.size(), key.secret.data()) == 0 &&
             size == sig.size(),
         "MLDSA sign");
  }
  bool authentic() const {
    auto h = digest();
    return sender == owner(chain, pub) && sender == payer &&
           PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
               sig.data(), sig.size(), h.data(), h.size(), pub.data()) == 0;
  }
  static Tx decode(std::span<const uint8_t> b) {
    need(b.size() <= 65536, "transaction bytes");
    Reader r{b};
    need(r.raw(5) == Bytes({'V', 'A', 'P', 'P', 1}) && r.n(2) == 1,
         "wire profile");
    Tx t;
    t.chain = r.id();
    t.bridge = r.id();
    t.bridgeVersion = r.n(4);
    t.sender = r.id();
    t.payer = r.id();
    t.nonce = r.n(8);
    auto a = r.n(2);
    need(supported(a), "unknown action");
    t.action = Action(a);
    t.moduleVersion = r.n(4);
    t.recipient = r.id();
    t.expiry = r.n(8);
    t.gasLimit = r.n(8);
    t.gasPricePpm = r.n(8);
    t.maxFee = r.n(8);
    t.payload = r.str(60000);
    auto pub = r.raw(1952), sig = r.raw(3309);
    std::copy(pub.begin(), pub.end(), t.pub.begin());
    std::copy(sig.begin(), sig.end(), t.sig.begin());
    r.end();
    need(t.encode() == Bytes(b.begin(), b.end()), "canonical transaction");
    return t;
  }
};
} // namespace app
