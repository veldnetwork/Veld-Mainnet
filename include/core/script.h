#pragma once

#include "../core/hash.h"
#include "../core/transaction.h"
#include "../crypto/ripemd160.h"
#include "../crypto/veld_signing.h"
#include <vector>
#include <stack>
#include <stdexcept>
#include <string>

#include "hash.h"

namespace veld {

enum class OpCode : uint8_t {
    OP_0 = 0x00,
    OP_PUSHDATA1 = 0x4C,
    OP_PUSHDATA2 = 0x4D,
    OP_PUSHDATA4 = 0x4E,
    OP_1NEGATE = 0x4F,
    OP_1 = 0x51,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5A,
    OP_11 = 0x5B,
    OP_12 = 0x5C,
    OP_13 = 0x5D,
    OP_14 = 0x5E,
    OP_15 = 0x5F,
    OP_16 = 0x60,
    OP_NOP = 0x61,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6A,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_2DROP = 0x6D,
    OP_SWAP = 0x7C,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_SHA256 = 0xA8,
    OP_HASH160 = 0xA9,
    OP_HASH256 = 0xAA,
    OP_CHECKSIG = 0xAC,
    OP_CHECKSIGVERIFY = 0xAD,
    OP_CHECKMULTISIG = 0xAE,
    OP_CHECKMULTISIGVERIFY = 0xAF,
    // Covenant opcodes (ex-OP_NOPn upgrades, BIP65/112/119). Inert and
    // default-rejected below COVENANTS_ACTIVATION_HEIGHT; meaningful at/above.
    OP_CHECKLOCKTIMEVERIFY = 0xB1, // BIP65 absolute timelock
    OP_CHECKSEQUENCEVERIFY = 0xB2, // BIP112 relative timelock
    OP_CHECKTEMPLATEVERIFY = 0xB3, // BIP119 covenant / templated spend
};

constexpr int MAX_OPS_PER_SCRIPT = 201;
constexpr size_t MAX_STACK_SIZE = 1000; // combined main+alt stack depth cap

// Execution context threaded through the interpreter. For the legacy P2PKH
// path every field is irrelevant except covenants_active=false, which keeps
// behaviour byte-identical to the pre-covenant interpreter. The timelock and
// covenant opcodes consult block_height / mtp / utxo_height.
struct ScriptContext {
    uint64_t block_height = 0; // connecting block (block path) or tip+1 (mempool)
    uint64_t mtp = 0;          // median-time-past of the last 11 blocks
    uint64_t utxo_height = 0;  // confirmation height of the output being spent (CSV)
    bool covenants_active = false;
};

// BIP65 boundary: a CLTV/locktime threshold below this is a block height,
// at or above it is a unix timestamp.
constexpr uint64_t LOCKTIME_THRESHOLD = 500000000ULL;

// Minimal CScriptNum: little-endian, sign-magnitude (high bit of the last
// byte is the sign). Bounded to `max_size` bytes so locktime reads can't be
// abused. Returns false on over-long encodings.
inline bool ReadScriptNum(const std::vector<uint8_t>& v, int max_size, int64_t& out) {
    if ((int)v.size() > max_size)
        return false;
    if (v.empty()) {
        out = 0;
        return true;
    }
    // Reject non-minimal number encodings: a trailing 0x00/0x80 byte that
    // isn't carrying a sign bit for the previous byte is just padding.
    if ((v.back() & 0x7f) == 0) {
        if (v.size() <= 1 || (v[v.size() - 2] & 0x80) == 0)
            return false;
    }
    int64_t result = 0;
    for (size_t i = 0; i < v.size(); ++i)
        result |= (int64_t)v[i] << (8 * i);
    if (v.back() & 0x80) {
        int64_t mask = (int64_t)1 << (8 * v.size() - 1);
        result &= ~mask;
        result = -result;
    }
    out = result;
    return true;
}

inline std::vector<uint8_t> EncodeScriptNum(int64_t value) {
    std::vector<uint8_t> result;
    if (value == 0)
        return result;
    bool neg = value < 0;
    uint64_t abs = neg ? (uint64_t)(-value) : (uint64_t)value;
    while (abs) {
        result.push_back(abs & 0xFF);
        abs >>= 8;
    }
    if (result.back() & 0x80)
        result.push_back(neg ? 0x80 : 0x00);
    else if (neg)
        result.back() |= 0x80;
    return result;
}

// Transaction-level lock-time enforcement: absolute (nLockTime) and relative
// (nSequence) locks checked against the chain. `utxo_conf(i, out_height,
// out_mtp)` yields the spent output's confirmation height and that height's
// median-time-past for input i (return false to skip — a missing UTXO is
// rejected elsewhere). This is the single authoritative elapsed-lock check;
// the CLTV/CSV opcodes only validate the values a transaction commits to, so
// enforcement lives in exactly one place and cannot diverge.
template <class ConfFn>
inline bool CheckTxLockTimes(const Transaction& tx, uint64_t height, uint64_t mtp,
                             ConfFn utxo_conf) {
    if (tx.locktime != 0) {
        bool all_final = true;
        for (const auto& in : tx.inputs)
            if (in.sequence != 0xFFFFFFFFu) {
                all_final = false;
                break;
            }
        if (!all_final) {
            uint64_t cmp = ((uint64_t)tx.locktime < LOCKTIME_THRESHOLD) ? height : mtp;
            if ((uint64_t)tx.locktime > cmp)
                return false; // not yet final
        }
    }
    for (size_t i = 0; i < tx.inputs.size(); ++i) {
        uint32_t seq = tx.inputs[i].sequence;
        if (seq & 0x80000000u)
            continue; // relative lock disabled
        uint64_t out_h = 0, out_mtp = 0;
        if (!utxo_conf(i, out_h, out_mtp))
            continue;
        const uint32_t TYPE = 0x00400000u, MASK = 0x0000FFFFu;
        uint32_t val = seq & MASK;
        if (seq & TYPE) { // time domain (512 s units)
            if (mtp < out_mtp + (uint64_t)val * 512ull)
                return false;
        } else { // height domain
            if (height < out_h + (uint64_t)val)
                return false;
        }
    }
    return true;
}

enum class ScriptType { P2PKH, P2PK, MULTISIG, OP_RETURN, UNKNOWN };

inline ScriptType DetectScriptType(const std::vector<uint8_t>& script) {
    if (script.size() == 25 && script[0] == 0x76 && script[1] == 0xA9 && script[2] == 0x14 &&
        script[23] == 0x88 && script[24] == 0xAC)
        return ScriptType::P2PKH;

    if (!script.empty() && script[0] == 0x6A)
        return ScriptType::OP_RETURN;

    if (script.size() == 1956 && script[0] == 0x4D && script[1] == 0xA0 && script[2] == 0x07 &&
        script[1955] == 0xAC)
        return ScriptType::P2PK;

    return ScriptType::UNKNOWN;
}

inline std::array<uint8_t, 20> ExtractP2PKHHash(const std::vector<uint8_t>& script) {
    std::array<uint8_t, 20> result{};
    if (script.size() == 25 && DetectScriptType(script) == ScriptType::P2PKH) {
        for (int i = 0; i < 20; ++i)
            result[i] = script[3 + i];
    }
    return result;
}

using StackItem = std::vector<uint8_t>;
using ScriptStack = std::stack<StackItem>;

constexpr uint8_t VELD_ADDR_VERSION_MAINNET = 0x46;
constexpr uint8_t VELD_ADDR_VERSION_TESTNET = 0x6F;
// P2SH address versions — covenant destinations (escrow / swap / channel).
constexpr uint8_t VELD_P2SH_VERSION_MAINNET = 0x05;
constexpr uint8_t VELD_P2SH_VERSION_TESTNET = 0xC4;

// Internal: Base58Check decode → returns the full 21-byte payload (1 byte
// version + 20-byte hash) on success, empty vector on failure (size,
// non-base58 chars, bad checksum, wrong payload length). Does NOT enforce
// version byte — that's the caller's job.
inline std::vector<uint8_t> Base58CheckDecode_(const std::string& address) {
    if (address.size() < 25 || address.size() > 35)
        return {};

    static const std::string B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::vector<uint8_t> dec;
    uint32_t leading = 0;
    for (char c : address) {
        if (c == '1') {
            ++leading;
        } else
            break;
    }
    std::vector<uint8_t> digits(1, 0);
    for (char c : address) {
        auto pos = B58.find(c);
        if (pos == std::string::npos)
            return {};
        int carry = (int)pos;
        for (auto& d : digits) {
            carry += 58 * (int)d;
            d = (uint8_t)(carry % 256);
            carry /= 256;
        }
        while (carry > 0) {
            digits.push_back((uint8_t)(carry % 256));
            carry /= 256;
        }
    }
    dec.assign(leading, 0);
    for (auto it = digits.rbegin(); it != digits.rend(); ++it)
        dec.push_back(*it);

    if (dec.size() < 5)
        return {};
    std::vector<uint8_t> payload(dec.begin(), dec.end() - 4);
    std::array<uint8_t, 4> chk = {dec[dec.size() - 4], dec[dec.size() - 3], dec[dec.size() - 2],
                                  dec[dec.size() - 1]};
    Hash256 h1 = Hash256d(payload);
    if (h1[0] != chk[0] || h1[1] != chk[1] || h1[2] != chk[2] || h1[3] != chk[3])
        return {};
    if (payload.size() != 21)
        return {};
    return payload;
}

inline bool IsValidVeldAddress(const std::string& address, bool testnet = false) {
    auto payload = Base58CheckDecode_(address);
    if (payload.size() != 21)
        return false;
    const uint8_t v = payload[0];
    if (v == (testnet ? VELD_ADDR_VERSION_TESTNET : VELD_ADDR_VERSION_MAINNET))
        return true;
    // Covenant P2SH destinations are valid send targets too.
    if (v == VELD_P2SH_VERSION_MAINNET)
        return true;
#ifndef VELD_MAINNET_POW
    if (v == VELD_P2SH_VERSION_TESTNET)
        return true;
#endif
    return false;
}

inline std::vector<uint8_t> AddressToScript(const std::string& address) {
    auto payload = Base58CheckDecode_(address);
    if (payload.size() != 21)
        return {};
    const uint8_t ver = payload[0];

    // Covenant P2SH destination (escrow / swap / channel): OP_HASH160 <20> OP_EQUAL.
    if (ver == VELD_P2SH_VERSION_MAINNET
#ifndef VELD_MAINNET_POW
        || ver == VELD_P2SH_VERSION_TESTNET
#endif
    ) {
        std::vector<uint8_t> script = {0xA9, 0x14};
        script.insert(script.end(), payload.begin() + 1, payload.end());
        script.push_back(0x87);
        return script;
    }

#ifdef VELD_MAINNET_POW
    if (ver != VELD_ADDR_VERSION_MAINNET)
        return {};
#else
    if (ver != VELD_ADDR_VERSION_MAINNET && ver != VELD_ADDR_VERSION_TESTNET)
        return {};
#endif

    std::vector<uint8_t> script = {0x76, 0xA9, 0x14};
    script.insert(script.end(), payload.begin() + 1, payload.end());
    script.push_back(0x88);
    script.push_back(0xAC);
    return script;
}

// Token balances are authorized exclusively by the standard Veld P2PKH
// account model. P2SH is a valid native-coin covenant destination, but no
// token-ledger redeem-script authorization path exists. Keep this predicate in
// the script layer so consensus and isolated signing policy cannot drift.
inline bool IsCanonicalTokenCreditAddress(const std::string& address) {
    const std::vector<uint8_t> script = AddressToScript(address);
    return script.size() == 25 && script[0] == 0x76 && script[1] == 0xA9 && script[2] == 0x14 &&
           script[23] == 0x88 && script[24] == 0xAC;
}

inline std::string ScriptToAddress(const std::vector<uint8_t>& script, bool testnet = false) {
    if (script.size() != 25 || script[0] != 0x76 || script[1] != 0xA9 || script[2] != 0x14 ||
        script[23] != 0x88 || script[24] != 0xAC)
        return "";

    uint8_t version = testnet ? 0x6F : 0x46;
    std::vector<uint8_t> data = {version};
    data.insert(data.end(), script.begin() + 3, script.begin() + 23);
    Hash256 chk = Hash256d(data);
    data.push_back(chk[0]);
    data.push_back(chk[1]);
    data.push_back(chk[2]);
    data.push_back(chk[3]);

    static const std::string B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    int lead = 0;
    for (auto b : data) {
        if (b == 0)
            ++lead;
        else
            break;
    }
    std::vector<uint8_t> digits = {0};
    for (auto byte : data) {
        int carry = byte;
        for (auto& d : digits) {
            carry += 256 * d;
            d = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }
    std::string addr(lead, '1');
    for (auto it = digits.rbegin(); it != digits.rend(); ++it)
        addr += B58[*it];
    return addr;
}

class ScriptInterpreter {
  public:
    // Legacy entry point (no covenant context). Behaviour is byte-identical to
    // the pre-covenant interpreter: covenants are inactive so only the original
    // P2PKH opcode set is accepted. Existing callers compile unchanged.
    bool Execute(const std::vector<uint8_t>& script_sig, const std::vector<uint8_t>& script_pubkey,
                 const Transaction& tx, uint32_t input_index) {
        ScriptContext ctx; // covenants_active = false
        return Execute(script_sig, script_pubkey, tx, input_index, ctx);
    }

    // Context-aware entry point. With ctx.covenants_active, the full covenant
    // opcode set and BIP16-style P2SH redeem evaluation are enabled.
    bool Execute(const std::vector<uint8_t>& script_sig, const std::vector<uint8_t>& script_pubkey,
                 const Transaction& tx, uint32_t input_index, const ScriptContext& ctx) {
        std::vector<StackItem> stack, alt;

        // P2SH: scriptPubKey == OP_HASH160 <20> OP_EQUAL (A9 14 .. 87).
        const bool is_p2sh = ctx.covenants_active && script_pubkey.size() == 23 &&
                             script_pubkey[0] == 0xA9 && script_pubkey[1] == 0x14 &&
                             script_pubkey[22] == 0x87;

        if (is_p2sh) {
            if (!IsPushOnly(script_sig))
                return false; // BIP16 + canonical pushes
            current_subscript_ = script_pubkey;
            if (!RunScript(script_sig, stack, alt, tx, input_index, ctx))
                return false;
            if (stack.empty())
                return false;
            StackItem redeem = stack.back(); // top push = redeemScript
            // Run the P2SH template; OP_HASH160 consumes the redeemScript push and
            // OP_EQUAL leaves the hash-match bool on top.
            if (!RunScript(script_pubkey, stack, alt, tx, input_index, ctx))
                return false;
            if (stack.empty() || !IsTrue(stack.back()))
                return false;
            stack.pop_back();            // discard the EQUAL bool
            current_subscript_ = redeem; // sighash subscript = redeemScript
            if (!RunScript(redeem, stack, alt, tx, input_index, ctx))
                return false;
            // Enforce CLEANSTACK for P2SH so ignored pushes cannot alter a
            // signed transaction ID while preserving script validity. Every
            // supported covenant builder leaves exactly one Boolean result.
            return stack.size() == 1 && alt.empty() && IsTrue(stack.back());
        }

        current_subscript_ = script_pubkey;
        if (!RunScript(script_sig, stack, alt, tx, input_index, ctx))
            return false;
        if (!RunScript(script_pubkey, stack, alt, tx, input_index, ctx))
            return false;
        return !stack.empty() && IsTrue(stack.back());
    }

    bool ValidateP2PKH(const std::vector<uint8_t>& script_sig,
                       const std::vector<uint8_t>& script_pubkey, const Transaction& tx,
                       uint32_t input_index) {
        if (DetectScriptType(script_pubkey) != ScriptType::P2PKH)
            return false;
        return Execute(script_sig, script_pubkey, tx, input_index);
    }

  private:
    std::vector<uint8_t> current_subscript_;

    // A scriptSig is push-only and minimally encoded if it contains nothing but
    // canonical data/number pushes.  Signatures do not commit to scriptSig, so
    // accepting an equivalent PUSHDATA spelling would permit third-party TXID
    // mutation even when CLEANSTACK holds.
    static bool IsPushOnly(const std::vector<uint8_t>& s) {
        size_t pc = 0;
        while (pc < s.size()) {
            uint8_t op = s[pc++];
            if (op <= 0x4B) {
                const size_t n = op;
                if (n > s.size() - pc)
                    return false;
                if (n == 1 && (s[pc] == 0x81 || (s[pc] >= 1 && s[pc] <= 16))) {
                    return false; // must use OP_1NEGATE / OP_1..OP_16
                }
                pc += n;
            } else if (op == 0x4C) {
                if (pc >= s.size())
                    return false;
                const size_t n = s[pc++];
                if (n < 0x4C || n > s.size() - pc)
                    return false;
                pc += n;
            } else if (op == 0x4D) {
                if (pc + 2 > s.size())
                    return false;
                const size_t n = (size_t)s[pc] | ((size_t)s[pc + 1] << 8);
                pc += 2;
                if (n <= 0xFF || n > s.size() - pc)
                    return false;
                pc += n;
            } else if (op == 0x4F ||
                       (op >= 0x51 &&
                        op <= 0x60)) { /* OP_1NEGATE / OP_1..OP_16: single-byte numeric push */
            } else
                return false; // any executable opcode → not push-only
        }
        return true;
    }

    // BIP119-style template hash: pins the spend's structure (version, locktime,
    // input count, all sequences, output count, all outputs, this input index).
    // Deterministic and independent of the sighash, so it constrains WHERE funds
    // may go next without touching signatures.
    Hash256 ComputeTemplateHash(const Transaction& tx, uint32_t input_index) const {
        auto le32 = [](std::vector<uint8_t>& o, uint32_t v) {
            o.push_back(v & 0xFF);
            o.push_back((v >> 8) & 0xFF);
            o.push_back((v >> 16) & 0xFF);
            o.push_back((v >> 24) & 0xFF);
        };
        std::vector<uint8_t> seqs, outs;
        for (const auto& in : tx.inputs)
            le32(seqs, in.sequence);
        for (const auto& o : tx.outputs) {
            for (int i = 0; i < 8; ++i)
                outs.push_back((o.value >> (i * 8)) & 0xFF);
            Transaction::put_varint(outs, (uint64_t)o.script_pubkey.size());
            outs.insert(outs.end(), o.script_pubkey.begin(), o.script_pubkey.end());
        }
        Hash256 seq_h = Hash256d(seqs);
        Hash256 out_h = Hash256d(outs);
        std::vector<uint8_t> pre;
        le32(pre, tx.version);
        le32(pre, tx.locktime);
        le32(pre, (uint32_t)tx.inputs.size());
        pre.insert(pre.end(), seq_h.begin(), seq_h.end());
        le32(pre, (uint32_t)tx.outputs.size());
        pre.insert(pre.end(), out_h.begin(), out_h.end());
        le32(pre, input_index);
        return Hash256d(pre);
    }

    bool RunScript(const std::vector<uint8_t>& script, std::vector<StackItem>& stack,
                   std::vector<StackItem>& alt, const Transaction& tx, uint32_t input_index,
                   const ScriptContext& ctx) {
        size_t pc = 0;
        int op_count = 0;
        std::vector<bool> exec; // IF/ELSE branch-execution flags
        auto fExec = [&]() {
            for (bool b : exec)
                if (!b)
                    return false;
            return true;
        };
        const bool cov = ctx.covenants_active;

        while (pc < script.size()) {
            if (stack.size() + alt.size() > MAX_STACK_SIZE)
                return false; // depth cap
            uint8_t opcode = script[pc++];
            const bool executing = fExec();

            // Data pushes: advance pc regardless of branch, push only if executing.
            if (opcode <= 0x4B) {
                size_t n = opcode;
                if (pc + n > script.size())
                    return false;
                if (executing)
                    stack.push_back(StackItem(script.begin() + pc, script.begin() + pc + n));
                pc += n;
                continue;
            }
            if (opcode == 0x4C) { // PUSHDATA1
                if (pc >= script.size())
                    return false;
                size_t n = script[pc++];
                if (pc + n > script.size())
                    return false;
                if (executing)
                    stack.push_back(StackItem(script.begin() + pc, script.begin() + pc + n));
                pc += n;
                continue;
            }
            if (opcode == 0x4D) { // PUSHDATA2
                if (pc + 2 > script.size())
                    return false;
                size_t n = (size_t)script[pc] | ((size_t)script[pc + 1] << 8);
                pc += 2;
                if (pc + n > script.size())
                    return false;
                if (executing)
                    stack.push_back(StackItem(script.begin() + pc, script.begin() + pc + n));
                pc += n;
                continue;
            }

            if (opcode > 0x60 && ++op_count > MAX_OPS_PER_SCRIPT)
                return false;

            OpCode op = static_cast<OpCode>(opcode);

            // Control-flow opcodes run even inside a non-executing branch so that
            // nesting stays balanced.
            if (op == OpCode::OP_IF || op == OpCode::OP_NOTIF) {
                if (!cov)
                    return false;
                bool val = false;
                if (executing) {
                    if (stack.empty())
                        return false;
                    // MINIMALIF closes selector malleability: an IF condition
                    // must be exactly false (empty) or true ({1}), not any of
                    // the many byte strings IsTrue would otherwise accept.
                    const StackItem& cond = stack.back();
                    if (!cond.empty() && !(cond.size() == 1 && cond[0] == 1))
                        return false;
                    val = !cond.empty();
                    stack.pop_back();
                    if (op == OpCode::OP_NOTIF)
                        val = !val;
                }
                exec.push_back(executing && val);
                continue;
            }
            if (op == OpCode::OP_ELSE) {
                if (!cov || exec.empty())
                    return false;
                exec.back() = !exec.back();
                continue;
            }
            if (op == OpCode::OP_ENDIF) {
                if (!cov || exec.empty())
                    return false;
                exec.pop_back();
                continue;
            }
            if (!executing)
                continue; // skip everything else in a dead branch

            switch (op) {
            case OpCode::OP_0:
                stack.push_back({});
                break;

            // ---- legacy P2PKH opcode set (always available) -----------------
            case OpCode::OP_DUP:
                if (stack.empty())
                    return false;
                stack.push_back(stack.back());
                break;

            case OpCode::OP_HASH160: {
                if (stack.empty())
                    return false;
                auto top = stack.back();
                stack.pop_back();
                Hash160 h = Hash160Compute(top.data(), top.size());
                stack.push_back(StackItem(h.begin(), h.end()));
                break;
            }

            case OpCode::OP_EQUAL: {
                if (stack.size() < 2)
                    return false;
                auto b = stack.back();
                stack.pop_back();
                auto a = stack.back();
                stack.pop_back();
                stack.push_back(a == b ? StackItem{1} : StackItem{});
                break;
            }

            case OpCode::OP_EQUALVERIFY: {
                if (stack.size() < 2)
                    return false;
                auto b = stack.back();
                stack.pop_back();
                auto a = stack.back();
                stack.pop_back();
                if (a != b)
                    return false;
                break;
            }

            case OpCode::OP_CHECKSIG: {
                if (stack.size() < 2)
                    return false;
                auto pubkey = stack.back();
                stack.pop_back();
                auto sig = stack.back();
                stack.pop_back();
                bool ok = VerifySignature(sig, pubkey, tx, input_index);
                stack.push_back(ok ? StackItem{1} : StackItem{});
                break;
            }

            case OpCode::OP_RETURN:
                return false;

            case OpCode::OP_NOP:
                break;

            // ---- covenant opcode set (gated) --------------------------------
            case OpCode::OP_1NEGATE:
                if (!cov)
                    return false;
                stack.push_back(StackItem{0x81});
                break;

            case OpCode::OP_1:
            case OpCode::OP_2:
            case OpCode::OP_3:
            case OpCode::OP_4:
            case OpCode::OP_5:
            case OpCode::OP_6:
            case OpCode::OP_7:
            case OpCode::OP_8:
            case OpCode::OP_9:
            case OpCode::OP_10:
            case OpCode::OP_11:
            case OpCode::OP_12:
            case OpCode::OP_13:
            case OpCode::OP_14:
            case OpCode::OP_15:
            case OpCode::OP_16:
                if (!cov)
                    return false;
                stack.push_back(EncodeScriptNum((int)opcode - 0x50));
                break;

            case OpCode::OP_VERIFY:
                if (!cov)
                    return false;
                if (stack.empty() || !IsTrue(stack.back()))
                    return false;
                stack.pop_back();
                break;

            case OpCode::OP_DROP:
                if (!cov || stack.empty())
                    return false;
                stack.pop_back();
                break;

            case OpCode::OP_2DROP:
                if (!cov || stack.size() < 2)
                    return false;
                stack.pop_back();
                stack.pop_back();
                break;

            case OpCode::OP_SWAP: {
                if (!cov || stack.size() < 2)
                    return false;
                std::swap(stack[stack.size() - 1], stack[stack.size() - 2]);
                break;
            }

            case OpCode::OP_SHA256: {
                if (!cov || stack.empty())
                    return false;
                auto top = stack.back();
                stack.pop_back();
                SHA256 h;
                h.update(top.data(), top.size());
                Hash256 d = h.digest();
                stack.push_back(StackItem(d.begin(), d.end()));
                break;
            }

            case OpCode::OP_HASH256: {
                if (!cov || stack.empty())
                    return false;
                auto top = stack.back();
                stack.pop_back();
                Hash256 d = Hash256d(top);
                stack.push_back(StackItem(d.begin(), d.end()));
                break;
            }

            case OpCode::OP_CHECKSIGVERIFY: {
                if (!cov || stack.size() < 2)
                    return false;
                auto pubkey = stack.back();
                stack.pop_back();
                auto sig = stack.back();
                stack.pop_back();
                if (!VerifySignature(sig, pubkey, tx, input_index))
                    return false;
                break;
            }

            case OpCode::OP_CHECKMULTISIG:
            case OpCode::OP_CHECKMULTISIGVERIFY: {
                if (!cov)
                    return false;
                if (!OpCheckMultisig(stack, tx, input_index, op_count)) {
                    if (op == OpCode::OP_CHECKMULTISIGVERIFY)
                        return false;
                    stack.push_back(StackItem{});
                } else if (op == OpCode::OP_CHECKMULTISIG) {
                    stack.push_back(StackItem{1});
                }
                break;
            }

            case OpCode::OP_CHECKLOCKTIMEVERIFY: {
                if (!cov || stack.empty())
                    return false;
                if (input_index >= tx.inputs.size())
                    return false; // defensive bound
                int64_t want = 0;
                if (!ReadScriptNum(stack.back(), 5, want))
                    return false;
                if (want < 0)
                    return false;
                // Same domain (height vs time) as tx.locktime.
                bool want_time = (uint64_t)want >= LOCKTIME_THRESHOLD;
                bool lt_time = (uint64_t)tx.locktime >= LOCKTIME_THRESHOLD;
                if (want_time != lt_time)
                    return false;
                if ((uint64_t)want > (uint64_t)tx.locktime)
                    return false;
                // Input must be non-final, else locktime is disabled.
                if (tx.inputs[input_index].sequence == 0xFFFFFFFF)
                    return false;
                // CLTV leaves the value on the stack (a following OP_DROP clears it).
                break;
            }

            case OpCode::OP_CHECKSEQUENCEVERIFY: {
                if (!cov || stack.empty())
                    return false;
                if (input_index >= tx.inputs.size())
                    return false; // defensive bound
                int64_t want = 0;
                if (!ReadScriptNum(stack.back(), 5, want))
                    return false;
                if (want < 0)
                    return false;
                uint32_t want_seq = (uint32_t)want;
                if (want_seq & 0x80000000UL)
                    break; // disable bit set → no-op (BIP112)
                uint32_t in_seq = tx.inputs[input_index].sequence;
                if (in_seq & 0x80000000UL)
                    return false;                   // spender disabled relative lock
                const uint32_t TYPE = 0x00400000UL; // bit22 time/blocks flag
                const uint32_t MASK = 0x0000FFFFUL; // low 16 bits = value
                if ((want_seq & TYPE) != (in_seq & TYPE))
                    return false; // domains must match
                if ((in_seq & MASK) < (want_seq & MASK))
                    return false; // input commits to >= the required lock
                // The elapsed height/time check is the transaction-level
                // relative-locktime rule (CheckTxLockTimes); the opcode only
                // confirms the spend committed to a sufficient lock.
                break;
            }

            case OpCode::OP_CHECKTEMPLATEVERIFY: {
                if (!cov || stack.empty())
                    return false;
                const auto& commit = stack.back();
                if (commit.size() != 32)
                    return false; // fail closed on a malformed (non-32-byte) commitment
                Hash256 actual = ComputeTemplateHash(tx, input_index);
                if (!std::equal(actual.begin(), actual.end(), commit.begin()))
                    return false;
                break;
            }

            default:
                return false;
            }
        }

        return exec.empty(); // unbalanced OP_IF without OP_ENDIF → invalid
    }

    // m-of-n verify. Stack (top→down): <n> <pub_n..pub_1> <m> <sig_m..sig_1> <dummy>.
    // Sigs must match keys in the same top-down order (Bitcoin semantics), and the
    // extra dummy element is popped (the historical off-by-one, now consensus).
    bool OpCheckMultisig(std::vector<StackItem>& stack, const Transaction& tx, uint32_t input_index,
                         int& op_count) {
        if (stack.empty())
            return false;
        int64_t nkeys = 0;
        if (!ReadScriptNum(stack.back(), 4, nkeys))
            return false;
        stack.pop_back();
        if (nkeys < 0 || nkeys > 15)
            return false;
        if ((op_count += (int)nkeys) > MAX_OPS_PER_SCRIPT)
            return false;
        if ((int64_t)stack.size() < nkeys)
            return false;
        std::vector<StackItem> keys;
        for (int i = 0; i < nkeys; ++i) {
            keys.push_back(stack.back());
            stack.pop_back();
        }

        if (stack.empty())
            return false;
        int64_t nsigs = 0;
        if (!ReadScriptNum(stack.back(), 4, nsigs))
            return false;
        stack.pop_back();
        if (nsigs < 0 || nsigs > nkeys)
            return false;
        if ((int64_t)stack.size() < nsigs)
            return false;
        std::vector<StackItem> sigs;
        for (int i = 0; i < nsigs; ++i) {
            sigs.push_back(stack.back());
            stack.pop_back();
        }

        if (stack.empty())
            return false; // the historical dummy element
        if (!stack.back().empty())
            return false; // NULLDUMMY / TXID canonicality
        stack.pop_back();

        // Walk sigs and keys top-down; each sig must verify against the next key.
        size_t ki = 0, si = 0;
        while (si < sigs.size()) {
            bool matched = false;
            while (ki < keys.size()) {
                if (VerifySignature(sigs[si], keys[ki], tx, input_index)) {
                    ++ki;
                    matched = true;
                    break;
                }
                ++ki;
            }
            if (!matched)
                return false;
            ++si;
            if (keys.size() - ki < sigs.size() - si)
                return false; // not enough keys left
        }
        return true;
    }

    //  Scheme-dispatched single-signature verify.
    // sig blob: [scheme_id (1B)] [raw scheme sig] [SIGHASH_ALL=0x01]
    // ML-DSA-65 (scheme_id=0x01): sig 3311 B, pubkey 1952 B. sighash binds
    // scheme_id so cross-scheme replay is impossible.
    bool VerifySignature(const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pubkey,
                         const Transaction& tx, uint32_t input_index) {
        if (sig.empty())
            return false;
        uint8_t scheme_id = sig[0];

        switch (scheme_id) {
        case 0x01: {
            if (sig.size() != 3311)
                return false;
            if (pubkey.size() != 1952)
                return false;
            if (sig.back() != 0x01)
                return false;

            Secp256k1SigDER raw_sig(sig.begin() + 1, sig.end() - 1);
            if (raw_sig.size() != 3309)
                return false;
            Secp256k1PubKey pk;
            std::copy(pubkey.begin(), pubkey.end(), pk.begin());

            Hash256 sighash = ComputeSighash(tx, input_index, current_subscript_, scheme_id);
            return Verify(pk, sighash, raw_sig);
        }
        default:
            return false;
        }
    }

    static bool IsTrue(const StackItem& item) {
        if (item.empty())
            return false;
        for (size_t i = 0; i < item.size() - 1; ++i)
            if (item[i] != 0)
                return true;
        return item.back() != 0 && item.back() != 0x80;
    }
};

} // namespace veld
