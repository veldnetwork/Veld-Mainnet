"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../include/network/ui_desktop.h"), "utf8");
function extract(name) {
  const start = source.indexOf("function " + name + "(");
  assert(start >= 0, name);
  const end = source.indexOf("\n}", start);
  assert(end > start, name);
  return source.slice(start, end + 2);
}
function element() {
  return {style: {}, children: [], value: "", appendChild(child) { this.children.push(child); },
    set textContent(value) { this.value = value; this.children = []; },
    get textContent() { return this.value; },
    set innerHTML(_) { throw new Error("numeric display must never parse HTML"); }};
}
const display = vm.createContext({document: {createElement: () => element()}});
vm.runInContext(extract("_veldRenderStakingCountdown"), display);
for (const blocks of [0, 1, 480]) {
  const label = element();
  display._veldRenderStakingCountdown(label, blocks);
  assert.equal(label.textContent, blocks + " blocks ");
  assert.equal(label.children.length, 1);
  assert.equal(label.children[0].textContent, "(~" + blocks * 3 + " min)");
}
for (const invalid of [null, undefined, "480", "ordinary text", {}, [], -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER]) {
  const label = element();
  display._veldRenderStakingCountdown(label, invalid);
  assert.equal(label.textContent, "—");
  assert.equal(label.children.length, 0);
}
display._veldRenderStakingCountdown(null, 1);

// Opaque parser fixtures and inert signer/broadcast stubs. These tests create
// no key, signed transaction, executable markup, network request, or exploit.
const ownerScript = "76a914" + "19".repeat(20) + "88ac";
let transaction = {inputs: [{}, {}], outputs: [{value_units_str: "1000", script_pubkey_hex: ownerScript}]};
let signed = 0, authenticated = 0, failBroadcast = false;
const prep = {unsigned_tx_hex: "ordinary-parser-fixture", inputs: [{}, {}], inputs_consolidated: 99999,
  verified_consolidation_inputs: 99999, verified_consolidation_output_units: "99999"};
const signing = vm.createContext({
  VELD_MIN_TX_FEE_UNITS: 100000,
  _veldParseUnsignedTx: () => transaction,
  _veldRequireSelfCustodySigner: () => {},
  _veldRequireBoundIdentity: () => ({address: "fixture-owner"}),
  _veldAddrToHash160Hex: () => "19".repeat(20),
  _veldVerifyUnsignedTxOutputs: () => {},
  _veldAssertAllP2PKHOutputsToSelf: () => {},
  _veldAssertAllP2PKHOutputsInAllowed: () => {},
  _veldAssertOpReturnExact: (_, policy) => assert.equal(policy, ""),
  _veldVerifyInputSighashes: () => {},
  _veldAuthenticatePreparedPrevouts: async () => { ++authenticated; },
  veldCrypto: {
    injectSignatures: async () => { ++signed; return "inert-signer-result"; },
    sha256d: () => "12".repeat(32)
  },
  _veldBroadcastExactSigned: async () => {
    if (failBroadcast) throw new Error("fixture transport unavailable");
    return "12".repeat(32);
  },
  rpc: async () => ({...prep})
});
vm.runInContext(["_veldConsolidationProgress", "_veldConsolidationBudget", "signAndBroadcast"].map(extract).join("\n"), signing);
const call = budget => signing.signAndBroadcast("prepareconsolidatetx", ["fixture-owner"], "inert-seed-placeholder", null, null, null, null, "", budget);
(async () => {
  const result = await call();
  assert.equal(result.verified_consolidation_inputs, 2);
  assert.equal(result.verified_consolidation_reduction, 1);
  assert.equal(result.verified_consolidation_output_units, "1000");
  assert.equal(signed, 1);
  assert.equal(authenticated, 1);
  const valid = transaction;
  for (const candidate of [
    {...valid, inputs: [{}]},
    {...valid, outputs: [...valid.outputs, ...valid.outputs]},
    {...valid, outputs: [{value_units_str: "1000", script_pubkey_hex: "ordinary-other-script"}]},
    {...valid, outputs: [{value_units_str: "0", script_pubkey_hex: ownerScript}]}
  ]) {
    transaction = candidate;
    const before = signed;
    await assert.rejects(call());
    assert.equal(signed, before);
  }
  transaction = valid;
  const shared = signing._veldConsolidationBudget(1);
  const before = signed;
  const results = await Promise.allSettled([call(shared), call(shared)]);
  assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
  assert.equal(shared.remaining(), 0);
  assert.equal(signed, before + 1);
  const failed = signing._veldConsolidationBudget(1);
  failBroadcast = true;
  await assert.rejects(call(failed), /transport unavailable/);
  failBroadcast = false;
  const afterFailure = signed;
  await assert.rejects(call(failed), /budget reached/);
  assert.equal(signed, afterFailure);
  assert.equal(failed.remaining(), 0);
  const feeBudget = signing._veldConsolidationBudget(8);
  assert.throws(() => feeBudget.reserve(100001), /budget reached/);
  assert.equal(feeBudget.remaining(), 8);
  for (let i = 0; i < 8; ++i) feeBudget.reserve(100000);
  assert.throws(() => feeBudget.reserve(100000), /budget reached/);
  assert.throws(() => signing._veldConsolidationBudget(65), /Invalid/);
  // Exercise the actual automatic caller and scheduler with a fake clock.
  // Scheduled refreshes cannot create fresh signing authority after exhaustion.
  let clock = 1000000, rpcCalls = 0;
  signing.Date = {now: () => clock};
  signing.currentAddr = "fixture-owner";
  signing.__autoConsolidateActive = false;
  signing.__autoConsolidateChecking = false;
  signing.__autoConsolidatePreferenceRevision = 0;
  // Identity changes and operation locks are covered by wallet_auto_consolidation_tests.
  signing.autoConsolidateContextReady = () => true;
  signing.__opLock = () => true;
  signing.__opUnlock = () => {};
  signing.__autoConsolidateSigningBudget = null;
  signing.__autoConsolidateLastRun = 0;
  signing.__autoConsolidateMinGapMs = 300000;
  signing.AUTO_CONSOLIDATE_PER_BATCH = 150;
  signing.AUTO_CONSOLIDATE_TRIGGER_TOTAL = 20;
  signing.AUTO_CONSOLIDATE_TRIGGER_DUST = 5;
  signing.AUTO_CONSOLIDATE_THRESHOLD_VELD = "5.0";
  signing.__veldKey = {get: () => "inert fixture".padEnd(64, "X")};
  signing.autoConsolidateEnabled = () => true;
  signing.autoConsolidateNotify = () => {};
  signing.loadWalletAddr = () => {};
  signing.setTimeout = resolve => setImmediate(resolve);
  signing.rpc = async method => {
    ++rpcCalls;
    if (method === "getbalance") return {pending_in_veld: 0, pending_out_veld: 0};
    if (method === "getdustutxocount") return {total_count: 100, dust_count: 100};
    return {...prep};
  };
  vm.runInContext(["_veldAutomaticConsolidationBudget", "autoConsolidateRun", "autoConsolidateMaybe"].map(extract).join("\n"), signing);
  const beforeAuto = signed;
  signing.autoConsolidateMaybe();
  for (let i = 0; i < 32; ++i) await new Promise(setImmediate);
  assert.equal(signing.__autoConsolidateActive, false);
  assert.equal(signed, beforeAuto + 8);
  assert.equal(signing._veldAutomaticConsolidationBudget().remaining(), 0);
  const afterAutoRpc = rpcCalls;
  clock += 6 * 60 * 1000;
  signing.autoConsolidateMaybe();
  signing.autoConsolidateRun("inert fixture", "fixture-owner", 0, 100, "0");
  for (let i = 0; i < 4; ++i) await new Promise(setImmediate);
  assert.equal(signed, beforeAuto + 8);
  assert.equal(rpcCalls, afterAutoRpc);
  // A distinct explicit manual operation still has its own finite authority.
  await call(signing._veldConsolidationBudget(1));
  assert.equal(signed, beforeAuto + 9);
  console.log("PASS: countdown text nodes; owned UTXO reduction; local progress; concurrent fee reservation; failed-broadcast accounting; scheduler cannot renew authority");
})().catch(error => { console.error(error); process.exitCode = 1; });
