'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {extractFunction} = require('./javascript_function_source');
const source = fs.readFileSync(process.env.VELD_WALLET_TEST_SOURCE ||
  path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
const extract = name => extractFunction(source, name);

// Parse embedded scripts without evaluating startup code or loading WASM.
let scriptCount = 0;
for (const match of source.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) {
  if (match[1].trim()) new vm.Script(match[1], {filename: 'wallet-block-' + (++scriptCount)});
}
assert(scriptCount > 0);

// Static boundary evidence complements ordinary session controls below. No
// lock/unlock race, malformed request, exploit, real key, or signature is run.
const checker = extract('_veldAssertActiveSignerSeed');
assert(checker.includes('expectedGeneration !== undefined && generation !== expectedGeneration'));
assert(checker.includes('_veldRequireSelfCustodySigner'));
assert(checker.includes('_veldAutoLockSigner'));
assert(checker.includes("document.visibilityState === 'hidden'"));
assert(extract('_veldBroadcastExactSigned').includes('!Number.isSafeInteger(expectedGeneration)'));
assert(extract('withKeypair').includes('_veldAssertActiveSignerSeed(seedHex, expectedGeneration)'));
assert(extract('sign').includes('}, true, expectedGeneration)'));
assert(extract('buildScriptSig').includes('}, true, expectedGeneration)'));
assert(extract('signMessage').includes('sign(seedHex, hashHex, expectedGeneration)'));
assert(extract('injectSignatures').includes('function signNext() {\n      _veldAssertActiveSignerSeed(seedHex, signerGeneration);'));

const asynchronousEntries = {
  signAndBroadcast: 'return Promise.resolve()',
  bvDoSwap: "bvRequireFreshFeature('swap')",
  bvDoSeed: "bvRequireFreshFeature('swap')",
  bvDoAddLp: "bvRequireFreshFeature('swap')",
  bvDoRemoveLpConfirmed: "bvRequireFreshFeature('swap')",
  bvDoRedeem: "fetch(BV_WRAP_API+'/spk",
  bvGetDeposit: "bvRequireFreshFeature('wrap')",
  _bvAttachAdmission: 'return (async function()',
  autoConsolidateMaybe: 'return Promise.resolve()',
  autoConsolidateRun: 'return Promise.resolve()',
  doConsolidateUtxos: "rpc('getdustutxocount'",
  doRegisterValidator: "rpc('getmininginfo'",
  doIncrementalUnstake: "await rpc('getstakehistory'",
  doUnstake: 'doIncrementalUnstake(addr,',
  govSubmitProposal: "rpc('getblockchaininfo'",
  govVote: "rpc('getblockchaininfo'"
};
for (const [name, firstAsync] of Object.entries(asynchronousEntries)) {
  const body = extract(name);
  assert(body.indexOf('_veldAssertActiveSignerSeed(') >= 0, name);
  assert(body.indexOf('_veldAssertActiveSignerSeed(') < body.indexOf(firstAsync), name + ': capture before async');
}
for (const name of ['signAndBroadcast', 'bvDoSwap', 'bvDoSeed', 'bvDoAddLp',
  'bvDoRemoveLpConfirmed', 'bvDoRedeem', 'govSubmitProposal', 'govVote']) {
  const body = extract(name);
  assert(/veldCrypto\.injectSignatures\([^\n;]+,\s*signerGeneration\)/.test(body), name + ': signer token');
  assert(/_veldBroadcastExactSigned\(signedHex,\s*(?:seed|keyHex),\s*signerGeneration\)/.test(body), name + ': broadcast token');
}
for (const name of ['govSubmitProposal', 'govVote']) {
  assert(extract(name).includes('signMessage(keyHex, challenge, signerGeneration)'));
  assert(extract(name).includes('sign(keyHex, challenge, signerGeneration)'));
}
assert(extract('_bvAttachAdmission').includes('veldCrypto.sign(seed,veldCrypto.sha256d(messageHex),signerGeneration)'));
assert(extract('bvGetDeposit').includes('request_id:requestId},seed,signerGeneration)'));
assert(extract('bvDoRemoveLp').includes('plan.signerGeneration=_veldAssertActiveSignerSeed(seed)'));
assert(extract('bvDoRemoveLpConfirmed').includes('_veldAssertActiveSignerSeed(seed,approved.signerGeneration)'));

// A fixed inert token stands in for the existing unlocked closure. It is never
// used for key derivation. Signing, parent lookup and transport stay in memory.
const fixtureToken = 'ab'.repeat(32), generation = 41, fixtureId = '42'.repeat(32);
let currentGeneration = generation;
const ownerHash = '19'.repeat(20), ownerScript = '76a914' + ownerHash + '88ac';
const input = '12'.repeat(32) + '00000000' + '00' + 'ffffffff';
const secondInput = '12'.repeat(32) + '01000000' + '00' + 'ffffffff';
const ordinaryBytes = '01000000' + '02' + input + secondInput +
  '01' + 'e803000000000000' + '19' + ownerScript + '00000000';
const prepared = {unsigned_tx_hex: ordinaryBytes,
  inputs: [{sighash_hex: 'ordinary-input-one'}, {sighash_hex: 'ordinary-input-two'}]};
const events = [], signatureGenerations = [], progress = [];
const context = vm.createContext({
  VELD_BROWSER_SELF_CUSTODY: true, VELD_TRUSTED_LOCAL_SIGNER: true,
  VELD_SELF_CUSTODY_REQUIRED_MESSAGE: 'Self custody required',
  isSecureContext: true, VELD_SIGNER_IDLE_MS: 300000,
  _veldSignerLastActivity: Date.now(), VELD_MIN_TX_FEE_UNITS: 100000,
  __veldKey: {get: () => fixtureToken, generation: () => currentGeneration},
  document: {visibilityState: 'visible'},
  setTimeout: fn => setImmediate(fn),
  _veldAutoLockSigner() { throw new Error('ordinary fixture unexpectedly expired'); },
  _veldRequireBoundIdentity: () => ({address: 'ordinary-owner'}),
  _veldAddrToKeyCommitmentHex: () => ownerHash,
  _veldAssertOpReturnExact: (_, value) => assert.equal(value, ''),
  _veldVerifyInputSighashes() {},
  _veldAuthenticatePreparedPrevouts: async () => { events.push('parents'); },
  // Storage itself is exercised in wallet_outbox_browser_controls.cjs.
  _veldJournalSign: async (_bytes, _inputs, _seed, _generation, sign) => sign(),
  _veldJournalBroadcast: async () => { events.push('broadcast'); return fixtureId; },
  buildScriptSig(_token, _hash, expectedGeneration) {
    assert.equal(expectedGeneration, generation);
    signatureGenerations.push(expectedGeneration);
    return '00'; // inert serialization stand-in, never a cryptographic signature
  },
  rpc: async method => {
    if (method === 'preparerawtransaction') { events.push('prepare'); return prepared; }
    if (method === 'sendrawtransaction') { events.push('broadcast'); return fixtureId; }
    throw new Error('unexpected fixture transport method');
  },
  veldCrypto: {sha256d: () => fixtureId}
});
const names = ['_veldRequireSelfCustodySigner', '_veldAssertActiveSignerSeed', '_veldActivateBoundIdentity',
  'hexToBytes', 'bytesToHex', '_veldHexToBytes', '_veldBytesToHex', '_veldParseVarint',
  '_veldParseUnsignedTx', '_veldAssertPreparedRelaySize', 'injectSignatures',
  '_veldBroadcastExactSigned', '_veldKeyCommitmentToScriptHex', 'signAndBroadcast'];
vm.runInContext(names.map(extract).join('\n'), context);
context.veldCrypto.injectSignatures = (...args) => {
  events.push('sign');
  assert.equal(args[4], generation);
  return context.injectSignatures(...args);
};

(async () => {
  assert.equal(context._veldAssertActiveSignerSeed(fixtureToken), generation);
  assert.equal(context._veldAssertActiveSignerSeed(fixtureToken.toUpperCase(), generation), generation);
  const signed = await context.injectSignatures(ordinaryBytes, prepared.inputs, fixtureToken,
    (current, total) => progress.push([current, total]), generation);
  assert.equal(typeof signed, 'string');
  assert.equal(signatureGenerations.length, 2);
  assert.deepEqual(progress, [[1, 2], [2, 2], [2, 2]]);

  // Preserve the supported mixed owned/sigless-input form.
  await context.injectSignatures(ordinaryBytes,
    [prepared.inputs[0], {sigless: true}], fixtureToken, null, generation);
  assert.equal(signatureGenerations.length, 3);
  assert.equal(await context._veldBroadcastExactSigned(signed, fixtureToken, generation), fixtureId);

  for (const explicitGeneration of [undefined, generation]) {
    events.length = 0;
    const result = await context.signAndBroadcast('preparerawtransaction', ['ordinary-owner'],
      fixtureToken, null, null, null, null, '', null, explicitGeneration);
    assert.equal(result.txid, fixtureId);
    assert.deepEqual(events, ['prepare', 'parents', 'sign', 'broadcast']);
  }
  // The normal secure browser profile uses the same session check.
  context.VELD_TRUSTED_LOCAL_SIGNER = false;
  assert.equal(context._veldAssertActiveSignerSeed(fixtureToken, generation), generation);
  // Revalidating the already-active identity during an ordinary operation must
  // not renew or cancel its session. Explicit activation retains its old API.
  let addressChecks = 0, activations = 0, clears = 0;
  context.currentAddr = 'ordinary-owner';
  context._setCurrentAddr = address => { ++addressChecks; return address === context.currentAddr; };
  context.__veldKey.set = token => { assert.equal(token, fixtureToken); ++activations; ++currentGeneration; };
  context.__veldKey.clear = () => { ++clears; ++currentGeneration; };
  const identity = {key: fixtureToken, address: 'ordinary-owner'};
  assert.equal(context._veldActivateBoundIdentity(identity, true), identity);
  assert.equal(currentGeneration, generation);
  assert.equal(activations, 0);
  assert.equal(addressChecks, 1);
  context._veldActivateBoundIdentity(identity);
  assert.equal(currentGeneration, generation + 1);
  assert.equal(activations, 1);
  assert.equal(addressChecks, 2);
  context._setCurrentAddr = () => false;
  assert.throws(() => context._veldActivateBoundIdentity(identity, true), /binding failed/);
  assert.equal(clears, 1);
  console.log(JSON.stringify({result: 'PASS', embedded_scripts: scriptCount,
    static_async_entrypoints: Object.keys(asynchronousEntries).length,
    ordinary_signature_standins: signatureGenerations.length,
    real_keys: 0, cryptographic_signatures: 0, network_requests: 0, race_reproductions: 0}));
})().catch(error => { console.error(error); process.exitCode = 1; });
