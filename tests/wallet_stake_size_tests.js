'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {extractFunction} = require('./javascript_function_source');
const source = fs.readFileSync(path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
const functions = ['_veldHexToBytes', '_veldParseVarint', '_veldBytesToHex',
  '_veldParseUnsignedTx', '_veldAssertPreparedRelaySize', '_veldBroadcastExactSigned',
  'signAndBroadcast'].map(name => extractFunction(source, name)).join('\n');

async function runFixture(context) {
  let checks = 0;
  const check = (value, message) => { ++checks; if (!value) throw new Error(message); };
  async function rejects(call, pattern) {
    try { await call(); } catch (error) {
      check(pattern.test(error.message), error.message);
      return;
    }
    throw new Error('expected rejection');
  }
  const owner = '76a914' + '19'.repeat(20) + '88ac';
  function transaction(count) {
    const varint = count < 253 ? count.toString(16).padStart(2, '0')
      : 'fd' + (count & 255).toString(16).padStart(2, '0') + (count >> 8).toString(16).padStart(2, '0');
    const input = '12'.repeat(32) + '00000000' + '00' + 'ffffffff';
    return '01000000' + varint + input.repeat(count) + '01' + '00'.repeat(8) + '19' + owner + '00000000';
  }
  const rows = [];
  for (const count of [1, 21, 150, 197, 198, 319]) {
    const hex = transaction(count), inputs = Array.from({length: count}, () => ({}));
    const expected = hex.length / 2 + count * 5271;
    if (expected <= 1048576) {
      check(context._veldAssertPreparedRelaySize(hex, inputs) === expected, 'signed size mismatch');
      rows.push({inputs: count, signed_bytes: expected, accepted: true});
    } else {
      await rejects(() => context._veldAssertPreparedRelaySize(hex, inputs), /Combine my outputs/);
      rows.push({inputs: count, signed_bytes: expected, accepted: false});
    }
  }
  for (const bad of [null, {}, '', '0', 'zz', transaction(1) + '00'])
    await rejects(() => context._veldAssertPreparedRelaySize(bad, [{}]), /malformed|trailing/);
  await rejects(() => context._veldAssertPreparedRelaySize(transaction(1), []), /incomplete/);

  let signed = 0, authenticated = 0, hashed = 0, broadcast = 0;
  const seed = '23'.repeat(32), txid = '34'.repeat(32);
  let prepared = {unsigned_tx_hex: transaction(319), inputs: Array.from({length:319}, () => ({}))};
  Object.assign(context, {
    VELD_MIN_TX_FEE_UNITS: 100000,
    _veldRequireSelfCustodySigner() {},
    _veldRequireBoundIdentity: () => ({address: 'disposable-fixture'}),
    _veldAddrToHash160Hex: () => '19'.repeat(20),
    _veldAssertActiveSignerSeed: key => { if (key !== seed) throw new Error('signer changed'); },
    _veldAssertOpReturnExact() {},
    _veldVerifyInputSighashes() {},
    _veldAuthenticatePreparedPrevouts: async () => { ++authenticated; },
    veldCrypto: {
      injectSignatures: async () => { ++signed; return 'ab'; },
      sha256d: () => { ++hashed; return txid; }
    },
    rpc: async method => {
      if (method === 'preparestake') return prepared;
      if (method === 'sendrawtransaction') { ++broadcast; return txid; }
      throw new Error('unexpected RPC');
    }
  });
  const stake = () => context.signAndBroadcast('preparestake', ['disposable-fixture', '500', '1'], seed, null, null, null, null, '');
  await rejects(stake, /Combine my outputs/);
  check(signed === 0 && authenticated === 0 && hashed === 0 && broadcast === 0,
    'oversized stake reached signing, parent reads, hashing or broadcast');
  prepared = {unsigned_tx_hex: transaction(21), inputs: Array.from({length:21}, () => ({}))};
  check((await stake()).txid === txid && signed === 1 && broadcast === 1,
    'consolidated stake did not reach exact-byte broadcast');

  for (const bad of [null, {}, '', '0', 'zz', 'ab'.repeat(1048577)]) {
    const before = [hashed, broadcast].join(',');
    await rejects(() => context._veldBroadcastExactSigned(bad, seed), /malformed|too large/);
    check(before === [hashed, broadcast].join(','), 'invalid bytes reached hashing or broadcast');
  }
  check(await context._veldBroadcastExactSigned('AB'.repeat(1048576), seed) === txid,
    'valid maximum-size hex rejected');
  await rejects(() => context._veldBroadcastExactSigned('ab', '45'.repeat(32)), /signer changed/);
  context.rpc = async () => '56'.repeat(32);
  await rejects(() => context._veldBroadcastExactSigned('ab', seed), /different from the signed bytes/);
  return {result: 'PASS', checks, rows};
}

module.exports = {functions, runFixture};
if (require.main === module) {
  const context = vm.createContext({});
  vm.runInContext(functions, context);
  runFixture(context).then(result => console.log(JSON.stringify(result)))
    .catch(error => { console.error(error); process.exitCode = 1; });
}
