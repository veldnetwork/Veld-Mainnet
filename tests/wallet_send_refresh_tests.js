'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {extractFunction} = require('./javascript_function_source');
const source = fs.readFileSync(process.env.VELD_WALLET_TEST_SOURCE ||
  path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
const names = ['sendSourceAddress', 'refreshWalletAfterBroadcast', 'onFromChange',
  '_veldAssertActiveSignerSeed', 'signAndBroadcast', '_veldConsolidationBudget', '_veldConsolidationProgress'];
const elements = new Map();
const element = id => {
  if (!elements.has(id)) elements.set(id, {value:'', textContent:'', style:{}});
  return elements.get(id);
};
element('s-from-row').style.display = 'none';
element('s-from').value = 'stale-hidden-address';
element('s-avail').textContent = '600.00 VELD';
let requests = [], walletRefreshes = [], broadcasts = [], stored = new Map();
const context = vm.createContext({
  currentAddr: 'owner', sendBalanceRevision: 0,
  window: {_sUtxoData:[{txid:'stale-output'}]},
  document:{getElementById:element},
  fmt:(value, precision) => Number(value).toFixed(precision),
  renderSendUtxos() {}, updateConfirm() {},
  loadWalletAddr:address => walletRefreshes.push(address),
  localStorage:{getItem:key => stored.get(key), setItem:(key, value) => stored.set(key, value)},
  __veldTxChannel:{postMessage:message => broadcasts.push(message)},
  rpc(method, params) {
    return new Promise((resolve, reject) => requests.push({method, params, resolve, reject}));
  }
});
vm.runInContext(names.map(name => extractFunction(source, name)).join('\n'), context);
const settle = async () => { for (let i = 0; i < 8; ++i) await Promise.resolve(); };
function answer(batch, balance, outputs = []) {
  batch.find(r => r.method === 'getbalance').resolve({balance_veld:600, spendable_veld:balance});
  batch.find(r => r.method === 'listunspent').resolve(outputs);
}

(async () => {
  const old = context.onFromChange();
  const oldRequests = requests.splice(0);
  assert(oldRequests.every(r => r.params[0] === 'owner'));
  assert.equal(element('s-avail').textContent, 'Updating…');
  assert.equal(context.window._sUtxoData.length, 0);
  const current = context.onFromChange();
  const currentRequests = requests.splice(0);
  answer(currentRequests, 300, [{txid:'remaining'}]); await current;
  answer(oldRequests, 600, [{txid:'already-spent'}]); await old;
  assert.equal(element('s-avail').textContent, '300.00 VELD');
  assert.equal(context.window._sUtxoData[0].txid, 'remaining');

  const pending = context.onFromChange();
  const previousWallet = requests.splice(0);
  context.currentAddr = 'other-owner';
  const switched = context.onFromChange();
  answer(requests.splice(0), 8); await switched;
  answer(previousWallet, 300); await pending;
  assert.equal(element('s-avail').textContent, '8.00 VELD');
  const failure = context.onFromChange();
  requests.splice(0).forEach(r => r.reject(new Error('offline'))); await failure;
  assert.equal(element('s-avail').textContent, 'Unavailable');
  assert.equal(context.window._sUtxoData.length, 0);
  const zero = context.onFromChange(); answer(requests.splice(0), 0); await zero;
  assert.equal(element('s-avail').textContent, '0.00 VELD');

  context.currentAddr = 'owner';
  Object.assign(context, {
    VELD_MIN_TX_FEE_UNITS:100000,
    VELD_SIGNER_IDLE_MS:300000, _veldSignerLastActivity:Date.now(),
    __veldKey:{get:() => 'inert-test-seed', generation:() => 7},
    _veldRequireSelfCustodySigner() {},
    _veldRequireBoundIdentity:() => ({address:'owner'}),
    _veldAddrToHash160Hex:() => '19'.repeat(20),
    _veldAssertPreparedRelaySize() {}, _veldAssertOpReturnExact() {},
    _veldVerifyInputSighashes() {}, _veldAuthenticatePreparedPrevouts:async () => {},
    veldCrypto:{injectSignatures:async () => 'inert-test-bytes', sha256d:() => '12'.repeat(32)},
    _veldBroadcastExactSigned:async () => '12'.repeat(32)
  });
  const call = context.signAndBroadcast('preparerawtransaction', ['owner','recipient','50'],
    'inert-test-seed', null, null, null, null, '');
  await settle();
  const preparation = requests.shift();
  assert.equal(preparation.method, 'preparerawtransaction');
  preparation.resolve({unsigned_tx_hex:'inert-test-bytes', inputs:[{}]});
  await call;
  assert.equal(walletRefreshes.at(-1), 'owner');
  assert.equal(broadcasts.at(-1).from_addr, 'owner');
  assert.equal(element('s-avail').textContent, 'Updating…');
  answer(requests.splice(0), 100, [{txid:'second-send-remaining'}]); await settle();
  assert.equal(element('s-avail').textContent, '100.00 VELD');

  const channelStart = source.indexOf('var __veldTxChannel = null;');
  const channelEnd = source.indexOf('\nfunction _veldHexToBytes', channelStart);
  context.BroadcastChannel = class { postMessage() {} };
  vm.runInContext(source.slice(channelStart, channelEnd), context);
  context.__veldTxChannel.onmessage({data:{kind:'tx_sent', from_addr:'owner'}});
  answer(requests.splice(0), 0); await settle();
  assert.equal(element('s-avail').textContent, '0.00 VELD');
  context.__veldTxChannel.onmessage({data:{kind:'tx_sent', from_addr:'unrelated-owner'}});
  assert.equal(requests.length, 0);
  console.log('PASS: send success, cross-tab updates, zero balances, failures, and stale response ordering');
})().catch(error => { console.error(error); process.exitCode = 1; });
