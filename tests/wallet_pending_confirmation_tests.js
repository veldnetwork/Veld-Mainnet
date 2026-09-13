'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const {extractFunction} = require('./javascript_function_source');
const source = fs.readFileSync(process.env.VELD_WALLET_TEST_SOURCE || path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
const names = ['_veldIsConfirmedTransaction', '_veldPruneConfirmedPending', '_veldPendingHistoryHints', 'loadPendingSends', 'renderPendingSends', '__waitForTxConfirm'];
const txid = 'e779cb772ea851b977365c082f03df0a696ed40e9db40c2eb7668d21a9539370';
const other = 'b'.repeat(64), newSend = 'c'.repeat(64);
const entry = (id = txid, owner = 'owner', age = 14400) => ({txid:id, from_addr:owner, prepare_method:'preparestake', ts:Math.floor(Date.now()/1000)-age});
const page = (entries = [], next = '') => ({entries, has_more:!!next, next_cursor:next});
const confirmed = (id = txid, height = 4997) => ({txid:id, block_height:height, confirmations:92});
const missing = () => { throw Object.assign(new Error('Lookup incomplete or busy'), {code:-32005}); };
let cases = 0;
function fixture(entries, handler) {
  const storage = new Map([['veld_pending_txs', JSON.stringify(entries)]]), elements = new Map(), calls = [], timers = [];
  function element(id) { if (!elements.has(id)) elements.set(id, {style:{}, textContent:'', innerHTML:''}); return elements.get(id); }
  const context = vm.createContext({
    currentAddr:'owner', pendingSendsLoad:null, document:{getElementById:element},
    localStorage:{getItem:key => storage.get(key), setItem:(key, value) => storage.set(key, value)},
    escHtml:value => String(value), shortHash:value => value.slice(0,10),
    setInterval:callback => {timers.push(callback); return timers.length;}, clearInterval() {},
    rpc(method, params) { calls.push({method, params}); return Promise.resolve().then(() => handler(method, params)); }
  });
  vm.runInContext(names.map(name => extractFunction(source, name)).join('\n'), context);
  return {context, storage, calls, element, timers, saved:() => JSON.parse(storage.get('veld_pending_txs'))};
}
const settle = async () => {for (let i=0; i<20; i++) await Promise.resolve();};
(async () => {
  let f = fixture([entry()], (method, params) => {
    if (method === 'getrawmempool') return [];
    if (method === 'getaddresshistory') return page([{txid, block_height:4997}]);
    if (method === 'gettransaction') {assert.deepEqual(Array.from(params), [txid, '4997']); return confirmed();}
    return missing();
  });
  await f.context.loadPendingSends();
  assert.deepEqual(f.saved(), []); assert.equal(f.element('w-pending-card').style.display, 'none');
  assert(!f.calls.some(call => call.method === 'gettransactionrecent')); cases++;

  f = fixture([entry()], (method, params) => {
    if (method === 'getrawmempool') return [];
    if (method === 'getaddresshistory') return !params[2] ? page([{txid:other, block_height:5000}], 'cursor-1') : page([{txid, block_height:4997}]);
    if (method === 'gettransaction') return confirmed();
    return missing();
  });
  await f.context.loadPendingSends(); assert.deepEqual(f.saved(), []);
  assert.equal(f.calls.filter(call => call.method === 'getaddresshistory').length, 2); cases++;

  for (const history of [page(), null]) {
    f = fixture([entry()], method => {
      if (method === 'getrawmempool') return [];
      if (method === 'getaddresshistory') {if (!history) return missing(); return history;}
      if (method === 'gettransactionrecent') return confirmed();
      return missing();
    });
    await f.context.loadPendingSends(); assert.deepEqual(f.saved(), []); cases++;
  }

  for (const invalid of [null, {}, {block_height:4997}, confirmed(other), {...confirmed(), confirmations:0}, {...confirmed(), block_height:'4997'}]) {
    f = fixture([entry()], method => {
      if (method === 'getrawmempool') return [];
      if (method === 'getaddresshistory') return page([{txid, block_height:4997}]);
      return invalid;
    });
    await f.context.loadPendingSends(); assert.equal(f.saved().length, 1);
    assert(f.element('w-pending-list').innerHTML.includes('Checking confirmation')); cases++;
  }

  f = fixture([entry()], method => method === 'getrawmempool' ? [txid] : missing());
  await f.context.loadPendingSends(); assert.equal(f.saved().length, 1);
  assert.equal(f.calls.length, 1); assert(f.element('w-pending-list').innerHTML.includes('In mempool')); cases++;

  for (const pool of [null, 'offline']) {
    f = fixture([entry(txid, 'owner', 48*3600)], method => {if (pool === 'offline') return missing(); return pool;});
    await f.context.loadPendingSends(); assert.equal(f.saved().length, 1);
    assert.equal(f.element('w-pending-card').style.display, 'block');
    assert(f.element('w-pending-list').innerHTML.includes('Status unavailable')); cases++;
  }

  let release;
  f = fixture([entry(), entry(other, 'different-wallet')], method => {
    if (method === 'getrawmempool') return [];
    if (method === 'getaddresshistory') return page([{txid, block_height:4997}]);
    return new Promise(resolve => {release = resolve;});
  });
  const first = f.context.loadPendingSends(); await settle();
  assert.equal(first, f.context.loadPendingSends());
  f.storage.set('veld_pending_txs', JSON.stringify([...f.saved(), entry(newSend)]));
  release(confirmed()); await first;
  assert.deepEqual(f.saved().map(e => e.txid), [other, newSend]); cases++;

  f = fixture([entry()], method => {
    if (method === 'getrawmempool') return [];
    if (method === 'getaddresshistory') return page([{txid, block_height:4997}]);
    return new Promise(resolve => {release = resolve;});
  });
  const stale = f.context.loadPendingSends(); await settle();
  f.context.currentAddr = 'empty-wallet'; await f.context.loadPendingSends();
  f.context.currentAddr = 'owner'; release(confirmed()); await stale;
  assert.equal(f.saved().length, 1); cases++;

  f = fixture([entry()], (method, params) => {
    if (method === 'getrawmempool') return [];
    if (method === 'getaddresshistory') return page([{txid:other, block_height:5000}], params[2] || 'cycle');
    return missing();
  });
  await f.context.loadPendingSends(); assert.equal(f.saved().length, 1);
  assert.equal(f.calls.filter(c => c.method === 'getaddresshistory').length, 2); cases++;

  let cursorCount = 0;
  f = fixture([entry()], method => {
    if (method === 'getrawmempool') return [];
    if (method === 'getaddresshistory') return page([{txid:other, block_height:5000}], 'page-'+(++cursorCount));
    return missing();
  });
  await f.context.loadPendingSends(); assert.equal(f.saved().length, 1);
  assert.equal(cursorCount, 20); cases++;

  f = fixture([entry()], method => {
    if (method === 'getrawmempool') return [];
    if (method === 'getaddresshistory') return page([{txid, block_height:4997}]);
    if (method === 'gettransaction') return confirmed(txid, 4996);
    return missing();
  });
  await f.context.loadPendingSends(); assert.equal(f.saved().length, 1); cases++;

  f = fixture([entry()], method => method === 'gettransactionrecent' ? confirmed() : missing());
  let notified = false;
  f.context.__waitForTxConfirm(txid, 30, () => {notified=true;});
  f.timers[0](); await settle();
  assert(notified); assert.deepEqual(f.saved(), []); cases++;

  f = fixture([entry()], () => new Promise(() => {}));
  let timedOut = 0;
  f.context.__waitForTxConfirm(txid, 5, null, () => { ++timedOut; });
  f.timers[0](); await settle();
  f.timers[0](); await settle();
  assert.equal(timedOut, 1); assert.equal(f.saved().length, 1); cases++;

  let rejectLookup;
  f = fixture([entry()], () => new Promise((_, reject) => { rejectLookup = reject; }));
  const wait = f.context.__waitForTxConfirm(txid, 5, null, () => { ++timedOut; });
  f.timers[0](); await settle();
  wait.cancel(); rejectLookup(new Error('Ordinary cancelled lookup')); await settle();
  assert.equal(timedOut, 1); assert.equal(f.saved().length, 1); cases++;
  console.log('PASS: '+cases+' pending-confirmation cases; no broadcasts or signing');
})().catch(error => {console.error(error); process.exitCode=1;});
