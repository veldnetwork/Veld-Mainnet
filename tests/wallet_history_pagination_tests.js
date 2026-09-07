'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(process.argv[2] || path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
function extract(name) {
  const start = source.indexOf('function ' + name + '(');
  assert(start >= 0, name);
  return source.slice(start, source.indexOf('\n}', start) + 2);
}
const id = n => n.toString(16).padStart(64, '0');
const reward = n => ({txid:id(10000+n), block_height:2000-n, type:'coinbase', net_veld:1.57, fee_veld:0});
const sent = {txid:id(709), block_height:709, type:'sent', net_veld:-1, fee_veld:0.001};
const cleanup = {txid:id(710), block_height:710, type:'consolidation', net_veld:0, fee_veld:0.001};
const functions = ['historyLoadIsCurrent','renderHistoryLoadStatus','loadHistoryPages','finishHistoryLoad',
  'loadOlderHistory','loadHistory','renderHistory','formatHistoryFee','setHistoryFilter','setHistoryPage'];
function fixture(handler) {
  const elements = {};
  function element(id) { return elements[id] || (elements[id] = {value:'', innerHTML:'', textContent:'', style:{}, classList:{add(){},remove(){}}}); }
  element('h-addr').value = 'wallet-A';
  const calls = [];
  const ctx = vm.createContext({window:{}, document:{getElementById:element,querySelectorAll:()=>[]},
    historyLoadState:null, historyData:[], historyFilter:'sent', HISTORY_PAGE_SIZE:25,
    historyIsConsolidation:async()=>false, renderTokenHistory(){},
    escHtml:s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),
    fmt:(n,d)=>Number(n||0).toFixed(d), shortHash:s=>s.slice(0,8),
    rpc:async(method,params)=>{
      calls.push({method,params});
      assert(['getaddresshistory','gettokenhistory','getbalance'].includes(method), 'Read-only history RPCs');
      if (method === 'getbalance') return {balance_veld:520.11};
      if (method === 'gettokenhistory') return [];
      assert.equal(params[1], '50');
      return handler(params, calls.filter(c=>c.method==='getaddresshistory').length);
    }});
  vm.runInContext(functions.map(extract).join('\n'), ctx);
  return {ctx, element, calls};
}
function history(rows) {
  return params => {
    const start = Number(params[2] || 0), entries = rows.slice(start, start+50);
    const more = start+entries.length < rows.length;
    return {entries, has_more:more, next_cursor:more ? String(start+entries.length) : ''};
  };
}
(async()=>{
  // A real send remains discoverable after hundreds of later mining rewards.
  const f = fixture(history([...Array.from({length:151},(_,n)=>reward(n+1)),cleanup,sent]));
  await f.ctx.loadHistory();
  assert.equal(f.ctx.historyData.length,153);
  assert.equal(f.calls.filter(c=>c.method==='getaddresshistory').length,4);
  assert.deepEqual(f.calls.filter(c=>c.method==='getaddresshistory').map(c=>c.params[2]||''),['','50','100','150']);
  assert.match(f.element('h-list').innerHTML,/709/);
  assert.match(f.element('h-list').innerHTML,/Sent/);
  assert.match(f.element('h-list').innerHTML,/Consolidation/);
  assert.doesNotMatch(f.element('h-list').innerHTML,/Block Reward/);
  assert.match(f.element('h-summary').innerHTML,/-1.00 out/);
  assert.match(f.element('h-summary').innerHTML,/0.002 VELD fees paid/);
  assert.equal(f.element('h-load-status').style.display,'none');
  assert.equal(f.ctx.historyLoadState.hasMore,false);
  assert.equal(f.ctx.window._histBal,520.11);

  // An interrupted or malformed page is partial, never a false empty history.
  for (const failure of [new Error('index unavailable'), {entries:[],has_more:true,next_cursor:'next'},
    {entries:[sent],has_more:true,next_cursor:'50'}, {entries:[],has_more:'yes',next_cursor:''}]) {
    const p = fixture((params,n)=>{
      if(n===1)return {entries:[reward(1)],has_more:true,next_cursor:'50'};
      if(failure instanceof Error)throw failure;
      return failure;
    });
    await p.ctx.loadHistory();
    assert(p.ctx.historyLoadState.error);
    assert.match(p.element('h-load-status').textContent,/could not finish loading/);
    assert.match(p.element('h-list').innerHTML,/loaded so far/);
    assert.equal(p.ctx.historyData.length,1);
  }
  const empty = fixture(history([])); await empty.ctx.loadHistory();
  assert.match(empty.element('h-list').innerHTML,/No transactions match filter/);
  assert.equal(empty.ctx.historyLoadState.error,'');

  // Large histories stop at a bounded batch and can continue past it.
  const large = fixture(history([...Array.from({length:1001},(_,n)=>reward(n+1)),sent]));
  await large.ctx.loadHistory();
  assert.equal(large.calls.filter(c=>c.method==='getaddresshistory').length,20);
  assert.equal(large.ctx.historyData.length,1000);
  assert.equal(large.element('h-load-older').style.display,'inline-block');
  assert.match(large.element('h-load-status').textContent,/Older activity remains/);
  await large.ctx.loadHistory(true);
  assert.equal(large.calls.filter(c=>c.method==='getaddresshistory').length,20,'Auto refresh does not reset partial browsing');
  await large.ctx.loadOlderHistory();
  assert.equal(large.ctx.historyData.length,1002);
  assert.equal(large.ctx.historyLoadState.hasMore,false);
  assert.match(large.element('h-list').innerHTML,/709/);

  // A response for a previously selected address cannot overwrite the new one.
  let resolveA;
  const race = fixture(params=>params[0]==='wallet-A' ? new Promise(r=>{resolveA=r;}) : {entries:[sent],has_more:false,next_cursor:''});
  const first = race.ctx.loadHistory();
  const repeated = race.ctx.loadHistory();
  assert.equal(race.calls.filter(c=>c.method==='getaddresshistory').length,1,'Coalesce same-address loads');
  race.element('h-addr').value = 'wallet-B';
  await race.ctx.loadHistory();
  resolveA({entries:[reward(3)],has_more:true,next_cursor:'50'});
  await Promise.all([first,repeated]);
  assert.equal(race.ctx.historyLoadState.address,'wallet-B');
  assert.equal(race.ctx.historyData[0].txid,sent.txid);
  assert.equal(race.calls.filter(c=>c.method==='getaddresshistory'&&c.params[0]==='wallet-A').length,1);

  // Typing another address during a request must not leave a stuck busy state.
  let resolveTyping;
  const typing = fixture(()=>new Promise(r=>{resolveTyping=r;}));
  const pending = typing.ctx.loadHistory(); typing.element('h-addr').value = 'wallet-B';
  resolveTyping({entries:[sent],has_more:false,next_cursor:''}); await pending;
  assert.equal(typing.ctx.historyLoadState.busy,false);
  typing.element('h-addr').value=''; await typing.ctx.loadHistory();
  assert.equal(typing.ctx.historyLoadState,null); assert.equal(typing.ctx.historyData.length,0);

  // Duplicate page-boundary rows never double count the transfer or its fee.
  const duplicate = fixture((params,n)=>n===1 ? {entries:[sent],has_more:true,next_cursor:'next'} : {entries:[sent,cleanup],has_more:false,next_cursor:''});
  await duplicate.ctx.loadHistory();
  assert.equal(duplicate.ctx.historyData.length,2);
  assert.match(duplicate.element('h-summary').innerHTML,/0.002 VELD fees paid/);
  console.log('PASS wallet history pagination: older sends, all fee rows, bounded cursor batches, explicit partial/error states, deduplication, refresh coalescing and address races');
})().catch(e=>{console.error(e);process.exitCode=1;});
