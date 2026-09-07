'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(process.argv[2] || path.join(__dirname,'../include/network/ui_desktop.h'),'utf8');
function extract(name) {
  const begin=source.indexOf('function '+name+'('); assert(begin>=0,name);
  return source.slice(begin,source.indexOf('\n}',begin)+2);
}
const address='VTestWallet';
const id=i=>i.toString(16).padStart(64,'0');
const row=i=>({txid:id(i),block_height:2221,type:'self',net_veld:0,fee_veld:0.001});
const good=t=>({txid:t.txid,block_height:t.block_height,coinbase:false,vin:[{},{}],vout:[{address,value:5}]});
const elements={};
function el(id){return elements[id]||(elements[id]={innerHTML:'',value:'',style:{},classList:{add(){},remove(){}}});}
let calls=0,active=0,maxActive=0,entries=[],details=new Map();
const context=vm.createContext({Map,Date,Number,Promise,Object,Array,
  window:{},document:{getElementById:el},historyData:[],historyFilter:'all',HISTORY_PAGE_SIZE:25,WALLET_RECENT_PAGE_SIZE:25,
  fmt:(x,d)=>Number(x||0).toFixed(d),escHtml:s=>String(s).replace(/[<>&"']/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c])),shortHash:s=>s.slice(0,8),
  rpc:async(method,params)=>{
    assert(['getaddresshistory','gettransactionrecent'].includes(method),'No mutation RPC');
    if(method==='getaddresshistory'){assert(Number(params[1])<=50);return {entries};}
    calls++; active++; maxActive=Math.max(active,maxActive);
    await new Promise(r=>setTimeout(r,2));active--;
    const value=details.get(params[0]);if(value instanceof Error)throw value;return value;
  }
});
vm.runInContext('var historyConsolidationCache=new Map(),historyDetailQueue=[],historyDetailActive=0;\n'+
 ['historyDetailDrain','historyIsConsolidation','publicAddressHistory','renderWalletRecentTxs','formatHistoryFee','renderHistory'].map(extract).join('\n'),context);
(async()=>{
  const t=row(1);details.set(t.txid,good(t));
  assert.equal(await context.historyIsConsolidation(t,address),true);
  assert.equal(await context.historyIsConsolidation(t,'DifferentWallet'),false,'Address scopes classification/cache');
  const cases=[
    {...good(t),coinbase:true}, {...good(t),vin:[{}]},
    {...good(t),vout:[{address,value:2},{address,value:3}]},
    {...good(t),vout:[{address:'Other',value:5}]},
    {...good(t),vout:[{address,value:0}]},
    {...good(t),block_height:2220}, {...good(t),txid:id(900)}, new Error('unavailable')
  ];
  for(let i=0;i<cases.length;i++){
    const r=row(i+2),tx=cases[i];if(!(tx instanceof Error)&&i!==6)tx.txid=r.txid;
    details.set(r.txid,tx);assert.equal(await context.historyIsConsolidation(r,address),false);
  }
  const before=calls;
  assert.equal(await context.historyIsConsolidation({...t,type:'received'},address),false);
  assert.equal(await context.historyIsConsolidation({...t,txid:'invalid'},address),false);
  assert.equal(calls,before,'Unrelated/invalid rows do not trigger detail calls');
  entries=Array.from({length:12},(_,i)=>row(i+30));
  for(const r of entries)details.set(r.txid,good(r));
  const raw=JSON.stringify(entries),prior=calls;
  const [a,b]=await Promise.all([context.publicAddressHistory(address,500),context.publicAddressHistory(address,50)]);
  assert.equal(calls-prior,12,'Concurrent consumers coalesce transaction reads');
  assert.equal(maxActive,2,'At most two detail reads run across consumers');
  assert(a.every(t=>t.type==='consolidation'));assert(b.every(t=>t.type==='consolidation'));
  assert.equal(JSON.stringify(entries),raw,'Indexed accounting and raw types stay unchanged');
  assert.equal(a[0].fee_veld,0.001);assert.equal(a[0].net_veld,0);
  context.historyData=[a[0],{...row(90),type:'self'},{...row(91),type:'coinbase',net_veld:1.57,fee_veld:0}];
  context.window._wRecentTxs=context.historyData;
  context.renderHistory();context.renderWalletRecentTxs();
  for(const host of ['h-list','w-recent-txs']){
    assert.match(el(host).innerHTML,/Consolidation/);assert.match(el(host).innerHTML,/Self-transfer/);
    assert.match(el(host).innerHTML,/Block Reward/);assert.doesNotMatch(el(host).innerHTML,/Auto.consolidation/);
  }
  assert.match(el('h-list').innerHTML,/0.001 VELD/,'Consolidation fee remains visible');
  assert.match(el('h-summary').innerHTML,/0.002 VELD fees paid/,'Small fees do not round to zero');
  context.historyFilter='sent';context.renderHistory();
  assert.match(el('h-list').innerHTML,/Consolidation/);assert.match(el('h-list').innerHTML,/Self-transfer/);
  assert.doesNotMatch(el('h-list').innerHTML,/Block Reward/);
  for(const [fee,text] of [[0,'0'],[0.001,'0.001'],[0.0110,'0.011'],[0.00000001,'0.00000001'],[1.01,'1.01']])assert.equal(context.formatHistoryFee(fee),text);
  const rule=source.slice(source.indexOf('class="card governance-rules"'),source.indexOf('<!-- EARNINGS -->'));
  for(const text of ['51% yes','67% yes','10-vote minimum','7-day timelock','6,720 blocks','Registered validators'])assert(rule.includes(text));
  assert.equal((rule.match(/class="gov-rule"/g)||[]).length,4);
  assert(!rule.includes('<table'),'Governance rules do not require horizontal table scrolling');
  console.log('PASS wallet governance/activity: verified consolidation, self-transfer distinction, unchanged accounting, two-call concurrency, caching, failure fallback and complete rules');
})().catch(e=>{console.error(e);process.exitCode=1;});
