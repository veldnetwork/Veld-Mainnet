'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(process.argv[2] || path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
const begin = source.indexOf('// Optional automatic cleanup.');
const end = source.indexOf('// Consolidate-dust handler.', begin);
assert(begin > 0 && end > begin);
function extract(name) {
  const start=source.indexOf('function '+name+'('); assert(start>=0,name);
  return source.slice(start,source.indexOf('\n}',start)+2);
}
function setup() {
  const items=new Map(), elements=new Map(), listeners={}, calls=[], batches=[];
  let key='1'.repeat(64), readFails=false, writeFails=false;
  const el=id=>elements.get(id)||elements.set(id,{style:{},checked:false,textContent:'',innerHTML:'',dataset:{},disabled:false}).get(id);
  const state={items,el,calls,batches,listeners,changeKey:v=>key=v,readError:v=>readFails=v,writeError:v=>writeFails=v};
  state.balance={pending_in_veld:0,pending_out_veld:0};
  state.counts={total_count:34,dust_count:30,dust_value_veld:50};
  const ctx=vm.createContext({Promise,Number,Date,Object,String,console:{warn(){}},
    VELD_MIN_TX_FEE_UNITS:100000,currentAddr:'WalletA',__opLocks:{},__veldKey:{get:()=>key},
    document:{getElementById:el},window:{addEventListener:(event,fn)=>listeners[event]=fn},
    localStorage:{getItem:k=>{if(readFails)throw Error('storage');return items.get(k)??null;},setItem:(k,v)=>{if(writeFails)throw Error('storage');items.set(k,v);}},
    setInterval(){},setTimeout:fn=>{queueMicrotask(fn);},loadWalletAddr(){},fmt:(x,n)=>Number(x).toFixed(n),escHtml:s=>String(s),
    _veldAddrToHash160Hex:a=>'hash:'+a,
    rpc:async(method,params)=>{calls.push([method,...params]);return state.rpc?state.rpc(method,params):(method==='getbalance'?state.balance:state.counts);},
    signAndBroadcast:async(...args)=>{batches.push(args);return state.sign?state.sign(args):{verified_consolidation_inputs:0};},
    __opLock:(name)=>{if(ctx.__opLocks[name])return false;ctx.__opLocks[name]=true;return true;},
    __opUnlock:(name)=>{ctx.__opLocks[name]=false;}
  });
  vm.runInContext(extract('_veldConsolidationBudget')+'\n'+source.slice(begin,end)+'\n'+extract('loadDustUtxoCount')+'\n'+extract('doConsolidateUtxos'),ctx);
  ctx.autoConsolidateNotify=()=>{};
  state.ctx=ctx;
  state.enable=()=>ctx.setAutoConsolidatePreference(true);
  return state;
}
function deferred(){let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};}
const tick=()=>new Promise(r=>setImmediate(r));
(async()=>{
  let s=setup();
  s.items.set('veld_auto_consolidate','true');
  assert.equal(s.ctx.autoConsolidateEnabled(),false,'Legacy automatic default does not opt in');
  await s.ctx.autoConsolidateMaybe();assert.equal(s.calls.length,0);
  for(const value of [null,'false','TRUE','1','garbage']) {
    if(value===null)s.items.delete(s.ctx.AUTO_CONSOLIDATE_PREFERENCE);else s.items.set(s.ctx.AUTO_CONSOLIDATE_PREFERENCE,value);
    assert.equal(s.ctx.autoConsolidateEnabled(),false);
  }
  s.enable();assert.equal(s.ctx.autoConsolidateEnabled(),true);assert.equal(s.el('w-auto-consolidate').checked,true);
  s.readError(true);assert.equal(s.ctx.autoConsolidateEnabled(),false);s.readError(false);
  s.writeError(true);s.ctx.setAutoConsolidatePreference(false);
  assert.equal(s.ctx.autoConsolidateEnabled(),false,'Failed opt-out disables this session');
  assert.match(s.el('w-auto-consolidate-pref-status').textContent,/Could not save/);
  s.writeError(false);s.ctx.setAutoConsolidatePreference(false);
  assert.equal(s.items.get(s.ctx.AUTO_CONSOLIDATE_PREFERENCE),'false');
  s.enable();await s.ctx.autoConsolidateMaybe();
  assert.equal(s.batches.length,1);assert.equal(s.batches[0][0],'prepareconsolidatetx');
  assert.deepEqual(Array.from(s.batches[0][1]),['WalletA','150','0']);
  assert.equal(s.batches[0][4],'hash:WalletA');assert.equal(s.batches[0][7],'');
  assert.equal(s.ctx.__opLocks.consolidate,false);assert.equal(s.ctx.__autoConsolidateChecking,false);
  await s.ctx.autoConsolidateMaybe();assert.equal(s.batches.length,1,'Five-minute gate');
  for(const name of ['send','consolidate','stake','unstake:WalletA','validator-op','gov-submit','gov-vote:1']) {
    s=setup();s.enable();s.ctx.__opLocks[name]=true;await s.ctx.autoConsolidateMaybe();assert.equal(s.calls.length,0,name);
  }
  for(const balance of [null,{}, {pending_in_veld:1,pending_out_veld:0},{pending_in_veld:0,pending_out_veld:1},{pending_in_veld:'invalid',pending_out_veld:0}]) {
    s=setup();s.enable();s.balance=balance;await s.ctx.autoConsolidateMaybe();assert.equal(s.batches.length,0,'Pending or unavailable balance');
  }
  for(const counts of [{total_count:4,dust_count:4},{total_count:30,dust_count:31},{total_count:'bad',dust_count:9}]) {
    s=setup();s.enable();s.counts=counts;await s.ctx.autoConsolidateMaybe();assert.equal(s.batches.length,0);
  }
  const interventions=[
    s=>s.ctx.setAutoConsolidatePreference(false),
    s=>{s.ctx.setAutoConsolidatePreference(false);s.enable();},
    s=>s.changeKey(''),s=>s.changeKey('2'.repeat(64)),s=>s.ctx.currentAddr='WalletB',
    s=>s.ctx.__opLocks['gov-vote:2']=true,
    s=>{s.items.set(s.ctx.AUTO_CONSOLIDATE_PREFERENCE,'false');s.listeners.storage({key:s.ctx.AUTO_CONSOLIDATE_PREFERENCE});}
  ];
  for(const stage of ['getbalance','getdustutxocount'])for(const stop of interventions) {
    s=setup();s.enable();const wait=deferred();s.rpc=m=>m===stage?wait.promise:(m==='getbalance'?s.balance:s.counts);
    const pending=s.ctx.autoConsolidateMaybe();await tick();stop(s);wait.resolve(stage==='getbalance'?s.balance:s.counts);await pending;
    assert.equal(s.batches.length,0,'Changed context during '+stage);
  }
  for(const stop of interventions) {
    s=setup();s.enable();s.sign=()=>{stop(s);return {verified_consolidation_inputs:150,txid:'fixture'};};
    await s.ctx.autoConsolidateMaybe();assert.equal(s.batches.length,1,'Stops future batches');assert.equal(s.ctx.__opLocks.consolidate,false);
  }
  s=setup();s.enable();const wait=deferred();s.rpc=m=>m==='getbalance'?wait.promise:s.counts;
  const pending=s.ctx.autoConsolidateMaybe();await tick();await s.ctx.autoConsolidateMaybe();assert.equal(s.calls.length,1,'Coalesces overlapping checks');
  wait.resolve(s.balance);await pending;
  s=setup();s.enable();s.sign=()=>{throw Error('fixture signing failed');};await s.ctx.autoConsolidateMaybe();
  assert.equal(s.ctx.__opLocks.consolidate,false);assert.equal(s.ctx.__autoConsolidateActive,false);assert.equal(s.ctx.__autoConsolidateChecking,false);
  s=setup();s.ctx.loadDustUtxoCount();await tick();
  assert.equal(s.el('w-utxo-consolidate').style.display,'flex');assert.match(s.el('w-utxo-dust-msg').textContent,/small outputs/);
  assert(source.includes('id="w-utxo-consolidate-btn" data-act-click="hconsolidate"'));
  assert(source.includes('hauto_consolidate: function(event){ setAutoConsolidatePreference(this.checked === true); }'));
  // Manual cleanup still reaches the existing signing flow with automation off.
  s=setup();s.counts={total_count:2,dust_count:2,dust_value_veld:3};s.sign=()=>{throw Error('Nothing to consolidate');};
  s.ctx.doConsolidateUtxos();await tick();assert.equal(s.batches.length,1);assert.equal(s.ctx.autoConsolidateEnabled(),false);
  assert.equal(s.ctx.__opLocks.consolidate,false);
  console.log('PASS: explicit opt-in, storage failures, fees/manual controls, pending balance, operation locks, async cancellation, batch stop, unchanged manual signing entry');
})().catch(e=>{console.error(e);process.exitCode=1;});
