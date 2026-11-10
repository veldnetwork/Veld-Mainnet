'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {extractFunction}=require('./javascript_function_source.js');
const source=fs.readFileSync(path.join(__dirname,'../include/network/ui_desktop.h'),'utf8');
const elements=new Map();
const get=id=>{if(!elements.has(id))elements.set(id,{style:{},textContent:'',innerHTML:'',hidden:false});return elements.get(id);};
let retired=true,balanceCalls=0;
const ctx={document:{getElementById:get},currentAddr:'test-wallet',Number,Error,
 fmt:n=>String(n),escHtml:s=>String(s),shortAddr:s=>s,
 rpc:async method=>{
  if(method==='getpoolinfo')return {co_mining_retired:retired,pool_balance_veld:12,window_size:100,blocks_until_payout:0,entries:[]};
  if(method==='getstakinginfo')return {co_mining_retired:retired,co_mining_min_stake_veld:1000};
  if(method==='getbalance'){balanceCalls++;return {staked_veld:1000};}
  throw Error(method);
 }};
vm.createContext(ctx);
vm.runInContext(extractFunction(source,'loadCominingPage')+'\n'+extractFunction(source,'loadCominingEligibility'),ctx);
const tick=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 ctx.loadCominingPage();await tick();await tick();
 assert.equal(get('cm-window').textContent,'Retired');assert.equal(get('cm-payout-in').textContent,'Ended');
 assert.equal(get('cm-minstake').textContent,'Retired');assert.equal(get('cm-nms-card').hidden,true);
 assert.equal(get('cm-how-it-works').hidden,true);assert.equal(balanceCalls,0);
 assert.match(get('cm-standings').innerHTML,/undistributed pool reserve is retained/);
 assert.match(get('cm-elig-body').innerHTML,/Ordinary staking remains available/);
 // Reorganization back before retirement restores the existing controls.
 retired=false;ctx.loadCominingPage();await tick();await tick();
 assert.equal(get('cm-nms-card').hidden,false);assert.equal(get('cm-how-it-works').hidden,false);
 assert.equal(get('cm-minstake').textContent,'1000 VELD');assert.equal(balanceCalls,1);
 assert.match(get('cm-elig-body').innerHTML,/Stake threshold met/);
 console.log('PASS_CO_MINING_RETIREMENT_WALLET cases=13');
})().catch(e=>{console.error(e);process.exitCode=1;});
