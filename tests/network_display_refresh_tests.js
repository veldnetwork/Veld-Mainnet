'use strict';
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const root=path.join(__dirname,'..');
const wallet=fs.readFileSync(process.argv[2]||path.join(root,'include/network/ui_desktop.h'),'utf8');
const explorer=fs.readFileSync(process.argv[3]||path.join(root,'include/network/explorer.h'),'utf8');
function extract(source,name){const a=source.indexOf('function '+name+'(');assert(a>=0,name);return source.slice(a,source.indexOf('\n}',a)+2);}
let now=1000000;
function context(){
 const els={},calls=[],listeners={},intervals=[];let resolveFetch;
 const state={result:{hashrate:16252.05,height:2335,generated_at:now/1000,nodes:[{id:1},{id:2}]},calls,els,listeners,intervals};
 const get=id=>els[id]||(els[id]={textContent:'',innerHTML:'',title:'',style:{}});
 const ctx=vm.createContext({Date:{now:()=>now},Number,String,Math,Set,Promise,AbortController,
  document:{hidden:false,getElementById:get,addEventListener:(n,f)=>listeners[n]=f},window:{addEventListener:(n,f)=>listeners[n]=f},
  setTimeout:()=>1,clearTimeout(){},setInterval:(fn,ms)=>intervals.push({fn,ms}),
  fetch:(url,options)=>{calls.push({url,options});return state.hold?new Promise(r=>resolveFetch=r):Promise.resolve({ok:!state.failure,json:async()=>state.result});},
  rpc:async()=>{if(state.fallback) return {expected_hashes_per_block:'2925369'};throw Error('unavailable');},
  fmt:(v,d)=>Number(v).toFixed(d),fmtInt:v=>String(v),ago:v=>String(v),loadBlocks:()=>{state.blockLoads=(state.blockLoads||0)+1;}
 });state.ctx=ctx;state.resolve=()=>resolveFetch({ok:true,json:async()=>state.result});return state;
}
(async()=>{
 let s=context(),c=s.ctx;
 vm.runInContext('var walletNetworkRatePending=false,walletNetworkRateAt=0;'+extract(wallet,'formatNetworkRate')+extract(wallet,'refreshWalletNetworkRate'),c);
 for(const [rate,text] of [[16252.05,'16.25 KH/s'],[0,'0.00 H/s'],[1000000,'1.00 MH/s'],[Infinity,'—'],[-1,'—']])assert.equal(c.formatNetworkRate(rate),text);
 await c.refreshWalletNetworkRate();assert.equal(s.els['d-hashrate'].textContent,'16.25 KH/s');
 await c.refreshWalletNetworkRate();assert.equal(s.calls.length,1,'Five-second pacing');
 now+=5001;s.hold=true;const wait=c.refreshWalletNetworkRate();await c.refreshWalletNetworkRate();assert.equal(s.calls.length,2,'No overlapping requests');s.resolve();await wait;s.hold=false;
 now+=5001;c.document.hidden=true;await c.refreshWalletNetworkRate();assert.equal(s.calls.length,2,'Hidden pages pause');c.document.hidden=false;
 s.failure=true;s.fallback=true;await c.refreshWalletNetworkRate();assert.equal(s.els['d-hashrate'].textContent,'16.25 KH/s','Local-node fallback uses the same target interval');
 now+=5001;s.fallback=false;await c.refreshWalletNetworkRate();assert.equal(s.els['d-hashrate'].textContent,'—');assert.equal(c.walletNetworkRatePending,false);
 s=context();c=s.ctx;
 vm.runInContext('var networkNodesPending=false,networkNodesAt=0,explorerStatsPending=false,knownH=0;'+extract(explorer,'refreshNetworkNodes')+extract(explorer,'fmtHashrate')+extract(explorer,'loadStats'),c);
 await c.refreshNetworkNodes();assert.equal(s.els['s-peers'].textContent,'2');
 now+=5001;s.result={generated_at:now/1000,nodes:[{id:1},{id:2},{id:2},{id:3}]};await c.refreshNetworkNodes();assert.equal(s.els['s-peers'].textContent,'3','Count updates without any block-height change');
 now+=5001;s.result={generated_at:now/1000,nodes:[]};await c.refreshNetworkNodes();assert.equal(s.els['s-peers'].textContent,'0');
 for(const result of [{generated_at:now/1000-121,nodes:[{id:1}]},{generated_at:now/1000+100,nodes:[{id:1}]},{nodes:[{}]},null]){
  now+=5001;s.result=result;await c.refreshNetworkNodes();assert.equal(s.els['s-peers'].textContent,'—');
 }
 now+=5001;s.result={height:2335,hashrate:16252.05,supply_veld:7333,generated_at:now/1000,nodes:[{id:1}]};
 await c.loadStats();await Promise.resolve();assert.match(s.els['s-hashrate'].innerHTML,/16.25/);assert.equal(s.blockLoads,1);
 await c.loadStats();assert.equal(s.blockLoads,1,'Same-height refresh does not reload blocks');
 s.result={...s.result,height:2336};await c.loadStats();assert.equal(s.blockLoads,2);
 s.hold=true;const pending=c.loadStats();const count=s.calls.length;await c.loadStats();assert.equal(s.calls.length,count);s.resolve();await pending;
 assert.equal(c.explorerStatsPending,false);
 assert(explorer.includes('setInterval(refreshNetworkNodes, 5000)'));
 assert(!wallet.includes('var sample = Math.min(h, 10);'),'Both old timing estimators are removed');
 console.log('PASS network displays: matching rate, local fallback, independent count, pacing, coalescing, stale data, hidden tabs and unchanged block list at same height');
})().catch(e=>{console.error(e);process.exitCode=1;});
