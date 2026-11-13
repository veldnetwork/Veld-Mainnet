'use strict';
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const {extractFunction} = require('./javascript_function_source');
const source = fs.readFileSync(path.join(__dirname,'../include/network/ui_desktop.h'),'utf8');
const hosted = fs.readFileSync(path.join(__dirname,'../website/hosted-wallet/wallet-bond-balance-v1.js'),'utf8');
const names = ['_veldWalletBondBalance','_veldApplyWalletBondBalance','_veldLoadWalletBondBalance','loadWalletAddr'];
for (const name of names) assert.equal(extractFunction(hosted,name),extractFunction(source,name),'Native/hosted parity: '+name);
const loader = extractFunction(source,'loadWalletAddr');
assert(!loader.includes('min_stake_veld'));
assert(loader.includes('bondBalance.addressTotal = effective;'));
assert(loader.includes('_veldLoadWalletBondBalance(bondBalance);'));
let resolve, reject, current = true;
const elements = new Map();
const element = id => {if(!elements.has(id))elements.set(id,{style:{},textContent:'',innerHTML:''});return elements.get(id);};
const context = vm.createContext({window:{},document:{getElementById:element},fmt:(n,d)=>n.toFixed(d),rpc(method,params){
  assert.equal(method,'getbondvaultinfo'); assert.equal(params.length,0);
  return new Promise((yes,no)=>{resolve=yes;reject=no;});
}});
vm.runInContext(names.slice(0,3).map(name=>extractFunction(source,name)).join('\n'),context);
let checks = 0;
const row = (amount, held=true, extra={}) => ({address:'owner',principal_held:held,bond_veld:amount,...extra});
const vault = (...validators) => ({min_stake_veld:5000,validators});
for (const [data,expected] of [
  [vault(row(10000)),10000],
  [vault(row(10000,true,{bond_reduction_pending:true,bond_retained_units:'500000000000'})),10000],
  [vault(row(5000,true,{bond_reduction_settled_at:50400,original_bond_veld:10000})),5000],
  [vault(row(10000,true,{active:false,pending_return:true})),10000],
  [vault(row(0,false,{original_bond_veld:10000})),0],
  [vault(row(0,false,{slashed:true})),0],
  [vault(row(10000,true,{address:'another-wallet'})),0],
  [vault(),0]
]) {assert.equal(context._veldWalletBondBalance(data,'owner'),expected);checks++;}
for (const data of [null,{},vault(row(-1)),vault(row('10000')),vault(row(NaN)),vault(row(Infinity)),vault({address:'owner',bond_veld:10000})]) {
  assert.throws(()=>context._veldWalletBondBalance(data,'owner'));checks++;
}
(async()=>{
  for(const bondFirst of [true,false]) {
    current=true;
    const state={address:'owner',isCurrent:()=>current,addressTotal:null,bonded:null};
    const request=context._veldLoadWalletBondBalance(state);
    if(bondFirst){resolve(vault(row(10000)));await request;}
    state.addressTotal=572;
    context._veldApplyWalletBondBalance(state);
    if(!bondFirst){resolve(vault(row(10000)));await request;}
    assert.equal(context.window._statusBalance,10572);
    assert.equal(element('w-bal-bonded').textContent,'10000.00');
    assert.equal(element('w-bal-bonded-row').style.display,'');checks++;
  }
  for(const failed of [false,true]) {
    current=true;
    const state={address:'owner',isCurrent:()=>current,addressTotal:123,bonded:null};
    const request=context._veldLoadWalletBondBalance(state);
    current=false;
    if(failed)reject(new Error('offline'));else resolve(vault(row(10000)));
    await request;
    assert.equal(context.window._statusBalance,10572);assert.equal(state.bonded,null);checks++;
  }
  current=true;
  const state={address:'owner',isCurrent:()=>current,addressTotal:123,bonded:null};
  const request=context._veldLoadWalletBondBalance(state);reject(new Error('offline'));await request;
  assert.equal(context.window._statusBalance,123);
  assert.equal(element('w-bal-bonded-row').style.display,'none');checks++;
  console.log('PASS: '+checks+' held-bond balance and response-order checks; no signing or broadcasts');
})().catch(error=>{console.error(error);process.exitCode=1;});
