'use strict';
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const assert=require('node:assert/strict');
const source=fs.readFileSync(path.join(__dirname,'../include/network/ui_desktop.h'),'utf8');
const start=source.indexOf('function loadCominingEligibility() {');
const end=source.indexOf('\nfunction loadMyComineStats()',start);
assert(start>=0 && end>start,'eligibility function required');
async function exercise(stake, policy, failed=false) {
  const elements=Object.fromEntries(['cm-elig-card','cm-elig-body','cm-minstake'].map(id=>[id,{style:{},innerHTML:'',textContent:''}]));
  const calls=[];
  const context=vm.createContext({currentAddr:'disposable-wallet',document:{getElementById:id=>elements[id]},
    fmt:(v,n)=>Number(v).toFixed(n),rpc:async(method)=>{
      calls.push(method);
      if(method==='getstakinginfo') {if(failed)throw Error('unavailable');return policy;}
      assert.equal(method,'getbalance');return {staked_veld:stake};
    }});
  vm.runInContext(source.slice(start,end),context);
  context.loadCominingEligibility();
  await new Promise(resolve=>setImmediate(resolve));
  return {elements,calls,body:elements['cm-elig-body'].innerHTML};
}
(async()=>{
  for(const ordinary of [1000,500]) {
    for(const stake of [0,499,500,999.99999999,1000,1001]) {
      const r=await exercise(stake,{min_stake_veld:ordinary,co_mining_min_stake_veld:1000});
      assert.equal(r.elements['cm-minstake'].textContent,'1000 VELD');
      assert.equal(r.body.includes('Stake threshold met'),stake>=1000);
      assert.equal(r.body.includes('Not yet qualified'),stake<1000);
    }
  }
  for(const policy of [null,{}, {min_stake_veld:500},
      {co_mining_min_stake_veld:0},{co_mining_min_stake_veld:'1000'},
      {co_mining_min_stake_veld:NaN},{co_mining_min_stake_veld:Infinity}]) {
    const r=await exercise(1000,policy);
    assert.equal(r.elements['cm-minstake'].textContent,'Unavailable');
    assert.deepEqual(r.calls,['getstakinginfo']);
    assert(!r.body.includes('Stake threshold met'));
  }
  const failed=await exercise(1000,{},true);
  assert.equal(failed.elements['cm-minstake'].textContent,'Unavailable');
  console.log('PASS wallet co-mining threshold, activation independence and unavailable policy');
})().catch(error=>{console.error(error);process.exitCode=1;});
