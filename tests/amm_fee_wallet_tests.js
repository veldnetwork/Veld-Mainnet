// Execute the real embedded wallet functions, never a copied quote algorithm.
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync(process.argv[2],'utf8');
const vectors=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
let scriptCount=0;
for(const match of source.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)){
  new vm.Script(match[1],{filename:'embedded-wallet-'+scriptCount+'.js'});
  scriptCount++;
}
assert(scriptCount>0,'the complete embedded wallet scripts must parse');
function fn(name){
  const start=source.indexOf('function '+name+'(');
  assert(start>=0,name); const end=source.indexOf('\n}',start)+2;
  assert(end>start,name); return source.slice(start,end);
}
function context(activation){
  const ctx={};vm.createContext(ctx);
  vm.runInContext(`var BV_FEE_MODEL='seed-ratio-output-asset-4band-v1';
    var BV_FLAT_FEE_MODEL='market-output-asset-flat-30bps-v1',BV_FLAT_FEE_BPS=30;
    var BV_FLAT_FEE_ACTIVATION_HEIGHT=${activation};
    var BV_BAND_EDGE=[500,1000,2000],BV_BAND_FEE=[30,50,75,100];`,ctx);
  // bvAbsBig is a one-line function; terminate its extraction at that line.
  vm.runInContext(source.match(/function bvAbsBig\(n\)\{[^\n]+/)[0],ctx);
  for(const name of ['bvSwapOut','bvFeeModelAllowed','bvBandFee','bvQuote'])
    vm.runInContext(fn(name),ctx);
  return ctx;
}
const c=context(100),pub=context(9500);
let count=0;
for(const t of vectors){
  const [v,b,av,ab,a,d,h]=t.input;
  const p={reserve_veld:v,reserve_btcveld:b,anchor_veld:av,anchor_btcveld:ab,
    fee_model:h>=100?c.BV_FLAT_FEE_MODEL:c.BV_FEE_MODEL,quote_height:h,fee_model_active:true};
  const q=c.bvQuote(p,!!d,a),n=t.native;
  assert.equal(q.reject,!!n[0],JSON.stringify(t));
  if(!q.reject && n[3]>0){
    const got=[q.band,q.feeBps,q.out,q.gross,q.feeOut,q.postV,q.postB,Number(q.rebalances)].map(String);
    assert.deepEqual(got,n.slice(1,9).map(String));
  }
  const pp={...p,fee_model:h>=9500?pub.BV_FLAT_FEE_MODEL:pub.BV_FEE_MODEL};
  const pq=pub.bvQuote(pp,!!d,a),pn=t.public;
  assert.equal(pq.reject,!!pn[0]);
  if(!pq.reject && pn[3]>0){
    const got=[pq.band,pq.feeBps,pq.out,pq.gross,pq.feeOut,pq.postV,pq.postB,Number(pq.rebalances)].map(String);
    assert.deepEqual(got,pn.slice(1,9).map(String));
  }
  assert(pub.bvQuote({...pp,fee_model:h>=9500?pub.BV_FEE_MODEL:pub.BV_FLAT_FEE_MODEL},!!d,a).reject);
  for(const bad of ['unknown',h>=100?c.BV_FEE_MODEL:c.BV_FLAT_FEE_MODEL])
    assert(c.bvQuote({...p,fee_model:bad},!!d,a).reject);
  // An arbitrary server fee does not change the compiled 30-bps policy.
  if(h>=100 && !q.reject) assert.equal(c.bvQuote({...p,fee_bps:0},!!d,a).feeBps,30);
  count++;
}
for(const h of [undefined,null,'100',-1,1.5,Number.MAX_SAFE_INTEGER+1])
  assert(!c.bvFeeModelAllowed({fee_model:c.BV_FLAT_FEE_MODEL,quote_height:h}));
console.log(JSON.stringify({status:'PASS',wallet_native_cases:count,full_scripts_parsed:scriptCount,scope:'actual embedded JS quote functions; no GUI or signing E2E'}));
