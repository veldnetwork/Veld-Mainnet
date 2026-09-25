'use strict';
// Ordinary recovery controls in disposable browser profiles. Transaction input
// scripts are inert stand-ins; no key generation, signature, RPC or broadcast.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const {chromium, webkit} = require('playwright');
const browserName = process.env.VELD_TEST_BROWSER === 'webkit' ? 'WebKit' : 'Chromium';
const {extractFunction} = require('./javascript_function_source');
const sourcePath = process.env.VELD_WALLET_TEST_SOURCE || path.join(__dirname, '../include/network/ui_desktop.h');
const source = fs.readFileSync(sourcePath, 'utf8').split(')HTMLEOF"')[0];
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'veld-outbox-controls-'));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const functions = ['_veldKeyCommitmentToScriptHex', 'hexToBytes', 'bytesToHex', 'sha256Compress', 'sha256', 'sha256d',
  '_veldHexToBytes', '_veldBytesToHex', '_veldParseVarint', '_veldParseUnsignedTx',
  '_veldAssertPreparedRelaySize', '_veldJournal', '_veldJournalOperation',
  '_veldGetSingleCanonicalOpReturnPayload', '_veldRecoverLegacyTransactions',
  '_veldJournalSign', '_veldJournalBroadcast', '_veldRetryJournalTransaction',
  '_veldBroadcastExactSigned', 'injectSignatures', 'rpc'];
const constants = source.slice(source.indexOf('  var K256 = ['), source.indexOf('  function sha256Compress('));
const application = constants + functions.map(name => extractFunction(source, name)).join('\n');
const fixture = `
var VELD_GENESIS_HASH='${'a1'.repeat(32)}', VELD_DEPLOYMENT_PROFILE_ID='disposable-outbox-controls';
var currentAddr='fixture-owner';
var owner='fixture-owner', generation=7, signatureCalls=0, sends=[], notifications=[];
var unavailable=false, selected=[], nodeSpendable=0;
var __veldTxChannel={postMessage:function(message){notifications.push(message);}};
var __veldKey={get:function(){return '${'1a'.repeat(32)}';}};
function refreshWalletAfterBroadcast() {}
function _veldAssertActiveSignerSeed(seed, expected) {
  if(seed!==__veldKey.get() || (expected!==undefined && expected!==generation)) throw Error('Session changed');
  return generation;
}
function _veldRequireBoundIdentity(){return {address:owner};}
function _veldAddrToKeyCommitmentHex(){return '19'.repeat(20);}
function _veldVerifyInputSighashes(prep){if(!prep.inputs.length)throw Error('Missing metadata');}
async function _veldAuthenticatePreparedPrevouts(){}
function buildScriptSig(){signatureCalls++;return '00';}
async function _veldRpcTransport(method, params){
  if(method==='sendrawtransaction') {
    sends.push(params[0]);
    if(unavailable) throw Error('Ordinary delivery response unavailable');
    return veldCrypto.sha256d(params[0]);
  }
  if(method==='listunspent')return selected;
  if(method==='getbalance')return {balance_veld:99,spendable_veld:nodeSpendable};
  throw Error('Unexpected transport: '+method);
}
async function _veldPendingHistoryHints(){return new Map();}
var veldCrypto={sha256d:sha256d,injectSignatures:injectSignatures};
var VELD_MIN_TX_FEE_UNITS=100000;
function ordinaryTransaction(index, amount){
  var out='76a914'+'19'.repeat(20)+'88ac';
  return '01000000'+'01'+'12'.repeat(32)+index.toString(16).padStart(2,'0')+'00000000ffffffff'+
    '01'+amount.toString(16).padStart(2,'0')+'00000000000000'+'19'+out+'00000000';
}
var unsigned=ordinaryTransaction(0,20), metadata=[{sighash_hex:'inert-reviewed-input'}];
`;
let browserContext;
let origin;
const server = http.createServer((_request,response) => {
  response.writeHead(200, {'Content-Type':'text/html','Cache-Control':'no-store'});
  response.end('<!doctype html><title>Disposable recovery controls</title>');
});
async function launch() {
  browserContext = await (browserName === 'WebKit' ? webkit : chromium).launchPersistentContext(profile, {
    headless:true, executablePath:process.env.VELD_TEST_BROWSER_EXECUTABLE || undefined,
    args:browserName === 'Chromium' ? ['--disable-background-networking', '--disable-component-update', '--no-default-browser-check'] : []
  });
  await browserContext.route('**/*', route => route.request().url().startsWith(origin + '/') ? route.continue() : route.abort());
}
async function page() {
  const p = await browserContext.newPage();
  await p.goto(origin);
  await p.evaluate(application + '\n' + fixture);
  return p;
}
const results = [];
(async () => {
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  origin='http://127.0.0.1:'+server.address().port;
  await launch();
  let p = await page();
  let first = await p.evaluate(async () => {
    const start = performance.now();
    const signed = await injectSignatures(unsigned, metadata, __veldKey.get(), null, generation);
    const txid = veldCrypto.sha256d(signed);
    const before = await _veldJournal().get(txid);
    if(before.payload.signed!==signed || before.record.state!=='ready')throw Error('Signed bytes were not committed');
    unavailable=true;
    try { await _veldBroadcastExactSigned(signed,__veldKey.get(),generation); } catch(e) {
      if(!e.message.includes('unavailable'))throw e;
    }
    return {signed,txid,signatureCalls,attempt:sends[0],claims:Array.from(await _veldJournal().guards(owner)),
      state:(await _veldJournal().get(txid)).record.state,ms:performance.now()-start};
  });
  assert.equal(first.signatureCalls, 1);
  assert.equal(first.signed, first.attempt);
  assert.equal(first.state, 'ready');
  assert.equal(first.claims.length, 1);
  results.push({case:'persist-before-delivery-and-uncertain-response', ms:first.ms, result:'PASS'});
  await browserContext.close();
  await launch();
  p = await page();
  const resumed = await p.evaluate(async txid => {
    await _veldRetryJournalTransaction(txid);
    const row = await _veldJournal().get(txid);
    return {signed:sends[0],signatureCalls,state:row.record.state,guardCount:(await _veldJournal().guards(owner)).size};
  }, first.txid);
  assert.equal(resumed.signed, first.signed);
  assert.equal(resumed.signatureCalls, 0);
  assert.equal(resumed.state, 'submitted');
  assert.equal(resumed.guardCount, 1);
  results.push({case:'browser-process-restart-exact-byte-retry',result:'PASS'});
  const second = await page();
  const tab = await second.evaluate(async () => {
    const signed = await injectSignatures(unsigned,metadata,__veldKey.get(),null,generation);
    return {signed,signatureCalls,guards:(await _veldJournal().guards(owner)).size};
  });
  assert.equal(tab.signed,first.signed);
  assert.equal(tab.signatureCalls,0);
  assert.equal(tab.guards,1);
  results.push({case:'second-tab-reuses-persisted-identical-intent',result:'PASS'});
  const blocked = await second.evaluate(async () => {
    try { await injectSignatures(ordinaryTransaction(0,19),metadata,__veldKey.get(),null,generation); }
    catch(error){return {message:error.message,signatureCalls};}
    throw Error('A reserved input was selected again');
  });
  assert.match(blocked.message,/earlier transaction/);
  assert.equal(blocked.signatureCalls,0);
  results.push({case:'ordinary-new-send-keeps-previous-input-reservation',result:'PASS'});
  const accounting = await p.evaluate(async txid => {
    selected=[{txid:'12'.repeat(32),vout:0,value_units:200000000},
      {txid:'12'.repeat(32),vout:1,value_units:300000000}];nodeSpendable=5;
    const initial=await rpc('getbalance',[owner]);
    const outputs=await rpc('listunspent',[owner]);
    await _veldJournal().confirmed([txid]);
    const hidden=(await _veldJournal().pending(owner)).length;
    selected=selected.slice(1);nodeSpendable=3;
    const confirmed=await rpc('getbalance',[owner]);
    selected.unshift({txid:'12'.repeat(32),vout:0,value_units:200000000});nodeSpendable=5;
    const restored=await rpc('getbalance',[owner]);
    return {initial,outputs,hidden,confirmed,restored,pending:(await _veldJournal().pending(owner)).length};
  },first.txid);
  assert.equal(accounting.initial.spendable_veld,3);
  assert.equal(accounting.outputs.length,1);
  assert.equal(accounting.hidden,0);
  assert.equal(accounting.confirmed.spendable_veld,3);
  assert.equal(accounting.restored.spendable_veld,3);
  assert.equal(accounting.pending,1);
  results.push({case:'pending-confirmed-and-restored-output-accounting',result:'PASS'});
  const interruption=await p.evaluate(async () => {
    const bytes=ordinaryTransaction(2,17);
    try {await _veldJournal().sign(bytes,metadata,owner,async()=>{throw Error('Ordinary cancellation');});}
    catch(e){if(!e.message.includes('cancellation'))throw e;}
    const held=(await _veldJournal().guards(owner)).size;
    const pending=await _veldJournal().pending(owner);
    window.confirm=()=>true;
    const id=veldCrypto.sha256d(bytes);
    await _veldRetryJournalTransaction(id);
    const saved=await _veldJournal().get(id);
    return {held,interrupted:pending.some(row=>row.interrupted),signed:saved.payload.signed,signatureCalls};
  });
  assert.equal(interruption.held,2);
  assert(interruption.interrupted);
  assert.equal(interruption.signatureCalls,1);
  results.push({case:'interrupted-signing-retains-intent-and-resumes',result:'PASS'});
  const legacy=await p.evaluate(async()=>{
    const raw=ordinaryTransaction(3,16);
    const txid=veldCrypto.sha256d(raw);
    localStorage.setItem('veld_pending_txs',JSON.stringify([{txid,from_addr:owner,ts:42}]));
    const previous=_veldRpcTransport;
    _veldRpcTransport=async(method,params)=>method==='gettransactionrecent'?{raw_hex:raw,txid}:previous(method,params);
    await _veldRecoverLegacyTransactions(owner);
    const recovered=await _veldJournal().get(txid);
    localStorage.removeItem('veld_pending_txs');
    _veldRpcTransport=previous;
    return {raw:recovered.payload.signed,txid:recovered.record.txid,guards:(await _veldJournal().guards(owner)).size};
  });
  assert.equal(legacy.guards,3);
  assert.equal(hash(Buffer.from(hash(Buffer.from(legacy.raw,'hex')),'hex')),legacy.txid);
  results.push({case:'older-pending-hash-checked-byte-migration',result:'PASS'});
  const disconnected=await p.evaluate(async()=>{
    const before=signatureCalls;
    localStorage.setItem('veld_pending_txs',JSON.stringify([{txid:'99'.repeat(32),from_addr:owner,ts:41}]));
    let message='';
    try{await injectSignatures(ordinaryTransaction(4,15),metadata,__veldKey.get(),null,generation);}
    catch(e){message=e.message;}
    const preserved=JSON.parse(localStorage.getItem('veld_pending_txs')).length;
    localStorage.removeItem('veld_pending_txs');
    return {message,preserved,signatures:signatureCalls-before};
  });
  assert.match(disconnected.message,/earlier transaction is unavailable/);
  assert.equal(disconnected.signatures,0);
  assert.equal(disconnected.preserved,1);
  results.push({case:'unavailable-older-record-retains-evidence-and-stops-signing',result:'PASS'});
  const storageFailure=await p.evaluate(async()=>{
    const initial=(await _veldJournal().guards(owner)).size;
    const before=signatureCalls;
    const add=IDBObjectStore.prototype.add;
    IDBObjectStore.prototype.add=function(...args){
      if(this.name==='payloads')throw new DOMException('Fixture storage capacity unavailable','QuotaExceededError');
      return add.apply(this,args);
    };
    let message='';
    try{await injectSignatures(ordinaryTransaction(4,15),metadata,__veldKey.get(),null,generation);}
    catch(error){message=error.message;}
    finally{IDBObjectStore.prototype.add=add;}
    return {initial,after:(await _veldJournal().guards(owner)).size,message,signatures:signatureCalls-before};
  });
  assert.match(storageFailure.message,/storage capacity/);
  assert.equal(storageFailure.signatures,0);
  assert.equal(storageFailure.initial,storageFailure.after);
  results.push({case:'reservation-write-failure-rolls-back-before-signing',result:'PASS'});
  const interruptedWrite=await p.evaluate(async()=>{
    const unsigned=ordinaryTransaction(4,15);
    const put=IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put=function(...args){
      if(this.name==='payloads')throw new DOMException('Fixture signed-record write unavailable','QuotaExceededError');
      return put.apply(this,args);
    };
    let returned=false, message='';
    try{await injectSignatures(unsigned,metadata,__veldKey.get(),null,generation);returned=true;}
    catch(error){message=error.message;}
    finally{IDBObjectStore.prototype.put=put;}
    const saved=await _veldJournal().get(veldCrypto.sha256d(unsigned));
    const recovered=await injectSignatures(unsigned,metadata,__veldKey.get(),null,generation);
    return {returned,message,state:saved.record.state,held:saved.record.inputs.length,
      unpublished:saved.payload.signed==='',recovered:!!recovered};
  });
  assert.match(interruptedWrite.message,/signed-record write/);
  assert.equal(interruptedWrite.returned,false);
  assert.equal(interruptedWrite.state,'reserved');
  assert.equal(interruptedWrite.held,1);
  assert(interruptedWrite.unpublished && interruptedWrite.recovered);
  results.push({case:'signed-record-write-failure-keeps-reservation-and-releases-no-bytes',result:'PASS'});
  const large=await p.evaluate(async()=>{
    const count=150;
    let unsigned='01000000'+count.toString(16);
    for(let i=5;i<count+5;i++)unsigned+='12'.repeat(32)+i.toString(16).padStart(2,'0')+'00000000ffffffff';
    unsigned+='01'+'0f00000000000000'+'19'+'76a914'+'19'.repeat(20)+'88ac'+'00000000';
    const items=Array.from({length:count},()=>({sighash_hex:'inert-reviewed-input'}));
    const build=buildScriptSig;
    buildScriptSig=()=>{signatureCalls++;return '00'.repeat(5269);};
    const start=performance.now();
    let signed;
    try{signed=await injectSignatures(unsigned,items,__veldKey.get(),null,generation);}
    finally{buildScriptSig=build;}
    const saved=await _veldJournal().get(veldCrypto.sha256d(signed));
    return {bytes:signed.length/2,ms:performance.now()-start,inputs:saved.record.inputs.length,
      exact:saved.payload.signed===signed};
  });
  assert(large.bytes>790000 && large.bytes<1024*1024);
  assert.equal(large.inputs,150);
  assert(large.exact);
  results.push({case:'bounded-large-ordinary-journal-payload',...large,result:'PASS'});
  const storage=await p.evaluate(async () => {
    if(!navigator.storage || !navigator.storage.estimate)return {usage:null,quota:null,measurement:'not exposed by this engine'};
    const estimate=await navigator.storage.estimate();
    return {usage:estimate.usage,quota:estimate.quota,details:estimate.usageDetails};
  });
  const version=browserContext.browser().version();
  await browserContext.close();
  server.close();
  console.log(JSON.stringify({status:'PASS',sourceSHA256:hash(Buffer.from(source)),sourcePath,
    browser:browserName,version,profile,results,storage,realKeys:0,cryptographicSignatures:0,
    productionRequests:0,limit:'Disposable browser-engine controls; installed iOS PWA, storage deletion and downgrade remain separate.'},null,2));
})().catch(async error=>{try{await browserContext?.close();}catch(_){} server.close(); console.error(error);process.exitCode=1;});
