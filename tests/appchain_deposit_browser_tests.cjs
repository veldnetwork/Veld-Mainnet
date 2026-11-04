'use strict';
// Real browser ML-DSA, parser, intent/fee checks and durable IndexedDB outbox.
// Adversarial responses use replayed fixtures. An optional actual native RPC
// process accepts, mines and replays the browser's exact signed transaction.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {spawn}=require('node:child_process');
const readline=require('node:readline');
const {chromium}=require('playwright');
const {extractFunction}=require('./javascript_function_source');
const root=path.resolve(__dirname,'..'),input=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const out=path.resolve(process.argv[3]);fs.mkdirSync(out,{recursive:false});
const nativeSpec=process.env.VELD_DEPOSIT_NATIVE_RPC ? JSON.parse(fs.readFileSync(process.env.VELD_DEPOSIT_NATIVE_RPC,'utf8')) : null;
if(nativeSpec)assert.equal(nativeSpec.scope,'isolated-disposable-native-deposit');
let nativeProcess,nativeClosed,nativeCode,queue=[];
function startNative(){
 if(!nativeSpec)return;
 const log=fs.openSync(path.join(out,'native.log'),'wx');
 nativeProcess=spawn(nativeSpec.executable,nativeSpec.args,{stdio:['pipe','pipe',log],windowsHide:true});fs.closeSync(log);
 const lines=readline.createInterface({input:nativeProcess.stdout});
 lines.on('line',line=>{const next=queue.shift();if(next)next.resolve(line);});
 nativeClosed=new Promise(resolve=>nativeProcess.on('close',code=>{nativeCode=code;for(const next of queue)next.reject(Error('Native RPC exited'));queue=[];resolve(code);}));
 nativeProcess.on('error',error=>{for(const next of queue)next.reject(error);queue=[];});
}
async function stopNative(){if(nativeProcess&&nativeCode===undefined){nativeProcess.stdin.end();await nativeClosed;}return nativeCode;}
function nativeCall(body){return new Promise((resolve,reject)=>{queue.push({resolve,reject});nativeProcess.stdin.write(body+'\n');});}
const source=fs.readFileSync(path.join(root,'include/network/ui_desktop.h'),'utf8');
const cryptoStart=source.indexOf('var veldCrypto = (function() {');
const cryptoEnd=source.indexOf('\n})();',cryptoStart)+7;
const names=['_veldRequireSelfCustodySigner','_veldAssertActiveSignerSeed','_veldHexToBytes','_veldBytesToHex','_veldParseVarint',
 '_veldParseUnsignedTx','_veldSha384PublicBytes','_veldBase58Decode','_veldAddrToHash160Hex','_veldAddrToKeyCommitmentHex',
 '_veldScriptToHash160Hex','_veldScriptToKeyCommitmentHex','_veldKeyCommitmentToScriptHex','_veldAddressForPublicKey','isValidVeldAddr',
 '_veldRequireBoundIdentity','_veldSha256dBytes','_veldVerifyInputSighashes','_veldAuthenticatePreparedPrevouts','_veldAssertPreparedRelaySize',
 '_veldGetSingleCanonicalOpReturnPayload','_veldNmsTransaction','_veldNmsReplacement','_veldJournal','_veldJournalOperation','_veldRecoverLegacyTransactions','_veldJournalSign',
 '_veldJournalBroadcast','_veldBroadcastExactSigned','_veldSavedTransactionReceipt','_veldRetryJournalTransaction',
 '_veldAppchainUnits','_veldAppchainLE','_veldAppchainField','_veldAppchainTaggedDigest','_veldAppchainSelection',
 '_veldCheckAppchainDepositNetwork','_veldVerifyAppchainDeposit','_veldAppchainPreparedReview','prepareAppchainDeposit'];
const app=source.slice(cryptoStart,cryptoEnd)+'\n'+names.map(n=>extractFunction(source,n)).join('\n');
const codec=fs.readFileSync(path.join(root,'include/network/covenant_client_js.h'),'utf8').split('R"VELDCJS(\n')[1].split(')VELDCJS"')[0];
const wasm=fs.readFileSync(path.join(root,'vendor/pqc/dilithium_wasm.js'),'utf8');
const fixture=`
var input=${JSON.stringify(input)};
var VELD_ADDRESS_VERSION=70,VELD_NETWORK_BYTE=0x4d,VELD_GENESIS_HASH=input.signature_genesis;
var VELD_APPCHAIN_PARENT_GENESIS=input.selected.parent_genesis;
var VELD_DEPLOYMENT_PROFILE_ID='isolated-native-deposit-browser',VELD_BROWSER_SELF_CUSTODY=true,VELD_TRUSTED_LOCAL_SIGNER=true;
var VELD_SELF_CUSTODY_REQUIRED_MESSAGE='Use the local wallet.',VELD_MIN_TX_FEE_UNITS=100000;
var VELD_SIGNER_IDLE_MS=300000,_veldSignerLastActivity=Date.now();
var currentAddr=input.address,generation=7,activeSeed=input.seed,unavailable=false,sends=[],requests=[],beforeSend=[];
var _BASE58_ALPHABET='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
var __veldKey={get:()=>activeSeed,generation:()=>generation};
var __veldTxChannel={postMessage:()=>{}};
function refreshWalletAfterBroadcast(){}
function _veldAutoLockSigner(){activeSeed='';generation++;}
function clone(v){return JSON.parse(JSON.stringify(v));}
var preparedReply=clone(input.prepared.result),networkReply=clone(input.network.result),transportHook=null;
var useNative=false;
async function rpc(method,params){
 requests.push({method,params:clone(params)});
 if(transportHook)await transportHook(method);
 if(useNative)return _veldRpcTransport(method,params);
 if(method==='getappchainbridgeinfo')return clone(networkReply);
 if(method==='prepareappchaindeposit')return clone(preparedReply);
 var coin=input.prevouts.find(p=>p.txid===params[0]);
 if(method==='gettxout'&&coin&&coin.vout===Number(params[1]))return clone(coin.live.result);
 if(method==='gettransaction'&&coin)return clone(coin.parent.result);
 throw Error('Unexpected offline native fixture request: '+method);
}
async function _veldRpcTransport(method,params){
 if(useNative&&method!=='sendrawtransaction'){
  var read=await fetch('/rpc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});
  var answer=await read.json();if(answer.error)throw Error(answer.error.message);return answer.result;
 }
 if(method!=='sendrawtransaction')throw Error('Unexpected transport');
 var id=veldCrypto.sha256d(params[0]),saved=await _veldJournal().get(id);
 if(!saved||saved.payload.signed!==params[0]||saved.record.state!=='ready')throw Error('Unsigned or unsaved broadcast');
 beforeSend.push(saved.record.state);sends.push(params[0]);
 if(useNative){
  var response=await fetch('/rpc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});
  var answer=await response.json();if(answer.error)throw Error(answer.error.message);
  if(answer.result!==id)throw Error('Native transaction identity mismatch');
 }
 if(unavailable)throw Error('Fixture delivery response unavailable');
 return id;
}
`;
const results=[];let context,origin;
const server=http.createServer(async(req,res)=>{
 if(req.method==='POST'&&req.url==='/rpc'&&nativeSpec){
  try{let body='';for await(const chunk of req){body+=chunk;if(body.length>2097152)throw Error('RPC request limit');}
   const result=await nativeCall(body);res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(result);
  }catch(e){res.writeHead(503,{'Content-Type':'application/json'});res.end(JSON.stringify({error:{message:e.message}}));}return;
 }
 res.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store'});res.end('<!doctype html><title>Native deposit qualification</title>');
});
async function launch(){
 context=await chromium.launchPersistentContext(path.join(out,'profile'),{headless:true,
  executablePath:process.env.VELD_TEST_BROWSER_EXECUTABLE||undefined,
  args:['--disable-background-networking','--disable-component-update','--no-default-browser-check']});
 await context.route('**/*',route=>route.request().url().startsWith(origin+'/')?route.continue():route.abort());
}
async function page(){
 const p=await context.newPage();await p.goto(origin);await p.bringToFront();
 await p.addScriptTag({content:wasm});await p.addScriptTag({content:codec});
 await p.addScriptTag({content:app+'\n'+fixture});await p.evaluate(()=>veldCrypto.init());return p;
}
function passed(name,detail={}){results.push({name,status:'PASS',...detail});}
const digest=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
(async()=>{
 startNative();
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin='http://127.0.0.1:'+server.address().port;
 await launch();let p=await page();
 const checks=await p.evaluate(async()=>{
  var count=0;
  function ok(test,label){if(!test)throw Error(label);count++;}
  function refuse(fn,label){var failed=false;try{fn();}catch(e){failed=true;}ok(failed,label);}
  var valid=clone(preparedReply),selection=clone(input.selected);
  var review=_veldVerifyAppchainDeposit(valid,selection,input.address);
  ok(review.trading_atoms==='15000000'&&review.fuel_backing_atoms==='5000000'&&review.fee_atoms==='100000','exact allocation review');
  ok(_veldJournalOperation(valid.unsigned_tx_hex,input.address).label==='Exchange Deposit','saved deposit is labeled accurately');
  for(var field of ['parent_genesis','bridge_id','descriptor_id','child_genesis','beneficiary_id']){
   var bad=clone(selection);bad[field]=(bad[field][0]==='a'?'b':'a')+bad[field].slice(1);
   refuse(()=>_veldVerifyAppchainDeposit(valid,bad,input.address),'wrong '+field);
  }
  for(var field of ['trading_atoms','fuel_backing_atoms']){
   var bad=clone(selection);bad[field]=String(BigInt(bad[field])+1n);
   refuse(()=>_veldVerifyAppchainDeposit(valid,bad,input.address),'wrong allocation');
  }
  for(var value of [-1,0.1,NaN,Infinity,Number.MAX_SAFE_INTEGER+1,'01','1e2','0.001','2100000000000001',{},null])
   refuse(()=>_veldAppchainUnits(value),'noncanonical integer');
  for(var field of ['total_input','total_output','fee','change','trading_atoms','fuel_backing_atoms']){
   var bad=clone(valid);bad[field]=Number(bad[field])+1;
   refuse(()=>_veldVerifyAppchainDeposit(bad,selection,input.address),'dishonest '+field);
  }
  for(var field of ['bridge_id','descriptor_id','child_genesis','beneficiary_id','operation_identity']){
   var bad=clone(valid);bad[field]='a'+bad[field].slice(1);
   if(bad[field]===valid[field])bad[field]='b'+bad[field].slice(1);
   refuse(()=>_veldVerifyAppchainDeposit(bad,selection,input.address),'dishonest domain');
  }
  for(var field of Object.keys(valid.signing_intent)){
   var bad=clone(valid);bad.signing_intent[field]=typeof bad.signing_intent[field]==='number'?bad.signing_intent[field]+1:'wrong';
   refuse(()=>_veldVerifyAppchainDeposit(bad,selection,input.address),'tampered intent '+field);
  }
  for(var field of ['index','value','prev_script_hex','sighash_hex','parent_tx_hex','sigless']){
   var bad=clone(valid);bad.inputs[0][field]=field==='sigless'?true:typeof bad.inputs[0][field]==='number'?bad.inputs[0][field]+1:'00';
   refuse(()=>_veldVerifyAppchainDeposit(bad,selection,input.address),'tampered parent evidence '+field);
  }
  for(var mutate of [x=>'02000000'+x.slice(8),x=>x.slice(0,-8)+'01000000',x=>x+'00',x=>x.toUpperCase(),
     x=>x.replace('c10130'+selection.bridge_id,'c10130'+'12'.repeat(48)),
     x=>x.replace('6a4c7b56454c445f415050317c01','6a4c7b56454c445f415050317c02')]){
   var bad=clone(valid);bad.unsigned_tx_hex=mutate(bad.unsigned_tx_hex);
   refuse(()=>_veldVerifyAppchainDeposit(bad,selection,input.address),'altered raw transaction');
  }
  for(var mutate of [n=>n.active=false,n=>n.parent_genesis='12'.repeat(32),n=>n.bridges[0].can_deposit=false,
      n=>n.bridges[0].exit_only=true,n=>n.bridges[0].stale=true,n=>n.bridges[0].remaining_capacity_atoms=1,
      n=>n.bridges[0].descriptor_id='12'.repeat(48),n=>n.bridges[0].child_genesis='12'.repeat(48),n=>n.bridges=[]]){
   var bad=clone(networkReply);mutate(bad);refuse(()=>_veldCheckAppchainDepositNetwork(bad,selection),'inactive or mismatched network');
  }
  var request=await prepareAppchainDeposit(selection,input.address);
  ok(sends.length===0,'review does not sign or broadcast');
  ok(Object.isFrozen(request)&&Object.isFrozen(request.review)&&Object.isFrozen(request.review.selection),'immutable review');
  var params=requests.find(r=>r.method==='prepareappchaindeposit').params;
  ok(params[5]==='0.15000000'&&params[6]==='0.05000000','exact RPC decimals');
  return count;
 });passed('real browser transaction and intent adversarial verification',{checks});
 const guard=await p.evaluate(async()=>{
  var q=await prepareAppchainDeposit(input.selected,input.address);
  transportHook=async method=>{if(method==='gettxout')generation++;};
  try{await q.confirm(input.seed);throw Error('should reject changed signing session');}
  catch(e){if(!e.message.includes('session changed'))throw e;}
  transportHook=null;
  var r=await prepareAppchainDeposit(input.selected,input.address);networkReply.bridges[0].exit_only=true;
  try{await r.confirm(input.seed);throw Error('should reject changed bridge policy');}
  catch(e){if(!e.message.includes('unavailable'))throw e;}
  networkReply=clone(input.network.result);
  return {sends:sends.length,records:(await _veldJournal().guards(input.address)).size};
 });assert.deepEqual(guard,{sends:0,records:0});passed('session and bridge changes before signing refuse without spent inputs');
 const first=await p.evaluate(async actual=>{
  useNative=actual;
  var selected=clone(input.selected),q=await prepareAppchainDeposit(selected,input.address);
  selected.trading_atoms='1';preparedReply.fee=1;unavailable=true;
  try{await q.confirm(input.seed);throw Error('expected delivery failure');}
  catch(e){if(!e.message.includes('delivery response unavailable'))throw e;}
  try{await q.confirm(input.seed);throw Error('expected duplicate-review refusal');}
  catch(e){if(!e.message.includes('already been used'))throw e;}
  var signed=sends[0],txid=veldCrypto.sha256d(signed),saved=await _veldJournal().get(txid);
  return {signed,txid,state:saved.record.state,saved:saved.payload.signed,sendCount:sends.length,
     claims:(await _veldJournal().guards(input.address)).size,beforeSend};
 },!!nativeSpec);
 assert.equal(first.signed,first.saved);assert.equal(first.state,'ready');assert.equal(first.sendCount,1);
 assert.equal(first.claims,input.prepared.result.inputs.length);assert.deepEqual(first.beforeSend,['ready']);
 passed('actual ML-DSA signed bytes persist before interrupted delivery; caller mutations and repeated confirmation cannot change review');
 fs.writeFileSync(path.join(out,'signed.hex'),first.signed+'\n',{flag:'wx'});
 await context.close();await launch();p=await page();
 const recovered=await p.evaluate(async ({txid,actual})=>{
  useNative=actual;
  var prior=await _veldJournal().get(txid);if(!prior)throw Error('saved deposit missing after browser restart');
  await _veldRetryJournalTransaction(txid);var after=await _veldJournal().get(txid);
  return {signed:after.payload.signed,sendCount:sends.length,state:after.record.state,claims:(await _veldJournal().guards(input.address)).size};
 },{txid:first.txid,actual:!!nativeSpec});
 assert.equal(recovered.signed,first.signed);
 assert.equal(recovered.state,nativeSpec&&nativeSpec.args.includes('serve-confirmed')?'confirmed':'submitted');
 assert.equal(recovered.sendCount,nativeSpec?0:1);assert.equal(recovered.claims,first.claims);
 passed('browser process restart recovers exact saved deposit',{state:recovered.state,resends:recovered.sendCount});
 if(nativeSpec){assert.equal(await stopNative(),0);passed('actual native RPC receives browser transaction once, then mines and fully replays it');}
 const report={status:'PASS_BROWSER_NATIVE_DEPOSIT_SIGNING_AND_RESTART',browser:await context.browser().version(),
  scope:nativeSpec?'Actual local native RPC, browser ML-DSA, lost acknowledgement, IndexedDB process recovery, native mining and full replay; no live network or funds':
   'Actual ML-DSA browser signing and IndexedDB recovery with replayed native RPC fixtures; no live network or funds',
  checks:results,transaction:first.txid,signed_sha256:digest(path.join(out,'signed.hex')),
  source:{'include/network/ui_desktop.h':digest(path.join(root,'include/network/ui_desktop.h')),
    'include/network/covenant_client_js.h':digest(path.join(root,'include/network/covenant_client_js.h')),
    'vendor/pqc/dilithium_wasm.js':digest(path.join(root,'vendor/pqc/dilithium_wasm.js')),
    'tests/appchain_deposit_browser_tests.cjs':digest(__filename),
    'src/veld-desktop.cpp':digest(path.join(root,'src/veld-desktop.cpp'))}};
 fs.writeFileSync(path.join(out,'result.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({status:report.status,checks,groups:results.length,transaction:first.txid}));
})().catch(error=>{fs.writeFileSync(path.join(out,'failure.json'),JSON.stringify({error:error.stack,checks:results},null,2));console.error(error);process.exitCode=1;})
.finally(async()=>{if(context)await context.close();await stopNative();await new Promise(resolve=>server.close(resolve));});
