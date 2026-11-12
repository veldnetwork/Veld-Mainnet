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
 lines.on('line',line=>{if(line.startsWith('RESULT ')){nativeEvidence=JSON.parse(line.slice(7));return;}const next=queue.shift();if(next)next.resolve(line);});
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
 '_veldCheckAppchainDepositNetwork','_veldVerifyAppchainDeposit','_veldAppchainPreparedReview','prepareAppchainDeposit','_veldDepositHandoff','_veldDepositHandoffDecode','_veldDepositHandoffStore','_veldDepositHandoffKey','_veldDepositHandoffRecord','prepareDepositHandoff','confirmDepositHandoff','_veldOpenDepositHandoff'];
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
let nativeEvidence=null,context,origin,dexOrigin,record=null,sendCount=0,prepareCount=0,resolved=[];
const exchangeRoot=path.resolve(root,'../Veld-Appchain-Exchange');
const network={chain:input.selected.child_genesis,bridge:input.selected.bridge_id,descriptor:input.selected.descriptor_id,parent_genesis:input.selected.parent_genesis};
const report={status:'RUNNING',checks:[],scope:'Actual browser ML-DSA/native RPC handoff with mined/replayed native transaction. Exchange account HTTP is a controlled fixture; child credit/order-book settlement is not simulated.'};
const errors=[];const check=(ok,label)=>{assert.ok(ok,label);report.checks.push(label);};
const server=http.createServer(async(req,res)=>{
 res.setHeader('Cross-Origin-Opener-Policy','same-origin');res.setHeader('Content-Security-Policy',"frame-ancestors 'none'; object-src 'none'");res.setHeader('X-Frame-Options','DENY');res.setHeader('Cache-Control','no-store');
 if(req.method==='POST'&&req.url==='/rpc'){
  try{let body='';for await(const chunk of req){body+=chunk;if(body.length>2097152)throw Error('RPC request limit');}
   const parsed=JSON.parse(body);if(parsed.method==='sendrawtransaction')sendCount++;if(parsed.method==='prepareappchaindeposit')prepareCount++;
   const result=await nativeCall(body);res.setHeader('Content-Type','application/json');res.end(result);
  }catch(e){res.writeHead(503,{'Content-Type':'application/json'});res.end(JSON.stringify({error:{message:e.message}}));}return;
 }
 res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Isolated native wallet</title><meta name="viewport" content="width=device-width"><style>.modal{background:white;padding:20px;max-width:580px}.modal-overlay{position:fixed;inset:0;background:#8888;align-items:center;justify-content:center}button{margin:10px;padding:12px}p{overflow-wrap:anywhere}</style><script>'+wasm+'</script><script>'+codec+'</script><script>'+app+'\n'+fixture+'\nuseNative=true;unavailable=true;veldCrypto.init().then(_veldOpenDepositHandoff);</script>');
});
const dex=http.createServer(async(req,res)=>{
 const json=v=>{res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(v));};
 try{
  if(req.url==='/api/account/native/options')return json({network,wallet_url:origin+'/',confirmations:120});
  if(req.url==='/api/account/native/deposits')return json({owner:input.selected.beneficiary_id,records:record?[record]:[]});
  if(req.method==='POST'){
   let text='';for await(const chunk of req){text+=chunk;if(text.length>4096)throw Error('Test request limit');}const body=JSON.parse(text);
   if(req.url==='/api/account/native/deposit/prepare'){
    assert.deepEqual(Object.keys(body).sort(),['fuel_atoms','id','trading_atoms']);assert.equal(body.trading_atoms,input.selected.trading_atoms);assert.equal(body.fuel_atoms,input.selected.fuel_backing_atoms);
    if(record)assert.equal(record.id,body.id);
    record={schema:1,...body,owner:input.selected.beneficiary_id,txid:null,index:null,status:'awaiting_wallet',observation:null,network,wallet_selection:input.selected};return json(record);
   }
   if(req.url==='/api/account/native/deposit/resolve'){
    assert.equal(body.id,record.id);assert.equal(body.index,1);resolved.push(body);
    return json({...record,txid:body.txid,index:1,status:'verification_unavailable'});
   }
   if(req.url==='/api/account/native/deposit/check')return json(record);
   throw Error('Unexpected test mutation route');
  }
  if(req.url==='/'||req.url.startsWith('/portfolio')){
   res.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store'});
   return res.end(`<!doctype html><meta name="viewport" content="width=device-width"><link rel="stylesheet" href="/exchange.css"><button id="deposit">Deposit VELD</button><script type="module">
    import {openNativeFunding} from '/native-funding.mjs';import {retainReturn} from '/native-handoff.mjs';
    const f=new URLSearchParams(location.hash.slice(1));if(f.has('native-deposit-result')){retainReturn(f.get('native-deposit-result'));history.replaceState(null,'','/portfolio');}
    const api=async(p,b)=>{const r=await fetch(p,{method:b?'POST':'GET',headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined});if(!r.ok)throw Error('Fixture API rejected');return r.json();};
    const open=()=>openNativeFunding({api,owner:${JSON.stringify(input.selected.beneficiary_id)},chain:${JSON.stringify(network.chain)},bridge:${JSON.stringify(network.bridge)},isCurrent:()=>true});
    document.getElementById('deposit').onclick=open;if(f.has('native-deposit-result'))open();window.fixtureReady=true;
   </script>`);
  }
  if(!['/exchange.css','/native-funding.mjs','/native-handoff.mjs','/controls.mjs','/model.mjs','/metadata.mjs'].includes(req.url)){res.writeHead(404);res.end();return;}
  res.setHeader('Content-Type',req.url.endsWith('.css')?'text/css':'text/javascript');res.end(fs.readFileSync(path.join(exchangeRoot,'app/static',req.url.slice(1))));
 }catch(e){errors.push(String(e));res.writeHead(500);res.end('{}');}
});
const digest=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
(async()=>{
 assert.ok(nativeSpec,'Actual disposable native RPC is required');startNative();
 await new Promise(r=>server.listen(0,'127.0.0.1',r));origin='http://127.0.0.1:'+server.address().port;
 await new Promise(r=>dex.listen(0,'127.0.0.1',r));dexOrigin='http://127.0.0.1:'+dex.address().port;
 async function launch(){context=await chromium.launchPersistentContext(path.join(out,'profile'),{headless:true,executablePath:process.env.VELD_TEST_BROWSER_EXECUTABLE});await context.route('**/*',r=>[origin,dexOrigin].some(o=>r.request().url().startsWith(o+'/'))?r.continue():r.abort());}
 await launch();let p=await context.newPage();p.on('pageerror',e=>errors.push(String(e)));await p.goto(dexOrigin);await p.waitForFunction(()=>window.fixtureReady);
 await p.evaluate(()=>sessionStorage.setItem('handoff-session-check','preserved'));await p.locator('#deposit').click();
 await p.getByLabel('VELD for trading',{exact:true}).fill('0.15');await p.getByLabel('FUEL for execution',{exact:true}).fill('50.00000');await p.getByRole('button',{name:'Review deposit',exact:true}).click();
 await p.getByRole('button',{name:'Continue in Veld wallet',exact:true}).waitFor();check(sendCount===0&&prepareCount===0,'exchange review creates no signature or native transaction');
 await p.getByRole('button',{name:'Continue in Veld wallet',exact:true}).click();await p.getByRole('button',{name:'Review deposit',exact:true}).waitFor();
 const walletURL=p.url();check(new URL(walletURL).origin===origin,'same tab reaches configured native wallet');check(await p.evaluate(()=>window.opener===null),'handoff does not need opener access');
 check((await p.request.get(origin)).headers()['cross-origin-opener-policy']==='same-origin','native COOP remains same-origin');
 const denied=await p.evaluate(()=>{
  const request=_veldDepositHandoffDecode(location.hash.slice('#veld-deposit='.length));let count=0;
  for(const return_origin of ['javascript:alert(1)','https://x.test/path','https://name@x.test','http://x.test','https://x.test/?token=x']){try{_veldDepositHandoff({...request,return_origin});throw Error('accepted');}catch(e){if(e.message==='accepted')throw e;count++;}}
  try{_veldDepositHandoff({...request,selection:{...request.selection,trading_atoms:1}});throw Error('accepted numeric amount');}catch(e){if(e.message==='accepted numeric amount')throw e;count++;}
  return count;
 });check(denied===6,'handoff refuses malformed origins and noncanonical amounts');
 await p.getByRole('button',{name:'Review deposit',exact:true}).click();await p.getByRole('button',{name:'Approve deposit',exact:true}).waitFor();
 check(prepareCount===1&&sendCount===0,'native preparation is saved before explicit approval');
 const changed=await p.evaluate(async()=>{const r=_veldDepositHandoffDecode(location.hash.slice('#veld-deposit='.length));try{await prepareDepositHandoff({...r,selection:{...r.selection,beneficiary_id:'ab'.repeat(48)}},input.address);return false;}catch(e){return e.message.includes('different request');}});
 check(changed&&prepareCount===1,'same request ID cannot be rebound to another exchange account');
 await p.goto(dexOrigin+'/portfolio');await p.waitForFunction(()=>window.fixtureReady);check(await p.evaluate(()=>sessionStorage.getItem('handoff-session-check'))==='preserved','same-tab cross-origin navigation retains exchange session storage');
 await p.goto(walletURL);await p.getByRole('button',{name:'Review deposit',exact:true}).click();await p.getByRole('button',{name:'Approve deposit',exact:true}).waitFor();
 await p.getByRole('button',{name:'Approve deposit',exact:true}).click();await p.getByText('Fixture delivery response unavailable',{exact:true}).waitFor({timeout:120000});
 check(sendCount===1,'one actual browser signature broadcast despite lost acknowledgement');
 const signed=await p.evaluate(()=>sends[0]);const txid=await p.evaluate(s=>veldCrypto.sha256d(s),signed);fs.writeFileSync(path.join(out,'signed.hex'),signed+'\n');
 await context.close();await launch();p=await context.newPage();p.on('pageerror',e=>errors.push(String(e)));await p.goto(walletURL);await p.getByRole('button',{name:'Review deposit',exact:true}).click();await p.getByRole('button',{name:'Recover deposit progress',exact:true}).waitFor();
 check(prepareCount===1,'browser restart restores original preparation without a replacement');
 await p.getByRole('button',{name:'Recover deposit progress',exact:true}).click();await p.getByRole('button',{name:'Return to exchange',exact:true}).waitFor({timeout:120000});check(sendCount===1,'known native transaction recovered without resigning or resending');
 await p.getByRole('button',{name:'Return to exchange',exact:true}).click();await p.getByText('Verification is unavailable. Your transaction is saved; do not send it again.',{exact:true}).waitFor();
 check(new URL(p.url()).origin===dexOrigin&&resolved.length===1&&resolved[0].txid===txid,'return automatically requests verified account-bound tracking');
 check(await p.evaluate(()=>window.opener===null),'return does not require cross-origin opener access');
 check((await p.locator('dialog').innerText()).includes('50.00000 FUEL'),'returned allocation retains exact FUEL display');
 check(!await p.getByText('Deposit credited.',{exact:false}).count(),'handoff never invents child credit');
 check(errors.length===0,'no browser or fixture exceptions');
 check(await stopNative()===0,'native RPC fixture stops after full replay');
 const summaries=fs.readFileSync(path.join(out,'native.log'),'utf8').split(/\r?\n/).filter(line=>line.startsWith('RESULT '));
 assert.equal(summaries.length,1,'exactly one native result');nativeEvidence=JSON.parse(summaries[0].slice(7));
 check(nativeEvidence.failed===0&&nativeEvidence.passed>=210,'actual native admission mining and replay checks passed');
 report.status='PASS_NATIVE_WALLET_HANDOFF_AND_RECOVERY';report.transaction=txid;report.native=nativeEvidence;report.browser=context.browser().version();report.signed_sha256=digest(path.join(out,'signed.hex'));
 report.source={};for(const f of ['include/network/ui_desktop.h','tests/appchain_handoff_browser_tests.cjs','src/veld-desktop.cpp'])report.source[f]=digest(path.join(root,f));
 for(const f of ['app/static/native-funding.mjs','app/static/native-handoff.mjs'])report.source['exchange/'+f]=digest(path.join(exchangeRoot,f));
})().catch(e=>{report.status='FAILED';report.error=e.stack;process.exitCode=1;})
.finally(async()=>{if(context)await context.close();await stopNative();await new Promise(r=>server.close(r));await new Promise(r=>dex.close(r));report.errors=errors;fs.writeFileSync(path.join(out,'result.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({status:report.status,checks:report.checks.length,native:report.native,error:report.error}));});
