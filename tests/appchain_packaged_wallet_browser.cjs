'use strict';
// Exercise the actual packaged wallet UI. RPC supplies read-only empty-state
// data; this qualifies wallet lifecycle, not chain balances or transactions.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const http = require('node:http'), crypto = require('node:crypto');
const assert = require('node:assert/strict'), {spawn} = require('node:child_process');
const {chromium} = require('playwright');
const [binary, expectedHash, output] = process.argv.slice(2);
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
assert.equal(sha(fs.readFileSync(binary)), expectedHash, 'pinned packaged wallet');
fs.mkdirSync(output, {recursive:false});
fs.copyFileSync(__filename, path.join(output, 'test-source.cjs'));
const report = {status:'RUNNING', started_at:new Date().toISOString(), checks:[],
  binary, binary_sha256:expectedHash, test_sha256:sha(fs.readFileSync(__filename)),
  scope:'Actual packaged wallet and browser key lifecycle; read-only loopback RPC fixture',
  real_funds:false, production_deployed:false, phases:[], rpc_methods:[], page_errors:[],
  blocked_external_origins:[], assets:{}, limitations:[
    'Does not qualify native installer, WebView shell, or automatic update restart.',
    'No financial operation or public chain RPC is performed in this test.']};
const save = () => fs.writeFileSync(path.join(output, 'result.json'), JSON.stringify(report,null,2)+'\n');
function check(value, label) {assert(value,label);report.checks.push(label);save();console.log('PASS '+label);}
const wait = ms => new Promise(r=>setTimeout(r,ms));
const privateRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'veld-packaged-wallet-'));
report.disposable_root=privateRoot;
let wallet=null, walletClosed=null, context=null, upstream=null, origin='', uiPort=0;
let browserVersion='', failedWrite=false;
const calls=new Set(), pageErrors=[], assets={};
async function listen(server, port=0) {await new Promise((ok,bad)=>{server.once('error',bad);server.listen(port,'127.0.0.1',ok);});return server.address().port;}
async function closeServer(server) {if(server)await new Promise(r=>server.close(r));}
async function stopWallet() {
  if(wallet && wallet.exitCode===null && wallet.signalCode===null) wallet.kill('SIGTERM');
  if(walletClosed)await Promise.race([walletClosed,wait(15000).then(()=>{throw Error('owned wallet did not stop');})]);
  wallet=null;walletClosed=null;
}
async function startWallet() {
  const token=crypto.randomBytes(32).toString('base64url');
  const args=['--wallet','--rpcurl',`http://127.0.0.1:${upstream.address().port}`,
    '--uiport',String(uiPort),'--datadir',path.join(privateRoot,'data')];
  const phase={command:[binary,...args],started_at:new Date().toISOString()};
  report.phases.push(phase);save();
  const fd=fs.openSync(path.join(output,`wallet-${report.phases.length}.log`),'wx');
  const env={...process.env,VELD_LOCAL_SIGNER_TOKEN:token};delete env.VELD_FLEET_ANCHOR_IPS;
  wallet=spawn(binary,args,{env,stdio:['ignore',fd,fd],windowsHide:true});fs.closeSync(fd);
  walletClosed=new Promise((resolve,reject)=>{wallet.once('error',reject);wallet.once('close',code=>{phase.exit_code=code;resolve();});});
  phase.pid=wallet.pid;
  for(let attempt=0;attempt<300;attempt++){
    if(wallet.exitCode!==null)throw Error('wallet exited before readiness');
    try {const res=await fetch(origin,{signal:AbortSignal.timeout(1000)});if(res.status===200)return token;}catch(_){}
    await wait(100);
  }
  throw Error('wallet readiness timed out');
}
async function browser(profile, token) {
  const existingProfile=fs.existsSync(path.join(privateRoot,profile,'Default'));
  context=await chromium.launchPersistentContext(path.join(privateRoot,profile),{
    channel:'msedge',headless:true,acceptDownloads:true,viewport:{width:1280,height:900},
    args:['--disable-background-networking','--disable-sync','--no-first-run']});
  context.setDefaultTimeout(45000);
  browserVersion=await context.browser()?.version() || 'Edge persistent context';
  await context.route('**/*', async route=>{
    const u=new URL(route.request().url());
    if(u.origin===origin || ['blob:','data:'].includes(u.protocol))return route.continue();
    if(!report.blocked_external_origins.includes(u.origin))report.blocked_external_origins.push(u.origin);
    await route.abort();
  });
  const page=context.pages()[0] || await context.newPage();
  let navigations=0;
  page.on('framenavigated',frame=>{if(frame===page.mainFrame())navigations++;});
  page.on('pageerror',e=>pageErrors.push(e.message));
  page.on('response',async res=>{
    const u=new URL(res.url());
    if(u.origin===origin && /\.(?:js|wasm)(?:$|\?)/.test(u.pathname)){
      try{assets[u.pathname]=sha(await res.body());}catch(_){}
    }
  });
  await page.goto(origin+'/?signer='+token,{waitUntil:'domcontentloaded'});
  // First install claims the page and the shipped UI reloads on controllerchange.
  // Wait for that existing startup lifecycle rather than clicking a replaced DOM.
  await page.waitForFunction(()=>!!navigator.serviceWorker.controller);
  if(!existingProfile){
    const deadline=Date.now()+45000;
    while(navigations<2){assert(Date.now()<deadline,'initial service-worker reload');await wait(50);}
  }
  await page.waitForLoadState('load');
  await page.waitForFunction(()=>typeof VELD_TRUSTED_LOCAL_SIGNER!=='undefined' && VELD_TRUSTED_LOCAL_SIGNER===true);
  check(new URL(page.url()).search==='', 'launch capability removed from browser address');
  return page;
}
async function openLogin(page) {await page.locator('#ks-btn').click();await page.locator('#ks-modal').waitFor({state:'visible'});}
async function unlocked(page,label) {
  await page.waitForFunction(()=>document.getElementById('ks-btn').getAttribute('aria-label')==='Wallet settings');
  check(await page.evaluate(()=>!document.getElementById('ks-modal').classList.contains('show')),label);
}
async function unlock(page,password) {
  await page.locator('#ks-unlock-pw').fill(password);
  await page.getByRole('button',{name:'Unlock',exact:true}).click();
  await unlocked(page,'passphrase unlock completes and closes dialog');
}
async function invariants(page,label) {
  check(await page.evaluate(()=>{
    const ks=JSON.parse(localStorage.getItem('veld_ks'));
    return ks.cipher==='AES-256-GCM' && ks.kdf.name==='scrypt' && ks.kdf.n>=65536 &&
      !!ks.salt && !!ks.iv && !!ks.data && !ks.key && !ks.private_key &&
      !localStorage.getItem('veld_key_persisted') && !window._pendingNewWallet &&
      ['s-key','sk-key','val-key'].every(id=>!document.getElementById(id)?.value);
  }),label);
}
(async()=>{
 try {
  fs.mkdirSync(path.join(privateRoot,'data'));
  upstream=http.createServer(async(req,res)=>{
    let body='';for await(const chunk of req){body+=chunk;if(body.length>100000){res.destroy();return;}}
    let data;try{data=JSON.parse(body);}catch(_){res.writeHead(400).end();return;}
    calls.add(data.method);
    let result, error;
    if(!/^(get|list)/.test(data.method)) {failedWrite=true;error={code:-32601,message:'Writes disabled in wallet lifecycle fixture'};}
    else if(['listunspent','getrawmempool','getvalidators','getwallets'].includes(data.method))result=[];
    else if(data.method==='getaddresshistory')result={transactions:[],total:0,has_more:false};
    else if(data.method==='getbalance')result={balance_veld:0,spendable_veld:0,staked_veld:0};
    else if(data.method==='getblockchaininfo')result={height:0,blocks:0,bestblockhash:'0'.repeat(64),initialblockdownload:false};
    else if(data.method==='getnetworkinfo')result={connections:0};
    else if(data.method==='getstakinginfo')result={stakes:[],total_staked:0};
    else if(data.method==='getpoolinfo')result={miners:[],participants:[],balance:0};
    else if(data.method==='getmempoolinfo')result={size:0,bytes:0};
    else if(data.method==='getlockuptiers')result={tiers:[]};
    else if(data.method==='getminerstatus')result={running:false,mining:false};
    else if(data.method==='getdustutxocount')result={count:0,total_veld:0};
    else {error={code:-32601,message:'Read method not modeled by wallet lifecycle fixture'};}
    const answer=JSON.stringify({jsonrpc:'2.0',id:data.id,...(error?{error}:{result})});
    res.writeHead(200,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(answer)}).end(answer);
  });
  await listen(upstream);
  const reserve=http.createServer();uiPort=await listen(reserve);await closeServer(reserve);origin=`http://127.0.0.1:${uiPort}`;
  const token=await startWallet();let page=await browser('profile-create',token);
  check(await page.evaluate(()=>!localStorage.getItem('veld_ks')), 'fresh profile starts without an imported key');
  await openLogin(page);
  await page.getByRole('button',{name:'Create New Wallet'}).click();
  await page.locator('#ks-gen-pw1').waitFor();
  check(!(await page.locator('#ks-gen-pk-display').innerText()).match(/[0-9a-f]{64}/i), 'generated private key remains masked');
  const password=crypto.randomBytes(30).toString('base64url');
  await page.locator('#ks-gen-pw1').fill(password);await page.locator('#ks-gen-pw2').fill(password+'mismatch');
  await page.locator('#ks-gen-save-btn').click();
  await page.waitForFunction(()=>document.getElementById('ks-gen-msg')?.textContent.includes('Passwords do not match'));
  check(await page.evaluate(()=>!localStorage.getItem('veld_ks')), 'mismatched passphrases cannot create a saved wallet');
  await page.locator('#ks-gen-pw2').fill(password);
  const downloadPromise=page.waitForEvent('download');await page.locator('#ks-gen-save-btn').click();
  const download=await downloadPromise;const backup=path.join(output,'disposable-wallet.veld-keys');await download.saveAs(backup);
  await unlocked(page,'new wallet creation completes through packaged UI');
  const address=await page.evaluate(()=>localStorage.getItem('veld_current_addr'));
  report.disposable_address=address;
  const exported=JSON.parse(fs.readFileSync(backup,'utf8'));
  check(/^V[1-9A-HJ-NP-Za-km-z]+$/.test(address) && exported.address===address && exported.version===1,
    'downloaded encrypted backup identifies the generated wallet');
  report.encrypted_backup_sha256=sha(fs.readFileSync(backup));
  check(!fs.readFileSync(backup,'utf8').includes(password), 'backup contains no passphrase');
  await invariants(page,'created wallet stores scrypt/AES-GCM ciphertext without plaintext key fields');
  await openLogin(page);await page.getByRole('button',{name:'Lock wallet',exact:true}).click();
  await page.waitForFunction(()=>document.getElementById('ks-btn').getAttribute('aria-label')==='Log in to wallet');
  check(await page.evaluate(()=>!__veldKey.get()),'Lock wallet clears active signing key');
  if(!(await page.locator('#ks-unlock-pw').isVisible()))await openLogin(page);
  await page.locator('#ks-unlock-pw').fill(password+'wrong');await page.getByRole('button',{name:'Unlock',exact:true}).click();
  await page.waitForFunction(()=>document.getElementById('ks-msg')?.textContent.includes('Wrong password'));
  check(await page.evaluate(()=>!__veldKey.get()),'wrong passphrase does not unlock signer');
  await page.waitForFunction(()=>!document.querySelector('#ks-modal [data-act-click="hdbb8d59d"]').disabled);
  await unlock(page,password);await invariants(page,'unlocked wallet keeps plaintext key out of DOM and localStorage');
  await page.reload({waitUntil:'domcontentloaded'});
  await page.waitForFunction(()=>document.getElementById('ks-btn').getAttribute('aria-label')==='Log in to wallet');
  check(await page.evaluate(()=>!__veldKey.get() && !!localStorage.getItem('veld_ks')), 'reload retains encrypted backup and requires unlock');
  await openLogin(page);await unlock(page,password);
  await context.close();context=null;await stopWallet();
  const nextToken=await startWallet();page=await browser('profile-create',nextToken);
  await page.waitForFunction(()=>document.getElementById('ks-btn').getAttribute('aria-label')==='Log in to wallet');
  check(await page.evaluate(a=>localStorage.getItem('veld_current_addr')===a && !__veldKey.get(),address),
    'browser and packaged-service restart preserve wallet identity without restoring unlocked key');
  await openLogin(page);await unlock(page,password);
  await context.close();context=null;
  // New launch capability and isolated profile establish a real restore path.
  await stopWallet();const restoreToken=await startWallet();page=await browser('profile-restore',restoreToken);
  check(await page.evaluate(()=>!localStorage.getItem('veld_ks')), 'restore profile has no previous wallet state');
  await openLogin(page);await page.locator('#ks-file-input').setInputFiles(backup);
  await page.locator('#ks-unlock-pw').waitFor();await unlock(page,password);
  check(await page.evaluate(a=>currentAddr===a && localStorage.getItem('veld_current_addr')===a,address),
    'downloaded keyfile restores the exact locally derived wallet address');
  await invariants(page,'restored wallet retains encrypted persistence and clears temporary secret fields');
  await openLogin(page);await page.locator('#ks-change-passphrase').click();
  const replacement=crypto.randomBytes(30).toString('base64url');
  await page.locator('#ks-change-pw1').fill(replacement);await page.locator('#ks-change-pw2').fill(replacement);
  await page.locator('#ks-change-save').click();
  await page.waitForFunction(()=>document.getElementById('ks-change-msg')?.textContent.includes('Passphrase changed'));
  check(await page.evaluate(()=>document.getElementById('ks-change-pw1').value==='' && document.getElementById('ks-change-pw2').value===''),
    'passphrase rotation clears both password inputs');
  await page.reload({waitUntil:'domcontentloaded'});await openLogin(page);await unlock(page,replacement);
  check(await page.evaluate(a=>currentAddr===a,address),'rotated passphrase unlocks the same wallet after reload');
  await invariants(page,'rotation preserves encrypted-only storage');
  check(!failedWrite,'wallet lifecycle made no write RPC requests');
  check(pageErrors.length===0,'packaged wallet lifecycle has no uncaught browser errors');
  report.status='PASS_PACKAGED_WALLET_BROWSER_LIFECYCLE';
 } catch(error) {report.status='FAILED';report.error=String(error.stack||error);process.exitCode=1;}
 finally {
  if(context)await context.close();await stopWallet();await closeServer(upstream);
  report.finished_at=new Date().toISOString();report.browser=browserVersion;report.rpc_methods=[...calls].sort();
  report.page_errors=pageErrors;report.assets=assets;report.owned_services_stopped=true;save();
  console.log(JSON.stringify({status:report.status,checks:report.checks.length,error:report.error}));
 }
})();
