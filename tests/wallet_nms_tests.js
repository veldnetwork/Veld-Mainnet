'use strict';
const fs=require('fs'), path=require('path'), assert=require('node:assert/strict'), crypto=require('crypto');
const {extractFunction}=require('./javascript_function_source');
const {chromium}=require(process.env.VELD_PLAYWRIGHT_MODULE || 'playwright');
const source=fs.readFileSync(path.join(__dirname,'../include/network/ui_desktop.h'),'utf8');
const owner='fixture-owner', hash='31'.repeat(20), self='76a914'+hash+'88ac';
function u32(n){const b=Buffer.alloc(4);b.writeUInt32LE(n);return b;}
function u64(n){const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(n));return b;}
function tx(index, signed=false, kind='nms', recipient=self, amount=800000, input='11'.repeat(32)){
  const payload='56454c445f4e4d5301'+'01000000'+index.toString(16).padStart(2,'0').repeat(32)+'22'.repeat(32)+'00'.repeat(20);
  const outputs=kind==='nms'?[[100000,self],[0,'6a4c61'+payload],[amount,self]]:[[amount+100000,recipient]];
  const parts=[u32(1),Buffer.from([1]),Buffer.from(input,'hex'),u32(0),Buffer.from(signed?'0101':'00','hex'),u32(0xffffffff),Buffer.from([outputs.length])];
  for(const [value,script] of outputs)parts.push(u64(value),Buffer.from([script.length/2]),Buffer.from(script,'hex'));
  parts.push(u32(0));return Buffer.concat(parts).toString('hex');
}
const hashes={};const digest=hex=>crypto.createHash('sha256').update(crypto.createHash('sha256').update(Buffer.from(hex,'hex')).digest()).digest('hex');
const fixtures={};for(let i=1;i<=34;i++)for(const signed of [false,true]){
  const hex=tx(i,signed);hashes[hex]=digest(hex);fixtures[i+(signed?'s':'u')]=hex;
}
for(const [name,hex] of Object.entries({recover:tx(1,false,'self'),recoverSigned:tx(1,true,'self'),redirect:tx(1,false,'self','76a914'+'32'.repeat(20)+'88ac'),fee:tx(1,false,'self',self,799999),otherInput:tx(2,false,'nms',self,800000,'12'.repeat(32))})){
 fixtures[name]=hex;hashes[hex]=digest(hex);
}
const names=['_veldHexToBytes','_veldBytesToHex','_veldParseVarint','_veldParseUnsignedTx','_veldKeyCommitmentToScriptHex','_veldNmsTransaction','_veldNmsReplacement','_veldReviewNmsProof','_veldJournal','submitAddressOnlyNms','importAddressOnlyNms'];
const code=names.map(n=>extractFunction(source,n)).join('\n');
let browser;const checks=[];
async function run(){
 browser=await chromium.launch({headless:true,executablePath:process.env.VELD_BROWSER_EXE});
 const context=await browser.newContext();const page=await context.newPage();
 await page.route('**/*',r=>r.fulfill({contentType:'text/html',body:'<!doctype html><title>Isolated wallet NMS recovery fixture</title><button id="cm-nms-sign"></button><textarea id="cm-nms-proof"></textarea><input id="cm-nms-file" type="file"><p id="cm-nms-status"></p>'}));
 await page.goto('http://127.0.0.1:18188/');
 const setup=async()=>{
  await page.evaluate(({fixtures,hashes,owner,hash})=>{
   window.fixture=fixtures;window.owner=owner;window.VELD_GENESIS_HASH='ab'.repeat(32);window.VELD_DEPLOYMENT_PROFILE_ID='nms-isolated-fixture';
   window._veldAddrToKeyCommitmentHex=a=>a===owner?hash:null;
   window.veldCrypto={sha256d:hex=>{if(!hashes[hex])throw new Error('Unknown fixture bytes');return hashes[hex];}};
   window._veldAssertPreparedRelaySize=()=>6000;
   window._veldJournalOperation=(hex,a)=>({label:window._veldNmsTransaction(hex,a)?'Near-miss entry':'Send'});
   window.refreshWalletAfterBroadcast=()=>{};window.__veldTxChannel=null;
   window.meta=[{index:0,sighash_hex:'aa'.repeat(32),prev_script_hex:'76a914'+hash+'88ac'}];
  },{fixtures,hashes,owner,hash});
  await page.addScriptTag({content:code});
 };
 await setup();
 async function check(label,fn){const result=await page.evaluate(fn);assert.equal(result,true,label);checks.push(label);}
 // Construct the deployed v1 store/index shape, without relying on Git history.
 const legacyJournal=extractFunction(source,'_veldJournal').replace('indexedDB.open(name, 2)','indexedDB.open(name, 1)')
   .replace(/^.*createIndex\('nms_alternates'.*$/gm,'');
 await page.addScriptTag({content:legacyJournal});
 await check('legacy schema stores an existing signed reservation',async()=>{
  await _veldJournal().sign(fixture['1u'],meta,owner,async()=>fixture['1s']);
  return (await _veldJournal().guards(owner)).size===1;
 });
 await page.reload();await setup();
 await check('schema upgrade preserves previous signed bytes and claim',async()=>{
  const item=await _veldJournal().get(veldCrypto.sha256d(fixture['1s']));
  return item.payload.signed===fixture['1s']&&(await _veldJournal().guards(owner)).size===1;
 });
 await check('proof envelope binds address, genesis, parent, height and fee',()=>{
  const p=_veldNmsTransaction(fixture['1u'],owner), packet={schema:1,genesis:VELD_GENESIS_HASH,address:owner,fee_units:'100000',height:102,window_draw:200,parent:p.parent,payload:p.payload,eligible:true,needed:true};
  const tip={blocks:102,best_block_hash:p.parent};_veldReviewNmsProof(JSON.stringify(packet),owner,tip);
  for(const patch of [{genesis:'cd'.repeat(32)},{address:'other'},{fee_units:'100001'},{height:103},{window_draw:300},{payload:p.payload+'00'},{eligible:1},{needed:'true'}]){
   let rejected=false;try{_veldReviewNmsProof(JSON.stringify({...packet,...patch}),owner,tip);}catch(_){rejected=true;}if(!rejected)return false;
  }return true;
 });
 await check('explicit wallet confirmation and exact signing guards',async()=>{
  const p=_veldNmsTransaction(fixture['1u'],owner), packet={schema:1,genesis:VELD_GENESIS_HASH,address:owner,fee_units:'100000',height:102,window_draw:200,parent:p.parent,payload:p.payload,eligible:true,needed:true};
  document.getElementById('cm-nms-proof').value=JSON.stringify(packet);
  let args=null, unlocked=0, confirmations=0;
  window.currentAddr=owner;window.__veldKey={get:()=> 'inert-signing-stub'};
  window.__opLock=()=>true;window.__opUnlock=()=>{unlocked++;};
  window._veldAssertActiveSignerSeed=()=>7;window._veldRequireBoundIdentity=()=>({address:owner});
  window.rpc=async()=>({blocks:102,best_block_hash:p.parent});window.loadCominingPage=()=>{};
  window.signAndBroadcast=async(...a)=>{args=a;return {txid:'cc'.repeat(32)};};
  window.confirm=()=>{confirmations++;return false;};await submitAddressOnlyNms();
  if(args!==null||unlocked!==1||confirmations!==1)return false;
  window.confirm=()=>true;await submitAddressOnlyNms();
  if(!args||args[0]!=='preparenmstx'||args[1][0]!==owner||args[1][1]!==p.payload||args[7]!=='6a4c61'+p.payload||args[9]!==7)return false;
  args=null;window.rpc=async()=>({blocks:103,best_block_hash:'cc'.repeat(32)});await submitAddressOnlyNms();
  return args===null&&document.getElementById('cm-nms-status').textContent.includes('expired');
 });
 await check('public proof file import uses real browser File API without signing',async()=>{
  const p=_veldNmsTransaction(fixture['1u'],owner), packet={schema:1,genesis:VELD_GENESIS_HASH,address:owner,fee_units:'100000',height:102,window_draw:200,parent:p.parent,payload:p.payload,eligible:true,needed:true};
  window.currentAddr=owner;let signs=0;window.signAndBroadcast=async()=>{signs++;};
  window.rpc=async()=>({blocks:102,best_block_hash:p.parent});
  const input=document.getElementById('cm-nms-file'),target=document.getElementById('cm-nms-proof');
  const select=async text=>{const data=new DataTransfer();data.items.add(new File([text],'address-only-nms.json',{type:'application/json'}));input.files=data.files;await importAddressOnlyNms(input);};
  const text=JSON.stringify(packet);await select(text);
  if(target.value!==text||input.value!==''||signs)return false;
  for(const bad of ['x'.repeat(1201),'null','not-json',JSON.stringify({...packet,address:'other'}),JSON.stringify({...packet,height:101})]){
   await select(bad);if(target.value!==''||signs)return false;
  }
  window.rpc=async()=>{window.currentAddr='changed';return {blocks:102,best_block_hash:p.parent};};
  await select(text);window.currentAddr=owner;
  return target.value===''&&document.getElementById('cm-nms-status').textContent.includes('Wallet changed')&&signs===0;
 });
 if(process.env.VELD_NATIVE_NMS_PROOF){
  const packet=JSON.parse(fs.readFileSync(process.env.VELD_NATIVE_NMS_PROOF,'utf8'));
  const result=await page.evaluate(async packet=>{
   const oldGenesis=VELD_GENESIS_HASH, oldOwner=currentAddr;
   try{
    window.VELD_GENESIS_HASH=packet.genesis;window.currentAddr=packet.address;
    window.rpc=async()=>({blocks:packet.height,best_block_hash:packet.parent});
    const input=document.getElementById('cm-nms-file'),data=new DataTransfer();
    data.items.add(new File([JSON.stringify(packet)],'address-only-nms.json'));input.files=data.files;
    await importAddressOnlyNms(input);
    return JSON.parse(document.getElementById('cm-nms-proof').value).payload===packet.payload;
   }finally{window.VELD_GENESIS_HASH=oldGenesis;window.currentAddr=oldOwner;}
  },packet);
  assert.equal(result,true,'real Linux mined and exported proof imports in browser');
  checks.push('real Linux mined and exported proof imports in browser; chain tip supplied by fixture');
 }
 await check('replacement preserves input, owner and exact economic output',()=>
  _veldNmsReplacement(fixture['1s'],fixture['2u'],owner)&&_veldNmsReplacement(fixture['1s'],fixture.recover,owner)&&
  !['redirect','fee','otherInput'].some(k=>_veldNmsReplacement(fixture['1s'],fixture[k],owner)));
 await check('predecessor confirmation during signing preserves recovery and cancels the successor',async()=>{
  const previous=_veldJournal.instance, profile=VELD_DEPLOYMENT_PROFILE_ID;
  window.VELD_DEPLOYMENT_PROFILE_ID='nms-signing-confirmation-fixture';_veldJournal.instance=null;
  try {
   const journal=_veldJournal();await journal.sign(fixture['1u'],meta,owner,async()=>fixture['1s']);
   let ready,finish;const started=new Promise(resolve=>{ready=resolve;});
   const signing=journal.sign(fixture['2u'],meta,owner,()=>new Promise(resolve=>{finish=resolve;ready();})).then(()=>false,()=>true);
   await started;await journal.confirmed([veldCrypto.sha256d(fixture['1s'])]);
   const saved=await journal.get(veldCrypto.sha256d(fixture['1s']));
   if(saved.record.state!=='reserved'||saved.record.nms_confirmed!==veldCrypto.sha256d(fixture['1s'])||(await journal.pending(owner)).length!==0)return false;
   finish(fixture['2s']);if(!await signing)return false;
   await journal.restored(['11'.repeat(32)+':0']);
   if((await journal.pending(owner)).length!==1)return false;
   await journal.sign(fixture['2u'],meta,owner,async()=>fixture['2s']);
   return (await journal.get(veldCrypto.sha256d(fixture['2s']))).record.state==='ready';
  } finally {_veldJournal.instance=previous;window.VELD_DEPLOYMENT_PROFILE_ID=profile;}
 });
 await check('first signed bytes durable and input guarded',async()=>{
  await _veldJournal().sign(fixture['1u'],meta,owner,async()=>fixture['1s']);
  const saved=await _veldJournal().get(veldCrypto.sha256d(fixture['1s']));
  return saved.payload.signed===fixture['1s']&&(await _veldJournal().guards(owner)).size===1;
 });
 await check('changed fee cannot replace a signed claim',async()=>{
  let rejected=false;try{await _veldJournal().sign(fixture.fee,meta,owner,async()=>{throw new Error('must not sign');});}catch(_){rejected=true;}
  return rejected&&(await _veldJournal().get(veldCrypto.sha256d(fixture['1s']))).payload.signed===fixture['1s'];
 });
 await check('refresh archives original signed bytes and owns exactly one claim',async()=>{
  await _veldJournal().sign(fixture['2u'],meta,owner,async()=>fixture['2s']);
  const saved=await _veldJournal().get(veldCrypto.sha256d(fixture['1s']));
  return saved.payload.signed===fixture['2s']&&saved.payload.nms_history[0].signed===fixture['1s']&&(await _veldJournal().guards(owner)).size===1;
 });
 await page.reload();await setup();
 await check('reload retains current and prior immutable signed bytes',async()=>{
  const saved=await _veldJournal().get(veldCrypto.sha256d(fixture['1s']));return saved.payload.signed===fixture['2s']&&saved.payload.nms_history.length===1;
 });
 await check('atomic write failure retains previous claim and bytes',async()=>{
  const original=IDBObjectStore.prototype.add;
  IDBObjectStore.prototype.add=function(...args){if(this.name==='records')throw new DOMException('Fixture storage full','QuotaExceededError');return original.apply(this,args);};
  let rejected=false;try{await _veldJournal().sign(fixture['3u'],meta,owner,async()=>fixture['3s']);}catch(_){rejected=true;}finally{IDBObjectStore.prototype.add=original;}
  const saved=await _veldJournal().get(veldCrypto.sha256d(fixture['2s']));return rejected&&saved.payload.signed===fixture['2s']&&(await _veldJournal().guards(owner)).size===1;
 });
 await check('bounded proof refresh leaves one final recovery slot',async()=>{
  for(let i=3;i<=32;i++)await _veldJournal().sign(fixture[i+'u'],meta,owner,async()=>fixture[i+'s']);
  let refused=false;try{await _veldJournal().sign(fixture['33u'],meta,owner,async()=>fixture['33s']);}catch(_){refused=true;}
  await _veldJournal().sign(fixture.recover,meta,owner,async()=>fixture.recoverSigned);
  const saved=await _veldJournal().get(veldCrypto.sha256d(fixture.recoverSigned));return refused&&saved.payload.nms_history.length===32;
 });
 await check('earlier variant confirmation resolves the one logical reservation',async()=>{
  await _veldJournal().confirmed([veldCrypto.sha256d(fixture['1s'])]);
  return (await _veldJournal().pending(owner)).length===0&&(await _veldJournal().guards(owner)).size===1;
 });
 await check('reorg restoration retains all variants and reopens recovery',async()=>{
  await _veldJournal().restored(['11'.repeat(32)+':0']);
  const saved=await _veldJournal().get(veldCrypto.sha256d(fixture.recoverSigned));return saved.record.state==='ready'&&saved.payload.nms_history.length===32;
 });
 console.log(JSON.stringify({status:'PASS',checks,coverage:'Real Chromium IndexedDB and Web Locks; synthetic transaction signatures. Native RPC fixture separately covers cryptography and VeldHash.'},null,2));
 await context.close();
}
run().catch(e=>{console.error(e.stack);process.exitCode=1;}).finally(async()=>{if(browser)await browser.close();});
