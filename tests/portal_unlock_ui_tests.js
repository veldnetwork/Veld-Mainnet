'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const {extractFunction} = require('./javascript_function_source');
const source = fs.readFileSync(path.join(__dirname, '../src/veld-miner-portal.py'), 'utf8');
const script = source.split('PORTAL_HTML = r"""')[1].split('"""')[0].match(/<script>([\s\S]*?)<\/script>/)[1];
const b64url = bytes => Buffer.from(bytes).toString('base64url');
const hex = bytes => Buffer.from(bytes).toString('hex');

async function main() {
  const rsa = await webcrypto.subtle.generateKey({name:'RSA-OAEP', modulusLength:2048,
    publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256'}, false, ['encrypt','decrypt']);
  const jwk = await webcrypto.subtle.exportKey('jwk', rsa.publicKey);
  const id = hex(new Uint8Array(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(`VELD_PORTAL_UNLOCK_KEY_V1\n${jwk.n}\n${jwk.e}`))));
  const unlock = {alg:'RSA-OAEP-256', n:jwk.n, e:jwk.e, id, identity:'a'.repeat(64)};
  const pair = await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  const elements = new Map(), pins = new Map(), requests = [];
  const $ = name => {
    if (!elements.has(name)) elements.set(name, {value:'',textContent:'',disabled:false,open:false,
      showModal(){this.open=true},close(){this.open=false},focus(){}});
    return elements.get(name);
  };
  const db = {transaction(){
    const transaction = {aborted:false,abort(){this.aborted=true;queueMicrotask(()=>this.onabort?.())},
      objectStore(){return {
        get(name){const request={};queueMicrotask(()=>{request.result=pins.get(name);request.onsuccess?.();
          queueMicrotask(()=>{if(!transaction.aborted)transaction.oncomplete?.()})});return request},
        put(value,name){pins.set(name,value)}
      }}};
    return transaction;
  }};
  let device = {id:17,name:'Test node',online:true,command_sequence:0,snapshot:{unlock_key:unlock,remote_control:true}};
  const context = vm.createContext({crypto:webcrypto,TextEncoder,Uint8Array,b64url,hex,$,
    snap:d=>d.snapshot,current:()=>device,openCommandDb:async()=>db,commandStore:'keys',
    commandKey:async()=>({pair,id:'b'.repeat(64)}),ensureDeviceCommandKey:async()=>{},
    api:async(url,method,body)=>{requests.push(JSON.parse(JSON.stringify({url,method,body})))},
    toast(){},refresh:async()=>{}});
  vm.runInContext('let nodeSignInTarget=null,nodeSignInBusy=false,actionQueue=Promise.resolve();',context);
  vm.runInContext(['encryptNodePassphrase','pinUnlockKey','openNodeSignIn','closeNodeSignIn',
    'submitNodeSignIn','signedAction','canonicalPayload','commandEnvelope','normalizeEcdsaSignature']
    .map(name=>extractFunction(script,name)).join('\n'),context);
  await context.openNodeSignIn();
  assert.equal(pins.get('node-unlock-17'),unlock.id);
  assert.equal($('node-signin-dialog').open,true);
  $('node-signin-password').value='Synthetic browser-only passphrase';
  const first = context.submitNodeSignIn({preventDefault(){}});
  const second = context.submitNodeSignIn({preventDefault(){}});
  await Promise.all([first,second]);
  assert.equal(requests.length,1);
  assert.equal(requests[0].body.action,'node.signin');
  assert.deepEqual(Object.keys(requests[0].body.payload).sort(),['ciphertext','identity','iv','key_id','wrapped_key']);
  assert(!JSON.stringify(requests).includes('Synthetic browser-only passphrase'));
  assert.equal($('node-signin-password').value,'');
  assert.equal($('node-signin-dialog').open,false);
  assert.equal($('node-signin-submit').disabled,false);
  const payload=requests[0].body.payload,command=requests[0].body;
  const raw = await webcrypto.subtle.decrypt({name:'RSA-OAEP'},rsa.privateKey,Buffer.from(payload.wrapped_key,'base64url'));
  const aes = await webcrypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);
  const plain = await webcrypto.subtle.decrypt({name:'AES-GCM',iv:Buffer.from(payload.iv,'base64url'),
    additionalData:new TextEncoder().encode(`VELD_PORTAL_UNLOCK_V1\n17\n${command.nonce}\n${id}\n${unlock.identity}`)},
    aes,Buffer.from(payload.ciphertext,'base64url'));
  assert.equal(Buffer.from(plain).toString(),'Synthetic browser-only passphrase');
  await context.openNodeSignIn();
  $('node-signin-password').value='Discard on cancel';
  context.closeNodeSignIn();
  assert.equal($('node-signin-password').value,'');
  pins.set('node-unlock-17','c'.repeat(64));
  await assert.rejects(context.openNodeSignIn(),/encryption key changed/);
  pins.set('node-unlock-17',id);
  await context.openNodeSignIn();
  $('node-signin-password').value='Must not be sent to a different device';
  vm.runInContext('actionQueue=new Promise(resolve=>globalThis.releaseQueue=resolve);',context);
  const pending=context.submitNodeSignIn({preventDefault(){}});
  device={...device,id:18};
  context.releaseQueue();
  await pending;
  assert.equal(requests.length,1);
  assert.match($('node-signin-error').textContent,/same paired machine/);
  assert.equal($('node-signin-submit').disabled,false);
  assert.equal($('node-signin-password').value,'');
  device.online=false;
  await assert.rejects(context.openNodeSignIn(),/online/);
  console.log('PASS: remote sign-in UI encryption, key pinning, cancellation, duplicate submission, queued device binding, offline handling');
}
main().catch(error=>{console.error(error);process.exitCode=1});
