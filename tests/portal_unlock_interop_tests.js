'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {execFileSync} = require('node:child_process');
const {webcrypto} = require('node:crypto');
const {extractFunction} = require('./javascript_function_source');
const source = fs.readFileSync(path.join(__dirname, '../src/veld-miner-portal.py'), 'utf8');
const script = source.split('PORTAL_HTML = r"""')[1].split('"""')[0].match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(script);
const binary = path.resolve(process.argv[2]);
const root = path.resolve(process.argv[3]);
assert(!fs.existsSync(root), 'Use a new isolated fixture directory');
const publicKey = JSON.parse(execFileSync(binary, ['init', root], {encoding:'utf8'}));
const b64url = bytes => Buffer.from(bytes).toString('base64url');
const nonce = b64url(webcrypto.getRandomValues(new Uint8Array(16)));
const context = vm.createContext({crypto:webcrypto, TextEncoder, Uint8Array, b64url,
  hex:bytes=>Buffer.from(bytes).toString('hex')});
vm.runInContext(['encryptNodePassphrase','canonicalPayload','commandEnvelope','normalizeEcdsaSignature'].map(name=>extractFunction(script,name)).join('\n'), context);
(async()=>{
  const payload = await context.encryptNodePassphrase('Portal test 日本語 é passphrase', publicKey, 17, nonce);
  const canonical = context.canonicalPayload('node.signin', payload);
  assert(!canonical.includes('passphrase'));
  assert.equal(payload.iv.length, 16);
  assert.equal(payload.wrapped_key.length, 342);
  fs.writeFileSync(path.join(root,'ciphertext.txt'), ['ciphertext','identity','iv','key_id','wrapped_key'].map(k=>payload[k]).concat(nonce).join('\n')+'\n');
  const pair = await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const jwk = await webcrypto.subtle.exportKey('jwk',pair.publicKey);
  const commandKey = {x:jwk.x,y:jwk.y,id:Buffer.from(await webcrypto.subtle.digest('SHA-256',new TextEncoder().encode(`VELD_PORTAL_KEY_V1\n${jwk.x}\n${jwk.y}`))).toString('hex')};
  const issued = Math.floor(Date.now()/1000);
  const command = {id:17,sequence:1,issued_at:issued,expires_at:issued+180,nonce,action:'node.signin',payload,key_id:commandKey.id};
  const signature = await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,new TextEncoder().encode(context.commandEnvelope(command)));
  command.signature = b64url(context.normalizeEcdsaSignature(signature));
  fs.writeFileSync(path.join(root,'signed-command.json'),JSON.stringify({portal_protocol:4,device_id:17,paired:true,pair_code:null,pair_expires:0,report_interval:5,command_key:commandKey,command:{...command,id:1}}));
  for (const action of ['node.start','node.stop','node.signin','updates.check','updates.install']) {
    const control = {...command,action,payload:action==='node.signin'?payload:{}};
    const signature = await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,new TextEncoder().encode(context.commandEnvelope(control)));
    control.signature = b64url(context.normalizeEcdsaSignature(signature));
    fs.writeFileSync(path.join(root,action+'.json'),JSON.stringify({portal_protocol:4,device_id:17,paired:true,pair_code:null,pair_expires:0,report_interval:5,command_key:commandKey,command:{...control,id:1}}));
  }
  const otherPair = await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const otherJwk = await webcrypto.subtle.exportKey('jwk',otherPair.publicKey);
  const otherKey = {x:otherJwk.x,y:otherJwk.y,id:Buffer.from(await webcrypto.subtle.digest('SHA-256',new TextEncoder().encode(`VELD_PORTAL_KEY_V1\n${otherJwk.x}\n${otherJwk.y}`))).toString('hex')};
  fs.writeFileSync(path.join(root,'other-pairing.json'),JSON.stringify({portal_protocol:4,device_id:17,paired:true,pair_code:null,pair_expires:0,report_interval:5,command_key:otherKey,command:null}));
  const output = execFileSync(binary, ['verify', root], {encoding:'utf8'});
  assert(output.includes('PASS:'));
  for (const value of ['', 'x'.repeat(1025), 'hello\0world']) {
    await assert.rejects(context.encryptNodePassphrase(value, publicKey, 17, nonce), /valid node passphrase/);
  }
  console.log(output.trim());
  console.log('PASS: shipping browser encryptor and native decryptor agree; invalid input rejected');
  if (process.argv[4]) console.log(execFileSync(path.resolve(process.argv[4]),[root],{encoding:'utf8',timeout:30000}).trim());
})().catch(error=>{console.error(error);process.exitCode=1;});
