'use strict';
// Receipt selection controls; real node and browser recovery is covered by
// appchain_deposit_browser_tests.cjs using the native RPC fixture.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {extractFunction} = require('./javascript_function_source');
const source = fs.readFileSync(path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
const txid = 'ab'.repeat(32), signed = '01020304';
let calls, generation, replies, checks = 0;
const context = vm.createContext({
  veldCrypto: {sha256d: bytes => { assert.equal(bytes, signed); return txid; }},
  _veldAssertActiveSignerSeed: (_seed, expected) => {
    if (generation !== expected) throw Error('Signing session changed');
  },
  _veldRpcTransport: async (method, params) => {
    assert.deepEqual(Array.from(params), [txid]); calls.push(method);
    const reply = replies[method];
    if (typeof reply === 'function') return reply();
    if (reply instanceof Error) throw reply;
    return reply;
  }
});
vm.runInContext(extractFunction(source, '_veldSavedTransactionReceipt'), context);
function reset(value) { calls=[]; generation=7; replies=value; }
async function read() { return context._veldSavedTransactionReceipt(signed, 'fixture', 7); }
(async () => {
  reset({getmempoolentry:{txid,raw_hex:signed}});
  assert.equal((await read()).raw_hex,signed); assert.deepEqual(calls,['getmempoolentry']); checks++;
  reset({getmempoolentry:{txid,raw_hex:signed,block_height:103}});
  assert.equal((await read()).block_height,null); checks++;
  reset({getmempoolentry:{error:'not in mempool',txid},getrawtransaction:{txid,raw_hex:signed,block_height:103,block_hash:'cd'.repeat(32)}});
  assert.equal((await read()).block_height,103); assert.equal(calls.length,2); checks++;
  reset({getmempoolentry:new Error('offline'),getrawtransaction:new Error('offline')});
  assert.equal(await read(),null); checks++;
  reset({getmempoolentry:null,getrawtransaction:{error:'not found'}});
  assert.equal(await read(),null); checks++;
  for (const method of ['getmempoolentry','getrawtransaction']) {
    for (const bad of [{txid,raw_hex:'01020305'}, {txid:'aa'.repeat(32),raw_hex:signed}, {txid}, 'untrusted']) {
      reset({getmempoolentry:null,[method]:bad});
      await assert.rejects(read,/receipt differs/); checks++;
    }
  }
  for (const height of [-1,0.5,'103',NaN,undefined]) {
    reset({getmempoolentry:null,getrawtransaction:{txid,raw_hex:signed,block_height:height,block_hash:'cd'.repeat(32)}});
    await assert.rejects(read,/receipt differs/); checks++;
  }
  reset({getmempoolentry:null,getrawtransaction:{txid,raw_hex:signed,block_height:103,block_hash:'wrong'}});
  await assert.rejects(read,/receipt differs/); checks++;
  for (const value of [{txid,raw_hex:signed}, new Error('offline')]) {
    reset({getmempoolentry:()=>{generation++;if(value instanceof Error)throw value;return value;}});
    await assert.rejects(read,/session changed/); checks++;
  }
  console.log(JSON.stringify({status:'PASS_RECEIPT_SELECTION_CONTROLS',checks,real_signatures:false,actual_rpc:false}));
})().catch(error=>{console.error(error);process.exitCode=1;});
