'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const context = vm.createContext({window:{}, document:{readyState:'loading', addEventListener(){}}, Map});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../website/explorer-transactions-v1.js'), 'utf8'), context);
const {feeText, isConsolidation} = context.window.VeldTransactionDisplay;
const {feeUnits, minerFeeTotal, indexedFee} = context.window.VeldTransactionDisplay;
const activationSource = fs.readFileSync(path.join(__dirname, '../include/consensus/native_334_activation.h'), 'utf8');
assert.equal(Number(activationSource.match(/NATIVE_334_ACTIVATION_HEIGHT = (\d+);/)[1]), 34750);
for (const value of [undefined, null, false, '', ' ', -1, Infinity, 0.000000001, 21000001])
  assert.equal(feeUnits(value), null);
assert.equal(feeUnits(0), 0n);
assert.equal(feeUnits(0.00000001), 1n);
assert.equal(feeUnits('1.23456789'), 123456789n);
assert.equal(feeUnits(21000000), 2100000000000000n);
assert.equal(indexedFee({type:'received',fee_veld:0,net_veld:5}),null);
assert.equal(indexedFee({type:'staking_distribution',fee_veld:0,net_veld:5}),null);
assert.equal(indexedFee({type:'staking_distribution',fee_veld:0,net_veld:-5}),'0');
assert.equal(indexedFee({type:'endorsement',fee_veld:0.001,net_veld:0}),'0.001');
assert.equal(indexedFee({type:'self',fee_veld:0,net_veld:0}),'0');
const feeIds = ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)];
const feeBlock = {height:34750, tx_count:3, tx:feeIds};
const fees = new Map([[feeIds[1], 0.00000001], [feeIds[2], '0.00000002']]);
assert.equal(minerFeeTotal(feeBlock,34750,feeIds,fees),'0.00000003');
assert.equal(minerFeeTotal({height:34750,tx_count:1,tx:[feeIds[0]]},34750,[feeIds[0]],new Map()),'0');
assert.equal(minerFeeTotal({...feeBlock,height:34749},34749,feeIds,fees),null);
assert.equal(minerFeeTotal(feeBlock,34751,feeIds,fees),null);
assert.equal(minerFeeTotal(feeBlock,34750,feeIds.slice(0,2),fees),null);
assert.equal(minerFeeTotal({...feeBlock,tx_count:4},34750,feeIds,fees),null);
assert.equal(minerFeeTotal(feeBlock,34750,[feeIds[0],feeIds[2],feeIds[1]],fees),null);
assert.equal(minerFeeTotal(feeBlock,34750,feeIds,new Map([[feeIds[1],0]])),null);
assert.equal(minerFeeTotal(feeBlock,34750,feeIds,new Map([[feeIds[1],null],[feeIds[2],0]])),null);
assert.equal(minerFeeTotal(feeBlock,34750,feeIds,new Map([[feeIds[1],21000000],[feeIds[2],1]])),null);
assert.equal(minerFeeTotal({...feeBlock,tx:[feeIds[0],feeIds[1],feeIds[1]]},34750,[feeIds[0],feeIds[1],feeIds[1]],fees),null);
console.log('PASS: exact miner fee totals, zero fees, activation, incomplete data and block identity');

for (const value of [undefined, null, '', ' ', false, true, {}, [], NaN, Infinity, -1, '-0.001']) {
  assert.equal(feeText(value), null, 'Invalid fee must remain unknown: ' + String(value));
}
for (const [value, expected] of [[0,'0'], ['0','0'], [0.001,'0.001'], [0.00000001,'0.00000001'], [1.23456789,'1.23456789']]) {
  assert.equal(feeText(value), expected);
}

const address = 'VYTVc2e49QRPbb2LWSeRBH95GsmYdszfRC';
const entry = {type:'self', net_veld:0, txid:'1'.repeat(64), block_height:4405};
const tx = {txid:entry.txid, block_height:4405, coinbase:false,
  vin:[{txid:'2'.repeat(64),vout:0}, {txid:'3'.repeat(64),vout:0}],
  vout:[{address, value:56.50584920}]};
assert.equal(isConsolidation(entry,tx,address),true);
for (const change of [{type:'sent'}, {type:'received'}, {net_veld:1}, {txid:'4'.repeat(64)}, {block_height:4406}]) {
  assert.equal(isConsolidation({...entry,...change},tx,address),false);
}
for (const change of [{coinbase:true}, {coinbase:undefined}, {vin:[]}, {vin:[tx.vin[0]]},
  {vout:[]}, {vout:[...tx.vout,...tx.vout]}, {vout:[{address:'another-wallet',value:1}]}, {vout:[{address,value:0}]}]) {
  assert.equal(isConsolidation(entry,{...tx,...change},address),false);
}
assert.equal(isConsolidation(null,tx,address),false);
assert.equal(isConsolidation(entry,null,address),false);
console.log('Explorer transaction display tests passed.');

const {extractFunction} = require('./javascript_function_source');
const script = fs.readFileSync(path.join(__dirname, '../website/explorer-transactions-v1.js'), 'utf8');
const proxy = fs.readFileSync(path.join(__dirname, '../pkg/reverse-proxy/veld-explorer-transaction-data.conf'), 'utf8');
const cursorRule = new RegExp(proxy.match(/\$arg_cursor !~ "([^"]+)"/)[1]);
(async () => {
  for (const version of [1, 2]) {
    const cursor = 'ah' + version + ':r:' + '1'.repeat(50) + ':' + '9'.repeat(20) + ':' + '0'.repeat(10) + ':' + '2'.repeat(64);
    assert(cursorRule.test(cursor));
    let calls = 0;
    const history = vm.createContext({addressPattern:/^V[1-9A-HJ-NP-Za-km-z]{25,40}$/,
      read:async url => {
        if (++calls === 1) return {entries:[{txid:'3'.repeat(64),block_height:4406}],has_more:true,next_cursor:cursor};
        assert(url.endsWith('&cursor=' + cursor));
        return {entries:[entry],has_more:false,next_cursor:''};
      }});
    vm.runInContext(extractFunction(script, 'historyEntry'), history);
    assert.equal((await history.historyEntry(address, entry.txid, 4405)).txid, entry.txid);
    assert.equal(calls, 2);
  }
  for (const invalid of ['ah3:r:', 'ah2:r:invalid', '"', 'ah2:r:' + '1'.repeat(300)])
    assert(!cursorRule.test(invalid));
  console.log('PASS: old and rebuilt reward-history cursors across Explorer and proxy');
})().catch(error => { console.error(error); process.exitCode = 1; });
