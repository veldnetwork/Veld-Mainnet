'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const context = vm.createContext({window:{}, document:{readyState:'loading', addEventListener(){}}, Map});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../website/explorer-transactions-v1.js'), 'utf8'), context);
const {feeText, isConsolidation} = context.window.VeldTransactionDisplay;

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
