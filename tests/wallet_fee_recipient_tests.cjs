'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {extractFunction} = require('./javascript_function_source.js');
const source = fs.readFileSync(path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
const element = {textContent: ''};
let answer;
const context = {
    document: {getElementById: () => element}, Number,
    rpc: async method => {
        assert.equal(method, 'getmininginfo');
        if (answer instanceof Error) throw answer;
        return answer;
    },
};
vm.createContext(context);
vm.runInContext(extractFunction(source, 'refreshSendFeeRecipient'), context);
(async () => {
    for (const [value, expected] of [
        [{reward_height: 100, miner_fees_active: false}, ' to vault'],
        [{reward_height: 101, miner_fees_active: true}, ' to miners'],
        [{reward_height: 100, miner_fees_active: false}, ' to vault'],
        [{reward_height: 101}, ''],
        [{reward_height: 0, miner_fees_active: true}, ''],
        [{reward_height: 101, miner_fees_active: 'false'}, ''],
        [new Error('read unavailable'), ''],
    ]) {
        answer = value;
        context.refreshSendFeeRecipient();
        assert.equal(element.textContent, '', 'clear stale policy while reading');
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(element.textContent, expected);
    }
    assert(!source.includes('0.001 VELD</span> → vault'));
    console.log('PASS_WALLET_FEE_RECIPIENT cases=7');
})().catch(error => {console.error(error); process.exitCode=1;});
