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
    const nodes = Object.fromEntries(['s-from','s-to','s-amount','confirm-box','c-from','c-to','c-amount','c-total','c-est-block']
        .map(id => [id, {value: '', textContent: '', classList: new Set()}]));
    let shown = false;
    nodes['confirm-box'].classList = {add: () => {shown=true;}, remove: () => {shown=false;}};
    nodes['s-from'].value='from';nodes['s-to'].value='to';
    const preview = {document:{getElementById: id=>nodes[id]}, BigInt,
        shortAddr: value=>value, rpc: async()=>({blocks:100})};
    vm.createContext(preview);
    for(const name of ['_veldParseVeldUnitsExact','_veldUnitsToAmountString','updateConfirm'])
        vm.runInContext(extractFunction(source,name),preview);
    for(const [amount,total] of [['2','2.001'],['0.00000001','0.00100001'],['0.12345678','0.12445678'],['20999999.99899999','20999999.99999999']]) {
        nodes['s-amount'].value=amount;preview.updateConfirm();
        assert(shown);assert.equal(nodes['c-amount'].textContent,amount+' VELD');
        assert.equal(nodes['c-total'].textContent,total+' VELD');
    }
    for(const amount of ['','0','-1','1e2','0.123456789','21000001','2x']) {
        nodes['s-amount'].value=amount;preview.updateConfirm();assert(!shown);
    }
    let sendRefreshes=0;
    const polling={document:{getElementById:id=>({classList:{contains:()=>id==='page-send'}})},
        onFromChange:()=>{sendRefreshes++;}};
    vm.createContext(polling);
    vm.runInContext(extractFunction(source,'refreshActiveTab'),polling);
    polling.refreshActiveTab();
    assert.equal(sendRefreshes,1,'confirmed change refreshes the active Send screen');
    polling.document.getElementById=()=>({classList:{contains:()=>false}});
    polling.refreshActiveTab();assert.equal(sendRefreshes,1,'inactive Send screen does not poll');
    nodes['s-avail']={textContent:''};nodes['s-from-row']={style:{display:'none'}};
    const funds={document:{getElementById:id=>nodes[id]},currentAddr:'from',sendBalanceRevision:0,window:{},
        renderSendUtxos:()=>{},updateConfirm:()=>{},fmt:(value,decimals)=>value.toFixed(decimals),
        rpc:async method=>method==='getbalance'?{balance_veld:17.999,spendable_veld:17.999}:[],BigInt,Number};
    vm.createContext(funds);
    for(const name of ['sendSourceAddress','onFromChange','_veldParseVeldUnitsExact','_veldUnitsToAmountString','fillSendAmountPct'])
        vm.runInContext(extractFunction(source,name),funds);
    await funds.onFromChange();
    assert.equal(nodes['s-avail'].textContent,'17.99900000 VELD','spendable display must not round up');
    for(const [available,percent,expected] of [
        ['17.99900000 VELD',100,'17.998'],['17.99900000 VELD',25,'4.4995'],
        ['0.00100001 VELD',100,'0.00000001'],['0.00100003 VELD',50,'0.00000001'],
        ['21,000,000.00000000 VELD',100,'20999999.999'],['0.00099999 VELD',100,''],
    ]) {
        nodes['s-avail'].textContent=available;nodes['s-amount'].value='';
        funds.fillSendAmountPct(percent);assert.equal(nodes['s-amount'].value,expected);
    }
    console.log('PASS_WALLET_FEE_RECIPIENT cases=7 exact_preview_cases=11 send_refresh_cases=2 exact_spendable_cases=7');
})().catch(error => {console.error(error); process.exitCode=1;});
