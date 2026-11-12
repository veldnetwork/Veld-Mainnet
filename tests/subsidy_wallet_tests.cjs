'use strict';
const assert = require('node:assert/strict'),
    fs = require('node:fs'),
    path = require('node:path'),
    vm = require('node:vm');
const { extractFunction } = require('./javascript_function_source.js');
const source = fs.readFileSync(path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
let scripts = 0;
for (const match of source.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) {
    new vm.Script(match[1]);
    scripts++;
}
const refresh = extractFunction(source, 'refreshWalletSubsidy');
let now = 1000,
    calls = 0,
    answer = { reward_height: 700801, miner_subsidy_next_480_units: 37357305860 };
const element = {};
const context = {
    walletSubsidy: null,
    walletSubsidyPending: false,
    Date: { now: () => now },
    Number,
    Error,
    document: { getElementById: () => element },
    fmt: (n) => n.toFixed(0),
    rpc: async (method) => {
        assert.equal(method, 'getmininginfo');
        calls++;
        if (answer instanceof Error) throw answer;
        return answer;
    },
};
vm.createContext(context);
vm.runInContext(refresh, context);
const tick = () => new Promise((resolve) => setImmediate(resolve));
(async () => {
    context.refreshWalletSubsidy(700800);
    context.refreshWalletSubsidy(700800);
    await tick();
    assert.equal(calls, 1);
    assert.equal(context.walletSubsidy.minerNext480, 373.5730586);
    assert.equal(context.walletSubsidy.height, 700800);
    assert.match(element.title, /fees excluded/);
    context.refreshWalletSubsidy(700800);
    await tick();
    assert.equal(calls, 1);
    now += 30001;
    context.refreshWalletSubsidy(700800);
    await tick();
    assert.equal(calls, 2);
    answer = { reward_height: 1401602, miner_subsidy_next_480_units: 0 };
    context.refreshWalletSubsidy(1401601);
    await tick();
    assert.equal(context.walletSubsidy.minerNext480, 0);
    assert.equal(element.textContent, '~0');
    for (const bad of [undefined, -1, Infinity, Number.MAX_SAFE_INTEGER + 1, '480']) {
        answer = { reward_height: 1401603, miner_subsidy_next_480_units: bad };
        context.refreshWalletSubsidy(1401602);
        await tick();
        assert.equal(context.walletSubsidy, null);
        assert.equal(element.textContent, '—');
        assert.equal(context.walletSubsidyPending, false);
    }
    answer = new Error('temporarily unavailable');
    context.refreshWalletSubsidy(1401602);
    await tick();
    assert.equal(context.walletSubsidy, null);
    assert.equal(element.textContent, '—');
    answer = { reward_height: 1401603, miner_subsidy_next_480_units: 17 };
    context.refreshWalletSubsidy(1401602);
    await tick();
    assert.equal(context.walletSubsidy.minerNext480, 0.00000017);
    assert(
        !source.includes('blocksMined*3.13926940'),
        'Lifetime income must not be inferred from one reward amount',
    );
    console.log('PASS_SUBSIDY_WALLET scripts=' + scripts + ' cases=11');
})().catch((e) => {
    console.error(e);
    process.exitCode = 1;
});
