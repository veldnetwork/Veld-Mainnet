'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs'),
    path = require('node:path'),
    vm = require('node:vm');
const { extractFunction } = require('./javascript_function_source');
const source = fs.readFileSync(path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
const names = [
    '_veldStakeFormAddress',
    'doUnstake',
    'planIncrementalUnstake',
    'doIncrementalUnstake',
    'doDeregisterValidator',
];
const owner = 'fixture-owner',
    token = 'inert'.padEnd(64, '_'),
    generation = 17;
const flush = async () => {
    for (let i = 0; i < 40; ++i) await Promise.resolve();
};

function fixture() {
    const elements = new Map(),
        calls = [],
        prompts = [],
        timers = [],
        locks = new Set();
    const element = (id) => {
        if (!elements.has(id))
            elements.set(id, {
                style: {},
                dataset: {},
                value: '',
                textContent: '',
                innerHTML: '',
                disabled: false,
            });
        return elements.get(id);
    };
    element('sk-addr').style.display = 'none';
    element('sk-addr').value = 'previous-wallet';
    element('sk-amount').value = '500';
    element('sk-current-stake').textContent = '3000';
    element('sk-mature-stake').dataset.value = '2500';
    element('d-height').textContent = '50000';
    element('val-addr-row').style.display = 'none';
    const context = vm.createContext({
        currentAddr: owner,
        window: {},
        UNSTAKE_BATCH_THRESHOLD_VELD: 2000,
        UNSTAKE_BATCH_COOLDOWN_MS: 65000,
        __veldKey: { get: () => token },
        _veldRequireBoundIdentity: (key, _, address) => ({ key, address }),
        _veldActivateBoundIdentity() {},
        _veldAssertActiveSignerSeed: (key, expected) => {
            assert.equal(key, token);
            if (expected !== undefined) assert.equal(expected, generation);
            return generation;
        },
        _veldParseVeldUnitsExact: (text) => BigInt(Math.round(Number(text) * 100000000)),
        _veldUnitsToAmountString: (units) => String(Number(units) / 100000000),
        _veldBuildProtocolOpReturnHex: (text) => text,
        _veldAddrToKeyCommitmentHex: (address) => 'owner-hash:' + address,
        veldCrypto: { derivePublicKey: () => 'inert-public-key' },
        document: { getElementById: element, querySelector: () => element('unstake-button') },
        __opLock: (name) => {
            if (locks.has(name)) return false;
            locks.add(name);
            return true;
        },
        __opUnlock: (name) => locks.delete(name),
        updateKsIndicator() {},
        loadStakingPage() {},
        onStakeAddrChange() {},
        loadValidatorsPage() {},
        fmt: (value, places) => Number(value).toFixed(places),
        escHtml: String,
        setTimeout: (fn, ms) => {
            timers.push({ fn, ms });
            return timers.length;
        },
        sleepMs: async (ms) => {
            calls.push({ sleep: ms });
        },
        confirm: (text) => {
            prompts.push(text);
            return true;
        },
        rpc: async (method, params) => {
            calls.push({ method, params });
            assert.equal(method, 'getstakehistory');
            return [
                { type: 'stake', active: true, unlock_at: 40000, block: 1000, amount_veld: 1000 },
                { type: 'stake', active: true, unlock_at: 41000, block: 1100, amount_veld: 1500 },
            ];
        },
        signAndBroadcast: async (...args) => {
            calls.push({ signed: args[0], args });
            return { txid: 'c'.repeat(64) };
        },
        __waitForTxConfirm: (id, _, confirmed) => {
            assert.equal(id, 'c'.repeat(64));
            confirmed({ block_height: 50001 });
        },
    });
    vm.runInContext(names.map((name) => extractFunction(source, name)).join('\n'), context);
    return { context, element, calls, prompts, timers, locks };
}

(async () => {
    let checks = 0;
    for (const name of ['doUnstake', 'doIncrementalUnstake']) {
        const body = extractFunction(source, name);
        assert(!/preparederegistervalidator|autoDeregister|getvalidators/.test(body));
    }
    assert(
        extractFunction(source, 'doDeregisterValidator').includes("'preparederegistervalidator'"),
    );
    ++checks;

    let f = fixture();
    f.context.doUnstake();
    await flush();
    let signed = f.calls.filter((call) => call.signed);
    assert.equal(signed.length, 1);
    assert.equal(signed[0].signed, 'prepareunstake');
    assert.deepEqual(Array.from(signed[0].args[1]), [owner, '500']);
    assert.equal(signed[0].args[4], 'owner-hash:' + owner);
    assert.equal(signed[0].args[7], 'VELD_STAKE|UNLOCK|' + owner + '|50000000000');
    assert.equal(signed[0].args[9], generation);
    assert.equal(f.prompts.length, 0);
    assert.match(f.element('stake-msg').innerHTML, /Waiting for confirmation/);
    f.timers.find((timer) => timer.ms === 4000).fn();
    assert(!f.locks.has('unstake:' + owner));
    ++checks;

    f = fixture();
    f.element('sk-amount').value = '2500';
    f.context.doUnstake();
    await flush();
    signed = f.calls.filter((call) => call.signed);
    assert.deepEqual(
        signed.map((call) => call.signed),
        ['prepareunstake', 'prepareunstake'],
    );
    assert.deepEqual(
        signed.map((call) => Array.from(call.args[1])),
        [
            [owner, '1000'],
            [owner, '1500'],
        ],
    );
    assert(signed.every((call) => call.args[9] === generation));
    assert.deepEqual(
        f.calls.filter((call) => call.sleep).map((call) => call.sleep),
        [65000],
    );
    assert.equal(f.prompts.length, 1);
    assert.match(f.prompts[0], /split into 2 batches/);
    assert(!f.locks.has('unstake:' + owner));
    assert.match(f.element('stake-msg').innerHTML, /Waiting for confirmation/);
    ++checks;

    f = fixture();
    f.element('sk-mature-stake').dataset.value = '0';
    f.element('sk-next-unlock-blocks').dataset.value = '100';
    f.context.doUnstake();
    await flush();
    assert.equal(f.calls.length, 0);
    assert.match(f.element('stake-msg').innerHTML, /Amount exceeds mature stake/);
    assert(!f.locks.has('unstake:' + owner));
    ++checks;

    f = fixture();
    f.context.doDeregisterValidator();
    await flush();
    signed = f.calls.filter((call) => call.signed);
    assert.equal(signed.length, 1);
    assert.equal(signed[0].signed, 'preparederegistervalidator');
    assert.deepEqual(Array.from(signed[0].args[1]), [owner, 'inert-public-key']);
    assert.equal(signed[0].args[4], 'owner-hash:' + owner);
    assert.equal(signed[0].args[7], 'VELD_VALIDATOR|DEREGISTER|inert-public-key');
    assert(!f.locks.has('validator-op'));
    ++checks;
    console.log(
        'PASS ' + checks + ' unstake and validator-exit controls; inert signatures and no network',
    );
})().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
