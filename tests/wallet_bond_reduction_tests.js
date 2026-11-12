'use strict';
const assert = require('node:assert/strict'),
    fs = require('node:fs'),
    vm = require('node:vm'),
    path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
function extract(name) {
    let start = source.indexOf('function ' + name + '(');
    assert(start >= 0);
    if (source.slice(start - 6, start) === 'async ') start -= 6;
    const end = source.indexOf('\n}', start);
    assert(end > start);
    return source.slice(start, end + 2);
}
const owner = 'fixture-owner',
    key = 'fixture-seed',
    pk = 'fixture-public-key';
const row = {
    address: owner,
    pubkey: pk,
    active: true,
    slashed: false,
    principal_held: true,
    registered_height: 6601,
    bond_reduction_eligible: true,
    bond_reduction_requested_at: 0,
    bond_units: '1000000000000',
    bond_retained_units: '500000000000',
    bond_reduction_units: '500000000000',
};
const info = () => ({ current_height: 7000, validators: [{ ...row }] });
let state = info(),
    generation = 1,
    locked = false,
    allow = true,
    signs = [],
    prompts = [],
    loads = 0,
    mutate = null;
const elements = {};
for (const id of ['val-msg', 'val-reduce-btn', 'val-reduce-note'])
    elements[id] = { hidden: false, textContent: '' };
const context = vm.createContext({
    document: { getElementById: (id) => elements[id] },
    currentAddr: owner,
    _veldValidatorBondAtHeight: (height) => (height >= 7000 ? 500000000000 : 1000000000000),
    __veldKey: { get: () => key },
    _veldRequireBoundIdentity: () => ({ address: owner }),
    _veldAssertActiveSignerSeed: (seed, expected) => {
        assert.equal(seed, key);
        if (expected !== undefined && generation !== expected) throw Error('Signer changed');
        return generation;
    },
    veldCrypto: { derivePublicKey: () => pk },
    rpc: async (method) => {
        assert.equal(method, 'getbondvaultinfo');
        if (mutate) mutate();
        return state;
    },
    __opLock: () => {
        if (locked) return false;
        locked = true;
        return true;
    },
    __opUnlock: () => {
        locked = false;
    },
    window: {
        confirm: (text) => {
            prompts.push(text);
            return allow;
        },
    },
    fmt: (n, d) => n.toFixed(d),
    VELD_MIN_TX_FEE_UNITS: 100000,
    _veldAddrToKeyCommitmentHex: (address) => 'commit:' + address,
    _veldBuildProtocolOpReturnHex: (op) => 'marker:' + op,
    signAndBroadcast: async (...args) => {
        signs.push(args);
        return { txid: 'fixture-tx' };
    },
    __waitForTxConfirm: (txid) => assert.equal(txid, 'fixture-tx'),
    loadValidatorsPage: () => {
        ++loads;
    },
});
vm.runInContext(
    [
        '_veldBondUnitsText',
        '_veldBondReductionReview',
        '_veldRenderBondReduction',
        'doReduceValidatorBond',
    ]
        .map(extract)
        .join('\n'),
    context,
);
const review = context._veldBondReductionReview,
    render = context._veldRenderBondReduction;
const op = 'VELD_VALIDATOR|REDUCE_BOND|' + pk + '|6601|500000000000';
assert.equal(review(info(), owner, pk).operation, op);
assert.equal(context._veldBondUnitsText('500000000001'), '5,000.00000001');
assert.equal(context._veldBondUnitsText('1'), '0.00000001');
assert.equal(context._veldBondUnitsText('18446744073709551615'), '184,467,440,737.09551615');
for (const patch of [
    { bond_reduction_eligible: false },
    { active: false },
    { slashed: true },
    { principal_held: false },
    { bond_reduction_requested_at: 7001 },
    { registered_height: 0 },
    { registered_height: 1.5 },
    { bond_retained_units: '499900000000' },
    { bond_reduction_units: '0' },
    { bond_reduction_units: '0500000000000' },
    { bond_units: '1000000000001' },
    { bond_units: 1000000000000 },
    { address: 'other' },
    { pubkey: 'other' },
]) {
    const bad = info();
    Object.assign(bad.validators[0], patch);
    assert.throws(() => review(bad, owner, pk));
}
for (const h of [0, 6998, NaN, Infinity, Number.MAX_SAFE_INTEGER]) {
    const bad = info();
    bad.current_height = h;
    assert.throws(() => review(bad, owner, pk));
}
render(info(), owner);
assert.equal(elements['val-reduce-btn'].hidden, false);
assert.match(elements['val-reduce-note'].textContent, /5,000 VELD back/);
const pending = info();
Object.assign(pending.validators[0], {
    bond_reduction_pending: true,
    bond_reduction_requested_at: 7001,
    bond_reduction_boundary: 50400,
});
render(pending, owner);
assert.equal(elements['val-reduce-btn'].hidden, true);
assert.match(elements['val-reduce-note'].textContent, /50400/);
const returned = info();
Object.assign(returned.validators[0], {
    bond_reduction_requested_at: 7001,
    bond_reduction_settled_at: 50400,
    bond_units: '500000000000',
});
render(returned, owner);
assert.equal(elements['val-reduce-btn'].hidden, true);
assert.match(elements['val-reduce-note'].textContent, /returned at block 50400/);
returned.validators[0].bond_reduction_settled_at = 0;
returned.validators[0].bond_reduction_cancelled = true;
render(returned, owner);
assert.match(elements['val-reduce-note'].textContent, /cancelled/);
render(info(), owner);
assert.equal(elements['val-reduce-btn'].hidden, false); // reorganization restores eligibility
context.currentAddr = 'different';
render(pending, owner);
assert.equal(elements['val-reduce-btn'].hidden, false);
context.currentAddr = owner;
(async () => {
    allow = false;
    await context.doReduceValidatorBond();
    assert.equal(signs.length, 0);
    assert.equal(locked, false);
    allow = true;
    await context.doReduceValidatorBond();
    assert.equal(signs.length, 1);
    const args = signs[0];
    assert.equal(args[0], 'preparereducevalidatorbond');
    assert.deepEqual(Array.from(args[1]), [owner, pk]);
    assert.equal(args[4], 'commit:' + owner);
    assert.equal(args[7], 'marker:' + op);
    assert.equal(args[9], 1);
    assert.match(prompts.at(-1), /full bond stays held and slashable/);
    assert.match(elements['val-msg'].textContent, /request submitted/);
    mutate = () => {
        context.currentAddr = 'different';
    };
    await context.doReduceValidatorBond();
    assert.equal(signs.length, 1);
    assert.match(elements['val-msg'].textContent, /Wallet changed/);
    context.currentAddr = owner;
    mutate = () => {
        ++generation;
    };
    await context.doReduceValidatorBond();
    assert.equal(signs.length, 1);
    assert.match(elements['val-msg'].textContent, /Signer changed/);
    mutate = null;
    state = info();
    state.validators[0].slashed = true;
    await context.doReduceValidatorBond();
    assert.equal(signs.length, 1);
    locked = true;
    await context.doReduceValidatorBond();
    assert.equal(signs.length, 1);
    assert(loads >= 5);
    console.log(
        'PASS exact amounts, local intent, owner/session binding, cancellation and reorganization display; RPC/signing mocked',
    );
})().catch((e) => {
    console.error(e);
    process.exitCode = 1;
});
