'use strict';
// Consume actual funded-native RPC responses; never fabricate financial state.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { extractFunction } = require('./javascript_function_source');
const directory = process.argv[2];
assert(directory, 'Supply the completed native admission fixture directory');
const source = fs.readFileSync(path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
const functions = [
    '_veldValidatorBondAtHeight',
    '_veldBondUnitsText',
    '_veldBondReductionReview',
    '_veldRenderBondReduction',
]
    .map((name) => extractFunction(source, name))
    .join('\n');
const countStart = source.indexOf("    var ctEl = document.getElementById('bv-counts');");
const countEnd = source.indexOf('    var vestDays =', countStart);
assert(countStart > 0 && countEnd > countStart);
for (const stage of ['inactive', 'eligible', 'reorg', 'pending', 'returned']) {
    const response = JSON.parse(fs.readFileSync(path.join(directory, 'wallet-' + stage + '.json')));
    assert.equal(response.error, null);
    const state = response.result;
    assert.equal(state.validators.length, 1);
    const row = state.validators[0];
    const elements = Object.fromEntries(
        ['val-reduce-btn', 'val-reduce-note', 'bv-counts', 'bv-counts-sub'].map((id) => [
            id,
            { hidden: false, textContent: '' },
        ]),
    );
    const context = vm.createContext({
        currentAddr: row.address,
        VELD_MIN_VALIDATOR_STAKE_UNITS: 1000000000000,
        VELD_VALIDATOR_POLICY_ACTIVATION_HEIGHT: 7000,
        document: { getElementById: (id) => elements[id] },
        b: state,
    });
    vm.runInContext(functions + '\n' + source.slice(countStart, countEnd), context);
    context._veldRenderBondReduction(state, row.address);
    const eligible = stage === 'eligible' || stage === 'reorg';
    assert.equal(elements['val-reduce-btn'].hidden, !eligible);
    assert.equal(
        elements['bv-counts-sub'].textContent,
        '1 active · ' + (stage === 'pending' ? 1 : 0) + ' pending return',
    );
    if (eligible) {
        const intent = context._veldBondReductionReview(state, row.address, row.pubkey);
        assert.equal(
            intent.operation,
            'VELD_VALIDATOR|REDUCE_BOND|' + row.pubkey + '|6601|500000000000',
        );
        assert.equal(intent.amount, '500000000000');
    } else {
        assert.throws(() => context._veldBondReductionReview(state, row.address, row.pubkey));
    }
    if (stage === 'inactive') assert.equal(elements['val-reduce-note'].hidden, true);
    if (stage === 'pending')
        assert.match(
            elements['val-reduce-note'].textContent,
            /5,000 VELD return pending at block 50400/,
        );
    if (stage === 'returned') {
        assert.match(
            elements['val-reduce-note'].textContent,
            /5,000 VELD excess returned at block 50400/,
        );
        assert.equal(row.bond_units, '500000000000');
        assert.equal(row.original_bond_veld, 10000);
    }
}
console.log(
    'PASS_ACTUAL_RPC_TO_WALLET_BOND_VIEWS stages=5 actual_native_responses=true DOM=standin',
);
