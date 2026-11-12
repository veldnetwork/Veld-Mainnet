// Execute the real registration flow up to its exact signing contract.
const fs = require('node:fs'),
    path = require('node:path'),
    vm = require('node:vm'),
    assert = require('node:assert/strict');
const source = fs.readFileSync(path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
function section(start, end) {
    const i = source.indexOf(start);
    assert(i >= 0);
    const j = source.indexOf(end, i);
    assert(j > i);
    return source.slice(i, j);
}
const helper = section('function _veldValidatorBondAtHeight(', '\n}') + '\n}';
const registration = section('function doRegisterValidator()', 'function doDeregisterValidator()');
let checks = 0;
async function test({
    activation = 6601,
    height = 6600,
    nodeMinimum = 5000,
    spendable = 6000,
    expected = 500000000000,
    error = false,
}) {
    const elements = new Map(),
        signed = [];
    const element = (id) => {
        if (!elements.has(id))
            elements.set(id, { value: 'Vowner', innerHTML: '', style: { display: 'none' } });
        return elements.get(id);
    };
    const context = {
        Promise,
        Number,
        String,
        Math,
        BigInt,
        console,
        VELD_MIN_VALIDATOR_STAKE_UNITS: 1000000000000,
        VELD_VALIDATOR_POLICY_ACTIVATION_HEIGHT: activation,
        VELD_MIN_TX_FEE_UNITS: 100000,
        VELD_STAKE_VAULT_ADDRESS: 'Vvault',
        currentAddr: 'Vowner',
        document: { getElementById: element },
        __veldKey: { get: () => 'a'.repeat(64) },
        escHtml: String,
        _veldRequireBoundIdentity: (key) => ({ key, address: 'Vowner' }),
        _veldActivateBoundIdentity: () => {},
        _veldAssertActiveSignerSeed: () => 1,
        __opLock: () => true,
        __opUnlock: () => {},
        updateKsIndicator: () => {},
        veldCrypto: { derivePublicKey: () => 'b'.repeat(3904) },
        _veldAddrToKeyCommitmentHex: (address) =>
            address === 'Vvault' ? '11'.repeat(20) : '22'.repeat(20),
        _veldBuildProtocolOpReturnHex: (x) => x,
        __waitForTxConfirm: () => {},
        loadValidatorsPage: () => {},
        rpc: async (method) => {
            if (method === 'getmininginfo') return { staking_active: true };
            if (method === 'getblockchaininfo') {
                if (error) throw Error('Node unavailable');
                return { blocks: height };
            }
            if (method === 'getvalidators') return { min_stake_veld: nodeMinimum };
            if (method === 'getbalance') return { spendable_veld: spendable };
            throw Error(method);
        },
        signAndBroadcast: async (...args) => {
            signed.push(args);
            return { txid: 'c'.repeat(64) };
        },
    };
    vm.createContext(context);
    vm.runInContext(helper + registration, context);
    context.doRegisterValidator();
    for (let n = 0; n < 5; n++) await new Promise(setImmediate);
    if (expected === null) {
        assert.equal(signed.length, 0);
        assert.match(element('val-msg').innerHTML, /alert-err/);
        checks += 2;
    } else {
        assert.equal(signed.length, 1);
        assert.equal(signed[0][0], 'prepareregistervalidator');
        assert.equal(signed[0][3][0].value_units_str, String(expected));
        assert.equal(signed[0][3][0].exact_hash160_total_units, String(expected));
        assert.equal(signed[0][3][0].exact_hash160_count, 1);
        assert.equal(signed[0][3][0].expected_hash160_hex, '11'.repeat(20));
        checks += 6;
    }
}
(async () => {
    const requirement = section(
        '    var minStake = parseFloat(d.min_stake_veld || 0);',
        '    if (currentAddr) {',
    );
    for (const [value, expected] of [
        [5000, '5000 VELD'],
        [10000, '10000 VELD'],
        [0, 'Unavailable'],
        [null, 'Unavailable'],
        [undefined, 'Unavailable'],
    ]) {
        const element = { innerHTML: '', textContent: '' };
        vm.runInNewContext(requirement, {
            d: { min_stake_veld: value },
            document: { getElementById: () => element },
            fmt: String,
        });
        assert.equal(element.innerHTML || element.textContent, expected);
        checks++;
    }
    await test({
        activation: 0,
        height: 2000000,
        nodeMinimum: 10000,
        spendable: 11000,
        expected: 1000000000000,
    });
    await test({ height: 6599, nodeMinimum: 10000, spendable: 11000, expected: 1000000000000 });
    await test({});
    await test({ height: 6601 });
    for (const height of [null, -1, '6600', Number.MAX_SAFE_INTEGER])
        await test({ height, expected: null });
    await test({ nodeMinimum: 10000, expected: null });
    await test({ height: 6599, expected: null });
    await test({ spendable: 5000, expected: null });
    await test({ error: true, expected: null });
    // Shipping activation: prepare for the next inclusion height, including
    // a reorganization back across the boundary and an out-of-date node reply.
    await test({ activation: 34750, height: 34748, nodeMinimum: 10000, spendable: 11000, expected: 1000000000000 });
    await test({ activation: 34750, height: 34749 });
    await test({ activation: 34750, height: 34750 });
    await test({ activation: 34750, height: 34748, nodeMinimum: 10000, expected: null });
    await test({ activation: 34750, height: 34749, nodeMinimum: 10000, expected: null });
    let scripts = 0;
    for (const m of source.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) {
        if (m[1].trim()) {
            new Function(m[1]);
            scripts++;
        }
    }
    console.log(
        JSON.stringify({
            status: 'PASS_VALIDATOR_WALLET_POLICY_SIGNING_CONTRACT',
            checks,
            scripts,
            financial_actions: false,
        }),
    );
})().catch((e) => {
    console.error(e);
    process.exit(1);
});
