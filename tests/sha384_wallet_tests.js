'use strict';
// Actual shipped browser functions, byte codecs and ML-DSA WASM. No RPC/network,
// no keys outside disposable deterministic fixtures. SHA-384 oracle: Node/OpenSSL.
const assert = require('node:assert/strict'),
    fs = require('node:fs'),
    vm = require('node:vm'),
    path = require('node:path'),
    crypto = require('node:crypto');
const root = path.join(__dirname, '..'),
    source = fs.readFileSync(path.join(root, 'include/network/ui_desktop.h'), 'utf8');
function extract(name) {
    const begin = source.indexOf('function ' + name + '(');
    assert(begin >= 0, name);
    const end = source.indexOf('\n}', begin);
    assert(end > begin, name);
    return source.slice(begin, end + 2);
}
const c = vm.createContext({
    Uint8Array,
    DataView,
    TextEncoder,
    BigInt,
    console,
    VELD_ADDRESS_VERSION: 70,
    VELD_NETWORK_BYTE: 0x4d,
    VELD_GENESIS_HASH: '880a0057852ffcfa35119a83e556802848ed5cb469b260fb9fbd20e8b97ae77b',
    _BASE58_ALPHABET: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    _veldRequireSelfCustodySigner: () => {},
    veldCrypto: {
        sha256: (h) => crypto.createHash('sha256').update(Buffer.from(h, 'hex')).digest('hex'),
        sha256d: (h) =>
            crypto
                .createHash('sha256')
                .update(crypto.createHash('sha256').update(Buffer.from(h, 'hex')).digest())
                .digest('hex'),
    },
});
const embedded = fs.readFileSync(path.join(root, 'include/network/covenant_client_js.h'), 'utf8');
vm.runInContext(embedded.split('R"VELDCJS(\n')[1].split(')VELDCJS"')[0], c);
for (const name of [
    '_veldHexToBytes',
    '_veldBytesToHex',
    '_veldSha384PublicBytes',
    '_veldBase58Decode',
    '_veldAddrToHash160Hex',
    '_veldAddrToKeyCommitmentHex',
    '_veldScriptToHash160Hex',
    '_veldScriptToKeyCommitmentHex',
    '_veldKeyCommitmentToScriptHex',
    '_veldAddressForPublicKey',
    'isValidVeldAddr',
    '_veldRequireBoundIdentity',
    '_veldParseAndBindKeyPayload',
    '_veldAssertAllP2PKHOutputsToSelf',
    '_veldAssertAllP2PKHOutputsInAllowed',
    '_veldVerifyUnsignedTxOutputs',
])
    vm.runInContext(extract(name), c);
let checks = 0;
const eq = (a, b) => {
    assert.equal(a, b);
    checks++;
};
for (const length of [
    0, 1, 3, 110, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 1952, 2049, 4096,
]) {
    const input = Uint8Array.from({ length }, (_, i) => (i * 17 + length) % 256);
    eq(
        Buffer.from(c._veldSha384PublicBytes(input)).toString('hex'),
        crypto.createHash('sha384').update(input).digest('hex'),
    );
}
assert.throws(() => c._veldSha384PublicBytes(new Uint8Array(4097)));
assert.throws(() => c._veldSha384PublicBytes([]));
checks += 2;
const fixed = Buffer.from(Uint8Array.from({ length: 1952 }, (_, i) => i % 256)).toString('hex');
const nativeCommitment =
    '4e3a555217be2451fc322b97489f6c0ae5a37047b0f0dadb88d1efc7330893e529973bee308ee97b54988dc108864a1d';
eq(c._veldAddrToKeyCommitmentHex(c._veldAddressForPublicKey(fixed, 'sha384-v1')), nativeCommitment);
(async () => {
    const m = await require(path.join(root, 'vendor/pqc/dilithium_wasm.js'))();
    const sp = m._malloc(32),
        pk = m._malloc(1952),
        sk = m._malloc(4032);
    try {
        const seed = Buffer.alloc(32, 73).toString('hex');
        m.HEAPU8.set(Buffer.from(seed, 'hex'), sp);
        eq(m._veld_mldsa65_keypair_from_seed(sp, pk, sk), 0);
        const pub = Buffer.from(m.HEAPU8.slice(pk, pk + 1952)).toString('hex');
        c.veldCrypto.derivePublicKey = (value) => {
            assert.equal(value, seed);
            return pub;
        };
        for (const type of ['legacy', 'sha384-v1']) {
            const address = c._veldAddressForPublicKey(pub, type),
                commitment = c._veldAddrToKeyCommitmentHex(address),
                script = c._veldKeyCommitmentToScriptHex(commitment);
            eq(c.isValidVeldAddr(address), true);
            eq(c._veldScriptToKeyCommitmentHex(script), commitment);
            eq(c._veldRequireBoundIdentity(seed, pub, address).address, address);
            eq(
                c._veldParseAndBindKeyPayload(
                    JSON.stringify({ privkey: seed, pubkey: pub, address }),
                ).address,
                address,
            );
            eq(c._veldParseAndBindKeyPayload(seed + '\n' + pub + '\n' + address).address, address);
            assert.throws(() => c._veldRequireBoundIdentity(seed, 'ff' + pub.slice(2), address));
            checks++;
            for (let i = 0; i < address.length; i++) {
                const changed =
                    address.slice(0, i) + (address[i] === '1' ? '2' : '1') + address.slice(i + 1);
                eq(c.isValidVeldAddr(changed), false);
            }
            c.VELD_NETWORK_BYTE = 0x54;
            c.VELD_ADDRESS_VERSION = 111;
            eq(c.isValidVeldAddr(address), false);
            c.VELD_NETWORK_BYTE = 0x4d;
            c.VELD_ADDRESS_VERSION = 70;
            let outputs = [{ value_units_str: '200', script_pubkey_hex: script }];
            c._veldParseUnsignedTx = () => ({ outputs });
            const prep = { unsigned_tx_hex: 'inert-parser-fixture' };
            c._veldAssertAllP2PKHOutputsToSelf(prep, commitment);
            c._veldAssertAllP2PKHOutputsInAllowed(prep, [commitment]);
            checks += 2;
            c._veldVerifyUnsignedTxOutputs(prep, [
                {
                    value_units_str: '200',
                    expected_hash160_hex: commitment,
                    exact_hash160_total_units: '200',
                    exact_hash160_count: 1,
                },
            ]);
            checks++;
            outputs.push({ ...outputs[0] });
            assert.throws(() =>
                c._veldVerifyUnsignedTxOutputs(prep, [
                    {
                        value_units_str: '200',
                        expected_hash160_hex: commitment,
                        exact_hash160_total_units: '200',
                        exact_hash160_count: 1,
                    },
                ]),
            );
            checks++;
            outputs = [{ value_units_str: '200', script_pubkey_hex: 'c00130' + '00'.repeat(48) }];
            assert.throws(() => c._veldAssertAllP2PKHOutputsToSelf(prep, commitment));
            assert.throws(() => c._veldAssertAllP2PKHOutputsInAllowed(prep, [commitment]));
            checks += 2;
            if (type === 'sha384-v1') eq(c._veldAddrToHash160Hex(address), null);
        }
        const wide = c._veldAddressForPublicKey(pub, 'sha384-v1');
        c.VELD_GENESIS_HASH = '00'.repeat(32);
        assert.throws(() => c._veldRequireBoundIdentity(seed, pub, wide));
        checks++;
    } finally {
        m.HEAPU8.fill(0, sp, sp + 32);
        m.HEAPU8.fill(0, sk, sk + 4032);
        m._free(sp);
        m._free(pk);
        m._free(sk);
    }
    console.log(
        'PASS ' +
            checks +
            ' browser destination, native commitment parity, WASM key binding and output policy checks',
    );
})().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
