'use strict';
// Actual browser crypto, parser, ownership/fee guards and signature injection.
// RPC transport is an offline native fixture, and journal storage is a labeled
// focused-test stand-in. Native verifier independently accepts signed bytes.
const fs = require('node:fs'),
    path = require('node:path'),
    vm = require('node:vm'),
    assert = require('node:assert/strict');
const { extractFunction } = require('./javascript_function_source');
const root = path.join(__dirname, '..'),
    source = fs.readFileSync(path.join(root, 'include/network/ui_desktop.h'), 'utf8');
const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const c = vm.createContext({
    console,
    Uint8Array,
    DataView,
    TextEncoder,
    BigInt,
    setTimeout,
    VeldDilithium: require(path.join(root, 'vendor/pqc/dilithium_wasm.js')),
    VELD_ADDRESS_VERSION: 70,
    VELD_NETWORK_BYTE: 0x4d,
    VELD_GENESIS_HASH: input.genesis,
    _BASE58_ALPHABET: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    _veldRequireSelfCustodySigner: () => {},
    _veldAssertActiveSignerSeed: (seed, generation) => {
        assert.equal(seed, input.seed);
        assert(generation === undefined || generation === 1);
        return 1;
    },
    _veldJournalSign: async (unsigned, metadata, seed, generation, sign) => sign(),
    rpc: async (method, params) => {
        if (method === 'gettxout')
            return {
                txid: params[0],
                vout: 0,
                block_height: 0,
                value_units: 2000000000,
                script_pubkey_hex: input.rpc.result.inputs[0].prev_script_hex,
            };
        if (method === 'gettransaction') return { txid: params[0], raw_hex: input.parent_hex };
        throw Error('unexpected offline fixture request');
    },
});
const begin = source.indexOf('var veldCrypto = (function() {'),
    end = source.indexOf('\n})();', begin) + 7;
vm.runInContext(source.slice(begin, end), c);
const codec = fs.readFileSync(path.join(root, 'include/network/covenant_client_js.h'), 'utf8');
vm.runInContext(codec.split('R"VELDCJS(\n')[1].split(')VELDCJS"')[0], c);
const names = [
    '_veldHexToBytes',
    '_veldBytesToHex',
    '_veldParseVarint',
    '_veldParseUnsignedTx',
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
    '_veldSha256dBytes',
    '_veldVerifyInputSighashes',
    '_veldAuthenticatePreparedPrevouts',
    '_veldAssertAllP2PKHOutputsInAllowed',
    '_veldVerifyUnsignedTxOutputs',
    '_veldAssertPreparedRelaySize',
];
vm.runInContext(names.map((name) => extractFunction(source, name)).join('\n'), c);
(async () => {
    await c.veldCrypto.init();
    const identity = c._veldRequireBoundIdentity(input.seed, input.public_key, input.address);
    const prep = input.rpc.result,
        owner = c._veldAddrToKeyCommitmentHex(identity.address),
        recipient = c._veldAddrToKeyCommitmentHex(input.recipient);
    const expected = [
        {
            value_units_str: '200000000',
            expected_hash160_hex: recipient,
            exact_hash160_total_units: '200000000',
            exact_hash160_count: 1,
        },
    ];
    c._veldVerifyUnsignedTxOutputs(prep, expected);
    c._veldAssertAllP2PKHOutputsInAllowed(prep, [owner, recipient]);
    c._veldVerifyInputSighashes(prep, [], c._veldKeyCommitmentToScriptHex(owner));
    await c._veldAuthenticatePreparedPrevouts(prep, 100000);
    const wrong = JSON.parse(JSON.stringify(prep));
    wrong.inputs[0].sighash_hex = '00'.repeat(32);
    assert.throws(() =>
        c._veldVerifyInputSighashes(wrong, [], c._veldKeyCommitmentToScriptHex(owner)),
    );
    const signed = await c.veldCrypto.injectSignatures(
        prep.unsigned_tx_hex,
        prep.inputs,
        input.seed,
        null,
        1,
    );
    fs.writeFileSync(process.argv[3], signed + '\n');
    console.log(
        'PASS actual browser key binding, parent authentication, exact fee/recipient and ML-DSA signing; offline fixture transport/journal',
    );
})().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
