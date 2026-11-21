'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {extractFunction} = require('./javascript_function_source');
const source = fs.readFileSync(process.env.VELD_WALLET_TEST_SOURCE ||
  path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
const names = ['planIncrementalUnstake', 'doIncrementalUnstake'];
const records = () => [
  {type:'stake', active:true, status:'unlocked', unlock_at:39000, block:35000, amount_veld:3000},
  {type:'stake', active:true, status:'locked', unlock_at:60000, block:38000, amount_veld:2500},
  {type:'stake', active:true, status:'unlocked', unlock_at:38000, block:34000, amount_veld:1500},
  {type:'stake', active:false, status:'consumed', unlock_at:30000, block:29000, amount_veld:900},
  {type:'unstake', active:false, status:'unstaked', unlock_at:0, block:30001, amount_veld:900}
];
function fixture(options = {}) {
  const calls = [], prompts = [], message = {innerHTML:'', textContent:''}, button = {disabled:true};
  let generation = 4;
  const context = vm.createContext({
    UNSTAKE_BATCH_COOLDOWN_MS:65000,
    document:{getElementById:() => options.missingHeight ? null : {textContent:options.height ?? '—'}},
    _veldAssertActiveSignerSeed:(_, expected) => {
      if (expected !== undefined && expected !== generation) throw new Error('Wallet locked or changed.');
      return generation;
    },
    _veldParseVeldUnitsExact:text => {
      assert.match(text, /^\d+(?:\.\d{1,8})?$/);
      const [whole, fraction = ''] = text.split('.');
      return BigInt(whole) * 100000000n + BigInt(fraction.padEnd(8, '0'));
    },
    _veldUnitsToAmountString:units => {
      const value = BigInt(units);
      return (value / 100000000n).toString() + '.' + (value % 100000000n).toString().padStart(8, '0');
    },
    _veldBuildProtocolOpReturnHex:text => text,
    _veldAddrToKeyCommitmentHex:address => 'bound:' + address,
    rpc:async (method, params) => {
      calls.push({method, params});
      assert.equal(method, 'getstakehistory');
      assert.equal(params[0], 'inert-owner');
      if (options.lockAfterRead) generation++;
      if (options.rpcError) throw new Error(options.rpcError);
      return options.history === undefined ? records() : options.history;
    },
    signAndBroadcast:async (...args) => {
      context._veldAssertActiveSignerSeed(args[2], args[9]);
      calls.push({signed:args[0], args});
      return {txid:'b'.repeat(64)};
    },
    confirm:text => { prompts.push(text); return options.cancel !== true; },
    sleepMs:async ms => calls.push({sleep:ms}),
    fmt:(value, places) => Number(value).toFixed(places),
    escHtml:text => String(text).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;'),
    loadStakingPage(){}, onStakeAddrChange(){}
  });
  vm.runInContext(names.map(name => extractFunction(source, name)).join('\n'), context);
  return {context, calls, prompts, message, button,
    run:amount => context.doIncrementalUnstake('inert-owner', amount ?? 4500, 'inert-key', message, button, 4),
    signed:() => calls.filter(call => call.signed)};
}

(async () => {
  let checks = 0;
  for (const options of [{height:'—'}, {height:'0'}, {height:'1,000'},
    {height:'99,999,999'}, {height:''}, {missingHeight:true}]) {
    const f = fixture(options);
    await f.run();
    assert.deepEqual(f.signed().map(call => call.args[1][1]), ['1500.00000000', '3000.00000000'],
      'Unlocked RPC records must work independently of the dashboard height: ' + JSON.stringify(options));
    assert(f.signed().every(call => call.args[4] === 'bound:inert-owner' && call.args[9] === 4));
    assert.equal(f.signed()[1].args[7], 'VELD_STAKE|UNLOCK|inert-owner|300000000000');
    assert.match(f.message.innerHTML, /4500\.00.*Waiting for confirmation/);
    assert.equal(f.button.disabled, false);
    checks++;
  }
  for (const history of [[], records().filter(r => r.status !== 'unlocked')]) {
    const f = fixture({height:'999999999', history}); await f.run();
    assert.equal(f.signed().length, 0); assert.match(f.message.innerHTML, /No mature stake records/); checks++;
  }
  for (const history of [{records:records()}, null, [null],
    [{...records()[0], status:undefined}], [{...records()[0], amount_veld:NaN}],
    [{...records()[0], amount_veld:-1}], [{...records()[0], amount_veld:0.000000001}]]) {
    const f = fixture({history}); await f.run();
    assert.equal(f.signed().length, 0); assert.equal(f.button.disabled, false);
    assert.match(f.message.innerHTML, /Unable to load|Invalid|unavailable/i); checks++;
  }
  let f = fixture({rpcError:'temporarily unavailable <retry>'}); await f.run();
  assert.equal(f.signed().length, 0); assert.match(f.message.innerHTML, /Unable to load stake records/);
  assert.match(f.message.innerHTML, /&lt;retry&gt;/); assert.doesNotMatch(f.message.innerHTML, /No mature stake/); checks++;
  f = fixture({history:[records()[0]]}); await f.run();
  assert.equal(f.signed().length, 0); assert.match(f.message.innerHTML, /exceeds.*mature stake records/i); checks++;
  f = fixture({cancel:true}); await f.run();
  assert.equal(f.signed().length, 0); assert.match(f.message.innerHTML, /cancelled/); checks++;
  f = fixture({lockAfterRead:true}); await f.run();
  assert.equal(f.signed().length, 0); assert.equal(f.prompts.length, 0); checks++;
  f = fixture(); await f.run(2000.00000001);
  assert.deepEqual(f.signed().map(call => call.args[1][1]), ['1500.00000000', '500.00000001']); checks++;

  const hostedPath = path.join(__dirname, '../website/hosted-wallet/wallet-unstake-maturity-v1.js');
  if (fs.existsSync(hostedPath)) {
    const hosted = fs.readFileSync(hostedPath, 'utf8');
    new vm.Script(hosted);
    for (const name of names) assert.equal(extractFunction(hosted, name), extractFunction(source, name));
    checks++;
  }
  console.log('PASS ' + checks + ' unstake maturity, amount coverage, session and native/hosted parity checks; inert signatures, no network');
})().catch(error => {console.error(error); process.exitCode = 1;});
