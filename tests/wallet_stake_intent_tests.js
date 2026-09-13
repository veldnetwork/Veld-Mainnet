'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const {extractFunction} = require('./javascript_function_source');
const source = fs.readFileSync(path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
const names = ['_veldStakeFormAddress', '_veldStakeAvailableUnits', 'onStakeAddrChange',
  '__opLock', '__opUnlock', 'setStakingActivationUi', 'doStake', '_doStakeContinue'];
const owner = 'ordinary-fixture-owner', txid = 'c'.repeat(64);
const flush = async () => { for (let i = 0; i < 25; ++i) await Promise.resolve(); };

function fixture(options = {}) {
  const nodes = new Map(), calls = [], pending = [], lookup = [];
  const element = id => {
    if (!nodes.has(id)) nodes.set(id, {style:{}, dataset:{}, value:'', textContent:'',
      innerHTML:'', title:'', disabled:false, setAttribute(name, value) { this[name] = value; }});
    return nodes.get(id);
  };
  element('sk-addr-row').style.display = '';
  element('sk-addr').style.display = 'none';
  element('sk-addr').value = owner;
  element('sk-amount').value = '500';
  element('sk-tier').value = '2';
  element('stake-button').textContent = 'Stake VELD';
  let generation = 1, refreshes = 0;
  const context = vm.createContext({
    _veldStakeOperation:null, _veldStakeBalanceRevision:0, __opLocks:{},
    currentAddr:owner, window:{}, VELD_MIN_TX_FEE_UNITS:100000,
    stakingMinVeld:500, stakingMaxVeld:10000,
    _veldStakingActivation:{active:true, known:true, supply:16000, threshold:10000},
    __veldKey:{get:() => 'inert-fixture-key', generation:() => generation},
    _veldRequireBoundIdentity:key => ({key, address:owner}),
    _veldActivateBoundIdentity:() => { ++generation; },
    _veldAssertActiveSignerSeed:(_, expected) => {
      if (expected != null && expected !== generation) throw new Error('Session changed');
      return generation;
    },
    _veldParseVeldUnitsExact:text => BigInt(text) * 100000000n,
    _veldUnitsToAmountString:units => String(Number(units) / 100000000),
    _veldAddrToHash160Hex:() => 'inert-owner-hash',
    _veldBuildProtocolOpReturnHex:text => text,
    fmt:(value, places) => Number(value).toFixed(places), escHtml:String,
    formatBlockDuration:blocks => blocks + ' blocks',
    document:{getElementById:element, querySelector:selector => {
      if (selector === '#page-staking .btn-em') return element('stake-button');
      if (selector === 'button[data-act-click="haa7ba916"]') return element('unstake-button');
      throw new Error('Unexpected selector: ' + selector);
    }},
    updateKsIndicator(){}, loadStakingPage(){},
    loadPendingSends(){ ++refreshes; },
    rpc:async (method, params) => {
      calls.push({method, params});
      if (options.rpc) return options.rpc(method, params);
      if (method === 'getstake') return {staked_veld:1000, blocks_until_unlock:10, unlock_height:6000};
      if (method === 'getbalance') return {balance_veld:1800, spendable_veld:525.26, staked_veld:1000};
      throw new Error('Unexpected RPC: ' + method);
    },
    signAndBroadcast:async (...args) => {
      pending.push({txid, method:args[0], args});
      return {txid};
    },
    __waitForTxConfirm:(id, seconds, confirmed, timeout) => {
      lookup.push({id, seconds, confirmed, timeout});
    }
  });
  vm.runInContext(names.map(name => extractFunction(source, name)).join('\n'), context);
  return {context, element, calls, pending, lookup, refreshes:() => refreshes};
}

(async () => {
  let checks = 0;
  let f = fixture();
  f.element('sk-addr').value = 'previous-wallet';
  assert.equal(f.context._veldStakeFormAddress(), owner); ++checks;
  f.element('sk-addr').style.display = '';
  assert.equal(f.context._veldStakeFormAddress(), 'previous-wallet'); ++checks;
  f.element('sk-addr').style.display = 'none';
  assert.equal(f.context._veldStakeAvailableUnits({spendable_veld:525.26}), 52525900000n); ++checks;
  assert.equal(f.context._veldStakeAvailableUnits({spendable_veld:0.0005}), 0n); ++checks;
  await f.context.onStakeAddrChange();
  assert.equal(f.element('sk-balance').textContent, '525.259');
  assert.equal(f.element('sk-current-stake').textContent, '1000.00'); ++checks;

  let release;
  f = fixture({rpc:async method => {
    if (method === 'getstake') return new Promise(resolve => { release = resolve; });
    return {spendable_veld:525.26};
  }});
  const submit = f.context.doStake();
  f.element('sk-tier').value = '3';
  release({staked_veld:1000});
  await submit;
  assert.equal(f.pending.length, 1);
  assert.deepEqual(Array.from(f.pending[0].args[1]), [owner, '500', '2']);
  assert.equal(f.pending[0].args[7], 'VELD_STAKE|LOCK|' + owner + '|50000000000|T2');
  assert.equal(f.pending[0].args[9], 2); ++checks;
  assert.equal(f.lookup[0].id, txid);
  assert.match(f.element('stake-msg').innerHTML, /Stake submitted/);
  f.context.setStakingActivationUi(true, 16000, 10000, true);
  assert.equal(f.element('stake-button').disabled, true); ++checks;
  f.lookup[0].confirmed({txid, block_height:5001, confirmations:1});
  assert.match(f.element('stake-msg').innerHTML, /Stake confirmed/);
  assert.equal(f.context.__opLocks.stake, false);
  assert.equal(f.element('stake-button').disabled, false); ++checks;

  f = fixture();
  await f.context.doStake();
  f.lookup[0].timeout();
  assert.equal(f.context.__opLocks.stake, false);
  assert.equal(f.pending.length, 1);
  assert.match(f.element('stake-msg').innerHTML, /still awaiting confirmation/);
  assert.equal(f.refreshes(), 1); ++checks;

  f = fixture({rpc:async method => method === 'getstake'
    ? {staked_veld:0} : {balance_veld:1000, spendable_veld:499}});
  await f.context.doStake();
  assert.equal(f.pending.length, 0);
  assert.equal(f.context.__opLocks.stake, false);
  assert.equal(f.element('stake-button').textContent, 'Stake VELD');
  assert.match(f.element('stake-msg').innerHTML, /available to stake after the network fee/); ++checks;

  f = fixture({rpc:async () => { throw new Error('Fixture service unavailable'); }});
  await f.context.doStake();
  assert.equal(f.pending.length, 0);
  assert.equal(f.context.__opLocks.stake, false); ++checks;
  await f.context.onStakeAddrChange();
  assert.equal(f.element('sk-balance').textContent, '—'); ++checks;

  f = fixture();
  await f.context.doStake();
  f.context.currentAddr = 'another-fixture-wallet';
  f.element('stake-msg').innerHTML = 'Current wallet status';
  f.lookup[0].confirmed({txid, block_height:5001, confirmations:1});
  await flush();
  assert.equal(f.element('stake-msg').innerHTML, 'Current wallet status');
  assert.equal(f.context.__opLocks.stake, false); ++checks;
  console.log('PASS ' + checks + ' stake UI controls; inert signing stub, no keys or network');
})().catch(error => { console.error(error); process.exitCode = 1; });
