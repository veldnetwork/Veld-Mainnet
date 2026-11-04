'use strict';
// Exercise the shipping pairing flow with isolated device/API/DOM fixtures.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../src/veld-miner-portal.py'), 'utf8');
const html = source.split('PORTAL_HTML = r"""')[1].split('"""')[0];
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(script);
function extract(name) {
  const start = script.indexOf('function ' + name + '(');
  const lineEnd = script.indexOf('\n', start);
  const end = script[lineEnd - 1] === '}' ? lineEnd : script.indexOf('\n}', start) + 2;
  assert(start >= 0 && end > start);
  return (script.slice(start - 6, start) === 'async ' ? 'async ' : '') + script.slice(start, end);
}
function setup() {
  const nodes = new Map();
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, {value: '', textContent: '', open: false,
      showModal() {this.open = true;}, close() {this.open = false;}, focus() {this.focused = true;}});
    return nodes.get(id);
  };
  const original = [{id: 11, name: 'First machine'}, {id: 22, name: 'Second machine'}];
  const calls = [], notices = [];
  const state = {remote: original.slice(), failure: '', failRefresh: false, gate: null};
  const context = vm.createContext({
    $: node, devices: original.slice(), selected: 22, page: 'settings', csrf: 'fixture-csrf',
    closePortalMore() {}, render() {}, renderSelector() {},
    commandKey: async () => ({key: 'fixture-command-key'}),
    toast: (...args) => notices.push(args),
    api: async (url, method, body) => {
      calls.push({url, method, body});
      if (url === '/api/v1/devices') {
        if (state.failRefresh) throw new Error('Connection interrupted');
        return {devices: state.remote.slice(), csrf: 'fixture-csrf'};
      }
      assert.equal(url, '/api/v1/devices/claim');
      assert.equal(method, 'POST');
      if (state.gate) await state.gate;
      if (state.failure) throw new Error(state.failure);
      state.remote.push({id: 33, name: 'Added machine'});
      return {ok: true};
    }
  });
  vm.runInContext('let pairingBusy=false;\n' + ['openAddMachine', 'closeAddMachine', 'claimMachine', 'refresh'].map(extract).join('\n'), context);
  return {context, node, state, calls, notices};
}
const event = () => ({preventDefault() {}});
(async () => {
  const f = setup();
  f.context.openAddMachine();
  assert.equal(f.node('pair-dialog').open, true);
  f.node('add-pair-code').value = ' abcd-efgh ';
  await f.context.refresh();
  assert.equal(f.node('add-pair-code').value, ' abcd-efgh ', 'Background refresh preserves input');
  assert.equal(f.context.selected, 22);
  await f.context.claimMachine(event());
  assert.deepEqual(Array.from(f.context.devices, d => d.id), [11, 22, 33]);
  assert.equal(f.context.selected, 33);
  assert.equal(f.context.page, 'overview');
  assert.equal(f.node('pair-dialog').open, false);
  assert.equal(f.calls.find(c => c.method === 'POST').body.code, 'ABCD-EFGH');
  assert.equal(f.calls.find(c => c.method === 'POST').body.command_key, 'fixture-command-key');

  const bad = setup();
  bad.state.failure = 'Pair code is invalid or expired';
  bad.context.openAddMachine();
  bad.node('add-pair-code').value = 'BAD-CODE';
  await bad.context.claimMachine(event());
  assert.equal(bad.node('pair-dialog').open, true);
  assert.equal(bad.node('add-pair-code').value, 'BAD-CODE');
  assert.equal(bad.node('add-pair-error').textContent, bad.state.failure);
  assert.equal(bad.context.selected, 22);
  assert.deepEqual(Array.from(bad.context.devices, d => d.id), [11, 22]);
  assert.equal(bad.node('add-pair-submit').disabled, false);
  bad.context.closeAddMachine();
  assert.equal(bad.node('pair-dialog').open, false);

  const busy = setup();
  let resolve;
  busy.state.gate = new Promise(done => {resolve = done;});
  busy.context.openAddMachine();
  busy.node('add-pair-code').value = 'ABCD-EFGH';
  const pending = busy.context.claimMachine(event());
  await Promise.resolve();
  assert.equal(busy.node('add-pair-submit').disabled, true);
  assert.equal(busy.node('cancel-pair').disabled, true);
  assert.equal(busy.node('add-pair-code').readOnly, true);
  busy.context.closeAddMachine();
  assert.equal(busy.node('pair-dialog').open, true);
  await busy.context.claimMachine(event());
  resolve();
  await pending;
  assert.equal(busy.calls.filter(c => c.method === 'POST').length, 1, 'Double-submit does not duplicate claims');

  const retry = setup();
  retry.context.openAddMachine();
  retry.node('add-pair-code').value = 'ABCD-EFGH';
  retry.state.failRefresh = true;
  await retry.context.claimMachine(event());
  assert.equal(retry.node('pair-dialog').open, false, 'A successful claim is not submitted twice after a refresh failure');
  assert.match(retry.notices[0][0], /Machine paired/);
  assert.equal(retry.state.remote.length, 3);

  const empty = setup();
  empty.context.openAddMachine();
  await empty.context.claimMachine(event());
  assert.equal(empty.calls.length, 0);
  assert.match(empty.node('add-pair-error').textContent, /Enter the pair code/);

  // The Settings entry must remain available in installed PWA mode.
  const settings = extract('settings');
  assert(!settings.includes('installedPortal()'));
  assert(html.includes('id="add-machine"'));
  assert(html.indexOf('<dialog') > html.indexOf('id="page"'));
  console.log('PASS pairing: existing devices, refresh preservation, success selection, errors, retry, double-submit, cancel, and PWA entry');
})().catch(error => {console.error(error); process.exitCode = 1;});
