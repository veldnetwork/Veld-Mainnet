'use strict';
// Run the shipping navigation and activation functions with an isolated DOM.
// No wallet keys, network services, transaction preparation or signing are used.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const sourcePath = process.argv[2] || path.join(__dirname, '../include/network/ui_desktop.h');
const source = fs.readFileSync(sourcePath, 'utf8');
function extract(name) {
  const begin = source.indexOf('function ' + name + '(');
  const end = source.indexOf('\n}', begin);
  assert(begin >= 0 && end > begin);
  return source.slice(begin, end + 2);
}
function element(tag = '') {
  const classes = new Set();
  return {
    disabled: /\sdisabled(?:\s|=|>)/.test(tag), attributes: {},
    style: {}, dataset: {}, innerHTML: '', value: '',
    classList: {add: name => classes.add(name), remove: name => classes.delete(name),
                contains: name => classes.has(name)},
    setAttribute(name, value) { this.attributes[name] = value; },
    querySelectorAll() { return []; }
  };
}
const quickTag = source.match(/<button\b[^>]*data-act-click="h9c6994df"[^>]*>/)[0];
const submitTag = source.match(/<button\b[^>]*data-act-click="h2e4ed19f"[^>]*>/)[0];
const quick = element(quickTag), submit = element(submitTag);
const walletPage = element(), stakingPage = element(), stakingNav = element();
const message = element(), amount = element(), main = element();
const byId = {'page-wallet': walletPage, 'page-staking': stakingPage,
              'stake-msg': message, 'sk-amount': amount};
let pageLoads = 0, mobilePage = '', transactionCalls = 0;
const context = vm.createContext({
  _veldStakingActivation: {active: false, known: false, supply: 0, threshold: 10000},
  currentAddr: '',
  document: {
    querySelector(selector) {
      if (selector === '.act-round button.ar.stake') return quick;
      if (selector === '#page-staking .btn-em') return submit;
      if (selector === '[data-act-click="h7510b6e8"]') return stakingNav;
      if (selector === '.main') return main;
      throw new Error('Unexpected selector: ' + selector);
    },
    querySelectorAll(selector) {
      if (selector === '.page') return [walletPage, stakingPage];
      if (selector === '.nav-item') return [stakingNav];
      throw new Error('Unexpected selector: ' + selector);
    },
    getElementById: id => byId[id] || null,
    body: {}, documentElement: {}
  },
  window: {scrollTo() {}},
  initHelpTips() {}, fillKeyFields() {}, updateKsIndicator() {}, acRefreshUi() {},
  loadStakingPage() { ++pageLoads; },
  mobNav(page) { mobilePage = page; },
  escHtml: text => text,
  __opLock() { ++transactionCalls; throw new Error('Submission reached operation lock'); },
  rpc() { ++transactionCalls; throw new Error('Unexpected transaction RPC'); }
});
vm.runInContext(['nav', 'setStakingActivationUi', 'stakingActivationErrorText', 'doStake']
  .map(extract).join('\n'), context);
const handlers = [...source.matchAll(/h9c6994df: (function\(event\)\{[^\n]+\})\s*,/g)]
  .map(match => vm.runInContext('(' + match[1] + ')', context));
assert(handlers.length > 0, 'The shortcut must have a shipping click handler');
assert.equal(quick.disabled, false, 'Initial navigation must be enabled');
assert.equal(submit.disabled, true, 'Initial transaction submission must stay locked');
const states = [
  [false, 0, 10000, false],       // Activation status still loading.
  [false, 6800, 10000, true],     // Mainnet has not activated staking.
  [true, 10000, 10000, true],     // Staking has activated.
  [false, 0, 10000, false]        // A later status refresh failed.
];
for (const state of states) {
  context.setStakingActivationUi(...state);
  assert.equal(quick.disabled, false, 'Activation must not disable tab navigation');
  assert.equal(submit.disabled, !state[0]);
  assert.equal(submit.attributes['aria-disabled'], state[0] ? 'false' : 'true');
  for (const handler of handlers) {
    walletPage.style.display = 'block';
    stakingPage.style.display = 'none';
    if (!quick.disabled) handler.call(quick, {});
    assert.equal(walletPage.style.display, 'none');
    assert.equal(stakingPage.style.display, 'block');
    assert(stakingPage.classList.contains('active'));
    assert(stakingNav.classList.contains('active'));
    assert.equal(mobilePage, 'staking');
  }
  if (!state[0]) {
    context.doStake();
    assert.equal(submit.disabled, true);
    assert.match(message.innerHTML, /Staking is (locked|not active yet)/);
  }
}
assert.equal(pageLoads, states.length * handlers.length);
assert.equal(transactionCalls, 0);
console.log('PASS wallet stake navigation: initial state, ' + pageLoads +
  ' desktop/mobile route checks, activation transitions and locked submission');
