'use strict';
// Offline lifecycle tests: no real browser storage, wallet, or network is used.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.join(__dirname, '..');

async function checkWorker(file, prefix) {
  const handlers = {}, deleted = [], reads = [];
  let claimed = 0, installed = 0, failure = false;
  const origin = {status: 429, body: 'current response'};
  const context = vm.createContext({
    self: {addEventListener: (name, fn) => { handlers[name] = fn; },
      skipWaiting: async () => { installed++; }, clients: {claim: async () => { claimed++; }}},
    caches: {keys: async () => [prefix+'old', 'unrelated-cache'],
      delete: async key => { deleted.push(key); },
      open: () => { throw Error('Must not open or read saved pages'); },
      match: () => { throw Error('Must not return an old response'); }},
    fetch: async (request, options) => {
      reads.push({request, options});
      if (failure) throw Error('offline');
      return origin;
    }
  });
  vm.runInContext(fs.readFileSync(path.join(root, file), 'utf8'), context);
  for (const name of ['install', 'activate']) {
    let promise; handlers[name]({waitUntil: p => { promise = p; }}); await promise;
  }
  assert.equal(installed, 1); assert.equal(claimed, 1);
  assert.deepEqual(deleted, [prefix+'old'], 'Only application caches are removed');
  for (const destination of ['document', 'script', 'style', '']) {
    let promise;
    const request = {method: 'GET', destination};
    handlers.fetch({request, respondWith: p => { promise = p; }});
    assert.equal(await promise, origin, 'Return the actual status, including 429');
    assert.equal(reads.at(-1).options.cache, 'no-store');
  }
  failure = true;
  let promise;
  handlers.fetch({request: {method: 'GET', destination: 'document'}, respondWith: p => { promise = p; }});
  await assert.rejects(promise, /offline/);
  const before = reads.length;
  handlers.fetch({request: {method: 'POST'}, respondWith: () => { throw Error('Do not intercept signing requests'); }});
  assert.equal(reads.length, before);
}

async function checkNavigation() {
  const source = fs.readFileSync(path.join(root, 'website/explorer-route-context-v1.js'), 'utf8');
  for (const route of ['/', '/blocks', '/mempool', '/mining', '/rules', '/liquidity']) {
    const docListeners = {}, winListeners = {};
    let reloads = 0;
    const context = vm.createContext({
      navigator: {standalone: false},
      location: {pathname: route},
      window: {location: {pathname: route, reload: () => { reloads++; }},
        matchMedia: () => ({matches: false}), addEventListener: (name, fn) => { winListeners[name] = fn; }},
      document: {readyState: 'loading', documentElement: {dataset: {}},
        head: {appendChild() {}}, createElement: () => ({}),
        addEventListener: (name, fn) => { docListeners[name] = fn; }}
    });
    vm.runInContext(source, context);
    assert.equal(docListeners.click, undefined, route+' must use native link navigation');
    assert.equal(context.window.__veldExplorerSoftTxNav, true, 'Legacy inline partial navigation is disabled');
    winListeners.pageshow({persisted: false}); assert.equal(reloads, 0);
    winListeners.pageshow({persisted: true}); assert.equal(reloads, 1);
  }
}

(async () => {
  await checkWorker('website/explorer-sw.js', 'veld-explorer-shell-');
  await checkWorker('website/wallet-sw.js', 'veld-wallet-');
  await checkNavigation();
  console.log('PASS: current route navigation; fresh document/script/style/data reads; 429 preserved; offline rejects saved responses; only app caches removed; POST requests untouched');
})().catch(error => { console.error(error); process.exitCode = 1; });
