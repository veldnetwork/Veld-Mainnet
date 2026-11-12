'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {extractFunction} = require('./javascript_function_source');
const root = path.join(__dirname, '..');
const native = fs.readFileSync(path.join(root, 'include/network/ui_desktop.h'), 'utf8');
const hosted = fs.readFileSync(path.join(root, 'website/hosted-wallet/wallet-ui-refresh-v1.js'), 'utf8');
let checks = 0;
for (const [source, name] of [[native, 'refreshActiveTab'], [hosted, 'refreshValidators']]) {
    let active = true, calls = 0;
    const context = {
        document: {hidden: false, getElementById: id => id === 'page-validators'
            ? {classList: {contains: () => active}} : null},
        __opLocks: {}, loadValidatorsPage: () => { calls++; },
    };
    context.window = context;
    vm.createContext(context);
    vm.runInContext(extractFunction(source, name), context);
    context[name](); assert.equal(calls, 1); checks++;
    active = false;
    context[name](); assert.equal(calls, 1); checks++;
    active = true; context.__opLocks['validator-op'] = true;
    context[name](); assert.equal(calls, 1); checks++;
    context.__opLocks['validator-op'] = false;
    context[name](); assert.equal(calls, 2); checks++;
    if (name === 'refreshValidators') {
        context.document.hidden = true;
        context[name](); assert.equal(calls, 2); checks++;
    }
}
// Execute the actual native foreground handler, including its selectors.
const begin = native.indexOf('// ── PWA wake-on-foreground refresh');
const end = native.indexOf('// Keep the hidden tier select', begin);
assert(begin >= 0 && end > begin);
let foregroundCalls = 0;
const events = {}, docEvents = {};
const context = {
    document: {visibilityState: 'visible', getElementById: id => id === 'page-validators'
        ? {classList: {contains: () => true}} : null,
        addEventListener: (name, fn) => { docEvents[name] = fn; }},
    __opLocks: {}, loadValidatorsPage: () => { foregroundCalls++; },
    window: {addEventListener: (name, fn) => { events[name] = fn; }},
    Date: {now: () => 5000},
};
vm.runInNewContext(native.slice(begin, end), context);
docEvents.visibilitychange(); assert.equal(foregroundCalls, 1); checks++;
context.Date.now = () => 6000; context.__opLocks['validator-op'] = true;
events.focus(); assert.equal(foregroundCalls, 1); checks++;
context.Date.now = () => 7000; context.__opLocks['validator-op'] = false;
events.pageshow({persisted: true}); assert.equal(foregroundCalls, 2); checks++;
console.log('PASS_VALIDATOR_REFRESH checks=' + checks + ' financial_actions=false');
