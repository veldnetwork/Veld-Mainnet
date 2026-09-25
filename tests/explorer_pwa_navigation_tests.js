'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../website/explorer-route-context-v1.js'), 'utf8');
const marker = '// Keep the installed app\'s navigation controls mounted when opening Mempool.';
assert(source.includes(marker));
const navigation = source.slice(source.indexOf(marker));
const flush = () => new Promise(resolve => setImmediate(resolve));

function fixture(options = {}) {
    const events = {}, windowEvents = {}, requests = [], assignments = [], timers = new Map();
    const mounted = [];
    let timerId = 0;
    const location = new URL(options.url || 'https://explorer.test/');
    location.assign = url => assignments.push(url);
    function element(href, active = false) {
        const attrs = new Map(href ? [['href', href]] : []);
        const classes = new Set(active ? ['active'] : []);
        const styles = new Map();
        return {
            href: href ? new URL(href, location).href : '', target: '',
            classList: {contains: name => classes.has(name),
                toggle: (name, on) => on ? classes.add(name) : classes.delete(name)},
            getAttribute: name => attrs.has(name) ? attrs.get(name) : null,
            hasAttribute: name => attrs.has(name),
            setAttribute: (name, value) => attrs.set(name, value),
            removeAttribute: name => attrs.delete(name),
            get attributes() { return [...attrs].map(([name, value]) => ({name, value})); },
            style: {getPropertyValue: name => styles.get(name)?.value || '',
                getPropertyPriority: name => styles.get(name)?.priority || '',
                setProperty: (name, value, priority) => styles.set(name, {value, priority}),
                removeProperty: name => styles.delete(name)},
            querySelectorAll: () => [],
            after: item => mounted.push(item),
            remove: function () { const index = mounted.indexOf(this); if (index >= 0) mounted.splice(index, 1); }
        };
    }
    const origin = element(), nav = element(), more = element();
    const home = element('/', true), mempool = element('/mempool'), mining = element('/mining');
    const links = [home, mempool, mining];
    mounted.push(origin);
    let parsedContent, discardedScript, injectedLink;
    const document = {
        readyState: 'complete', title: 'Veld · Network',
        querySelector: selector => selector === 'body > .wrap' ? origin : selector === '.nav-bar' ? nav : null,
        querySelectorAll: () => links,
        getElementById: () => more,
        addEventListener: (name, handler) => { events[name] = handler; },
        importNode: content => content
    };
    const history = {
        state: null, entries: [{url: location.href, state: null}], index: 0,
        replaceState(state, title, url) { this.state = state; this.entries[this.index] = {url, state}; location.href = new URL(url, location).href; },
        pushState(state, title, url) { this.entries.splice(++this.index); this.entries.push({url, state}); this.state = state; location.href = new URL(url, location).href; },
        move(delta) { this.index += delta; const entry = this.entries[this.index]; this.state = entry.state; location.href = new URL(entry.url, location).href; windowEvents.popstate({state: entry.state}); }
    };
    const context = vm.createContext({
        URL, AbortController, Date, Math, Array, Error, history, document,
        navigator: {standalone: options.standalone !== false},
        window: {location, matchMedia: () => ({matches: false}), scrollTo() {},
            addEventListener: (name, handler) => { windowEvents[name] = handler; },
            setTimeout: (handler, ms) => { timers.set(++timerId, {handler, ms}); return timerId; },
            clearTimeout: id => timers.delete(id)},
        fetch: (url, settings) => new Promise((resolve, reject) => {
            requests.push({url, settings, resolve, reject});
            settings.signal.addEventListener('abort', () => reject(Error('aborted')));
        }),
        DOMParser: class {
            parseFromString() {
                parsedContent = element();
                discardedScript = {removed: false, remove() { this.removed = true; }};
                injectedLink = element('javascript:alert(1)');
                injectedLink.setAttribute('onclick', 'alert(2)');
                parsedContent.querySelectorAll = selector => selector === '*' ? [injectedLink] : [discardedScript];
                return {title: options.badTitle ? 'Error' : 'Veld · Mempool',
                    querySelector: () => options.noContent ? null : parsedContent};
            }
        }
    });
    vm.runInContext(navigation, context);
    function click(target, modifiers = {}) {
        const event = {button: 0, defaultPrevented: false, target: {closest: () => target},
            preventDefault() { this.defaultPrevented = true; }, ...modifiers};
        if (events.click) events.click(event);
        return event;
    }
    async function finish(response = {}) {
        requests.at(-1).resolve({ok: true, url: 'https://explorer.test/mempool',
            headers: {get: () => 'text/html; charset=utf-8'}, text: async () => '<main>Mempool</main>', ...response});
        await flush();
    }
    return {events, windowEvents, requests, assignments, timers, mounted, origin, nav, more,
        home, mempool, mining, links, document, history, location, click, finish,
        get parsedContent() { return parsedContent; },
        get discardedScript() { return discardedScript; },
        get injectedLink() { return injectedLink; }};
}

(async () => {
    assert.equal(fixture({standalone: false}).events.click, undefined, 'Browser tabs retain native navigation');
    assert.equal(fixture({url: 'https://explorer.test/mempool'}).events.click, undefined, 'Direct Mempool loads initialize normally');
    const f = fixture(), nav = f.nav;
    assert.equal(f.click(f.mempool, {ctrlKey: true}).defaultPrevented, false, 'Modified clicks retain their browser behavior');
    assert.equal(f.click(f.mining).defaultPrevented, false, 'Other routes retain native navigation');
    assert.equal(f.click(f.mempool).defaultPrevented, true);
    f.click(f.mempool);
    assert.equal(f.requests.length, 1, 'Repeated taps coalesce');
    assert.equal(f.requests[0].settings.cache, 'no-store', 'Read the current Mempool response');
    assert.equal(f.requests[0].settings.credentials, 'same-origin');
    await f.finish();
    assert.equal(f.nav, nav, 'The same navbar remains mounted');
    assert.equal(f.location.pathname, '/mempool');
    assert.equal(f.document.title, 'Veld · Mempool');
    assert.equal(f.origin.style.getPropertyValue('display'), 'none');
    assert.equal(f.mounted.length, 2);
    assert.equal(f.mempool.getAttribute('aria-current'), 'page');
    assert.equal(f.home.classList.contains('active'), false);
    assert.equal(f.discardedScript.removed, true, 'Fetched scripts are not reinjected');
    assert.equal(f.injectedLink.hasAttribute('onclick'), false);
    assert.equal(f.injectedLink.hasAttribute('href'), false);
    assert.equal(f.click(f.mempool).defaultPrevented, true);
    assert.equal(f.requests.length, 1, 'The selected Mempool tab does not reload the app');
    f.click(f.home);
    assert.equal(f.location.pathname, '/');
    assert.equal(f.document.title, 'Veld · Network');
    assert.equal(f.mounted.length, 1, 'Returning removes the temporary view');
    assert.equal(f.origin.style.getPropertyValue('display'), '');
    assert.equal(f.home.classList.contains('active'), true);
    f.history.move(-1);
    await f.finish();
    assert.equal(f.location.pathname, '/mempool');
    assert.equal(f.mounted.length, 2);
    f.history.move(1);
    assert.equal(f.mounted.length, 1);
    for (let i = 0; i < 3; i++) { f.click(f.mempool); await f.finish(); f.click(f.home); }
    assert.equal(f.mounted.length, 1, 'Repeated navigation does not accumulate hidden views');
    assert.equal(f.assignments.length, 0);

    for (const response of [{ok: false}, {url: 'https://other.test/mempool'},
        {url: 'https://explorer.test/error'}, {headers: {get: () => 'application/json'}},
        {text: async () => 'x'.repeat(2 * 1024 * 1024 + 1)}]) {
        const bad = fixture(); bad.click(bad.mempool); await bad.finish(response);
        assert.deepEqual(bad.assignments, ['/mempool'], 'Invalid responses fall back to ordinary navigation');
        assert.equal(bad.mounted.length, 1, 'Invalid content is never displayed');
    }
    for (const options of [{badTitle: true}, {noContent: true}]) {
        const bad = fixture(options); bad.click(bad.mempool); await bad.finish();
        assert.deepEqual(bad.assignments, ['/mempool']);
    }
    const cancelled = fixture(); cancelled.click(cancelled.mempool); cancelled.click(cancelled.home); await flush();
    assert.equal(cancelled.requests[0].settings.signal.aborted, true);
    assert.equal(cancelled.assignments.length, 0, 'Cancelling navigation cannot redirect afterward');
    const timedOut = fixture(); timedOut.click(timedOut.mempool);
    const timer = [...timedOut.timers.values()][0]; assert.equal(timer.ms, 15000); timer.handler(); await flush();
    assert.deepEqual(timedOut.assignments, ['/mempool'], 'Timeout returns to the normal page path');
    console.log('PASS Explorer PWA navigation: mounted controls, fresh content, history, modifiers, bounded requests, cancellation, sanitization and failure fallback');
})().catch(error => { console.error(error); process.exitCode = 1; });
