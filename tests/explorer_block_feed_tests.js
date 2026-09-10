'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const asset = fs.readFileSync(path.join(__dirname, '../website/explorer-route-context-v1.js'), 'utf8');
const start = asset.lastIndexOf('(function () {', asset.indexOf('var state = { pending: false'));
const end = asset.indexOf('// Keep the installed app\'s navigation controls mounted when opening Mempool.');
assert(start >= 0 && end > start);
const source = asset.slice(start, end);
const flush = async () => { for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve)); };

function fixture() {
    let now = 1800000000000, monotonic = 0, timerId = 0;
    const requests = [], timers = new Map(), events = {};
    class Element {
        constructor(tag = 'div') { this.tag = tag; this.className = ''; this.dataset = {}; this.children = []; this.attrs = new Map(); this.value = ''; }
        set textContent(value) { this.value = String(value); this.children = []; }
        get textContent() { return this.value + this.children.map(child => child.textContent).join(''); }
        appendChild(child) { if (child.tag === '#fragment') child.children.forEach(item => this.appendChild(item)); else this.children.push(child); return child; }
        replaceChildren(...children) { this.children = []; this.value = ''; children.forEach(child => this.appendChild(child)); }
        setAttribute(name, value) { this.attrs.set(name, value); }
        removeAttribute(name) { this.attrs.delete(name); if (name === 'title') this.title = ''; }
    }
    const list = new Element(), tipAge = new Element();
    tipAge.textContent = '+3 m';
    function descendants(node) { return node.children.flatMap(child => [child, ...descendants(child)]); }
    const document = {hidden: false,
        getElementById: id => id === 'blocks-list' ? list : id === 's-tip-age' ? tipAge : null,
        createElement: tag => new Element(tag), createDocumentFragment: () => new Element('#fragment'),
        querySelectorAll: selector => {
            assert.equal(selector, '#blocks-list [data-block-time]');
            return descendants(list).filter(node => node.dataset.blockTime != null);
        },
        querySelector: selector => descendants(list).find(node => selector === '.bk-badges[data-block-hash="' + node.dataset.blockHash + '"]' && node.className === 'bk-badges')};
    const location = new URL('https://explorer.test/');
    class Clock extends Date { static now() { return now; } }
    const window = {addEventListener: (name, handler) => { events[name] = handler; }};
    const context = vm.createContext({window, document, location, Date: Clock, performance: {now: () => monotonic},
        Map, Set, Number, Math, Array, Object, Error, AbortController, shortHash: hash => hash.slice(0, 10), shortAddr: address => address.slice(0, 10),
        setTimeout: (fn, delay) => { const id = ++timerId; timers.set(id, {fn, at: now + delay}); return id; },
        clearTimeout: id => timers.delete(id),
        fetch: (url, options) => new Promise((resolve, reject) => {
            const request = {url, options, resolve, reject}; requests.push(request);
            options.signal.addEventListener('abort', () => reject(new Error('aborted')));
        })});
    vm.runInContext(source, context);
    const hash = height => height.toString(16).padStart(64, '0');
    function batch(height, headerAge = 180, tipHash) {
        const blocks = Array.from({length: Math.min(10, height + 1)}, (_, index) => ({height: height - index,
            hash: hash(height - index), prev_hash: hash(height - index - 1),
            time: Math.floor(now / 1000) - headerAge - index * 180,
            tx_count: 1, size_kb: 2.5, miner: 'VExampleMinerAddress'}));
        if (tipHash) blocks[0].hash = tipHash;
        return {tip_height: height, tip_hash: blocks[0].hash, start: height, end: Math.max(0, height - 9), blocks};
    }
    async function respond(request, data, status = 200, headers = new Map()) {
        request.resolve({ok: status === 200, status, headers, json: async () => data});
        await flush();
    }
    async function advance(ms) {
        now += ms; monotonic += ms;
        for (const [id, timer] of [...timers]) if (timer.at <= now && timers.has(id)) { timers.delete(id); timer.fn(); }
        await flush();
    }
    return {list, tipAge, requests, events, document, location, batch, hash, respond, advance,
        load: (height, tipHash) => window.veldExplorerDashboard.load(height, tipHash || hash(height)),
        ages: () => document.querySelectorAll('#blocks-list [data-block-time]').map(node => node.textContent),
        ageElements: () => document.querySelectorAll('#blocks-list [data-block-time]'),
        skewWallClock: ms => { now += ms; }};
}

(async () => {
    const f = fixture();
    f.load(100);
    assert.equal(f.requests[0].url, '/api/v1/blocks/100/10');
    assert.equal(f.requests[0].options.cache, 'no-store');
    await f.respond(f.requests[0], f.batch(100));
    assert.equal(f.list.children.length, 10);
    assert.equal(f.ages()[0], '3 m', 'Existing blocks must not be presented as new arrivals');
    assert.equal(f.tipAge.textContent, '+3 m');
    assert.equal(f.ageElements()[0].title, undefined, 'The display must not add explanatory text');
    f.load(100); assert.equal(f.requests.length, 1);

    f.load(101);
    await f.respond(f.requests[1], f.batch(101, 530));
    assert.equal(f.ages()[0], '0 s', 'An old mining timestamp must not make a new arrival look delayed');
    assert.equal(f.tipAge.textContent, '+0 s');
    assert.equal(f.ages()[1], '11 m');
    await f.advance(6000); f.load(101);
    assert.equal(f.ages()[0], '6 s');
    assert.equal(f.tipAge.textContent, '+6 s');
    f.skewWallClock(3600000); f.load(101);
    assert.equal(f.ages()[0], '6 s', 'Arrival age must survive wall-clock correction');
    assert.equal(f.requests.length, 2);

    f.load(102);
    f.requests[2].reject(new Error('offline')); await flush();
    assert(f.list.textContent.includes('temporarily unavailable'));
    f.load(102); assert.equal(f.requests.length, 3, 'Failed refresh must respect backoff');
    await f.advance(2000); f.load(102);
    await f.respond(f.requests[3], f.batch(102));
    assert.equal(f.list.children[0].href, '/block/height/102');
    assert.equal(f.ages()[1], '8 s', 'Refreshing the feed must retain arrival times');

    f.load(103); await f.advance(8000);
    assert(f.requests[4].options.signal.aborted, 'Block batch must have a bounded deadline');
    assert(f.list.textContent.includes('temporarily unavailable'));
    await f.advance(2000); f.load(103);
    const malformed = f.batch(103); malformed.blocks[1].hash = 'f'.repeat(64);
    await f.respond(f.requests[5], malformed);
    assert(f.list.textContent.includes('temporarily unavailable'), 'Disconnected pages must be rejected');
    await f.advance(4000); f.load(103);
    await f.respond(f.requests[6], f.batch(103));

    f.load(104);
    await f.respond(f.requests[7], f.batch(104));
    assert.equal(f.list.children[0].href, '/block/height/104');
    f.load(104); assert.equal(f.requests.length, 8);
    f.load(104, 'f'.repeat(64));
    await f.respond(f.requests[8], f.batch(104, 180, 'f'.repeat(64)));
    assert.equal(f.ages()[0], '0 s', 'A different hash at the same height is a new arrival');
    assert(f.requests.every(request => /^\/api\/v1\/blocks\/\d+\/10$/.test(request.url)));

    const empty = fixture(); empty.load(100);
    await empty.respond(empty.requests[0], {}, 429, new Map([['Retry-After', '60']]));
    assert(empty.list.textContent.includes('temporarily unavailable'));
    await empty.advance(30000); empty.load(100); assert.equal(empty.requests.length, 1);
    await empty.advance(30000); empty.load(100); assert.equal(empty.requests.length, 2);
    empty.events.pagehide(); assert(empty.requests[1].options.signal.aborted);

    console.log('PASS Explorer arrival ages, unchanged format, batch validation, retry, timeout and reorg checks');
})().catch(error => { console.error(error); process.exitCode = 1; });
