'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const asset = fs.readFileSync(process.argv[2] || path.join(__dirname, '../website/explorer-route-context-v1.js'), 'utf8');
const start = asset.indexOf('// Both block lists derive their badges from the same event feed and renderer.');
const end = asset.indexOf('// Keep the installed app\'s navigation controls mounted when opening Mempool.');
assert(start >= 0 && end > start, 'Both block lists need the shared badge renderer');
const source = asset.slice(start, end);
const flush = async () => { for (let i = 0; i < 8; i++) await new Promise(resolve => setImmediate(resolve)); };

function fixture(route) {
    let now = 100000, timerId = 0, observer;
    const timers = new Map(), events = {}, requests = [];
    class Element {
        constructor(text = '') { this.value = text; this.children = []; this.dataset = {}; this.className = ''; }
        get textContent() { return this.value + this.children.map(child => child.textContent).join(''); }
        set textContent(text) { this.value = text; this.children = []; }
        appendChild(child) { this.children.push(child); }
        replaceChildren() { this.value = ''; this.children = []; }
        querySelector(selector) { assert.equal(selector, '.bk-badges'); return this.children.find(child => child.className === 'bk-badges') || null; }
    }
    function row(height, hash = 'a'.repeat(8) + '…' + 'b'.repeat(6), count = 2) {
        const heading = new Element('#' + height), meta = new Element(hash + ' · Vminer'), tx = new Element(count + ' tx · 5.7 KB');
        return {heading, meta, tx,
            getAttribute: name => name === 'href' ? '/block/height/' + height : null,
            querySelector: selector => ({'.info .h':heading, '.info .s':meta, '.tx':tx})[selector],
            labels: () => heading.querySelector('.bk-badges')?.children.map(child => child.textContent) || [],
            colors: () => heading.querySelector('.bk-badges')?.children.map(child => child.className) || []};
    }
    let rows = [row(5002), row(4997), row(4996), row(4995, undefined, 1)];
    const list = {querySelectorAll: selector => { assert.equal(selector, 'a.bk'); return rows; }, contains: item => rows.includes(item)};
    const document = {hidden:false, readyState:'complete',
        getElementById: id => { assert.equal(id, route === '/' ? 'blocks-list' : 'blocks-container'); return list; },
        createElement: () => new Element(), addEventListener: (name, handler) => { events[name] = handler; }};
    class Clock extends Date { static now() { return now; } }
    vm.runInNewContext(source, {document, location:{pathname:route},
        window:{addEventListener:(name, handler) => { events[name] = handler; }},
        MutationObserver:class { constructor(callback) { observer = callback; } observe(target, options) { assert.equal(target, list); assert.deepEqual({...options}, {childList:true}); } },
        Map, Set, Array, Object, Number, Date:Clock, AbortController, Error,
        setTimeout:(fn, delay) => { const id = ++timerId; timers.set(id, {fn, at:now + delay}); return id; },
        clearTimeout:id => timers.delete(id),
        fetch:(url, options) => new Promise((resolve, reject) => {
            requests.push({url, options, resolve, reject});
            options.signal.addEventListener('abort', () => reject(new Error('Aborted')));
        })});
    return {requests, document, events, row,
        get rows() { return rows; },
        replace: next => { rows = next; observer(); },
        async reply(index, types, status = 200, height, retryAfter) {
            const request = requests[index];
            const blockHeight = height === undefined ? Number(request.url.split('/').pop()) : height;
            request.resolve({ok:status === 200, status, headers:{get:() => retryAfter || null}, json:async () => ({height:blockHeight, events:types.map(type => ({type}))})});
            await flush();
        },
        async advance(ms) { now += ms; for (const [id, timer] of [...timers]) if (timer.at <= now) { timers.delete(id); timer.fn(); } await flush(); }};
}

(async () => {
    for (const route of ['/', '/blocks']) {
        const f = fixture(route);
        assert.equal(f.requests.length, 2, 'Limit event requests to two at a time');
        await f.reply(0, ['coinbase', 'near_miss', 'near_miss', '<img onerror=alert(1)>', '__proto__']);
        assert.deepEqual(f.rows[0].labels(), ['Near miss']);
        assert.deepEqual(f.rows[0].colors(), ['bk-badge veld-near-miss']);
        assert.equal(f.requests[2].url, '/api/v1/events/4996');
        await f.reply(1, ['stake_lock']);
        await f.reply(2, ['btc_header_relay', 'endorsement']);
        assert.deepEqual(f.rows[1].labels(), ['Stake']);
        assert.deepEqual(f.rows[1].colors(), ['bk-badge veld-reward-stake']);
        assert.deepEqual(f.rows[2].labels(), ['BTC hdr', 'Endorse']);
        assert(f.rows[2].colors().includes('bk-badge veld-reward-validator'));
        assert.equal(f.requests.length, 3, 'Coinbase-only blocks need no event request');
        const replacements = f.rows.map((item, index) => f.row([5002,4997,4996,4995][index], undefined, index === 3 ? 1 : 2));
        f.replace(replacements);
        assert.deepEqual(f.rows[0].labels(), ['Near miss'], 'Refresh retains cached labels on newly rendered rows');
        assert.deepEqual(f.rows[1].labels(), ['Stake']);
        assert.equal(f.requests.length, 3);
    }

    const retry = fixture('/blocks');
    await retry.reply(0, [], 503);
    await retry.reply(1, ['stake_lock']);
    await retry.reply(2, ['btc_header_relay']);
    assert.deepEqual(retry.rows[1].labels(), ['Stake'], 'One unavailable event feed must not hide other block labels');
    await retry.advance(6000);
    assert.equal(retry.requests[3].url, '/api/v1/events/5002');
    await retry.reply(3, ['near_miss']);
    assert.deepEqual(retry.rows[0].labels(), ['Near miss']);

    const limited = fixture('/blocks');
    await limited.reply(0, [], 429, undefined, '60');
    await limited.reply(1, ['stake_lock']);
    await limited.reply(2, ['btc_header_relay']);
    await limited.advance(6000);
    assert.equal(limited.requests.length, 3, 'Honor the server retry delay');
    await limited.advance(54000);
    assert.equal(limited.requests[3].url, '/api/v1/events/5002');
    const typeNames = ['btcveld_mint','btcveld_redeem','btcveld_transfer','amm_op','stake_lock','stake_unlock','endorsement','validator_register','staking_distribution','endorsement_distribution','anchor_post','btc_header_relay','near_miss'];
    await limited.reply(3, typeNames);
    assert.deepEqual(limited.rows[0].labels(), ['Mint','Redeem','btcVELD','AMM','Stake','Unstake','Endorse','Validator','Payout','Val payout','Anchor','BTC hdr','Near miss']);

    const page = fixture('/blocks');
    page.replace([page.row(4970)]);
    assert(page.requests[0].options.signal.aborted && page.requests[1].options.signal.aborted);
    await flush();
    assert.equal(page.requests[2].url, '/api/v1/events/4970');
    await page.reply(0, ['near_miss']);
    assert.deepEqual(page.rows[0].labels(), [], 'A previous page response cannot label the new page');
    await page.reply(2, ['stake_unlock']);
    assert.deepEqual(page.rows[0].labels(), ['Unstake']);
    page.replace([page.row(4970, 'c'.repeat(8) + '…' + 'd'.repeat(6))]);
    assert.equal(page.requests.length, 4, 'A replacement block at the same height must fetch its own events');
    await page.reply(3, ['btc_header_relay']);
    assert.deepEqual(page.rows[0].labels(), ['BTC hdr']);

    const paused = fixture('/');
    paused.document.hidden = true; paused.events.visibilitychange(); await flush();
    assert(paused.requests.every(request => request.options.signal.aborted));
    await paused.advance(6000);
    assert.equal(paused.requests.length, 2, 'Hidden pages do not retry');
    paused.document.hidden = false; paused.events.visibilitychange();
    assert.equal(paused.requests.length, 4);
    await paused.reply(2, ['near_miss'], 200, 123);
    assert.deepEqual(paused.rows[0].labels(), [], 'A mismatched event height cannot be labeled or cached');
    console.log('PASS shared Home/Blocks badges, near misses, colors, deduplication, refresh, pagination, reorg, retry and PWA suspension');
})().catch(error => { console.error(error); process.exitCode = 1; });
