/* Presentation-only compatibility for Explorer origins predating the Pool navigation update. */
(function () {
    'use strict';
    var icon =
        '<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="18" r="3"/><circle cx="19" cy="18" r="3"/><path d="m10.5 7.5-4 8m7-8 4 8M8 18h8"/></svg>';
    function update() {
        document.querySelectorAll('.nm-grid,.sn-links,.snav').forEach(function (group) {
            var links = Array.from(group.children).filter(function (e) {
                return e.tagName === 'A';
            });
            if (!links.length) return;
            var pool = links.find(function (e) {
                return e.getAttribute('href') === '/pool';
            });
            var how = links.find(function (e) {
                return e.getAttribute('href') === 'https://veld.network/how-to/';
            });
            if (!pool) {
                var reference = links.find(function (e) {
                    return e.getAttribute('href') === '/liquidity';
                });
                if (!reference) return;
                pool = document.createElement('a');
                pool.className = reference.className.replace(/\bactive\b/g, '').trim();
                pool.setAttribute('href', '/pool');
                pool.innerHTML = '<span class="ic"></span><span class="lb">Pool</span>';
            }
            var holder = pool.querySelector('.ic');
            if (holder) holder.innerHTML = icon;
            if (how) group.appendChild(how);
            group.appendChild(pool);
        });
        // The sidebar container name varies between the native and hosted pages.
        document.querySelectorAll('a.sn-link[href="/pool"]').forEach(function (pool) {
            var holder = pool.querySelector('.ic');
            if (holder) holder.innerHTML = icon;
            var group = pool.parentElement;
            var how = group.querySelector('a[href="https://veld.network/how-to/"]');
            var foot = group.querySelector(':scope > .sn-foot');
            if (how && how.parentElement === group) group.insertBefore(how, foot);
            group.insertBefore(pool, foot);
        });
    }
    if (document.readyState === 'loading')
        document.addEventListener('DOMContentLoaded', update, { once: true });
    else update();
})();

/* BEGIN GENERATED PUBLIC POOL OVERVIEW */
/* Public pool statistics. No account credentials or wallet access. */
(function () {
    'use strict';
    var page = document.querySelector('.pool-page');
    if (!page || document.getElementById('pool-overview')) return;
    var overview = document.createElement('section');
    overview.id = 'pool-overview';
    overview.setAttribute('aria-label', 'Pool performance and earnings');
    overview.innerHTML =
        '<div class="pool-overview-grid">' +
        '<article class="tile"><div class="l">Pool hashrate</div><div class="v" id="pool-rate">—</div><small id="pool-rate-note">Measured from verified work</small></article>' +
        '<article class="tile"><div class="l">Blocks won</div><div class="v" id="pool-blocks">—</div><small>Canonical pool blocks</small></article>' +
        '<article class="tile"><div class="l">Mining rewards earned</div><div class="v" id="pool-earned">—</div><small>Actual miner outputs · VELD</small></article>' +
        '<article class="tile"><div class="l">Paid to miners</div><div class="v" id="pool-paid">—</div><small id="pool-paid-note">Confirmed payments · VELD</small></article></div>' +
        '<p class="pool-note" id="pool-stats-updated" role="status">Loading pool statistics…</p>';
    var intro = page.querySelector('.pool-intro') || page.querySelector('h2');
    intro.insertAdjacentElement('afterend', overview);
    var recent = document.createElement('section');
    recent.className = 'pool-recent';
    recent.innerHTML =
        '<h3 id="pool-recent-title">Recent pool blocks</h3><p class="pool-note">Rewards need 120+ confirmations and must be spendable before payment.</p>' +
        '<div class="pool-block-table"><table aria-labelledby="pool-recent-title"><thead><tr><th scope="col">Block</th><th scope="col">Miner reward</th><th scope="col">Confirmations</th><th scope="col">Status</th></tr></thead><tbody id="pool-block-rows"></tbody></table></div>' +
        '<div class="pool-extra-rewards"><p>Lottery winnings <strong id="pool-lottery-earned">—</strong></p><p>Staking distributions <strong id="pool-stake-earned">—</strong></p></div>' +
        '<p class="pool-note">Earned rewards include funds still maturing or waiting for a payment batch. They are different from confirmed payments.</p>';
    var setup = Array.from(page.querySelectorAll('h3')).find(function (h) {
        return h.textContent === 'Start pool mining';
    });
    if (setup) page.insertBefore(recent, setup);
    else page.appendChild(recent);
    function put(id, text) {
        document.getElementById(id).textContent = text;
    }
    function object(v) {
        if (!v || typeof v !== 'object' || Array.isArray(v)) throw Error('Object required');
        return v;
    }
    function uint(v) {
        if (typeof v !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(v))
            throw Error('Invalid integer');
        return BigInt(v);
    }
    function money(v, places) {
        var n = uint(v),
            fraction = (n % 100000000n).toString().padStart(8, '0');
        return (
            (n / 100000000n).toLocaleString() +
            '.' +
            (places === 2 ? fraction.slice(0, 2) : fraction.replace(/0+$/, '').padEnd(2, '0'))
        );
    }
    function count(v) {
        return uint(v).toLocaleString();
    }
    function rate(v) {
        var n = uint(v),
            scale = n >= 1000000n ? 1000000n : n >= 1000n ? 1000n : 1n;
        return (
            (n / scale).toLocaleString() +
            (scale > 1n ? '.' + (((n % scale) * 100n) / scale).toString().padStart(2, '0') : '') +
            (scale === 1000000n ? ' MH/s' : scale === 1000n ? ' kH/s' : ' H/s')
        );
    }
    function validate(payload) {
        object(payload);
        var result = object(payload.result);
        if (
            payload.ok !== true ||
            result.chain !== '7be77ab9e820bd9ffb60b269b45ced48288056e5839a1135fafc2f8557000a88'
        )
            throw Error('Wrong network');
        var o = object(result.overview),
            w = object(o.work);
        object(o.payments);
        object(o.reward_totals);
        if (
            o.version !== 1 ||
            w.method !== 'verified-expected-work' ||
            w.bucket_seconds !== '10' ||
            uint(w.window_seconds) > 600n ||
            typeof w.warming_up !== 'boolean'
        )
            throw Error('Unknown statistics');
        if (w.hashrate_hs !== null) uint(w.hashrate_hs);
        uint(w.sample_shares);
        uint(o.blocks_won);
        uint(o.payments.paid_units);
        uint(o.payments.confirmed_transactions);
        ['mining', 'comine_payout', 'staking_distribution'].forEach(function (k) {
            uint(o.reward_totals[k]);
        });
        if (!Array.isArray(o.recent_blocks) || o.recent_blocks.length > 12)
            throw Error('Too many blocks');
        o.recent_blocks.forEach(function (b) {
            object(b);
            uint(b.height);
            uint(b.amount_units);
            uint(b.confirmations);
            if (
                !/^[0-9a-f]{64}$/.test(b.hash) ||
                !['pending', 'available', 'orphaned'].includes(b.state)
            )
                throw Error('Invalid block');
        });
        if (typeof result.co_mining_enabled !== 'boolean') throw Error('Invalid co-mining state');
        return { overview: o, coMining: result.co_mining_enabled };
    }
    function row(text, label) {
        var td = document.createElement('td');
        td.textContent = text;
        td.dataset.label = label;
        return td;
    }
    function empty(text) {
        var tr = document.createElement('tr'),
            td = row(text, '');
        td.colSpan = 4;
        tr.appendChild(td);
        document.getElementById('pool-block-rows').replaceChildren(tr);
    }
    function render(data) {
        var o = data.overview;
        put('pool-rate', o.work.hashrate_hs === null ? 'Measuring…' : rate(o.work.hashrate_hs));
        put(
            'pool-rate-note',
            (o.work.warming_up ? 'Warming up · ' : '') +
                count(o.work.sample_shares) +
                ' verified shares · ' +
                o.work.window_seconds +
                's window',
        );
        put('pool-blocks', count(o.blocks_won));
        put('pool-earned', money(o.reward_totals.mining, 2));
        put('pool-paid', money(o.payments.paid_units, 2));
        document.getElementById('pool-earned').title = money(o.reward_totals.mining) + ' VELD';
        document.getElementById('pool-paid').title = money(o.payments.paid_units) + ' VELD';
        var lotteryNote = document.getElementById('pool-public-comining-note');
        if (lotteryNote)
            lotteryNote.textContent = data.coMining
                ? 'Co-mining is enabled. Only confirmed pool winnings create earnings.'
                : 'The pool needs 1,000 VELD staked to qualify. Lottery winnings and staking distributions are shared with contributors.';
        put(
            'pool-paid-note',
            count(o.payments.confirmed_transactions) + ' confirmed payments · VELD',
        );
        put('pool-lottery-earned', money(o.reward_totals.comine_payout) + ' VELD');
        put('pool-stake-earned', money(o.reward_totals.staking_distribution) + ' VELD');
        var rows = document.createDocumentFragment();
        o.recent_blocks.forEach(function (b) {
            var tr = document.createElement('tr'),
                block = row('', 'Block'),
                link = document.createElement('a');
            link.href = '/block/' + b.hash;
            link.textContent = '#' + count(b.height);
            block.className = 'pool-block-height';
            block.appendChild(link);
            tr.appendChild(block);
            var reward = row(money(b.amount_units), 'Miner reward'),
                unit = document.createElement('span');
            reward.className = 'pool-block-reward';
            unit.className = 'pool-block-unit';
            unit.textContent = ' VELD';
            reward.appendChild(unit);
            tr.appendChild(reward);
            var confirmations = row(count(b.confirmations), 'Confirmations'),
                label = document.createElement('span');
            confirmations.className = 'pool-block-confirmations';
            label.className = 'pool-mobile-label';
            label.textContent = uint(b.confirmations) === 1n ? ' confirmation' : ' confirmations';
            confirmations.appendChild(label);
            tr.appendChild(confirmations);
            var status = row('', 'Status'),
                badge = document.createElement('span');
            status.className = 'pool-block-status';
            badge.className = 'pool-block-state ' + b.state;
            badge.textContent = { pending: 'Maturing', available: 'Mature', orphaned: 'Orphaned' }[
                b.state
            ];
            status.appendChild(badge);
            tr.appendChild(status);
            rows.appendChild(tr);
        });
        document.getElementById('pool-block-rows').replaceChildren(rows);
        if (!o.recent_blocks.length) empty('No pool blocks recorded yet.');
        put('pool-stats-updated', 'Statistics updated ' + new Date().toLocaleTimeString());
    }
    var busy = false,
        next = 0;
    async function refresh() {
        if (busy || document.hidden || Date.now() < next) return;
        busy = true;
        next = Date.now() + 30000;
        var abort = new AbortController(),
            timer = setTimeout(function () {
                abort.abort();
            }, 8000);
        try {
            var response = await fetch('https://pool.veld.network/v1/public', {
                credentials: 'omit',
                referrerPolicy: 'no-referrer',
                redirect: 'error',
                cache: 'no-store',
                signal: abort.signal,
            });
            if (!response.ok || !response.body) throw Error('Unavailable');
            var reader = response.body.getReader(),
                chunks = [],
                size = 0;
            for (;;) {
                var part = await reader.read();
                if (part.done) break;
                size += part.value.length;
                if (size > 32768) {
                    await reader.cancel();
                    throw Error('Response too large');
                }
                chunks.push(part.value);
            }
            var bytes = new Uint8Array(size),
                offset = 0;
            chunks.forEach(function (c) {
                bytes.set(c, offset);
                offset += c.length;
            });
            render(validate(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))));
        } catch (_) {
            [
                'pool-rate',
                'pool-blocks',
                'pool-earned',
                'pool-paid',
                'pool-lottery-earned',
                'pool-stake-earned',
            ].forEach(function (id) {
                put(id, '—');
            });
            put('pool-rate-note', 'Waiting for verified work statistics');
            put('pool-paid-note', 'Confirmed payments · VELD');
            put('pool-stats-updated', 'Statistics unavailable. Retrying automatically.');
            empty('Block history is temporarily unavailable.');
        } finally {
            clearTimeout(timer);
            busy = false;
        }
    }
    empty('Loading recent blocks…');
    setInterval(refresh, 1000);
    refresh();
})();
