'use strict';
const $ = (id) => document.getElementById(id);
let csrf = null,
    revision = null,
    formRevision = null,
    next = '0',
    before = '0',
    initial = true,
    pending = null,
    busy = false,
    loading = false;
function message(text) {
    $('message').textContent = text;
}
function number(text, places) {
    if (!new RegExp('^(0|[1-9][0-9]*)(\\.[0-9]{1,' + places + '})?$').test(text))
        throw Error('Enter a plain decimal amount.');
    const [a, b = ''] = text.split('.');
    return (BigInt(a) * 10n ** BigInt(places) + BigInt(b.padEnd(places, '0'))).toString();
}
function decimal(value, places) {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value))
        throw Error('Invalid amount response.');
    let n = BigInt(value),
        d = 10n ** BigInt(places);
    return n / d + '.' + (n % d).toString().padStart(places, '0');
}
async function call(path, value) {
    const options = {
        method: value === undefined ? 'GET' : 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        signal: AbortSignal.timeout(20000),
        headers: {},
    };
    if (value !== undefined) {
        options.headers['Content-Type'] = 'application/json';
        if (csrf) options.headers['X-CSRF-Token'] = csrf;
        options.body = JSON.stringify(value);
    }
    const r = await fetch(path, options),
        reader = r.body.getReader();
    let chunks = [],
        length = 0;
    for (;;) {
        const x = await reader.read();
        if (x.done) break;
        length += x.value.length;
        if (length > 65536) {
            await reader.cancel();
            throw Error('Response limit exceeded.');
        }
        chunks.push(x.value);
    }
    const raw = new Uint8Array(length);
    let offset = 0;
    for (const c of chunks) {
        raw.set(c, offset);
        offset += c.length;
    }
    const j = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    if (r.status === 401) {
        signedOut();
        throw Error(j.error || 'Sign in again.');
    }
    if (!r.ok || j.ok !== true) {
        const e = Error(j.error || 'Request could not be completed.');
        e.definitive = (r.status === 400 || r.status === 409) && j.retryable !== true;
        throw e;
    }
    return j.result;
}
function signedOut() {
    csrf = null;
    $('console').hidden = true;
    $('logout').hidden = true;
    $('login').hidden = false;
    $('audit').replaceChildren();
    $('metrics').replaceChildren();
}
function signedIn() {
    initial = true;
    $('login').hidden = true;
    $('logout').hidden = false;
    $('console').hidden = false;
}
function controls() {
    for (const id of ['save', 'reconcile', 'reload-settings']) $(id).disabled = busy || !!pending;
    $('retry').hidden = !pending;
    $('retry').disabled = busy;
}
function settings(s) {
    $('minimum').value = decimal(s.minimum_units, 8);
    $('interval').value = String(Number(s.batch_seconds) / 3600);
    $('fee').value = decimal(s.fee_ppm, 4);
    $('payments-paused').checked = s.payments_paused;
    $('comining-paused').checked = s.comining_paused;
}
async function refresh() {
    if (!csrf || loading) return;
    loading = true;
    try {
        const s = await call('/api/snapshot?before=' + before);
        revision = s.revision;
        $('health').textContent =
            s.health.status +
            ' · height ' +
            (s.health.reconciled_height || 'unknown') +
            ' · ' +
            s.health.active_accounts +
            ' active accounts · ' +
            s.health.verified_shares +
            ' verified shares';
        $('identity').textContent =
            'Co-mining ' +
            (s.settings.comining_paused ? 'paused' : 'enabled') +
            ': ' +
            s.identity_status +
            ' · Payments ' +
            (s.settings.payments_paused ? 'paused' : 'enabled') +
            ' · Minimum confirmations: ' +
            s.capabilities.minimum_confirmations;
        $('metrics').replaceChildren();
        for (const [key, label] of [
            ['pending', 'Pending'],
            ['available', 'Available'],
            ['reserved', 'In payment'],
            ['paid', 'Paid'],
            ['deficit', 'Reconciliation deficit'],
        ]) {
            const d = document.createElement('div');
            d.className = 'metric';
            const l = document.createElement('span'),
                v = document.createElement('strong');
            l.textContent = label;
            v.textContent = decimal(s.balances[key], 8) + ' VELD';
            d.append(l, v);
            $('metrics').append(d);
        }
        $('fee-limit').textContent =
            s.capabilities.max_fee_ppm === '0'
                ? 'Service fee is locked at 0% until a separate operator fee ceiling is approved and provisioned.'
                : 'Approved service fee ceiling: ' + decimal(s.capabilities.max_fee_ppm, 4) + '%.';
        $('fee').disabled = s.capabilities.max_fee_ppm === '0';
        $('payments-paused').disabled = !s.capabilities.payments;
        $('comining-paused').disabled = !s.capabilities.comining;
        $('revision').textContent =
            'Recorded policy revision ' +
            revision +
            '. New work and future batches use the updated policy; earned balances are preserved.';
        if (initial) {
            settings(s.settings);
            formRevision = revision;
            initial = false;
        }
        if (formRevision !== revision)
            $('revision').textContent +=
                ' Settings changed elsewhere; load current settings before applying.';
        $('audit').replaceChildren();
        for (const row of s.audit) {
            const tr = document.createElement('tr');
            for (const value of [
                new Date(Number(row.created) * 1000).toLocaleString(),
                row.action,
                row.status,
                row.actor + '\n' + row.reason + (row.detail ? '\n' + row.detail : ''),
            ]) {
                const td = document.createElement('td');
                td.textContent = value;
                tr.append(td);
            }
            if (row.settings) {
                const detail = document.createElement('details'),
                    summary = document.createElement('summary'),
                    pre = document.createElement('pre');
                summary.textContent = 'Policy change';
                pre.textContent = JSON.stringify(
                    { before: row.previous, after: row.settings },
                    null,
                    2,
                );
                detail.append(summary, pre);
                tr.lastElementChild.append(detail);
            }
            $('audit').append(tr);
        }
        if (!s.audit.length) {
            const tr = document.createElement('tr'),
                td = document.createElement('td');
            td.colSpan = 4;
            td.textContent = 'No operator changes recorded.';
            tr.append(td);
            $('audit').append(tr);
        }
        next = s.next_before;
        $('older').hidden = next === '0';
    } catch (e) {
        message(e.message);
    } finally {
        loading = false;
    }
}
async function send() {
    if (busy || !pending) return;
    busy = true;
    controls();
    try {
        const r = await call('/api/' + pending.action, pending.value);
        pending = null;
        message(
            r.status === 'pending'
                ? 'Reconciliation queued. Its result will appear in the audit history.'
                : 'Settings applied and recorded.',
        );
        initial = true;
        before = '0';
        await refresh();
    } catch (e) {
        if (e.definitive) {
            pending = null;
            message(e.message + ' Load current settings and review the form.');
        } else message(e.message + ' Use “Retry the same request” after checking the connection.');
    } finally {
        busy = false;
        controls();
    }
}
function command(action, body) {
    if (pending || busy) return;
    pending = {
        action,
        value: {
            request_id: crypto.randomUUID().replaceAll('-', ''),
            revision: action === 'settings' ? formRevision : revision,
            reason: body.reason,
            ...body,
        },
    };
    send();
}
$('login').addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = $('password').value;
    $('password').value = '';
    try {
        const r = await call('/api/login', { password });
        csrf = r.csrf;
        signedIn();
        message('Signed in.');
        await refresh();
        controls();
    } catch (e) {
        message(e.message);
    }
});
$('logout').addEventListener('click', async () => {
    try {
        await call('/api/logout', {});
        signedOut();
        message('Signed out.');
    } catch (e) {
        message(e.message);
    }
});
$('settings').addEventListener('submit', (e) => {
    e.preventDefault();
    try {
        const settings = {
            minimum_units: number($('minimum').value, 8),
            batch_seconds: String(Number($('interval').value) * 3600),
            fee_ppm: number($('fee').value, 4),
            payments_paused: $('payments-paused').checked,
            comining_paused: $('comining-paused').checked,
        };
        command('settings', { settings, reason: $('reason').value });
    } catch (e) {
        message(e.message);
    }
});
$('reconcile').addEventListener('click', () =>
    command('reconcile', { reason: 'Operator requested canonical reconciliation' }),
);
$('retry').addEventListener('click', send);
$('refresh').addEventListener('click', refresh);
$('reload-settings').addEventListener('click', () => {
    initial = true;
    refresh();
});
$('older').addEventListener('click', () => {
    before = next;
    refresh();
});
$('latest').addEventListener('click', () => {
    before = '0';
    refresh();
});
setInterval(() => {
    if (!document.hidden) refresh();
}, 10000);
(async () => {
    try {
        const r = await call('/api/session');
        csrf = r.csrf;
        signedIn();
        await refresh();
    } catch (e) {
        if (csrf) message(e.message);
    }
})();
