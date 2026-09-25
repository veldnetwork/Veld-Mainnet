const fs = require('fs'),
    path = require('path'),
    assert = require('assert/strict'),
    crypto = require('crypto'),
    { chromium } = require('playwright');
const S = path.resolve(__dirname, '..'),
    O = path.resolve(process.argv[2]);
fs.mkdirSync(O);
const html = fs
    .readFileSync(path.join(S, 'src/veld-miner-portal.py'), 'utf8')
    .split('PORTAL_HTML = r"""')[1]
    .split('"""')[0];
const evidence = {
    status: 'RUNNING',
    scope: 'Real portal browser crypto, controls and acknowledgement workflow; isolated fixture transport; no live commands',
    checks: [],
};
const check = (v, label) => {
    assert(v, label);
    evidence.checks.push(label);
};
(async () => {
    let browser;
    try {
        browser = await chromium.launch({ channel: 'msedge', headless: true });
        const context = await browser.newContext({
            viewport: { width: 390, height: 844 },
            serviceWorkers: 'block',
        });
        const tab = await context.newPage();
        let key = null,
            command = null,
            phase = 0,
            tick = 1790117000,
            tamper = false;
        const d = {
            id: 4,
            name: 'Disposable laptop',
            online: true,
            version: '3.2.4',
            command_key_id: '',
            command_sequence: 0,
            last_seen: tick,
            snapshot: {
                pool_remote_control: true,
                remote_control: true,
                process_running: false,
                pool: {
                    running: false,
                    current: false,
                    state: 'stopped',
                    active_workers: 0,
                    configured_workers: 14,
                    hashrate: 0,
                },
            },
        };
        const commands = [];
        const errors = [];
        tab.on('pageerror', (e) => errors.push(e.message));
        await tab.route('**/*', async (route) => {
            const req = route.request(),
                u = new URL(req.url());
            if (u.hostname !== 'fixture.test') return route.abort();
            if (u.pathname === '/') return route.fulfill({ contentType: 'text/html', body: html });
            if (u.pathname === '/api/v1/session')
                return route.fulfill({ json: { csrf: 'fixture-csrf' } });
            if (u.pathname === '/api/v1/devices') {
                d.last_seen = ++tick;
                if (command && phase >= 3) {
                    d.snapshot.pool.running = command.action === 'pool.start';
                    d.snapshot.pool.current = true;
                    d.snapshot.pool.state = d.snapshot.pool.running ? 'hashing' : 'stopped';
                    d.snapshot.pool.active_workers = d.snapshot.pool.running ? 14 : 0;
                }
                return route.fulfill({ json: { devices: [d] } });
            }
            if (req.method() !== 'POST') return route.abort();
            const body = req.postDataJSON();
            check(
                req.headers()['x-csrf-token'] === 'fixture-csrf',
                'mutating request has CSRF binding',
            );
            if (u.pathname === '/api/v1/devices/trust-key') {
                key = body.command_key;
                check(body.id === 4, 'trust key bound to selected device');
                return route.fulfill({ json: { ok: true } });
            }
            if (u.pathname === '/api/v1/devices/command') {
                check(
                    body.id === 4 &&
                        Object.keys(body.payload).length === 0 &&
                        ['pool.start', 'pool.stop'].includes(body.action),
                    'signed command changes only selected machine pool lifecycle',
                );
                const envelope = `VELD_PORTAL_COMMAND_V3\n${body.id}\n${body.sequence}\n${body.issued_at}\n${body.expires_at}\n${body.nonce}\n${body.action}\n{}`;
                check(
                    crypto.verify(
                        'sha256',
                        Buffer.from(envelope),
                        {
                            key: crypto.createPublicKey({ key, format: 'jwk' }),
                            dsaEncoding: 'ieee-p1363',
                        },
                        Buffer.from(body.signature, 'base64url'),
                    ),
                    'real browser P-256 signature verifies independently',
                );
                check(body.sequence === d.command_sequence + 1, 'monotonic signed sequence');
                d.command_sequence = body.sequence;
                d.command_key_id = body.key_id;
                command = body;
                phase = 0;
                commands.push(body);
                return route.fulfill({ json: { command_id: commands.length } });
            }
            if (u.pathname === '/api/v1/devices/command-status') {
                check(
                    body.id === 4 && body.command_id === commands.length,
                    'receipt polling bound to original selected machine',
                );
                ++phase;
                return route.fulfill({
                    json: {
                        command: {
                            id: tamper ? 999 : commands.length,
                            device_id: 4,
                            action: command.action,
                            sequence: command.sequence,
                            state: phase < 2 ? 'delivered' : 'completed',
                            result: '',
                        },
                    },
                });
            }
            return route.abort();
        });
        await tab.goto('https://fixture.test/');
        await tab.waitForSelector('#mobile-nav:not([hidden])');
        await tab.evaluate(() => {
            page = 'pool';
            render();
        });
        await tab.locator('#pool-start').click();
        await tab.waitForFunction(() => poolJobs.get(4)?.message.includes('acknowledge'));
        check(
            await tab.locator('#pool-start').isDisabled(),
            'repeated start disabled while waiting',
        );
        await tab.waitForFunction(() => poolJobs.get(4)?.message.startsWith('Start accepted'));
        check(
            !(await tab.locator('#pool-command-status').textContent()).includes('resumed'),
            'completed command receipt alone does not claim mining',
        );
        await tab.waitForFunction(() => poolJobs.get(4)?.busy === false, {}, { timeout: 20000 });
        check(
            (await tab.locator('#pool-command-status').textContent()).includes(
                'processing pool work',
            ),
            'later current hashing report confirms resume',
        );
        await tab.locator('#pool-stop').click();
        await tab.waitForFunction(() => poolJobs.get(4)?.busy === false, {}, { timeout: 20000 });
        check(
            (await tab.locator('#pool-command-status').textContent()).includes(
                'Automatic pool resume is off',
            ),
            'later stopped report confirms stop',
        );
        tamper = true;
        await tab.locator('#pool-start').click();
        await tab.waitForFunction(() => poolJobs.get(4)?.busy === false, {}, { timeout: 20000 });
        check(
            (await tab.locator('#pool-command-status').textContent()).includes('receipt mismatch'),
            'wrong command receipt fails closed',
        );
        command = null;
        d.snapshot.pool_remote_control = false;
        await tab.evaluate(() => refresh());
        check(
            (await tab.locator('#pool-start').isDisabled()) &&
                (await tab.locator('#pool-stop').isDisabled()),
            'older clients cannot send unsupported pool commands',
        );
        d.snapshot.pool_remote_control = true;
        d.online = false;
        await tab.evaluate(() => refresh());
        check(
            (await tab.locator('#pool-start').isDisabled()) &&
                (await tab.locator('#pool-control-note').textContent()).includes('offline'),
            'offline machine does not advertise remote wake',
        );
        d.online = true;
        d.snapshot.remote_control = false;
        await tab.evaluate(() => refresh());
        check(
            await tab.locator('#pool-start').isDisabled(),
            'unready pairing cannot send a pool command',
        );
        await tab.screenshot({ path: path.join(O, 'pool-controls-mobile.png') });
        check(errors.length === 0, 'no browser errors');
        evidence.status = 'PASS_PORTAL_POOL_BROWSER_CONTROLS';
        evidence.signedCommands = commands.map((c) => ({
            device: c.id,
            action: c.action,
            sequence: c.sequence,
        }));
    } catch (e) {
        evidence.status = 'FAILED';
        evidence.error = e.stack;
        process.exitCode = 1;
    } finally {
        if (browser) await browser.close();
        fs.writeFileSync(path.join(O, 'result.json'), JSON.stringify(evidence, null, 2));
        console.log(
            JSON.stringify({
                status: evidence.status,
                checks: evidence.checks.length,
                error: evidence.error,
            }),
        );
    }
})();
