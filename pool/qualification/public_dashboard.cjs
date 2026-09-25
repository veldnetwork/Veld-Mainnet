/* Website qualification against a real loopback TLS Gateway + Coordinator.
 * Synthetic receipt/payment events are explicitly NOT native mining E2E.
 * Usage: node pool/qualification/public_dashboard.cjs ORIGIN ACCESS CA OUTPUT
 */
'use strict';
const fs = require('fs'),
    path = require('path'),
    assert = require('assert/strict'),
    https = require('https'),
    crypto = require('crypto');
const { chromium } = require('playwright');
const [origin, accessFile, caFile, output] = process.argv.slice(2),
    url = new URL(origin);
assert(
    url.protocol === 'https:' &&
        ['localhost', '127.0.0.1'].includes(url.hostname) &&
        !url.username &&
        !url.password,
    'loopback TLS fixture required',
);
const auth = JSON.parse(fs.readFileSync(accessFile, 'utf8').replace(/^\uFEFF/, ''));
assert.equal(auth.endpoint, origin);
const ca = fs.readFileSync(caFile);
fs.mkdirSync(output, { recursive: true });
const result = {
    status: 'RUNNING',
    scope: 'website UI/API only; synthetic accounting fixtures; real candidate TLS gateway and private access enforcement',
    native_mining_e2e: false,
    mainnet: false,
    checks: [],
    screenshots: [],
};
const save = () =>
    fs.writeFileSync(path.join(output, 'result.json'), JSON.stringify(result, null, 2));
function request(action, payload) {
    return new Promise((resolve, reject) => {
        const data = payload ? JSON.stringify(payload) : null;
        const r = https.request(
            origin + '/v1/' + action,
            {
                method: data ? 'POST' : 'GET',
                ca,
                rejectUnauthorized: true,
                timeout: 20000,
                headers: data
                    ? {
                          'Content-Type': 'application/json',
                          'Content-Length': Buffer.byteLength(data),
                      }
                    : {},
            },
            (res) => {
                let body = '';
                res.on('data', (c) => {
                    body += c;
                    if (body.length > 16384) r.destroy(Error('size limit'));
                });
                res.on('end', () => {
                    try {
                        resolve({
                            status: res.statusCode,
                            headers: res.headers,
                            body: JSON.parse(body),
                        });
                    } catch (e) {
                        reject(e);
                    }
                });
            },
        );
        r.on('timeout', () => r.destroy(Error('timeout')));
        r.on('error', reject);
        r.end(data);
    });
}
let browser;
(async () => {
    try {
        const publicState = await request('public');
        assert.equal(publicState.status, 200);
        assert(publicState.headers['content-security-policy'].includes("frame-ancestors 'none'"));
        assert.equal(publicState.headers['cache-control'], 'no-store');
        assert(!JSON.stringify(publicState).includes(auth.account));
        assert(!JSON.stringify(publicState).includes(auth.token));
        const account = await request('account', { account: auth.account, token: auth.token });
        assert.equal(account.body.ok, true);
        const wrong = await request('account', { account: auth.account, token: '0'.repeat(64) });
        assert.equal(wrong.body.ok, false);
        assert.equal(wrong.body.result, undefined);
        result.checks.push(
            'TLS certificate and hostname verified independently',
            'public API excludes private account identifiers',
            'real coordinator rejects wrong viewing token',
            'CSP and no-store headers',
        );
        browser = await chromium.launch({ channel: 'msedge', headless: true });
        // Disposable certificate only; independently validated above, no system CA change.
        const ctx = await browser.newContext({
            ignoreHTTPSErrors: true,
            viewport: { width: 1440, height: 1000 },
        });
        const page = await ctx.newPage(),
            errors = [],
            outside = [];
        page.on('pageerror', (e) => errors.push(String(e)));
        await page.route('**/*', (route) => {
            if (new URL(route.request().url()).origin !== origin) {
                outside.push(route.request().url());
                return route.abort();
            }
            return route.continue();
        });
        await page.goto(origin);
        await page.waitForFunction(
            () => document.querySelector('#health').textContent === 'Pool service online',
        );
        assert.equal(await page.locator('#active').textContent(), '2');
        assert.equal(await page.locator('#blocks-won').textContent(), '4');
        assert.equal(await page.locator('#total-paid').textContent(), '23.00');
        assert.equal(await page.locator('#hashrate').textContent(), '1.75 kH/s');
        assert.equal(await page.locator('#minimum').textContent(), '1 VELD');
        assert.equal(await page.locator('#fee').textContent(), '0%');
        assert.equal(await page.locator('#schedule').textContent(), 'Daily');
        assert.equal(
            await page.locator('#comining-enabled').textContent(),
            'Not participating yet',
        );
        assert.equal(await page.locator('#public-blocks tr').count(), 4);
        assert.equal(await page.locator('#private').isVisible(), false);
        assert.equal(
            await page.locator('#public-blocks a').count(),
            0,
            'nonmainnet records must not link to mainnet explorer',
        );
        result.checks.push(
            'real public projection rendered exactly',
            'inactive co-mining clearly identified',
            'nonmainnet records do not link to mainnet',
        );
        for (const [name, width, height] of [
            ['desktop', 1440, 1000],
            ['tablet', 768, 1024],
            ['mobile', 390, 844],
            ['narrow', 320, 800],
        ]) {
            await page.setViewportSize({ width, height });
            await page.evaluate(() => scrollTo(0, 0));
            assert(
                await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
                'viewport overflow ' + name,
            );
            await page.screenshot({
                path: path.join(output, 'public-' + name + '.png'),
                fullPage: true,
            });
            result.screenshots.push('public-' + name + '.png');
            if (name === 'desktop')
                await page.screenshot({ path: path.join(output, 'desktop-first-screen.png') });
        }
        result.checks.push('320/390/768/1440 pixel layouts fit viewport');
        await page.setViewportSize({ width: 1440, height: 1000 });
        await page
            .locator('#access')
            .fill(JSON.stringify({ ...auth, endpoint: 'https://another.invalid' }));
        assert.match(await page.locator('#message').textContent(), /not imported/);
        await page.locator('#access').fill(JSON.stringify(auth));
        await page.locator('#view-account').click();
        await page.locator('#private').waitFor();
        await page.waitForFunction(() => document.querySelectorAll('#payments tr').length === 20);
        assert.equal(await page.locator('#paid').textContent(), '23.00000000 VELD');
        assert.equal(await page.locator('#address').textContent(), account.body.result.address);
        await page.locator('#older').click();
        await page.waitForFunction(() => document.querySelectorAll('#payments tr').length === 23);
        assert.equal(await page.locator('#older').isVisible(), false);
        await page
            .locator('#private')
            .screenshot({ path: path.join(output, 'private-account-desktop.png') });
        await page.setViewportSize({ width: 390, height: 844 });
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        await page
            .locator('#private')
            .screenshot({ path: path.join(output, 'private-account-mobile.png') });
        const fills = await page
            .locator('button:visible,.button:visible')
            .evaluateAll((es) =>
                es.map((e) => ({
                    label: e.textContent.trim(),
                    color: getComputedStyle(e).backgroundColor,
                    image: getComputedStyle(e).backgroundImage,
                })),
            );
        for (const fill of fills) {
            for (const m of (fill.color + ' ' + fill.image).matchAll(
                /rgba?\((\d+),\s*(\d+),\s*(\d+)/g,
            )) {
                assert(
                    Math.max(+m[1], +m[2], +m[3]) - Math.min(+m[1], +m[2], +m[3]) < 26 &&
                        Math.max(+m[1], +m[2], +m[3]) < 115,
                    'noncharcoal ' + fill.label,
                );
            }
        }
        result.checks.push(
            'private balances match actual coordinator API fixture',
            '23 payments paginated without duplication',
            'account access is origin bound',
            'all action surfaces charcoal',
        );
        await page.locator('#forget').click();
        assert.equal(await page.locator('#private').isVisible(), false);
        for (const id of [
            'paid',
            'pending',
            'available',
            'reserved',
            'address',
            'lottery',
            'shares',
        ])
            assert.equal(await page.locator('#' + id).textContent(), '', 'private DOM not cleared');
        assert.deepEqual(
            await page.evaluate(() => [localStorage.length, sessionStorage.length]),
            [0, 0],
        );
        assert.equal((await ctx.cookies()).length, 0);
        await page.locator('#access').fill(JSON.stringify({ ...auth, token: '0'.repeat(64) }));
        await page.locator('#view-account').click();
        await page.waitForFunction(() =>
            document.querySelector('#message').textContent.includes('Access refused'),
        );
        assert.equal(await page.locator('#private').isVisible(), false);
        // Faults are browser-injected and distinctly recorded; integrated healthy path above is unmodified.
        await page.route('**/v1/public', (route) =>
            route.fulfill({
                status: 503,
                contentType: 'application/json',
                body: JSON.stringify({ ok: false, retryable: true }),
            }),
        );
        await page.evaluate(() => health());
        assert.equal(await page.locator('#health').textContent(), 'Service unavailable');
        assert.match(await page.locator('#data-message').textContent(), /stale/);
        await page.unroute('**/v1/public');
        await page.evaluate(() => health());
        assert.equal(await page.locator('#health').textContent(), 'Pool service online');
        const bad = structuredClone(publicState.body);
        bad.result.overview.recent_blocks[0].hash = '<img src=x onerror=alert(1)>';
        await page.route('**/v1/public', (route) =>
            route.fulfill({ contentType: 'application/json', body: JSON.stringify(bad) }),
        );
        await page.evaluate(() => health());
        assert.equal(await page.locator('#health').textContent(), 'Service unavailable');
        assert.equal(await page.locator('#public-blocks img').count(), 0);
        await page.unroute('**/v1/public');
        await page.route('**/v1/public', (route) =>
            route.fulfill({ contentType: 'application/json', body: 'x'.repeat(20000) }),
        );
        await page.evaluate(() => health());
        assert.equal(await page.locator('#health').textContent(), 'Service unavailable');
        await page.unroute('**/v1/public');
        const sparse = structuredClone(account.body);
        sparse.result.reward_totals = {};
        await page.route('**/v1/account', (route) =>
            route.fulfill({ contentType: 'application/json', body: JSON.stringify(sparse) }),
        );
        await page.locator('#access').fill(JSON.stringify(auth));
        await page.locator('#view-account').click();
        await page.locator('#private').waitFor();
        assert.equal(
            await page.locator('#reward-totals strong').first().textContent(),
            '0.00000000 VELD',
        );
        await page.unroute('**/v1/account');
        // Slow response must not restore a cleared account.
        await page.locator('#forget').click();
        let release;
        const held = new Promise((r) => (release = r));
        let intercepted;
        const seen = new Promise((r) => (intercepted = r));
        await page.route('**/v1/account', async (route) => {
            intercepted();
            await held;
            await route
                .fulfill({ contentType: 'application/json', body: JSON.stringify(account.body) })
                .catch(() => {});
        });
        await page.locator('#access').fill(JSON.stringify(auth));
        await page.locator('#view-account').click({ noWaitAfter: true });
        await seen;
        await page.locator('#forget').click();
        release();
        await page.waitForTimeout(200);
        assert.equal(await page.locator('#private').isVisible(), false);
        assert.equal(await page.locator('#paid').textContent(), '');
        await page.unroute('**/v1/account');
        await page.reload();
        await page.waitForFunction(
            () => document.querySelector('#health').textContent === 'Pool service online',
        );
        assert.equal(await page.locator('#private').isVisible(), false);
        assert.equal(await page.locator('#token').inputValue(), '');
        result.checks.push(
            'clear removes all private DOM values and aborts in-flight requests',
            'reload has no saved access, storage or cookies',
            'refused access does not display private values',
            'fault injection: outage/recovery, invalid schema, oversized reply',
            'new accounts with absent reward categories show zero',
        );
        assert.deepEqual(errors, []);
        assert.deepEqual(outside, []);
        result.checks.push('no browser script errors or external requests');
        result.status = 'PASS_SCOPED_WEBSITE';
        const source = path.resolve(__dirname, '..', 'web');
        result.asset_sha256 = Object.fromEntries(
            ['index.html', 'pool.css', 'site.css', 'pool.js'].map((n) => [
                n,
                crypto
                    .createHash('sha256')
                    .update(fs.readFileSync(path.join(source, n)))
                    .digest('hex'),
            ]),
        );
    } catch (e) {
        result.status = 'FAILED';
        result.error = String(e);
        result.stack = e.stack;
        process.exitCode = 1;
    } finally {
        if (browser) await browser.close();
        result.finished_utc = new Date().toISOString();
        save();
        console.log(
            JSON.stringify({
                status: result.status,
                error: result.error,
                checks: result.checks.length,
            }),
        );
    }
})();
