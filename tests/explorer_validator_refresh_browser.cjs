'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.VELD_PLAYWRIGHT_MODULE || 'playwright');
const source = fs.readFileSync(path.join(__dirname, '../website/explorer-route-context-v1.js'), 'utf8');
const begin = source.indexOf('  var validatorRefreshBusy = false;');
const end = source.indexOf('  function colorRewardBadge(', begin);
assert(begin > 0 && end > begin);
const script = source.slice(begin, end);
(async () => {
    const browser = await chromium.launch({channel: process.env.VELD_BROWSER_CHANNEL || undefined, headless: true});
    let checks = 0;
    try {
        for (const width of [390, 1280]) {
            const page = await browser.newPage({viewport: {width, height: 900}});
            let minimum = '10000 VELD', count = '1', fail = false, invalid = false, navigations = 0, requests = 0;
            await page.clock.install();
            await page.route('**/*', async route => {
                assert.equal(route.request().url(), 'http://127.0.0.1:31289/validators');
                assert.equal(route.request().method(), 'GET');
                if (route.request().isNavigationRequest()) navigations++;
                else requests++;
                const html = '<!doctype html><title>Validators</title><div class="stat-grid">' +
                    '<div class="stat"><span class="stat-label">Min Stake to Register</span><span class="stat-value" id="minimum">' + minimum + '</span></div>' +
                    '<div class="stat"><span class="stat-label">Validators</span><span class="stat-value" id="count">' + count + '</span></div></div><script>' + script + '</script>';
                await route.fulfill({status: fail ? 503 : 200, contentType: 'text/html', body: invalid ? '<title>Temporarily unavailable</title>' : html});
            });
            await page.goto('http://127.0.0.1:31289/validators');
            await page.evaluate(() => window.loadValidatorsPage());
            assert.equal(navigations, 1); checks++;
            minimum = '5000 VELD';
            await page.clock.fastForward(6000);
            await page.evaluate(() => { window.loadValidatorsPage(); });
            await page.waitForFunction(() => document.getElementById('minimum')?.textContent === '5000 VELD');
            assert.equal(navigations, 2); checks++;
            // A reorganization restores the server's historical requirement.
            minimum = '10000 VELD';
            await page.clock.fastForward(6000);
            await page.evaluate(() => { window.loadValidatorsPage(); });
            await page.waitForFunction(() => document.getElementById('minimum')?.textContent === '10000 VELD');
            assert.equal(navigations, 3); checks++;
            count = '2';
            await page.clock.fastForward(6000);
            await page.evaluate(() => { window.loadValidatorsPage(); });
            await page.waitForFunction(() => document.getElementById('count')?.textContent === '2');
            assert.equal(navigations, 4); checks++;
            for (const kind of ['failure', 'invalid', 'unchanged']) {
                fail = kind === 'failure'; invalid = kind === 'invalid';
                await page.clock.fastForward(6000);
                const before = requests;
                await page.evaluate(() => Promise.all([window.loadValidatorsPage(), window.loadValidatorsPage()]));
                assert.equal(requests, before + 1);
                assert.equal(navigations, 4);
                assert.equal(await page.locator('#minimum').textContent(), '10000 VELD');
                checks += 3;
            }
            await page.close();
        }
    } finally { await browser.close(); }
    console.log(JSON.stringify({status: 'PASS_EXPLORER_VALIDATOR_ACTIVATION_REFRESH', checks, widths: [390, 1280], financial_actions: false, network: 'intercepted loopback fixture only'}));
})().catch(error => { console.error(error); process.exitCode = 1; });
