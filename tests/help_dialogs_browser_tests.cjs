'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.VELD_PLAYWRIGHT_MODULE || 'playwright');
const root = process.argv[2];
assert(root, 'compiled fixture directory required');
const cases = [];
(async () => {
    const browser = await chromium.launch({ channel: process.env.VELD_BROWSER_CHANNEL || undefined, headless: true });
    try {
        for (const width of [390, 1280]) {
            for (const theme of ['dark', 'light']) {
                const page = await browser.newPage({ viewport: { width, height: 900 } });
                await page.route('**/*', route => route.abort());
                let html = fs.readFileSync(path.join(root, 'wallet.html'), 'utf8');
                // Run the shipped help component against complete wallet markup.
                // Financial workflow scripts have their separate existing tests.
                html = html.replace(/<script\b[^>]*>([\s\S]*?)<\/script>/g, (whole, body) => body.includes('var serial=0,opened=0') ? whole : '');
                await page.setContent(html);
                await page.evaluate(theme => {
                    document.documentElement.dataset.theme = theme;
                    document.querySelectorAll('.page').forEach(el => { el.style.display = 'none'; });
                    document.getElementById('page-wallet').style.display = 'block';
                    document.getElementById('wallet-hero').style.display = 'block';
                }, theme);
                assert.equal(await page.locator('details,summary').count(), 0);
                const open = page.getByRole('button', { name: 'About wallet cleanup', exact: true });
                await open.click();
                const dialog = page.getByRole('dialog', { name: 'About wallet cleanup', exact: true });
                await dialog.waitFor({ state: 'visible' });
                assert.match(await dialog.innerText(), /Review the fee before approving/);
                assert(await dialog.getByRole('button', { name: 'Close', exact: true }).evaluate(el => el === document.activeElement));
                await page.keyboard.press('Tab');
                assert(await dialog.evaluate(el => el.contains(document.activeElement)));
                await page.keyboard.press('Shift+Tab');
                assert(await dialog.evaluate(el => el.contains(document.activeElement)));
                assert(await dialog.evaluate(el => el.scrollWidth <= el.clientWidth + 1));
                await page.screenshot({ path: path.join(root, `help-${theme}-${width}.png`) });
                await page.keyboard.press('Escape');
                await dialog.waitFor({ state: 'hidden' });
                assert(await open.evaluate(el => el === document.activeElement));
                assert(!await page.getByText('Fewer outputs make future transactions smaller', { exact: false }).isVisible());
                const auto = page.getByRole('button', { name: 'About automatic cleanup', exact: true });
                await auto.click();
                const autoDialog = page.getByRole('dialog', { name: 'About automatic cleanup', exact: true });
                assert.match(await autoDialog.innerText(), /Off by default/);
                assert.match(await autoDialog.innerText(), /network fees/);
                await autoDialog.getByRole('button', { name: 'Close', exact: true }).click();
                assert.equal(await page.locator('#w-utxo-consolidate-btn').getAttribute('data-act-click'), 'hconsolidate');
                assert.equal(await page.locator('#bv-lp-details').evaluate(el => el.tagName), 'SECTION');
                await page.evaluate(() => {
                    const section = document.createElement('section');
                    section.setAttribute('data-veld-help', '');
                    section.innerHTML = '<button type=button>Dynamic help</button><p>New explanation</p>';
                    document.getElementById('w-cleanup-card').appendChild(section);
                });
                await page.getByRole('button', { name: 'Dynamic help', exact: true }).click();
                await page.getByRole('dialog', { name: 'Dynamic help', exact: true }).waitFor({ state: 'visible' });
                await page.mouse.click(2, 2);
                await page.getByRole('dialog', { name: 'Dynamic help', exact: true }).waitFor({ state: 'hidden' });
                await page.waitForFunction(() => document.body.style.overflow === '');
                await page.setContent(fs.readFileSync(path.join(root, 'nested.html'), 'utf8'));
                await page.getByRole('button', { name: 'Read explanation', exact: true }).click();
                await page.getByRole('button', { name: 'Sync options', exact: true }).click();
                const nested = page.getByRole('dialog', { name: 'Sync options', exact: true });
                assert.equal(await page.locator('#live-value').count(), 1);
                await page.keyboard.press('Escape');
                await nested.waitFor({ state: 'hidden' });
                assert(await page.getByRole('dialog', { name: 'Syncing and trust', exact: true }).isVisible());
                await page.keyboard.press('Escape');
                await page.getByRole('dialog', { name: 'Syncing and trust', exact: true }).waitFor({ state: 'hidden' });
                await page.waitForFunction(() => document.body.style.overflow === '');
                cases.push({ width, theme });
                await page.close();
            }
        }
        fs.writeFileSync(path.join(root, 'result.json'), JSON.stringify({ status: 'PASS_HELP_DIALOGS_AND_CLEANUP_PRESENTATION', cases }, null, 2));
        console.log('PASS_HELP_DIALOGS_AND_CLEANUP_PRESENTATION cases=' + cases.length);
    } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
