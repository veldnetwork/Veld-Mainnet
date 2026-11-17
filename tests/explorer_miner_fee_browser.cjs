'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.VELD_PLAYWRIGHT_MODULE || 'playwright');
const script = fs.readFileSync(path.join(__dirname, '../website/explorer-transactions-v1.js'), 'utf8');
const ids = ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)];
const address = 'VYTVc2e49QRPbb2LWSeRBH95GsmYdszfRC';
const fixtures = [
  {name:'zero', fees:[], expected:'0 VELD'},
  {name:'one-unit-fees', fees:['-0.00000001','-0.00000002'], expected:'0.00000003 VELD'},
  {name:'unresolved', fees:['Unavailable'], expected:'Unavailable'},
  {name:'wrong-block', fees:['-0.01'], wrongBlock:true, expected:'Unavailable'},
  {name:'history-fallback', fees:['Unavailable'], history:[{txid:ids[1],block_height:34750,fee_veld:0.001,type:'sent'}], expected:'0.001 VELD'},
  {name:'recipient-zero-preserves-known-fee', fees:['-0.002'], history:[{txid:ids[1],block_height:34750,fee_veld:0,type:'received',net_veld:5}], expected:'0.002 VELD'},
  {name:'recipient-zero-remains-unknown', fees:['Unavailable'], history:[{txid:ids[1],block_height:34750,fee_veld:0,type:'received',net_veld:5}], expected:'Unavailable'},
  {name:'validator-payout-source', fees:['Unavailable'], types:['VALIDATOR PAYOUT'], funding:'VQ3MkHSNrXYXiWQErPfUUu4hWWEVvpfAFT', history:[{txid:ids[1],block_height:34750,fee_veld:0,type:'endorsement_reward',net_veld:-5}], expected:'0 VELD'},
  {name:'vault-payout-source', fees:['Unavailable'], types:['STAKING REWARDS'], funding:'VVzm6RG8W1t3U9KQYoD34z49jHcYb1sXdv', history:[{txid:ids[1],block_height:34750,fee_veld:0,type:'staking_distribution',net_veld:-5}], expected:'0 VELD'},
  {name:'legacy', height:34749, fees:['-0.01'], expected:null}
];

(async () => {
  const browser = await chromium.launch({headless:true, ...(process.env.VELD_BROWSER_CHANNEL ? {channel:process.env.VELD_BROWSER_CHANNEL} : {})});
  const results = [];
  try {
    for (const width of [390,1440]) for (const fixture of fixtures) {
      const page = await browser.newPage({viewport:{width,height:900}});
      const errors = [];
      page.on('pageerror',e=>errors.push(e.message));
      const height = fixture.height || 34750;
      const txids = ids.slice(0, fixture.fees.length + 1);
      const rows = txids.map((id,i)=>`<tr><td><a href="/tx/${id}">${id}</a></td><td><span>${i ? fixture.types?.[i-1] || 'TRANSFER' : 'COINBASE'}</span></td><td><a href="/address/${address}">${address}</a></td><td>1</td><td>${i ? fixture.fees[i-1] : 'Not applicable'}</td></tr>`).join('');
      const html = `<div class="pheader">Block #${height}</div><div class="card"><div class="card-title">Coinbase</div></div><div class="card"><table class="tbl"><thead><tr>${['TXID','Type','Flow','Total','Fee'].map(x=>`<th>${x}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table></div><script src="/display.js"></script>`;
      await page.route('**/*', route => {
        const url = new URL(route.request().url());
        if (url.pathname.startsWith('/block/')) return route.fulfill({contentType:'text/html',body:html});
        if (url.pathname === '/display.js') return route.fulfill({contentType:'application/javascript',body:script});
        if (url.pathname.startsWith('/api/v1/block/')) return route.fulfill({json:{height,tx_count:txids.length,tx:fixture.wrongBlock ? [...txids].reverse() : txids}});
        if (url.pathname === '/api/v1/transaction-history' && fixture.history && (!fixture.funding || url.searchParams.get('address') === fixture.funding))
          return route.fulfill({json:{entries:fixture.history,has_more:false}});
        return route.fulfill({status:503,body:'Fixture details unavailable'});
      });
      await page.goto(`https://fixture.invalid/block/height/${height}`);
      if (fixture.expected !== null) await page.waitForFunction(expected => document.querySelector('.miner-fee-total')?.textContent === expected, fixture.expected);
      await page.waitForLoadState('networkidle');
      const cells = await page.locator('tbody tr td:last-child').allTextContents();
      assert.equal(cells[0],'Not applicable');
      assert(cells.every(cell => !cell.includes('to miner')));
      const summary = await page.locator('.miner-fee-total').allTextContents();
      assert.deepEqual(summary, fixture.expected === null ? [] : [fixture.expected]);
      if (fixture.expected !== null) assert.equal(await page.locator('.miner-fee-summary').locator('..').locator('.card-title').textContent(),'Coinbase');
      assert.deepEqual(errors,[]);
      results.push({fixture:fixture.name,width,fees:cells,summary});
      await page.close();
    }
    if (process.env.VELD_FEE_BROWSER_OUTPUT) fs.writeFileSync(process.env.VELD_FEE_BROWSER_OUTPUT,JSON.stringify({status:'PASS_20_FEE_DISPLAY_CASES',cases:results},null,2)+'\n');
    console.log('PASS: 20 desktop/mobile fee display cases');
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});
