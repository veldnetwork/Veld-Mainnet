'use strict';
// Native Windows Edge, actual disposable HTTPS frontend/private IPC/coordinator.
// The chain backend is a fixture; this is not native mining/payout qualification.
const fs=require('fs'),path=require('path'),assert=require('assert/strict');
const {chromium}=require('playwright');
if(!process.argv[2])throw Error('usage: node pool_admin_browser_controls.cjs EVIDENCE_DIRECTORY');
const out=path.resolve(process.argv[2]),{origin}=JSON.parse(fs.readFileSync(path.join(out,'ready.json'),'utf8'));
assert.match(origin,/^https:\/\/127\.0\.0\.1:[0-9]+$/);
(async()=>{
 let browser;const result={status:'RUNNING',scope:'Windows Edge to real isolated HTTPS/IPC/operator/coordinator; fixture chain, no production keys or writes',checks:[]};
 try{
  browser=await chromium.launch({channel:'msedge',headless:true});
  const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1280,height:960}});
  // Only this ephemeral self-signed fixture context bypasses browser CA import.
  // Certificate validation and TLS refusal are independently tested with Python.
  await context.route('**/*',route=>route.request().url().startsWith(origin+'/')?route.continue():route.abort());
  const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(origin);await page.locator('#password').fill('isolated-panel-only-disposable-password');await page.locator('#login button').click();
  await page.locator('#console').waitFor();await page.waitForFunction(()=>document.getElementById('minimum').value==='1.00000000');
  assert.equal(await page.locator('#password').inputValue(),'');
  await page.screenshot({path:path.join(out,'desktop.png'),fullPage:true});
  let lost=false;
  await page.route('**/api/settings',async route=>{
   if(lost)return route.continue();lost=true;const r=await route.fetch();assert.equal(r.status(),200);await r.body();await route.abort('failed');
  });
  await page.locator('#minimum').fill('2');await page.locator('#interval').fill('2');await page.locator('#fee').fill('1');
  await page.locator('#reason').fill('Browser lost-response recovery');await page.locator('#save').click();
  await page.locator('#retry').waitFor();await page.locator('#retry').click();
  await page.waitForFunction(()=>document.getElementById('message').textContent.includes('applied and recorded'));
  const first=await page.evaluate(()=>call('/api/snapshot?before=0'));
  assert.equal(first.revision,'1');assert.equal(first.audit.length,1);assert.equal(first.settings.fee_ppm,'10000');
  result.checks.push('real sign-in; durable settings mutation; lost response retried with same operation id, one audit event and one revision');
  await page.unroute('**/api/settings');
  await page.evaluate(async()=>{const s=await call('/api/snapshot?before=0');await call('/api/settings',{request_id:'e'.repeat(32),revision:s.revision,reason:'Concurrent operator <img src=x onerror=window.injected=true>',settings:{...s.settings,minimum_units:'300000000'}});});
  await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('revision').textContent.includes('changed elsewhere'));
  await page.locator('#reason').fill('Stale form must not overwrite');await page.locator('#save').click();
  await page.waitForFunction(()=>document.getElementById('message').textContent.includes('Load current settings'));
  assert.equal((await page.evaluate(()=>call('/api/snapshot?before=0'))).revision,'2');
  await page.locator('#reload-settings').click();await page.waitForFunction(()=>document.getElementById('minimum').value==='3.00000000');
  await page.locator('#reconcile').click();await page.waitForFunction(()=>document.getElementById('message').textContent.includes('queued'));
  await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('audit').textContent.includes('completed'));
  assert.equal(await page.locator('#audit img').count(),0);assert.equal(await page.evaluate(()=>window.injected),undefined);
  result.checks.push('stored audit text is inert; stale form uses its original revision; cannot overwrite newer settings; canonical reconciliation completes through private service');
  await page.setViewportSize({width:390,height:844});await page.screenshot({path:path.join(out,'mobile.png'),fullPage:true});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  assert.deepEqual(await page.evaluate(()=>[localStorage.length,sessionStorage.length]),[0,0]);assert.deepEqual(errors,[]);
  await page.locator('#logout').click();await page.locator('#login').waitFor();
  assert.equal((await page.request.get(origin+'/api/snapshot?before=0')).status(),401);
  await page.reload();assert.equal(await page.locator('#console').isVisible(),false);
  result.checks.push('mobile layout without overflow; no browser token storage; logout revokes session; reload stays signed out; no JS errors');
  result.status='PASS';
 }catch(e){result.status='FAILED';result.error=String(e);process.exitCode=1;}
 finally{if(browser)await browser.close();fs.writeFileSync(path.join(out,'result.json'),JSON.stringify(result,null,2));fs.writeFileSync(path.join(out,'stop.request'),'stop\n');console.log(JSON.stringify(result));}
})();
