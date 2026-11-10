/* Presentation-only compatibility for Explorer origins predating the Pool navigation update. */
(function () {
  'use strict';
  var icon = '<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="18" r="3"/><circle cx="19" cy="18" r="3"/><path d="m10.5 7.5-4 8m7-8 4 8M8 18h8"/></svg>';
  function update() {
    document.querySelectorAll('.nm-grid,.sn-links,.snav').forEach(function (group) {
      var links = Array.from(group.children).filter(function (e) { return e.tagName === 'A'; });
      if (!links.length) return;
      var pool = links.find(function (e) { return e.getAttribute('href') === '/pool'; });
      var how = links.find(function (e) { return e.getAttribute('href') === 'https://veld.network/how-to/'; });
      if (!pool) {
        var reference = links.find(function (e) { return e.getAttribute('href') === '/liquidity'; });
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
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', update, {once: true});
  else update();
})();

/* BEGIN GENERATED PUBLIC POOL OVERVIEW */
// Shared public Pool-tab view, embedded in Explorer and portal by the source generator.
// No account identifiers, cookies, pairing credentials or private tokens leave the page.
(function(){
  'use strict';
  var page=document.querySelector('.pool-page');
  if(!page||page.dataset.poolStatusController)return;
  page.dataset.poolStatusController='2';
  var busy=false, next=0, last=null, failed=false, lastAt=0, operator=null, operatorFailed=false;
  function put(id,value){var e=document.getElementById(id);if(e)e.textContent=value;}
  function render(){
    var paused=operator&&operator.state==='paused_by_operator';
    var stale=failed||paused;
    page.dataset.poolOperatorState=paused?'paused':'unknown';
    page.dataset.poolStatisticsState=last?(stale?'stale':'fresh'):'unavailable';
    var message=paused?'Pool mining is paused by the operator. New work and payouts are stopped.':
      failed?'The statistics refresh is delayed. This does not confirm a pool outage. Retrying automatically.':
      last?last.status:'Connecting to Veld Pool…';
    if(paused&&operatorFailed)message+=' The operator notice could not be refreshed.';
    if(lastAt)message+=(stale?' Last received ':' Updated ')+new Date(lastAt).toLocaleString()+'.';
    if(stale&&lastAt)message+=' Figures below are the last received values.';
    put('pool-public-status',message);
    ['active_accounts','verified_shares','reconciled_height'].forEach(function(k){
      put('pool-public-'+k,last&&last[k]!==null?BigInt(last[k]).toLocaleString():'—');
    });
    put('pool-public-payments',paused?'Paused':!last?'Unknown':(failed?'Last reported: ':'')+(last.payments_enabled?'Enabled':'Not enabled'));
    put('pool-public-comining',paused?'Paused':!last?'Unknown':(failed?'Last reported: ':'')+(last.co_mining_enabled?'Participating':'Not participating yet'));
    put('pool-public-comining-note',paused?'Pool participation is paused. Earlier earned rewards remain recorded.':
      last?(failed?'Last reported: ':'')+(last.co_mining_enabled?'The pool is participating in co-mining. Only confirmed winnings create earnings.':'The pool needs 1,000 VELD staked to qualify for co-mining.'):
      'Co-mining participation has not loaded yet.');
    var intro=page.querySelector('.pool-intro');if(intro)intro.textContent='Pool activity, setup and rewards.';
    page.querySelectorAll('h3').forEach(function(h){if(h.textContent==='Start pool mining'||h.dataset.poolSetup){h.dataset.poolSetup='true';h.textContent=paused?'Pool setup for when mining resumes':'Start pool mining';}});
    var p=last&&last.payment_policy;
    put('pool-public-minimum',p?amount(p.minimum_units,8)+' VELD':'—');
    function amount(v,scale){var n=BigInt(v),d=10n**BigInt(scale);return (n/d+'.'+(n%d).toString().padStart(scale,'0')).replace(/\.?0+$/,'');}
    put('pool-public-policy',p?(stale?'Last reported policy: ':'')+amount(p.fee_ppm,4)+'% service fee · '+amount(p.minimum_units,8)+' VELD minimum per payout address · batches every '+(Number(p.batch_seconds)/3600)+' hours.':paused?'Payout processing is paused.':'Payment policy has not loaded yet.');
  }
  async function operatorStatus(){
    if(document.hidden)return;
    var stop=new AbortController(),timer=setTimeout(function(){stop.abort();},4000);
    try{
      var r=await fetch('/assets/pool-service-state.json',{credentials:'omit',redirect:'error',cache:'no-store',signal:stop.signal});
      if(!r.ok||!r.body)throw Error('notice unavailable');
      var reader=r.body.getReader(),parts=[],size=0;
      for(;;){var part=await reader.read();if(part.done)break;size+=part.value.length;if(size>2048){await reader.cancel();throw Error('notice size');}parts.push(part.value);}
      var bytes=new Uint8Array(size),offset=0;parts.forEach(function(p){bytes.set(p,offset);offset+=p.length;});
      var value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
      if(value.version!==1||!['paused_by_operator','no_operator_pause'].includes(value.state)||
         value.chain!=='7be77ab9e820bd9ffb60b269b45ced48288056e5839a1135fafc2f8557000a88'||
         typeof value.updated_at!=='string'||!Number.isFinite(Date.parse(value.updated_at)))throw Error('notice invalid');
      operator=value;operatorFailed=false;
    }catch(_){operatorFailed=true;}finally{clearTimeout(timer);render();document.dispatchEvent(new Event('veld-pool-state'));}
  }
  async function refresh(){
    if(!document.getElementById('pool-public-status')||document.hidden)return;
    render();if(busy||Date.now()<next)return;busy=true;next=Date.now()+15000;
    var stop=new AbortController(),timer=setTimeout(function(){stop.abort();},8000);
    try{
      var r=await fetch('https://pool.veld.network/v1/public',{credentials:'omit',referrerPolicy:'no-referrer',cache:'no-store',redirect:'error',signal:stop.signal});
      if(!r.ok||!r.body)throw Error('unavailable');
      var reader=r.body.getReader(),parts=[],size=0;
      for(;;){var part=await reader.read();if(part.done)break;size+=part.value.length;if(size>32768){await reader.cancel();throw Error('response limit');}parts.push(part.value);}
      var bytes=new Uint8Array(size),offset=0;parts.forEach(function(p){bytes.set(p,offset);offset+=p.length;});
      var j=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)),s=j&&j.result;
      if(j.ok!==true||!s||s.chain!=='7be77ab9e820bd9ffb60b269b45ced48288056e5839a1135fafc2f8557000a88')throw Error('network');
      ['active_accounts','verified_shares','reconciled_height'].forEach(function(k){if(k==='reconciled_height'&&s[k]===null)return;if(typeof s[k]!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(s[k]))throw Error('count');});
      if(typeof s.payments_enabled!=='boolean'||typeof s.co_mining_enabled!=='boolean')throw Error('flags');
      if(!['Service responding','Reconciliation paused or starting'].includes(s.status))throw Error('status');
      if(s.payment_policy!==undefined){
        if(!s.payment_policy||typeof s.payment_policy!=='object'||Array.isArray(s.payment_policy))throw Error('policy');
        ['fee_ppm','minimum_units','batch_seconds','revision'].forEach(function(k){if(typeof s.payment_policy[k]!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(s.payment_policy[k]))throw Error('policy value');});
        if(BigInt(s.payment_policy.fee_ppm)>100000n||BigInt(s.payment_policy.minimum_units)<100000000n||BigInt(s.payment_policy.minimum_units)>1000000000000n||BigInt(s.payment_policy.batch_seconds)<3600n||BigInt(s.payment_policy.batch_seconds)>604800n)throw Error('policy bounds');
      }
      last=s;lastAt=Date.now();failed=false;
    }catch(_){failed=true;}finally{clearTimeout(timer);busy=false;render();}
  }
  setInterval(refresh,1000);setInterval(operatorStatus,30000);operatorStatus();refresh();
})();

/* Public pool statistics. No account credentials or wallet access. */
(function () {
  'use strict';
  var page = document.querySelector('.pool-page');
  if (!page || document.getElementById('pool-overview')) return;
  var overview = document.createElement('section');
  overview.id = 'pool-overview';
  overview.setAttribute('aria-label', 'Pool performance and earnings');
  overview.innerHTML = '<div class="pool-overview-grid">' +
    '<article class="tile"><div class="l">Pool hashrate</div><div class="v" id="pool-rate">—</div><small id="pool-rate-note">Measured from verified work</small></article>' +
    '<article class="tile"><div class="l">Blocks won</div><div class="v" id="pool-blocks">—</div><small>Canonical pool blocks</small></article>' +
    '<article class="tile"><div class="l">Mining rewards earned</div><div class="v" id="pool-earned">—</div><small>Actual miner outputs · VELD</small></article>' +
    '<article class="tile"><div class="l">Paid to miners</div><div class="v" id="pool-paid">—</div><small id="pool-paid-note">Confirmed payments · VELD</small></article></div>' +
    '<p class="pool-note" id="pool-stats-updated" role="status">Loading pool statistics…</p>';
  var intro = page.querySelector('.pool-intro') || page.querySelector('h2');
  intro.insertAdjacentElement('afterend', overview);
  var recent = document.createElement('section');
  recent.className = 'pool-recent';
  recent.innerHTML = '<h3>Recent pool blocks</h3><p class="pool-note">Rewards mature for at least 120 confirmations and must be spendable before payment.</p>' +
    '<div class="pool-block-table"><table><thead><tr><th>Block</th><th>Miner reward</th><th>Confirmations</th><th>Status</th></tr></thead><tbody id="pool-block-rows"></tbody></table></div>' +
    '<div class="pool-extra-rewards"><p>Lottery winnings <strong id="pool-lottery-earned">—</strong></p><p>Staking distributions <strong id="pool-stake-earned">—</strong></p></div>' +
    '<p class="pool-note">Earned rewards include funds still maturing or waiting for a payment batch. They are different from confirmed payments.</p>';
  var setup = Array.from(page.querySelectorAll('h3')).find(function (h) { return h.textContent === 'Start pool mining'; });
  if (setup) page.insertBefore(recent, setup); else page.appendChild(recent);
  function put(id, text) { document.getElementById(id).textContent = text; }
  function object(v) { if (!v || typeof v !== 'object' || Array.isArray(v)) throw Error('Object required'); return v; }
  function uint(v) { if (typeof v !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(v)) throw Error('Invalid integer'); return BigInt(v); }
  function money(v, places) { var n = uint(v), fraction = (n % 100000000n).toString().padStart(8, '0'); return (n / 100000000n).toLocaleString() + '.' + (places === 2 ? fraction.slice(0, 2) : fraction.replace(/0+$/, '').padEnd(2, '0')); }
  function count(v) { return uint(v).toLocaleString(); }
  function rate(v) { var n = uint(v), scale = n >= 1000000n ? 1000000n : n >= 1000n ? 1000n : 1n; return (n / scale).toLocaleString() + (scale > 1n ? '.' + (n % scale * 100n / scale).toString().padStart(2, '0') : '') + (scale === 1000000n ? ' MH/s' : scale === 1000n ? ' kH/s' : ' H/s'); }
  function validate(payload) {
    object(payload); var result = object(payload.result);
    if (payload.ok !== true || result.chain !== '7be77ab9e820bd9ffb60b269b45ced48288056e5839a1135fafc2f8557000a88') throw Error('Wrong network');
    var o = object(result.overview), w = object(o.work); object(o.payments); object(o.reward_totals);
    if (o.version !== 1 || w.method !== 'verified-expected-work' || w.bucket_seconds !== '10' || uint(w.window_seconds) > 600n || typeof w.warming_up !== 'boolean') throw Error('Unknown statistics');
    if (w.hashrate_hs !== null) uint(w.hashrate_hs);
    uint(w.sample_shares); uint(o.blocks_won); uint(o.payments.paid_units); uint(o.payments.confirmed_transactions);
    ['mining', 'comine_payout', 'staking_distribution'].forEach(function (k) { uint(o.reward_totals[k]); });
    if (!Array.isArray(o.recent_blocks) || o.recent_blocks.length > 12) throw Error('Too many blocks');
    o.recent_blocks.forEach(function (b) { object(b); uint(b.height); uint(b.amount_units); uint(b.confirmations); if (!/^[0-9a-f]{64}$/.test(b.hash) || !['pending', 'available', 'orphaned'].includes(b.state)) throw Error('Invalid block'); });
    if (typeof result.co_mining_enabled !== 'boolean') throw Error('Invalid co-mining state');
    return {overview: o, coMining: result.co_mining_enabled};
  }
  function row(text, label) { var td = document.createElement('td'); td.textContent = text; td.dataset.label = label; return td; }
  function empty(text) { var tr = document.createElement('tr'), td = row(text, ''); td.colSpan = 4; tr.appendChild(td); document.getElementById('pool-block-rows').replaceChildren(tr); }
  function render(data) {
    var o = data.overview;
    put('pool-rate', o.work.hashrate_hs === null ? 'Measuring…' : rate(o.work.hashrate_hs));
    put('pool-rate-note', (o.work.warming_up ? 'Warming up · ' : '') + count(o.work.sample_shares) + ' verified shares · ' + o.work.window_seconds + 's window');
    put('pool-blocks', count(o.blocks_won)); put('pool-earned', money(o.reward_totals.mining, 2)); put('pool-paid', money(o.payments.paid_units, 2));
    document.getElementById('pool-earned').title = money(o.reward_totals.mining) + ' VELD';
    document.getElementById('pool-paid').title = money(o.payments.paid_units) + ' VELD';
    var lotteryNote = document.getElementById('pool-public-comining-note');
    if (lotteryNote) lotteryNote.textContent = data.coMining ? 'Co-mining is enabled. Only confirmed pool winnings create earnings.' : 'The pool needs 1,000 VELD staked to qualify. Lottery winnings and staking distributions are shared with contributors.';
    put('pool-paid-note', count(o.payments.confirmed_transactions) + ' confirmed payments · VELD');
    put('pool-lottery-earned', money(o.reward_totals.comine_payout) + ' VELD'); put('pool-stake-earned', money(o.reward_totals.staking_distribution) + ' VELD');
    var rows = document.createDocumentFragment();
    o.recent_blocks.forEach(function (b) {
      var tr = document.createElement('tr'), block = row('', 'Block'), link = document.createElement('a');
      link.href = '/block/' + b.hash; link.textContent = '#' + count(b.height); block.appendChild(link); tr.appendChild(block);
      tr.appendChild(row(money(b.amount_units) + ' VELD', 'Miner reward')); tr.appendChild(row(count(b.confirmations), 'Confirmations'));
      var status = row({pending: 'Maturing', available: 'Mature', orphaned: 'Orphaned'}[b.state], 'Status'); status.className = 'pool-block-state ' + b.state; tr.appendChild(status); rows.appendChild(tr);
    });
    document.getElementById('pool-block-rows').replaceChildren(rows);
    if (!o.recent_blocks.length) empty('No pool blocks recorded yet.');
    lastGoodAt = Date.now(); statisticsFailed = false; updateStatus();
  }
  var busy = false, next = 0, lastGoodAt = 0, statisticsFailed = false;
  function updateStatus() {
    var paused = page.dataset.poolOperatorState === 'paused';
    var text = paused ? 'Pool mining is paused. Statistics are not live.' : statisticsFailed ? 'Statistics refresh delayed. Retrying automatically.' : 'Statistics updated.';
    if (lastGoodAt) text += ' Last received ' + new Date(lastGoodAt).toLocaleString() + '.';
    if (lastGoodAt && (paused || statisticsFailed)) text += ' The last received figures and block history remain visible.';
    put('pool-stats-updated', text);
  }
  document.addEventListener('veld-pool-state', updateStatus);
  async function refresh() {
    if (busy || document.hidden || Date.now() < next) return;
    busy = true; next = Date.now() + 30000;
    var abort = new AbortController(), timer = setTimeout(function () { abort.abort(); }, 8000);
    try {
      var response = await fetch('https://pool.veld.network/v1/public', {credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', cache: 'no-store', signal: abort.signal});
      if (!response.ok || !response.body) throw Error('Unavailable');
      var reader = response.body.getReader(), chunks = [], size = 0;
      for (;;) { var part = await reader.read(); if (part.done) break; size += part.value.length; if (size > 32768) { await reader.cancel(); throw Error('Response too large'); } chunks.push(part.value); }
      var bytes = new Uint8Array(size), offset = 0; chunks.forEach(function (c) { bytes.set(c, offset); offset += c.length; });
      render(validate(JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes))));
    } catch (_) {
      statisticsFailed = true; updateStatus();
      if (!lastGoodAt) {
        put('pool-rate-note', 'Waiting for verified work statistics');
        empty('Block history has not loaded yet. Retrying automatically.');
      }
    } finally { clearTimeout(timer); busy = false; }
  }
  empty('Loading recent blocks…'); setInterval(refresh, 1000); refresh();
})();
