(function () {
  'use strict';
  const sources = {
    coinbase: 'mining', block_reward: 'mining', miner_reward: 'mining',
    comine_payout: 'comine', staking_distribution: 'staking', vault_distribution: 'staking',
    endorsement_reward: 'endorse', endorsement_payout: 'endorse'
  };
  const labels = {mining:'Mining', comine:'Co-mining pool', staking:'Staking vault', endorse:'Validators'};
  const kinds = {mining:'Block reward', comine:'Co-mining reward', staking:'Staking reward', endorse:'Validator reward'};
  let state = null;
  const element = id => document.getElementById(id);
  const text = (id, value) => { const node = element(id); if (node) node.textContent = value; };
  const visible = () => { const page = element('page-payouts'); return page && getComputedStyle(page).display !== 'none'; };
  const current = run => state === run && String(window.currentAddr || '') === run.address;
  function syncCaptionColor() {
    const reference=element('d-dist-label'), page=element('page-payouts');
    if (reference && page) page.style.setProperty('--rewards-caption', getComputedStyle(reference).color);
  }
  function units(value) {
    const n = Number(value), scaled = Math.round(n * 100000000);
    if (!Number.isFinite(n) || !Number.isSafeInteger(scaled)) throw new Error('Invalid reward amount.');
    return BigInt(scaled);
  }
  function amount(value, decimals) {
    const scale = 10n ** BigInt(8 - decimals);
    const rounded = (value + scale / 2n) / scale;
    const s = rounded.toString().padStart(decimals + 1, '0');
    return decimals ? s.slice(0,-decimals) + '.' + s.slice(-decimals) : s;
  }
  function status(run, message) {
    const node = element('rewards-status');
    if (!node) return;
    node.textContent = message || '';
    node.hidden = !message;
    const button = element('rewards-more');
    if (button) {
      button.hidden = !run || run.busy || (!run.more && !run.error && !run.datesPending);
      button.disabled = !!(run && run.busy);
      button.textContent = run && run.error ? 'Try again' : run && run.more ? 'Load older rewards' : 'Refresh dates';
    }
  }
  function paint(run) {
    if (!current(run)) return;
    if (run.deferPaint && run.busy) { status(run, 'Refreshing confirmed rewards…'); return; }
    run.deferPaint = false;
    const sums = {mining:0n, comine:0n, staking:0n, endorse:0n};
    let recent = 0n;
    const rows = run.rows.filter(row => sources[row.type] && units(row.net_veld) > 0n);
    rows.forEach(row => {
      const value = units(row.net_veld);
      sums[sources[row.type]] += value;
      const when = run.times.get(Number(row.block_height));
      if (when && when >= run.now - 30 * 86400 && when <= run.now + 600) recent += value;
    });
    const total = Object.values(sums).reduce((a,b) => a+b, 0n);
    run.datesPending = rows.some(row => !run.times.has(Number(row.block_height)));
    const complete = !run.more && !run.error;
    text('earn-life', complete ? amount(total,2) + ' VELD' : '—');
    text('earn-life-sub', complete ? 'Confirmed rewards through block ' + run.height.toLocaleString() : 'Load the remaining history for a lifetime total');
    text('earn-30d', complete && !run.datesPending ? amount(recent,2) + ' VELD' : '—');
    text('earn-30d-sub', !complete ? 'Waiting for complete history' : run.datesPending ? 'Loading confirmed block dates…' : 'Confirmed in the last 30 days');
    Object.keys(sums).forEach(source => {
      text('earn-bar-' + source + '-amt', amount(sums[source],2));
      const percent = total ? Number(sums[source] * 10000n / total) / 100 : 0;
      text('earn-bar-' + source + '-pct', percent.toFixed(1) + '%');
      const value = element('earn-bar-' + source + '-amt');
      const fill = value && value.closest('.earn-bar-row').querySelector('.earn-bar-fill');
      if (fill) fill.style.width = percent + '%';
    });
    const breakdown = element('rewards-source-scope');
    if (breakdown) breakdown.textContent = complete ? 'lifetime' : 'loaded history';
    const body = element('earn-recent-body');
    if (body) {
      body.replaceChildren();
      rows.slice(0,25).forEach(row => {
        const tr = document.createElement('tr');
        const cells = Array.from({length:5}, () => tr.appendChild(document.createElement('td')));
        const link = document.createElement('a');
        link.href = 'https://explorer.veld.network/block/height/' + row.block_height;
        link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = Number(row.block_height).toLocaleString();
        cells[0].appendChild(link);
        const tx = document.createElement('a');
        tx.href = 'https://explorer.veld.network/tx/' + row.txid;
        tx.target = '_blank'; tx.rel = 'noopener noreferrer'; tx.textContent = kinds[sources[row.type]];
        cells[1].appendChild(tx);
        cells[2].textContent = labels[sources[row.type]];
        cells[3].textContent = '+' + amount(units(row.net_veld),4) + ' VELD';
        const time = run.times.get(Number(row.block_height));
        cells[4].textContent = time ? new Date(time * 1000).toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'}) : 'Loading date…';
        cells[3].style.textAlign = cells[4].style.textAlign = 'right';
        body.appendChild(tr);
      });
      if (!rows.length) {
        const tr = body.appendChild(document.createElement('tr')), td = tr.appendChild(document.createElement('td'));
        td.colSpan = 5; td.textContent = run.busy ? 'Loading confirmed rewards…' : 'No confirmed rewards yet.';
        td.style.cssText = 'padding:20px;text-align:center;color:var(--muted)';
      }
    }
    status(run, run.error || (run.busy ? 'Loading confirmed rewards…' : run.more ? 'More history is available. Load it to complete the totals.' : run.datesPending ? 'Block dates are updating. Reward totals remain available.' : ''));
    if (!run.busy && complete) document.documentElement.dataset.veldRewards = 'ready';
  }
  async function dates(run) {
    run.datesError = '';
    const heights = [...new Set([run.height, ...run.rows.filter(r => sources[r.type] && units(r.net_veld)>0n).map(r => Number(r.block_height)).filter(h => !run.times.has(h))])];
    for (let i=0; i<heights.length && current(run); i+=50) {
      const batch = heights.slice(i,i+50);
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 15000);
      let data;
      try {
        const response = await fetch('/history-api/v1/block-times?heights=' + batch.join(','), {cache:'no-store',credentials:'same-origin',signal:controller.signal});
        if (!response.ok) throw new Error('Block dates could not load. Please try again.');
        data = await response.json();
      } finally { clearTimeout(timer); }
      if (!data || !Array.isArray(data.blocks) || data.blocks.length>batch.length || !Array.isArray(data.missing) || !Number.isSafeInteger(data.server_time)) throw new Error('Invalid block-date response.');
      if (!run.now) run.now = data.server_time;
      for (const block of data.blocks) {
        if (!batch.includes(block.height) || !Number.isSafeInteger(block.time) || block.time<0 || !/^[0-9a-f]{64}$/.test(block.hash)) throw new Error('Invalid block date.');
      }
      // Each batch is one canonical index read. Verify its highest block against
      // the node before accepting dates from that branch.
      const anchor = data.blocks.reduce((tip, block) => !tip || block.height>tip.height ? block : tip, null);
      if (anchor && await window.rpc('getblockhash',[String(anchor.height)]) !== anchor.hash) throw new Error('Block dates are catching up with the current chain.');
      if (!current(run)) return;
      for (const block of data.blocks) {
        run.times.set(block.height,block.time);
      }
    }
  }
  async function loadPages(run) {
    for (let n=0; n<20 && run.more && current(run); n++) {
      const params = [run.address,'50']; if (run.cursor) params.push(run.cursor);
      const page = await window.rpc('getaddresshistory',params);
      if (!current(run)) return;
      if (!page || !Array.isArray(page.entries) || page.entries.length>50 || typeof page.has_more!=='boolean' || typeof page.next_cursor!=='string' || (page.has_more && (!page.entries.length || !page.next_cursor || page.next_cursor.length>192 || run.cursors.has(page.next_cursor)))) throw new Error('Invalid reward-history response.');
      for (const row of page.entries) {
        if (!row || !/^[0-9a-f]{64}$/.test(row.txid) || !Number.isSafeInteger(row.block_height) || row.block_height<0 || typeof row.type!=='string') throw new Error('Invalid reward transaction.');
        if (row.block_height>run.height) continue;
        units(row.net_veld);
        if (!run.txids.has(row.txid)) { run.txids.add(row.txid); run.rows.push(row); }
      }
      run.more=page.has_more; run.cursor=page.next_cursor;
      if (run.stopHeight !== undefined && page.entries.some(row => row.block_height<=run.stopHeight)) { run.more=false;run.cursor=''; }
      if (run.cursor) run.cursors.add(run.cursor);
    }
    run.rows.sort((a,b) => b.block_height-a.block_height || a.txid.localeCompare(b.txid));
  }
  async function continueLoad(run) {
    if (!current(run) || run.busy) return;
    run.busy=true; run.error=''; paint(run);
    try {
      await loadPages(run);
      if (!current(run)) return;
      const hash = await window.rpc('getblockhash',[String(run.height)]);
      if (hash !== run.hash) throw new Error('The chain changed. Refresh rewards to use the current history.');
      try { await dates(run); } catch (error) { run.datesError=error.message; }
      if (!current(run)) return;
      if (await window.rpc('getblockhash',[String(run.height)]) !== run.hash) throw new Error('The chain changed. Refresh rewards to use the current history.');
      if (!run.now) run.now = Math.floor(Date.now()/1000);
      run.datesPending=run.rows.some(row => sources[row.type] && units(row.net_veld)>0n && !run.times.has(row.block_height));
    } catch (error) { run.error=error.message || 'Rewards could not load.'; }
    finally { run.busy=false; if (current(run)) { paint(run); if (run.datesError && !run.error) status(run,run.datesError); } }
  }
  async function load(address, force) {
    address=String(address || window.currentAddr || '').trim();
    if (!window.currentAddr) { clear(); return; }
    if (address!==String(window.currentAddr||'')) return;
    if (state && state.address===address && state.busy) return;
    if (!force && state && state.address===address && !state.error && (state.more || Date.now()-state.started<30000)) { paint(state); return; }
    const previous=!force && state && state.address===address && !state.more && !state.error ? state : null;
    const deferPaint=state && state.address===address && !state.error;
    const run={address,rows:[],times:new Map(),txids:new Set(),cursors:new Set(),cursor:'',more:true,busy:true,error:'',height:0,hash:'',now:0,started:Date.now(),deferPaint};
    state=run; document.documentElement.dataset.veldRewards='loading';
    text('earn-recent-addr',address.slice(0,10)+'…'+address.slice(-4));
    if (!deferPaint) { text('earn-life','—');text('earn-30d','—');text('earn-next','—');text('earn-next-sub','Loading distribution…'); }
    paint(run);
    const distribution=window.rpc('getstakinginfo',[address]).then(info => {
      if (!current(run)) return;
      if (!info || !Number.isSafeInteger(info.current_height) || !Number.isSafeInteger(info.next_distribution_in) || info.next_distribution_in<1) throw new Error('Distribution unavailable.');
      text('earn-next',info.next_distribution_in.toLocaleString()+' blocks');
      text('earn-next-sub','At block '+(info.current_height+info.next_distribution_in).toLocaleString());
    }).catch(() => { if(current(run)) { text('earn-next','—');text('earn-next-sub','Distribution unavailable'); } });
    try {
      const chain=await window.rpc('getblockchaininfo',[]);
      if (!current(run)) return;
      if (!chain || !Number.isSafeInteger(chain.blocks) || !/^[0-9a-f]{64}$/.test(chain.best_block_hash)) throw new Error('Current chain state unavailable.');
      run.height=chain.blocks;run.hash=chain.best_block_hash;
      if (previous && previous.height<=run.height && await window.rpc('getblockhash',[String(previous.height)])===previous.hash) {
        if (!current(run)) return;
        run.rows=previous.rows.slice();run.times=new Map(previous.times);run.txids=new Set(previous.txids);
        run.stopHeight=previous.height;
        if (run.hash===previous.hash) run.more=false;
      }
      run.busy=false;
      await continueLoad(run);
    } catch(error) {run.busy=false;run.error=error.message || 'Rewards could not load.';paint(run);}
    await distribution;
  }
  function clear() {
    state=null;delete document.documentElement.dataset.veldRewards;
    for(const id of ['earn-life','earn-30d','earn-next'])text(id,'—');
    for(const id of ['earn-life-sub','earn-30d-sub','earn-next-sub','earn-recent-addr'])text(id,'Load a wallet to see rewards');
    text('rewards-source-scope','lifetime');
    for(const source of Object.keys(labels)) {
      text('earn-bar-'+source+'-amt','0.00');text('earn-bar-'+source+'-pct','0.0%');
    }
    const page=element('page-payouts');
    if(page)page.querySelectorAll('.earn-bar-fill').forEach(fill=>{fill.style.width='0%';});
    const body=element('earn-recent-body');
    if(body) {body.replaceChildren();const td=body.appendChild(document.createElement('tr')).appendChild(document.createElement('td'));td.colSpan=5;td.textContent='Load a wallet to see recent rewards';}
    status(null,'');
  }
  function fixHistoryDirection() {
    const list=element('h-list');if(!list)return;
    const older=list.querySelector('[data-act-click="hhist_prev"]'), newer=list.querySelector('[data-act-click="hhist_next"]');
    if(!older || !newer || older.dataset.rewardPager)return;
    const olderDisabled=newer.disabled,newerDisabled=older.disabled;
    older.dataset.actClick='hhist_next';newer.dataset.actClick='hhist_prev';
    older.dataset.rewardPager=newer.dataset.rewardPager='1';
    for(const [button,disabled,label,title] of [[older,olderDisabled,'← Older','Show older transactions'],[newer,newerDisabled,'Newer →','Show newer transactions']]) {
      button.disabled=disabled;button.textContent=label;button.title=title;button.setAttribute('aria-label',title);
      button.style.opacity=disabled?'.4':'';button.style.cursor=disabled?'not-allowed':'';
    }
  }
  function install() {
    const page=element('page-payouts');if(!page)return;
    syncCaptionColor();
    new MutationObserver(syncCaptionColor).observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});
    page.querySelector('.ptitle').textContent='Rewards';
    const sourceScope=page.querySelector('#earn-bars').previousElementSibling.lastElementChild;
    if(sourceScope)sourceScope.id='rewards-source-scope';
    const controls=document.createElement('div');controls.className='rewards-load-status';
    const message=controls.appendChild(document.createElement('p'));message.id='rewards-status';message.setAttribute('role','status');message.hidden=true;
    const more=controls.appendChild(document.createElement('button'));more.id='rewards-more';more.type='button';more.className='btn btn-ghost';more.hidden=true;
    more.addEventListener('click',()=>{if(!state||state.error)load(window.currentAddr,true);else continueLoad(state);});
    page.querySelector('.earn-sum').after(controls);
    window.veldRewards={load,clear};window.loadEarningsPage=load;
    const render=window.renderHistory;
    if(typeof render==='function')window.renderHistory=function(){const result=render.apply(this,arguments);fixHistoryDirection();return result;};
    fixHistoryDirection();
    if(window.__veldPendingRewardsAddress || (visible() && window.currentAddr))load(window.__veldPendingRewardsAddress || window.currentAddr,true);
    delete window.__veldPendingRewardsAddress;
    window.setInterval(()=>{
      if(document.hidden || !visible() || !window.currentAddr)return;
      load(window.currentAddr);
    },30000);
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',install,{once:true});else install();
})();
