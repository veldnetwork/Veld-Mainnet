(function () {
  'use strict';
  if (window.__veldBackgroundBudget || typeof window.fetch !== 'function') return;
  window.__veldBackgroundBudget = true;
  var original = window.fetch.bind(window), queue = [], active = 0, timer = null, closed = false;
  var key = 'veld-explorer-background-v1', fallback = {sent: [], until: 0};
  var WINDOW = 61000, LIMIT = 24, SPACING = 500, MAX_QUEUE = 32;

  function abortError() { return new DOMException('Background request cancelled', 'AbortError'); }
  function read(now) {
    var data = fallback;
    try { data = JSON.parse(localStorage.getItem(key)) || fallback; } catch (_) {}
    if (!data || !Array.isArray(data.sent)) data = fallback;
    return {
      sent: data.sent.filter(function (n) { return Number.isFinite(n) && n > now - WINDOW && n <= now + WINDOW; }).slice(-LIMIT).sort(function (a, b) { return a - b; }),
      until: Number.isFinite(data.until) && data.until <= now + 300000 ? data.until : 0
    };
  }
  function save(data) {
    fallback = data;
    try { localStorage.setItem(key, JSON.stringify(data)); } catch (_) {}
  }
  function locked(fn) {
    if (navigator.locks && typeof navigator.locks.request === 'function')
      return navigator.locks.request(key, {mode: 'exclusive'}, fn);
    return Promise.resolve().then(fn);
  }
  function reserve(item) {
    return locked(function () {
      if (closed || document.hidden || item.cancelled) return {stop: true};
      var now = Date.now(), state = read(now), next = state.until;
      if (state.sent.length) next = Math.max(next, state.sent[state.sent.length - 1] + SPACING);
      if (state.sent.length >= LIMIT) next = Math.max(next, state.sent[0] + WINDOW + 1);
      if (next > now) return {wait: next - now};
      state.sent.push(now); save(state);
      return {send: true};
    });
  }
  function cooldown(response) {
    if (response.status !== 429) return Promise.resolve();
    var hint = response.headers.get('Retry-After'), delay = /^\d+$/.test(hint || '') ? Number(hint) * 1000 : Date.parse(hint) - Date.now();
    return locked(function () {
      var now = Date.now(), state = read(now);
      state.until = Math.max(state.until, now + Math.max(WINDOW, Number.isFinite(delay) ? Math.min(300000, delay) : 0));
      save(state);
    });
  }
  function detach(item) { if (item.signal) item.signal.removeEventListener('abort', item.onAbort); }
  function reject(item) { detach(item); item.reject(abortError()); }
  function wake(delay) {
    if (timer !== null) clearTimeout(timer);
    timer = setTimeout(function () { timer = null; drain(); }, delay);
  }
  function drain() {
    if (closed || document.hidden || active || !queue.length) return;
    var item = queue.shift();
    if (item.cancelled) { reject(item); drain(); return; }
    active++;
    reserve(item).then(function (permit) {
      if (item.cancelled || closed) { reject(item); return; }
      if (!permit.send) {
        queue.unshift(item);
        if (permit.wait) wake(permit.wait);
        return;
      }
      return original(item.input, item.options).then(function (response) {
        return cooldown(response).then(function () { detach(item); item.resolve(response); });
      }, function (error) { detach(item); item.reject(error); });
    }).catch(function (error) { detach(item); item.reject(error); }).finally(function () {
      active--; if (timer === null) drain();
    });
  }
  window.fetch = function (input, options) {
    var url, method;
    try {
      url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url, location.href);
      method = String(options && options.method || input && input.method || 'GET').toUpperCase();
    } catch (_) { return original(input, options); }
    if (method !== 'GET' || url.origin !== location.origin || !/^\/api\/v1\/events\/\d+$/.test(url.pathname))
      return original(input, options);
    var signal = options && options.signal || input && input.signal;
    if (closed || signal && signal.aborted || queue.length >= MAX_QUEUE) return Promise.reject(abortError());
    return new Promise(function (resolve, rejectPromise) {
      var item = {input: input, options: options, signal: signal, resolve: resolve, reject: rejectPromise, cancelled: false};
      item.onAbort = function () {
        item.cancelled = true;
        var index = queue.indexOf(item);
        if (index >= 0) { queue.splice(index, 1); reject(item); }
      };
      if (signal) signal.addEventListener('abort', item.onAbort, {once: true});
      queue.push(item); drain();
    });
  };
  document.addEventListener('visibilitychange', function () { if (!document.hidden) drain(); });
  window.addEventListener('pagehide', function () {
    closed = true;
    if (timer !== null) clearTimeout(timer);
    timer = null;
    queue.splice(0).forEach(reject);
  });
})();

(function () {
  'use strict';

  // Do not replay a captured page, including when arriving from an older tab.
  function stopPageSnapshot(event) {
    if (event.viewTransition) event.viewTransition.skipTransition();
  }
  window.addEventListener('pageswap', stopPageSnapshot);
  window.addEventListener('pagereveal', stopPageSnapshot);

  // This origin stores only public Explorer responses in Cache Storage.
  // Remove entries left by older workers without changing browser preferences.
  function clearExplorerResponseCaches() {
    if (!window.caches) return Promise.resolve();
    return caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (key) { return caches.delete(key); }));
    }).catch(function () {});
  }
  clearExplorerResponseCaches();
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('controllerchange', clearExplorerResponseCaches);
  }


  var compactLayout = window.matchMedia && window.matchMedia('(max-width: 900px)').matches;
  var touchLayout = window.matchMedia && window.matchMedia('(hover: none) and (pointer: coarse)').matches;
  document.documentElement.dataset.deviceLayout = compactLayout || touchLayout ? 'mobile' : 'desktop';

  // CSS owns the navbar geometry. Resizing only selects the page layout.
  function updateDeviceLayout() {
    var compact = window.matchMedia('(max-width: 900px)').matches;
    var touch = window.matchMedia('(hover: none) and (pointer: coarse)').matches;
    document.documentElement.dataset.deviceLayout = compact || touch ? 'mobile' : 'desktop';
  }
  window.addEventListener('resize', updateDeviceLayout, { passive: true });
  window.addEventListener('pageshow', updateDeviceLayout);

  if (window.location.pathname === '/liquidity') {
    var containmentStyle = document.createElement('style');
    containmentStyle.id = 'veld-liquidity-viewport-containment';
    containmentStyle.textContent =
      'html,html[data-device-layout]{width:100%!important;max-width:100vw!important;overflow-x:hidden!important}' +
      'html[data-device-layout] body.liquidity-page{width:100%!important;max-width:100vw!important;min-width:0!important;overflow-x:hidden!important}' +
      'html[data-device-layout] body.liquidity-page .liquidity-wrap{width:100%!important;max-width:100vw!important;min-width:0!important;overflow-x:hidden!important}' +
      'html[data-device-layout] body.liquidity-page .liquidity-wrap>*,html[data-device-layout] body.liquidity-page .liq-card,html[data-device-layout] body.liquidity-page .liq-card-head,html[data-device-layout] body.liquidity-page .liq-grid,html[data-device-layout] body.liquidity-page .earn-flow,html[data-device-layout] body.liquidity-page .earn-summary{max-width:100%!important;min-width:0!important}' +
      'html[data-device-layout] body.liquidity-page .nav-bar,html[data-device-layout] body.liquidity-page .nav-bar.is-sticky{width:100vw!important;min-width:100vw!important;max-width:100vw!important}' +
      'html[data-device-layout] body.liquidity-page .nav-bar .nb-tab{flex:0 0 20%!important;width:20%!important;min-width:0!important;max-width:20%!important}' +
      'html[data-device-layout] body.liquidity-page .nav-more{width:100vw!important;max-width:100vw!important;overflow-x:hidden!important}';
    document.head.appendChild(containmentStyle);
  }

  var txPath = /^\/tx\/[0-9a-f]{64}$/i;

  function removeLegacyMiningGuide() {
    if (window.location.pathname !== '/mining') return;
    document.querySelectorAll('.card > .card-title').forEach(function (title) {
      if (title.textContent.trim() !== 'How to Mine') return;
      var card = title.closest('.card');
      if (card) card.remove();
    });
  }

  function formatRichListBalances() {
    if (window.location.pathname !== '/rich') return;
    document.querySelectorAll('.rl-val .rl-v').forEach(function (element) {
      var balance = Number(element.textContent.trim());
      if (Number.isFinite(balance)) element.textContent = balance.toFixed(2);
    });
  }

  function clarifyStakingMinimum() {
    if (window.location.pathname === '/staking') {
      document.querySelectorAll('table.tbl tbody tr').forEach(function (row) {
        var cells = row.querySelectorAll('td');
        if (cells.length !== 3 || !/^Minimum (Ordinary )?Stake$/.test(cells[0].textContent.trim())) return;
        cells[0].textContent = 'Minimum Stake';
        cells[2].textContent = 'Transaction fee is additional.';
      });
    }
    if (window.location.pathname === '/validators') {
      document.querySelectorAll('.stat-label').forEach(function (label) {
        if (label.textContent.trim() === 'Min Stake to Register') {
          label.textContent = 'Minimum Validator Bond';
        }
      });
    }
  }

  // Read current server-rendered values instead of duplicating bond policy in JS.
  // The page has no signing controls. A changed minimum or validator count needs
  // a fresh document so its bond records and pagination stay consistent too.
  var validatorRefreshBusy = false;
  var validatorRefreshAt = 0;
  function validatorSummary(page) {
    var values = {};
    page.querySelectorAll('.stat-grid .stat').forEach(function (stat) {
      var label = stat.querySelector('.stat-label');
      var value = stat.querySelector('.stat-value');
      if (!label || !value) return;
      var name = label.textContent.trim();
      if (name === 'Min Stake to Register') name = 'Minimum Validator Bond';
      if (name === 'Minimum Validator Bond' || name === 'Validators')
        values[name] = value.textContent.trim();
    });
    if (!values['Minimum Validator Bond'] || !values.Validators) return null;
    return values['Minimum Validator Bond'] + '|' + values.Validators;
  }
  window.loadValidatorsPage = function () {
    if (location.pathname !== '/validators' || document.hidden || validatorRefreshBusy ||
        Date.now() - validatorRefreshAt < 5000) return;
    validatorRefreshBusy = true;
    validatorRefreshAt = Date.now();
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, 8000);
    return fetch('/validators', {cache: 'no-store', credentials: 'same-origin', signal: controller.signal})
      .then(function (response) {
        if (!response.ok || !/^text\/html\b/i.test(response.headers.get('content-type') || ''))
          throw new Error('Validator page unavailable');
        return response.text();
      }).then(function (html) {
        if (html.length > 2 * 1024 * 1024) throw new Error('Validator page too large');
        var next = validatorSummary(new DOMParser().parseFromString(html, 'text/html'));
        var current = validatorSummary(document);
        if (!document.hidden && location.pathname === '/validators' && next && current && next !== current)
          window.location.reload();
      }).catch(function () {
        // Retain the last document and retry through the existing page timer.
      }).finally(function () {
        clearTimeout(timer);
        validatorRefreshBusy = false;
      });
  };

  function colorRewardBadge(badge) {
    var label = badge.textContent.trim().replace(/\s+/g, ' ').toLowerCase();
    var staking = /^(stake|unstake|stake lock|stake unlock|staking dist|staking rewards)$/.test(label) ||
      (label === 'payout' && badge.classList.contains('bk-badge'));
    var validator = /^(endorse|endorsement|endorse reward|validator|validator reg|validator dereg|val payout|validator payout)$/.test(label);
    if (!staking && !validator) return;
    badge.classList.add(staking ? 'veld-reward-stake' : 'veld-reward-validator');
    if (staking && badge.classList.contains('badge')) {
      var row = badge.closest('tr');
      var table = row && row.closest('table');
      var heading = table && table.querySelector('tr');
      if (heading) Array.from(heading.cells).forEach(function (cell, index) {
        if (cell.textContent.trim().toLowerCase() === 'total' && row.cells[index]) {
          row.cells[index].classList.add('veld-stake-total');
        }
      });
    }
  }

  function colorRewardBadges(root) {
    if (root.nodeType === 3) root = root.parentElement;
    if (!root) return;
    if (root.matches && root.matches('.badge,.op,.bk-badge')) colorRewardBadge(root);
    if (root.querySelectorAll) root.querySelectorAll('.badge,.op,.bk-badge').forEach(colorRewardBadge);
  }

  function initializeRewardColors() {
    colorRewardBadges(document);
    // Check only added content so refreshed lists retain their category colors.
    var rewardObserver = new MutationObserver(function (records) {
      records.forEach(function (record) {
        record.addedNodes.forEach(colorRewardBadges);
      });
    });
    rewardObserver.observe(document.body, {childList:true, subtree:true});
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', removeLegacyMiningGuide, { once: true });
    document.addEventListener('DOMContentLoaded', formatRichListBalances, { once: true });
    document.addEventListener('DOMContentLoaded', clarifyStakingMinimum, { once: true });
    document.addEventListener('DOMContentLoaded', window.loadValidatorsPage, { once: true });
    document.addEventListener('DOMContentLoaded', initializeRewardColors, { once: true });
  } else {
    removeLegacyMiningGuide();
    formatRichListBalances();
    clarifyStakingMinimum();
    window.loadValidatorsPage();
    initializeRewardColors();
  }

  function markMempoolContext() {
    document.querySelectorAll('.nav-bar .nb-tab.active, .side-nav .sn-link.active').forEach(function (item) {
      item.classList.remove('active');
    });
    var mobile = document.querySelector('.nav-bar .nb-tab[href="/mempool"]');
    var desktop = document.querySelector('.side-nav .sn-link[href="/mempool"]');
    if (mobile) mobile.classList.add('active');
    if (desktop) desktop.classList.add('active');
    return Boolean(mobile || desktop);
  }

  if (txPath.test(window.location.pathname)) {
    if (!markMempoolContext()) {
      var observer = new MutationObserver(function () {
        if (markMempoolContext()) observer.disconnect();
      });
      observer.observe(document.documentElement, { childList: true, subtree: true });
      document.addEventListener('DOMContentLoaded', function () {
        markMempoolContext();
        observer.disconnect();
      }, { once: true });
    }
  }

  // Every route loads a current document and initializes its own scripts.
  // Partial content swaps skipped the incoming page initialization and nonce.
  window.__veldExplorerSoftTxNav = true;
  window.addEventListener('pageshow', function (event) {
    if (event.persisted) window.location.reload();
  });
})();

(function () {
  'use strict';
  if (location.pathname !== '/') return;

  var state = { pending: false, target: '', loaded: '', retryAt: 0, failures: 0, controller: null,
    tip: null, continuous: false, lastPoll: null, epoch: 0 };
  var firstSeen = new Map();

  function textElement(tag, className, text) {
    var el = document.createElement(tag);
    el.className = className;
    if (text != null) el.textContent = text;
    return el;
  }
  function retryDelay(response) {
    var value = response.headers.get('Retry-After');
    var delay = /^\d+$/.test(value || '') ? Number(value) * 1000 : Date.parse(value) - Date.now();
    return Number.isFinite(delay) && delay > 0 ? delay : (response.status === 429 ? 60000 : 2000);
  }
  function displayAge(seconds) {
    seconds = Math.max(0, Math.floor(seconds));
    if (seconds < 60) return seconds + ' s';
    if (seconds < 3600) return Math.floor(seconds / 60) + ' m';
    if (seconds < 86400) return Math.floor(seconds / 3600) + ' h';
    return Math.floor(seconds / 86400) + ' d';
  }
  function updateAge(el) {
    var seen = firstSeen.get(el.dataset.blockHash);
    var observed = typeof seen === 'number';
    var seconds = observed ? (performance.now() - seen) / 1000 : Date.now() / 1000 - Number(el.dataset.blockTime);
    el.textContent = displayAge(seconds);
  }
  function updateAges() {
    document.querySelectorAll('#blocks-list [data-block-time]').forEach(updateAge);
  }
  function updateTipAge(hash) {
    var seen = firstSeen.get(hash);
    var el = document.getElementById('s-tip-age');
    if (el && typeof seen === 'number') el.textContent = '+' + displayAge((performance.now() - seen) / 1000);
  }
  function pauseObservation() {
    state.continuous = false; state.lastPoll = null; state.tip = null; state.loaded = ''; state.epoch++;
    firstSeen.clear();
    if (state.controller) state.controller.abort();
  }
  function validate(data, height, hash) {
    if (!data || !Number.isSafeInteger(data.tip_height) || data.tip_height < height ||
        !/^[0-9a-f]{64}$/.test(data.tip_hash || '') || data.start !== height ||
        data.end !== Math.max(0, height - 9) || !Array.isArray(data.blocks) ||
        data.blocks.length !== data.start - data.end + 1) throw new Error('Invalid block page');
    data.blocks.forEach(function (block, index) {
      if (!block || block.height !== height - index || !/^[0-9a-f]{64}$/.test(block.hash || '') ||
          !Number.isFinite(block.time) || block.time < 0) throw new Error('Invalid block');
      if (index && data.blocks[index - 1].prev_hash !== block.hash) throw new Error('Disconnected block page');
    });
    if (hash && data.blocks[0].hash !== hash) {
      var changed = new Error('Tip changed'); changed.retryMs = 2000; throw changed;
    }
    return data.blocks;
  }
  function paint(blocks, observed) {
    var list = document.getElementById('blocks-list');
    if (!list) return;
    var fragment = document.createDocumentFragment();
    blocks.forEach(function (block, index) {
      if (!firstSeen.has(block.hash)) firstSeen.set(block.hash, observed && index === 0 ? performance.now() : null);
      if (firstSeen.size > 40) firstSeen.delete(firstSeen.keys().next().value);
      var link = textElement('a', 'bk' + (index === 0 ? ' fresh' : ''));
      link.href = '/block/height/' + block.height;
      link.appendChild(textElement('div', 'ic', Math.floor(block.height / 1000) + 'k'));
      var info = textElement('div', 'info');
      var heading = textElement('div', 'h', '#' + block.height.toLocaleString());
      if (block.miner === 'VQmKGWN5B5YWhudSL1ZdNcxGvZ8JdEtH5Q') {
        var poolBadge = textElement('span', 'bk-badge veld-pool-win', 'Pool');
        poolBadge.title = 'Mined to the Veld Pool reward address';
        heading.appendChild(poolBadge);
      }
      var slot = textElement('span', 'bk-badges');
      slot.dataset.bh = block.height; slot.dataset.blockHash = block.hash;
      heading.appendChild(slot); info.appendChild(heading);
      info.appendChild(textElement('div', 's', shortHash(block.hash) + (block.miner ? ' · ' + shortAddr(block.miner) : '')));
      link.appendChild(info);
      var right = textElement('div', 'right');
      var age = textElement('div', 'ago');
      age.dataset.blockTime = block.time; age.dataset.blockHash = block.hash; updateAge(age);
      right.appendChild(age);
      right.appendChild(textElement('div', 'tx', (block.tx_count || block.ntx || 0) + ' tx · ' + (block.size_kb || Math.round((block.size || 0) / 102.4) / 10) + ' KB'));
      link.appendChild(right); fragment.appendChild(link);
    });
    list.replaceChildren(fragment);
    state.tip = blocks[0]; state.continuous = true;
    updateTipAge(blocks[0].hash);
  }
  window.veldExplorerDashboard = {
    load: function (height, hash) {
      if (!Number.isSafeInteger(height) || height < 0) return;
      if (document.hidden || location.pathname !== '/') { pauseObservation(); return; }
      var now = performance.now();
      if (state.lastPoll !== null && now - state.lastPoll > 15000) pauseObservation();
      state.lastPoll = now;
      hash = /^[0-9a-f]{64}$/.test(hash || '') ? hash : '';
      var key = height + ':' + hash;
      state.target = key;
      updateAges();
      updateTipAge(hash);
      if (state.pending || Date.now() < state.retryAt) return;
      if (state.loaded === key) return;
      state.pending = true;
      var epoch = state.epoch, previous = state.tip, continuous = state.continuous;
      var controller = new AbortController(); state.controller = controller;
      var timer = setTimeout(function () { controller.abort(); }, 8000);
      var list = document.getElementById('blocks-list');
      if (list) list.setAttribute('aria-busy', 'true');
      return fetch('/api/v1/blocks/' + height + '/10', {cache:'no-store', signal:controller.signal})
        .then(function (response) {
          if (!response.ok) { var error = new Error('Block page unavailable'); error.retryMs = retryDelay(response); throw error; }
          return response.json();
        }).then(function (data) {
          var blocks = validate(data, height, hash);
          if (key !== state.target || controller.signal.aborted || epoch !== state.epoch || document.hidden || location.pathname !== '/') return;
          var tip = blocks[0];
          var observed = continuous && previous && (
            (tip.height === previous.height + 1 && tip.prev_hash === previous.hash) ||
            (tip.height === previous.height && tip.hash !== previous.hash && tip.prev_hash === previous.prev_hash));
          paint(blocks, observed); state.loaded = key; state.failures = 0; state.retryAt = 0;
        }).catch(function (error) {
          if (epoch !== state.epoch || (controller.signal.aborted && document.hidden)) return;
          if (key !== state.target) return;
          state.failures++;
          state.retryAt = Date.now() + Math.max(error.retryMs || 0, Math.min(30000, 1000 * Math.pow(2, state.failures)));
          state.loaded = '';
          state.continuous = false;
          if (list) {
            var status = textElement('div', 'explorer-data-status', 'Recent blocks are temporarily unavailable. Retrying automatically.');
            status.setAttribute('role', 'status'); list.replaceChildren(status);
          }
        }).finally(function () {
          clearTimeout(timer); state.pending = false; state.controller = null;
          if (list) list.removeAttribute('aria-busy');
        });
    }
  };
  document.addEventListener('visibilitychange', function () { if (document.hidden) pauseObservation(); });
  window.addEventListener('pagehide', pauseObservation);
})();

// Both block lists derive their badges from the same event feed and renderer.
(function () {
  'use strict';
  if (location.pathname !== '/' && location.pathname !== '/blocks') return;
  var badgeTypes = {btcveld_mint:['Mint','gold'],btcveld_redeem:['Redeem','gold'],btcveld_transfer:['btcVELD','gold'],amm_op:['AMM','blue'],stake_lock:['Stake','veld-reward-stake'],stake_unlock:['Unstake','veld-reward-stake'],endorsement:['Endorse','veld-reward-validator'],validator_register:['Validator','veld-reward-validator'],staking_distribution:['Payout','veld-reward-stake'],endorsement_distribution:['Val payout','veld-reward-validator'],anchor_post:['Anchor','gold'],btc_header_relay:['BTC hdr','gold'],near_miss:['Near miss','veld-near-miss']};
  var cache = new Map(), pending = new Map(), retries = new Map();
  var retryTimer = null, list = null;
  function visible() { return !document.hidden && (location.pathname === '/' || location.pathname === '/blocks'); }
  function describe(row) {
    var match = /^\/block\/height\/(\d+)$/.exec(row.getAttribute('href') || '');
    var meta = row.querySelector('.info .s'), count = row.querySelector('.tx');
    if (!match || !meta || !count || parseInt(count.textContent, 10) <= 1) return null;
    var height = Number(match[1]);
    if (!Number.isSafeInteger(height)) return null;
    return {row:row, height:height, key:height + ':' + meta.textContent.trim().split(/\s/)[0]};
  }
  function render(item, types) {
    if (!list.contains(item.row)) return;
    var current = describe(item.row);
    if (!current || current.key !== item.key) return;
    var heading = item.row.querySelector('.info .h');
    if (!heading) return;
    var slot = heading.querySelector('.bk-badges');
    if (!slot && !types.length) return;
    if (!slot) {
      slot = document.createElement('span'); slot.className = 'bk-badges';
      heading.appendChild(slot);
    }
    if (slot.dataset.eventsKey === item.key) return;
    slot.replaceChildren();
    types.forEach(function (type) {
      var badge = document.createElement('span');
      badge.className = 'bk-badge ' + badgeTypes[type][1]; badge.textContent = badgeTypes[type][0];
      slot.appendChild(badge);
    });
    slot.dataset.eventsKey = item.key;
  }
  function scheduleRetry() {
    if (retryTimer !== null || !visible()) return;
    retryTimer = setTimeout(function () { retryTimer = null; refresh(); }, 2000);
  }
  function refresh() {
    if (!list || !visible()) return;
    var items = Array.from(list.querySelectorAll('a.bk')).map(describe).filter(Boolean);
    var keys = new Set(items.map(function (item) { return item.key; }));
    pending.forEach(function (controller, key) { if (!keys.has(key)) controller.abort(); });
    retries.forEach(function (_, key) { if (!keys.has(key)) retries.delete(key); });
    items.forEach(function (item) {
      if (cache.has(item.key)) { render(item, cache.get(item.key)); return; }
      if (pending.has(item.key)) return;
      if (Date.now() < (retries.get(item.key) || 0)) { scheduleRetry(); return; }
      if (pending.size >= 2) return;
      var controller = new AbortController(); pending.set(item.key, controller);
      var timer = setTimeout(function () { controller.abort(); }, 8000);
      fetch('/api/v1/events/' + item.height, {cache:'no-store', signal:controller.signal})
        .then(function (response) {
          if (!response.ok) {
            var error = new Error('Events unavailable');
            var hint = response.headers && response.headers.get('Retry-After');
            var delay = /^\d+$/.test(hint || '') ? Number(hint) * 1000 : Date.parse(hint) - Date.now();
            error.retryMs = Number.isFinite(delay) && delay > 0 ? delay : (response.status === 429 ? 60000 : 5000);
            throw error;
          }
          return response.json();
        }).then(function (data) {
          if (controller.signal.aborted || !visible()) return;
          if (!data || data.height !== item.height || !Array.isArray(data.events)) throw new Error('Invalid events');
          var types = Array.from(new Set(data.events.map(function (event) { return event && event.type; })))
            .filter(function (type) { return Object.prototype.hasOwnProperty.call(badgeTypes, type); });
          cache.set(item.key, types); retries.delete(item.key);
          if (cache.size > 128) cache.delete(cache.keys().next().value);
          render(item, types);
        }).catch(function (error) {
          retries.set(item.key, Date.now() + Math.max(5000, error.retryMs || 0)); scheduleRetry();
        }).finally(function () {
          clearTimeout(timer); pending.delete(item.key); refresh();
        });
    });
  }
  function start() {
    list = document.getElementById(location.pathname === '/' ? 'blocks-list' : 'blocks-container');
    if (!list) return;
    var observer = new MutationObserver(refresh);
    observer.observe(list, {childList:true});
    refresh();
  }
  function pause() {
    if (retryTimer !== null) clearTimeout(retryTimer);
    retryTimer = null;
    pending.forEach(function (controller) { controller.abort(); });
  }
  document.addEventListener('visibilitychange', function () { if (document.hidden) pause(); else refresh(); });
  window.addEventListener('pagehide', pause);
  window.addEventListener('popstate', refresh);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, {once:true});
  else start();
})();

// Keep the installed app's navigation controls mounted when opening Mempool.
(function () {
  'use strict';
  function removePendingFeeSummary(root) {
    root.querySelectorAll('.hero .meta > .it').forEach(function (item) {
      if (!/\bVELD\s+pending fees\s*$/.test(item.textContent)) return;
      var size = item.querySelector('b');
      if (!size || !/^\d+\s+(?:B|KB)$/.test(size.textContent.trim())) return;
      while (size.nextSibling) size.nextSibling.remove();
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { removePendingFeeSummary(document); }, {once: true});
  } else removePendingFeeSummary(document);

  var standalone = navigator.standalone === true ||
    (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);
  if (!standalone || window.location.pathname === '/mempool') return;

  function initialize() {
    var originView = document.querySelector('body > .wrap');
    var nav = document.querySelector('.nav-bar');
    if (!originView || !nav) return;
    var originUrl = window.location.href;
    var originTitle = document.title;
    var originDisplay = originView.style.getPropertyValue('display');
    var originPriority = originView.style.getPropertyPriority('display');
    var links = Array.from(document.querySelectorAll('.nav-bar .nb-tab, .side-nav .sn-link'));
    var selection = links.map(function (link) {
      return {link: link, active: link.classList.contains('active'),
        sticky: link.getAttribute('data-active-sticky'), current: link.getAttribute('aria-current')};
    });
    var stateKey = 'mempool-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2);
    var historyReady = false;
    var mempoolView = null;
    var controller = null;
    var timeout = null;
    var generation = 0;

    function closeMore() {
      var more = document.getElementById('nav-more');
      if (more) more.removeAttribute('data-open');
    }

    function cancelRequest() {
      generation++;
      if (timeout !== null) window.clearTimeout(timeout);
      timeout = null;
      if (controller) controller.abort();
      controller = null;
      originView.removeAttribute('aria-busy');
    }

    function restoreOrigin() {
      cancelRequest();
      if (mempoolView) mempoolView.remove();
      mempoolView = null;
      if (originDisplay) originView.style.setProperty('display', originDisplay, originPriority);
      else originView.style.removeProperty('display');
      document.title = originTitle;
      closeMore();
      selection.forEach(function (item) {
        item.link.classList.toggle('active', item.active);
        if (item.sticky === null) item.link.removeAttribute('data-active-sticky');
        else item.link.setAttribute('data-active-sticky', item.sticky);
        if (item.current === null) item.link.removeAttribute('aria-current');
        else item.link.setAttribute('aria-current', item.current);
      });
      window.scrollTo(0, 0);
    }

    function loadMempool(push) {
      if (controller) return;
      controller = new AbortController();
      var request = controller;
      var requestGeneration = ++generation;
      originView.setAttribute('aria-busy', 'true');
      timeout = window.setTimeout(function () { request.abort(); }, 15000);
      fetch('/mempool', {cache: 'no-store', credentials: 'same-origin', signal: request.signal})
        .then(function (response) {
          var finalUrl = new URL(response.url);
          if (!response.ok || finalUrl.origin !== window.location.origin ||
              finalUrl.pathname !== '/mempool' ||
              !/^text\/html\b/i.test(response.headers.get('Content-Type') || '')) {
            throw new Error('Mempool page unavailable');
          }
          return response.text();
        })
        .then(function (html) {
          if (requestGeneration !== generation) return;
          if (html.length > 2 * 1024 * 1024) throw new Error('Mempool page too large');
          var page = new DOMParser().parseFromString(html, 'text/html');
          var content = page.querySelector('body > .wrap');
          if (!content || !/Mempool/i.test(page.title)) throw new Error('Invalid Mempool page');
          // The existing document owns scripts and controls; the response supplies content.
          content.querySelectorAll('script,base,iframe,object,embed,link,meta').forEach(function (el) { el.remove(); });
          content.querySelectorAll('*').forEach(function (el) {
            Array.from(el.attributes).forEach(function (attr) {
              if (/^on/i.test(attr.name)) el.removeAttribute(attr.name);
            });
            if (el.hasAttribute('href') && /^\s*javascript:/i.test(el.getAttribute('href'))) el.removeAttribute('href');
          });
          var next = document.importNode(content, true);
          removePendingFeeSummary(next);
          next.setAttribute('data-veld-mempool-view', '1');
          if (push) {
            if (!historyReady) {
              history.replaceState({veldMempool: stateKey, view: 'origin', previous: history.state}, '', originUrl);
              historyReady = true;
            }
            history.pushState({veldMempool: stateKey, view: 'mempool'}, '', '/mempool');
          }
          if (mempoolView) mempoolView.remove();
          originView.style.setProperty('display', 'none', 'important');
          originView.after(next);
          mempoolView = next;
          document.title = page.title;
          closeMore();
          links.forEach(function (link) {
            var active = link.getAttribute('href') === '/mempool';
            link.classList.toggle('active', active);
            link.removeAttribute('data-active-sticky');
            if (active) link.setAttribute('aria-current', 'page');
            else link.removeAttribute('aria-current');
          });
          window.scrollTo(0, 0);
        })
        .catch(function () {
          if (requestGeneration === generation) window.location.assign('/mempool');
        })
        .finally(function () {
          if (requestGeneration !== generation) return;
          if (timeout !== null) window.clearTimeout(timeout);
          timeout = null;
          controller = null;
          originView.removeAttribute('aria-busy');
        });
    }

    document.addEventListener('click', function (event) {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      var target = event.target.closest && event.target.closest('.nav-bar a.nb-tab[href], .side-nav a.sn-link[href]');
      if (!target || target.hasAttribute('download') || (target.target && target.target !== '_self')) return;
      var url = new URL(target.href, window.location.href);
      if (url.origin !== window.location.origin) return;
      if (url.pathname === '/mempool' && !url.search && !url.hash) {
        event.preventDefault();
        if (!mempoolView) loadMempool(true);
      } else if ((mempoolView || controller) && url.href === originUrl) {
        event.preventDefault();
        if (mempoolView) history.pushState({veldMempool: stateKey, view: 'origin'}, '', originUrl);
        restoreOrigin();
      } else if (controller) {
        cancelRequest();
      }
    });
    window.addEventListener('popstate', function (event) {
      if (!event.state || event.state.veldMempool !== stateKey) return;
      if (event.state.view === 'origin') restoreOrigin();
      else if (event.state.view === 'mempool') loadMempool(false);
    });
    window.addEventListener('pagehide', cancelRequest);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize, {once: true});
  else initialize();
})();
