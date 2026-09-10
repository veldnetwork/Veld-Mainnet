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

  if (window.location.pathname === '/mining') {
    document.documentElement.dataset.veldMiningConsensus = 'pending';
    var miningConsensusStyle = document.createElement('style');
    miningConsensusStyle.id = 'veld-mining-consensus-first-paint';
    miningConsensusStyle.textContent =
      'html[data-veld-mining-consensus="pending"] .container>.stat-grid+.card{visibility:hidden!important}';
    document.head.appendChild(miningConsensusStyle);
  }

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

  function cardByTitle(titleText) {
    var titles = document.querySelectorAll('.card > .card-title');
    for (var i = 0; i < titles.length; i++) {
      if (titles[i].textContent.trim() === titleText) return titles[i].closest('.card');
    }
    return null;
  }

  function setStat(labelText, valueText, detailText) {
    var labels = document.querySelectorAll('.stat-label');
    for (var i = 0; i < labels.length; i++) {
      if (labels[i].textContent.trim() !== labelText) continue;
      var stat = labels[i].closest('.stat');
      var value = stat && stat.querySelector('.stat-value');
      var detail = stat && stat.querySelector('.stat-sub');
      if (value) value.textContent = valueText;
      if (detail && detailText != null) detail.textContent = detailText;
      return;
    }
  }

  function renderConsensusPhase(stats) {
    var active = Boolean(stats && stats.staking_active);
    var path = window.location.pathname;

    if (path === '/mining') {
      var miningCard = cardByTitle('Coinbase Split');
      var body = miningCard && miningCard.querySelector('tbody');
      if (body) {
        body.innerHTML = active
          ? '<tr><td style="color:var(--em);font-weight:600">Miner</td><td><strong>50%</strong></td><td>Direct reward to block finder</td></tr>' +
            '<tr><td style="color:#4CB8FF;font-weight:600">Co-Mining Pool</td><td><strong>20%</strong></td><td>Eligible near-miss miners</td></tr>' +
            '<tr><td style="color:var(--gold);font-weight:600">Vault</td><td><strong>20%</strong></td><td>Staker reward pool</td></tr>' +
            '<tr><td style="color:#B07CFF;font-weight:600">Validators</td><td><strong>10%</strong></td><td>Active validator reward pool</td></tr>'
          : '<tr><td style="color:var(--em);font-weight:600">Miner</td><td><strong>50%</strong></td><td>Direct reward to block finder</td></tr>' +
            '<tr><td style="color:var(--gold);font-weight:600">Vault</td><td><strong>50%</strong></td><td>Accumulates until staking activates at 10,000 VELD issued supply</td></tr>';
      }
      document.documentElement.dataset.veldMiningConsensus = 'ready';
    }

    if (path === '/vault') {
      var reward = Number(stats.block_reward_veld || 3.13926940);
      var ordinaryShare = active ? 0.20 : 0.50;
      var inflow = 480 * reward * ordinaryShare +
        480 * 0.01 * reward * (1 - ordinaryShare);
      setStat('Daily Inflow', '~' + inflow.toFixed(1), 'VELD/day into vault');
      setStat('Daily Payout', active ? '~' + (inflow * 0.90).toFixed(1) : '0.0',
        active ? 'VELD/day to stakers (90% inflow cap)' : 'staking inactive; no distribution');
      setStat('Daily Retention', active ? '~' + (inflow * 0.10).toFixed(1) : '~' + inflow.toFixed(1),
        active ? 'VELD/day vault growth (10%)' : 'all inflow retained before activation');
      var funding = cardByTitle('Vault Funding Sources');
      var firstRow = funding && funding.querySelector('tbody tr');
      if (firstRow) firstRow.innerHTML = '<td>Ordinary block reward share</td><td style="color:var(--em)">' +
        (active ? '20%' : '50%') + '</td><td style="color:var(--muted)">Every non-vault block</td>';
    }

    if (path === '/rules') {
      var split = document.getElementById('splits');
      var splitIntro = split && split.parentElement.querySelector('p');
      if (splitIntro) splitIntro.innerHTML = 'Before staking activates at 10,000 VELD issued supply, each ordinary block pays <strong>50% to the miner and 50% to the vault</strong>. After activation, ordinary blocks use the four-way split below. Every 100th block routes its full subsidy to the vault in both phases.';
      var privacy = document.getElementById('privacy');
      var items = privacy && privacy.parentElement.querySelectorAll('li');
      if (items) Array.from(items).forEach(function (item) {
        if (item.textContent.indexOf('Post-quantum signatures.') !== 0) return;
        item.innerHTML = '<strong>Cryptographic boundary.</strong> Native VELD transaction and finality signatures use ML-DSA-65. Native ordinary outputs currently use 160-bit HASH160 key commitments, so this is not an end-to-end post-quantum claim. btcVELD custody inherits Bitcoin Taproot\u2019s current secp256k1/Schnorr assumptions.';
      });
    }
  }

  function clarifyStakingMinimum() {
    if (window.location.pathname === '/staking') {
      document.querySelectorAll('table.tbl tbody tr').forEach(function (row) {
        var cells = row.querySelectorAll('td');
        if (cells.length !== 3 || !/^Minimum (Ordinary )?Stake$/.test(cells[0].textContent.trim())) return;
        cells[0].textContent = 'Minimum Ordinary Stake';
        var minimum = Number.parseFloat(cells[1].textContent.replace(/,/g, ''));
        cells[2].textContent = minimum > 500
          ? '500 VELD from block 3,840'
          : 'Per new ordinary stake; transaction fee is additional';
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

  function renderInitialConsensusPhase() {
    if (window.location.pathname !== '/mining') return;
    var labels = document.querySelectorAll('.stat-label');
    var supply = NaN;
    for (var i = 0; i < labels.length; i++) {
      if (labels[i].textContent.trim() !== 'Total Supply') continue;
      var stat = labels[i].closest('.stat');
      var value = stat && stat.querySelector('.stat-value');
      if (value) supply = Number.parseFloat(value.textContent.replace(/,/g, ''));
      break;
    }
    if (Number.isFinite(supply)) {
      renderConsensusPhase({ staking_active: supply >= 10000 });
    }
  }

  function refreshConsensusPhase() {
    fetch('/api/stats', {cache: 'no-store', credentials: 'same-origin'})
      .then(function (response) {
        if (!response.ok) throw new Error('stats unavailable');
        return response.json();
      })
      .then(renderConsensusPhase)
      .catch(function () {});
  }


  // Transaction and event badges share the coinbase recipient palette.
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
    document.addEventListener('DOMContentLoaded', renderInitialConsensusPhase, { once: true });
    document.addEventListener('DOMContentLoaded', refreshConsensusPhase, { once: true });
    document.addEventListener('DOMContentLoaded', clarifyStakingMinimum, { once: true });
    document.addEventListener('DOMContentLoaded', initializeRewardColors, { once: true });
  } else {
    removeLegacyMiningGuide();
    formatRichListBalances();
    renderInitialConsensusPhase();
    refreshConsensusPhase();
    clarifyStakingMinimum();
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

  var state = { pending: false, target: '', loaded: '', retryAt: 0, failures: 0, controller: null };
  var badges = new Map();
  var badgeTypes = {btcveld_mint:['Mint','gold'],btcveld_redeem:['Redeem','gold'],btcveld_transfer:['btcVELD','gold'],amm_op:['AMM','blue'],stake_lock:['Stake','veld-reward-stake'],stake_unlock:['Unstake','veld-reward-stake'],endorsement:['Endorse','veld-reward-validator'],validator_register:['Validator','veld-reward-validator'],staking_distribution:['Payout','veld-reward-stake'],endorsement_distribution:['Val payout','veld-reward-validator'],anchor_post:['Anchor','gold'],btc_header_relay:['BTC hdr','gold']};

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
  function paint(blocks) {
    var list = document.getElementById('blocks-list');
    if (!list) return;
    var fragment = document.createDocumentFragment();
    blocks.forEach(function (block, index) {
      var link = textElement('a', 'bk' + (index === 0 ? ' fresh' : ''));
      link.href = '/block/height/' + block.height;
      link.appendChild(textElement('div', 'ic', Math.floor(block.height / 1000) + 'k'));
      var info = textElement('div', 'info');
      var heading = textElement('div', 'h', '#' + block.height.toLocaleString());
      var slot = textElement('span', 'bk-badges');
      slot.dataset.bh = block.height; slot.dataset.blockHash = block.hash;
      heading.appendChild(slot); info.appendChild(heading);
      info.appendChild(textElement('div', 's', shortHash(block.hash) + (block.miner ? ' · ' + shortAddr(block.miner) : '')));
      link.appendChild(info);
      var right = textElement('div', 'right');
      var age = textElement('div', 'ago', ago(block.time)); age.dataset.blockTime = block.time;
      right.appendChild(age);
      right.appendChild(textElement('div', 'tx', (block.tx_count || block.ntx || 0) + ' tx · ' + (block.size_kb || Math.round((block.size || 0) / 102.4) / 10) + ' KB'));
      link.appendChild(right); fragment.appendChild(link);
    });
    list.replaceChildren(fragment);
  }
  async function paintBadges(blocks, key, signal) {
    for (var block of blocks) {
      if (key !== state.target || document.hidden || signal.aborted) return;
      if ((block.tx_count || block.ntx || 0) <= 1) continue;
      try {
        var types = badges.get(block.hash);
        if (!types) {
          var response = await fetch('/api/v1/events/' + block.height, {cache:'no-store', signal:signal});
          if (!response.ok) return;
          var data = await response.json();
          if (!data || !Array.isArray(data.events)) return;
          types = Array.from(new Set(data.events.map(function (event) { return event && event.type; }))).filter(function (type) { return Boolean(badgeTypes[type]); });
          badges.set(block.hash, types);
          if (badges.size > 40) badges.delete(badges.keys().next().value);
        }
        if (key !== state.target) return;
        var slot = document.querySelector('.bk-badges[data-block-hash="' + block.hash + '"]');
        if (slot) {
          slot.replaceChildren();
          types.forEach(function (type) { slot.appendChild(textElement('span', 'bk-badge ' + badgeTypes[type][1], badgeTypes[type][0])); });
        }
      } catch (_) { return; }
    }
  }
  window.veldExplorerDashboard = {
    load: function (height, hash) {
      if (!Number.isSafeInteger(height) || height < 0) return;
      hash = /^[0-9a-f]{64}$/.test(hash || '') ? hash : '';
      var key = height + ':' + hash;
      state.target = key;
      if (document.hidden || state.pending || Date.now() < state.retryAt) return;
      if (state.loaded === key) {
        document.querySelectorAll('#blocks-list [data-block-time]').forEach(function (el) { el.textContent = ago(Number(el.dataset.blockTime)); });
        return;
      }
      state.pending = true;
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
          if (key !== state.target || controller.signal.aborted) return;
          paint(blocks); state.loaded = key; state.failures = 0; state.retryAt = 0;
          return paintBadges(blocks, key, controller.signal);
        }).catch(function (error) {
          if (controller.signal.aborted && document.hidden) return;
          if (key !== state.target) return;
          state.failures++;
          state.retryAt = Date.now() + Math.max(error.retryMs || 0, Math.min(30000, 1000 * Math.pow(2, state.failures)));
          state.loaded = '';
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
  window.addEventListener('pagehide', function () { if (state.controller) state.controller.abort(); });
})();

// Keep the installed app's navigation controls mounted when opening Mempool.
(function () {
  'use strict';
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
