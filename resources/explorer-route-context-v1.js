(function () {
  'use strict';

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

  function refreshConsensusPhase() {
    fetch('/api/stats', {cache: 'no-store', credentials: 'same-origin'})
      .then(function (response) {
        if (!response.ok) throw new Error('stats unavailable');
        return response.json();
      })
      .then(renderConsensusPhase)
      .catch(function () {});
  }

  function calculateExpectedHashes(bits) {
    var exponent = bits >>> 24;
    var mantissa = bits & 0x007fffff;
    if (exponent < 3 || exponent > 32 || mantissa <= 0) return 0;
    return Math.pow(2, 256 - 8 * (exponent - 3) - Math.log2(mantissa));
  }

  function refreshObservedHashrate() {
    if (window.location.pathname !== '/') return;
    fetch('/api/stats', {cache: 'no-store', credentials: 'same-origin'})
      .then(function (response) {
        if (!response.ok) throw new Error('stats unavailable');
        return response.json();
      })
      .then(function (stats) {
        var height = Number(stats.height || 0);
        if (!Number.isSafeInteger(height) || height < 1) return;
        var sample = Math.min(height, 10);
        return Promise.all([
          fetch('/api/v1/block/' + height, {cache: 'no-store'}).then(function (r) { return r.json(); }),
          fetch('/api/v1/block/' + (height - sample), {cache: 'no-store'}).then(function (r) { return r.json(); })
        ]).then(function (blocks) {
          var latest = blocks[0];
          var earlier = blocks[1];
          var elapsed = Number(latest.time) - Number(earlier.time);
          var expected = calculateExpectedHashes(Number(latest.bits));
          if (!(elapsed > 0) || !(expected > 0)) return;
          var rate = expected / (elapsed / sample);
          var value = document.getElementById('s-hashrate');
          if (value) value.innerHTML = (rate / 1000).toFixed(1) + '<span class="u">KH/s</span>';
          var tile = value && value.closest('.tile');
          var label = tile && tile.querySelector('.l');
          if (label) label.textContent = 'Hashrate (10-block estimate)';
        });
      })
      .catch(function () {});
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', removeLegacyMiningGuide, { once: true });
    document.addEventListener('DOMContentLoaded', formatRichListBalances, { once: true });
    document.addEventListener('DOMContentLoaded', refreshConsensusPhase, { once: true });
    document.addEventListener('DOMContentLoaded', refreshObservedHashrate, { once: true });
  } else {
    removeLegacyMiningGuide();
    formatRichListBalances();
    refreshConsensusPhase();
    refreshObservedHashrate();
  }

  window.setInterval(refreshObservedHashrate, 10000);

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

  if (window.__veldExplorerSoftTxNav) return;
  window.__veldExplorerSoftTxNav = true;
  var enteredMempoolInShell = false;

  function eligiblePath(path) {
    return path === '/mempool' || txPath.test(path);
  }

  function scrollToTop() {
    window.scrollTo(0, 0);
    var wrap = document.querySelector('.wrap');
    if (wrap && typeof wrap.scrollTo === 'function') wrap.scrollTo(0, 0);
  }

  async function loadInShell(url, push) {
    try {
      var response = await fetch(url, {
        cache: 'no-store',
        credentials: 'same-origin',
        headers: { Accept: 'text/html' }
      });
      if (!response.ok || response.redirected) {
        window.location.assign(response.url || url);
        return;
      }

      var parsed = new DOMParser().parseFromString(await response.text(), 'text/html');
      var incoming = parsed.querySelector('.wrap');
      var current = document.querySelector('.wrap');
      if (!incoming || !current) throw new Error('Explorer content pane missing');

      current.replaceChildren.apply(current, Array.from(incoming.childNodes).map(function (node) {
        return document.importNode(node, true);
      }));
      document.title = parsed.title || document.title;

      var resolved = new URL(response.url || url, window.location.href);
      if (push) history.pushState({ veldExplorerSoftTxNav: true }, '', resolved.pathname + resolved.search + resolved.hash);
      markMempoolContext();
      refreshConsensusPhase();
      scrollToTop();
    } catch (_) {
      window.location.assign(url);
    }
  }

  document.addEventListener('click', function (event) {
    var link = event.target.closest ? event.target.closest('a[href]') : null;
    if (!link) return;
    var target = new URL(link.href, window.location.href);
    var enteringMempool = target.origin === window.location.origin &&
      target.pathname === '/mempool' && window.location.pathname !== '/mempool' &&
      link.matches('.nav-bar .nb-tab, .side-nav .sn-link');
    var openingTransaction = window.location.pathname === '/mempool' && txPath.test(target.pathname);
    if (!enteringMempool && !openingTransaction) return;
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    if (enteringMempool) enteredMempoolInShell = true;
    loadInShell(link.href, true);
  });

  window.addEventListener('popstate', function () {
    if (eligiblePath(window.location.pathname)) {
      loadInShell(window.location.href, false);
    } else if (enteredMempoolInShell) {
      window.location.reload();
    }
  });
})();
