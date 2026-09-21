(function () {
  'use strict';

  function removeLegacyBanner() {
    var banner = document.getElementById('veld-history-unavailable');
    if (banner) banner.remove();
  }

  function normalizeSwapAction() {
    var group = document.querySelector('.wallet-bal-hero .act-round');
    if (!group) return;
    var swaps = Array.prototype.filter.call(group.querySelectorAll('button'), function (button) {
      var label = button.querySelector('.lbl');
      return label && label.textContent.trim().toLowerCase() === 'swap';
    });
    var keep = swaps.filter(function (button) {
      return button.classList.contains('swap') && !button.classList.contains('recv');
    })[0] || swaps[0];
    swaps.forEach(function (button) {
      if (button !== keep) button.remove();
    });
    if (keep) {
      keep.classList.remove('recv');
      keep.classList.add('swap');
    }
  }

  var style = document.createElement('style');
  style.textContent = 'html[data-theme="light"] .wallet-bal-hero .act-round .ar.swap .ic{background:transparent!important;color:#121514!important;box-shadow:none!important}';
  document.head.appendChild(style);

  window.showPublicHistoryUnavailable = function () {};
  window.publicHistoryUnavailable = function () {
    removeLegacyBanner();
    var historyInput = document.getElementById('h-addr');
    var historyPage = document.getElementById('page-history');
    var historyPageActive = historyPage && getComputedStyle(historyPage).display !== 'none';
    var address = String((historyPageActive && historyInput && historyInput.value) || window.currentAddr || '').trim();
    if (!address) return Promise.resolve([]);
    return fetch('/history-api/v1/history?address=' + encodeURIComponent(address) + '&limit=5000', {
      method: 'GET',
      cache: 'no-store',
      credentials: 'same-origin'
    }).then(function (response) {
      if (!response.ok) throw new Error('Transaction history service unavailable');
      return response.json();
    }).then(function (payload) {
      if (!payload || !Array.isArray(payload.history))
        throw new Error('Invalid transaction history response');
      return payload.history;
    });
  };

  removeLegacyBanner();
  normalizeSwapAction();
  var observer = new MutationObserver(function () {
    removeLegacyBanner();
    normalizeSwapAction();
  });
  observer.observe(document.documentElement, {childList: true, subtree: true});
  window.setTimeout(function () {
    observer.disconnect();
    removeLegacyBanner();
    normalizeSwapAction();
  }, 15000);
})();
