(function () {
  'use strict';

  var pendingBtcNavigation = null;
  var btcRefreshInFlight = false;

  function removeProjectedYield() {
    var projection = document.getElementById('sk-yield-projection');
    if (projection) projection.remove();
  }

  function btcElement(id) {
    return document.getElementById(id);
  }

  function ensureBtcLoadingCard() {
    var page = btcElement('page-btcveld');
    if (!page) return null;
    var loading = btcElement('bv-current-loading');
    if (loading) return loading;
    loading = document.createElement('div');
    loading.id = 'bv-current-loading';
    loading.className = 'card';
    loading.setAttribute('role', 'status');
    loading.setAttribute('aria-live', 'polite');
    loading.style.cssText = 'display:none;text-align:center;padding:28px 22px;color:var(--muted);font-size:13px';
    loading.textContent = 'Loading current btcVELD state…';
    var header = page.querySelector('.page-header');
    if (header && header.nextSibling) page.insertBefore(loading, header.nextSibling);
    else page.appendChild(loading);
    return loading;
  }

  function setText(id, value) {
    var element = btcElement(id);
    if (element) element.textContent = value;
  }

  function beginBtcRefresh() {
    var page = btcElement('page-btcveld');
    var inactive = btcElement('bv-inactive');
    var peg = btcElement('bv-peg');
    var loading = ensureBtcLoadingCard();
    if (!page || !inactive || !peg || !loading) return;

    page.setAttribute('aria-busy', 'true');
    inactive.style.display = 'none';
    peg.style.display = 'none';
    loading.style.display = '';

    setText('bv-overview-balance', '—');
    setText('bv-overview-values', 'Loading current balance…');
    setText('bv-wrap-bal', '—');
    setText('bv-redeem-bal', '—');
    setText('bv-pay-bal', '—');
    setText('bv-get-bal', '—');
    setText('bv-pool-price', '—');
    setText('bv-pool-veld', '—');
    setText('bv-pool-btc', '—');
    setText('bv-lp-share-pct', '—');
    setText('bv-lp-veld-val', '—');
    setText('bv-lp-btc-val', '—');
    setText('bv-lp-total-val', '—');
    setText('bv-ticker-usd', '$—');
    setText('bv-ticker-sats', '— sats');

    if (window.bvState) {
      window.bvState.pool = null;
      window.bvState.veldSats = 0;
      window.bvState.btcSats = 0;
      window.bvState.lp = 0;
      window.bvState.lpSupply = 0;
      window.bvState.btcUsd = 0;
      window.bvState.removePlan = null;
    }
  }

  function finishBtcRefreshWhenAuthoritative() {
    var page = btcElement('page-btcveld');
    var inactive = btcElement('bv-inactive');
    var peg = btcElement('bv-peg');
    var loading = btcElement('bv-current-loading');
    if (!page || !inactive || !peg || !loading) return;
    if (inactive.style.display === 'none' && peg.style.display === 'none') return;

    if (inactive.style.display !== 'none') {
      var validatorRemaining = btcElement('bv-validator-remaining');
      if (validatorRemaining && /checking active validators/i.test(validatorRemaining.textContent || '')) return;
    }

    loading.style.display = 'none';
    page.removeAttribute('aria-busy');

    btcRefreshInFlight = false;
    if (pendingBtcNavigation && typeof window.__veldWalletNav === 'function') {
      var navigationTarget = pendingBtcNavigation;
      pendingBtcNavigation = null;
      window.__veldSkipBtcReload = true;
      window.__veldWalletNav('btcveld', navigationTarget);
    }
  }

  function startAtomicBtcNavigation(navigationTarget) {
    if (typeof window.__veldLoadBtcveldPage !== 'function' || typeof window.__veldWalletNav !== 'function') {
      return false;
    }
    pendingBtcNavigation = navigationTarget;
    if (btcRefreshInFlight) return true;
    btcRefreshInFlight = true;
    beginBtcRefresh();
    try {
      window.__veldLoadBtcveldPage();
      return true;
    } catch (_) {
      btcRefreshInFlight = false;
      pendingBtcNavigation = null;
      return false;
    }
  }

  function installBtcRefreshGate() {
    var inactive = btcElement('bv-inactive');
    var peg = btcElement('bv-peg');
    if (inactive && peg) {
      var observer = new MutationObserver(finishBtcRefreshWhenAuthoritative);
      observer.observe(inactive, {
        attributes: true,
        attributeFilter: ['style'],
        childList: true,
        characterData: true,
        subtree: true
      });
      observer.observe(peg, { attributes: true, attributeFilter: ['style'] });
    }

    // The wallet's route functions are block-scoped and are not exposed on
    // window.  Its delegated dispatcher listens on document in the capture
    // phase, so this guard must listen on window to run first.
    window.addEventListener('click', function (event) {
      var target = event.target;
      if (!target || typeof target.closest !== 'function') return;
      if (!target.closest('[data-act-click="hbtcveld_nav"]')) return;

      var page = btcElement('page-btcveld');
      if (page && page.classList.contains('active') && getComputedStyle(page).display !== 'none') {
        var moreMenu = btcElement('mobile-more-menu');
        if (moreMenu) moreMenu.style.display = 'none';
        event.preventDefault();
        event.stopImmediatePropagation();
        return;
      }

      var navigationTarget = target.closest('[data-act-click="hbtcveld_nav"]');
      if (!startAtomicBtcNavigation(navigationTarget)) {
        beginBtcRefresh();
        return;
      }

      var menu = btcElement('mobile-more-menu');
      if (menu) menu.style.display = 'none';
      event.preventDefault();
      event.stopImmediatePropagation();
    }, true);
  }

  function initialize() {
    var activity = document.getElementById('page-history');
    if (activity) {
      var load = activity.querySelector('[data-act-click="hd40f00e8"]');
      if (load) load.remove();
      var address = document.getElementById('h-addr');
      if (address) {
        address.setAttribute('aria-label', 'Activity address');
        if (!address.hasAttribute('data-act-input')) {
          var addressTimer = null;
          address.addEventListener('input', function () {
            clearTimeout(addressTimer);
            addressTimer = setTimeout(function () {
              var value = address.value.trim();
              if (!value || /^[1-9A-HJ-NP-Za-km-z]{26,120}$/.test(value)) {
                address.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true}));
              }
            }, 550);
          });
        }
      }
    }
    removeProjectedYield();
    var inactiveCopy = btcElement('bv-inactive-copy');
    if (inactiveCopy) inactiveCopy.remove();
    var older = btcElement('h-load-older');
    var history = btcElement('h-list');
    if (older && history) {
      var footer = document.createElement('div');
      footer.className = 'history-footer';
      history.insertAdjacentElement('afterend', footer);
      footer.appendChild(older);
      older.classList.add('btn-em');
      older.style.marginBottom = '0';
    }
    ensureBtcLoadingCard();
    installBtcRefreshGate();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize, { once: true });
  } else {
    initialize();
  }
})();
