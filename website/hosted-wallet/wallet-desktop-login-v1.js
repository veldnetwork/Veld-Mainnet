// Label the existing wallet modal action for its current session state.
(function () {
  'use strict';
  function ready() {
    var action = document.getElementById('ks-btn');
    var state = document.getElementById('ks-label');
    if (!action || !state) return;
    function sync() {
      var locked = state.classList.contains('ks-locked');
      action.textContent = locked ? 'Log in' : 'Settings';
      action.setAttribute('aria-label', locked ? 'Log in to wallet' : 'Wallet settings');
    }
    sync();
    new MutationObserver(sync).observe(state, {attributes:true,attributeFilter:['class'],childList:true});
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded',ready,{once:true});
  else ready();
}());
