(function () {
  'use strict';

  var governanceActive = false;
  var statusKnown = false;
  var requestPending = false;

  function submitButton() {
    return document.getElementById('gov-submit-btn');
  }

  function renderState() {
    var button = submitButton();
    if (!button) return;
    button.disabled = !statusKnown || !governanceActive;
    button.textContent = governanceActive ? 'Submit Proposal' : 'Governance Locked';
  }

  function refreshState() {
    if (requestPending || typeof window.rpc !== 'function') return;
    requestPending = true;
    Promise.resolve(window.rpc('getgovernanceinfo', []))
      .then(function (status) {
        governanceActive = !!(status && status.governance_active === true);
        statusKnown = true;
        renderState();
      })
      .catch(function () {
        governanceActive = false;
        statusKnown = false;
        renderState();
      })
      .then(function () { requestPending = false; });
  }

  function init() {
    renderState();
    refreshState();
    var page = document.getElementById('page-governance');
    if (page && window.MutationObserver) {
      new MutationObserver(function () {
        if (page.classList.contains('active')) refreshState();
      }).observe(page, {attributes:true, attributeFilter:['class']});
    }
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden) refreshState();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, {once:true});
  } else {
    init();
  }
}());
