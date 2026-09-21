// Hosted navigation only. Transaction authorization stays in the native page.
(function () {
  'use strict';
  function ready() {
    // The native function preserves the profile's external-value policy and
    // only exposes the explanatory landing page. It does not enable actions.
    if (typeof window.bvProbeNav === 'function') window.bvProbeNav();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ready, {once:true});
  } else {
    ready();
  }
}());
