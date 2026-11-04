'use strict';
(function () {
  function revealTopic() {
    let id;
    try { id = decodeURIComponent(location.hash.slice(1)); } catch (_) { return; }
    if (!id) return;
    const heading = document.getElementById(id);
    const details = heading && heading.nextElementSibling;
    if (details && details.matches('details.veld-details')) details.open = true;
  }
  window.addEventListener('hashchange', revealTopic);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', revealTopic, {once: true});
  } else revealTopic();
})();
