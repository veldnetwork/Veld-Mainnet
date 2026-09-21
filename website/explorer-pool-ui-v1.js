/* Presentation-only compatibility for Explorer origins predating the Pool navigation update. */
(function () {
  'use strict';
  var icon = '<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="18" r="3"/><circle cx="19" cy="18" r="3"/><path d="m10.5 7.5-4 8m7-8 4 8M8 18h8"/></svg>';
  function update() {
    document.querySelectorAll('.nm-grid,.sn-links,.snav').forEach(function (group) {
      var links = Array.from(group.children).filter(function (e) { return e.tagName === 'A'; });
      if (!links.length) return;
      var pool = links.find(function (e) { return e.getAttribute('href') === '/pool'; });
      var how = links.find(function (e) { return e.getAttribute('href') === 'https://veld.network/how-to/'; });
      if (!pool) {
        var reference = links.find(function (e) { return e.getAttribute('href') === '/liquidity'; });
        if (!reference) return;
        pool = document.createElement('a');
        pool.className = reference.className.replace(/\bactive\b/g, '').trim();
        pool.setAttribute('href', '/pool');
        pool.innerHTML = '<span class="ic"></span><span class="lb">Pool</span>';
      }
      var holder = pool.querySelector('.ic');
      if (holder) holder.innerHTML = icon;
      if (how) group.appendChild(how);
      group.appendChild(pool);
    });
    // The sidebar container name varies between the native and hosted pages.
    document.querySelectorAll('a.sn-link[href="/pool"]').forEach(function (pool) {
      var holder = pool.querySelector('.ic');
      if (holder) holder.innerHTML = icon;
      var group = pool.parentElement;
      var how = group.querySelector('a[href="https://veld.network/how-to/"]');
      if (how && how.parentElement === group) group.appendChild(how);
      group.appendChild(pool);
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', update, {once: true});
  else update();
})();
