(function () {
  'use strict';
  function trimFeeZeros(text) {
    return text.replace(/(\d+\.\d*?[1-9])0+\b/g, '$1').replace(/(\d+)\.0+\b/g, '$1');
  }
  function paintExplorerDisplay() {
    if (location.pathname === '/mempool') {
      const values = [...document.querySelectorAll('.hero .meta b')];
      document.querySelectorAll('.tile').forEach(tile => {
        const label = tile.querySelector('.l');
        if (label && /^(Lifetime fees collected|Mempool fees)/i.test(label.textContent.trim())) {
          const value = tile.querySelector('.v');
          if (value) values.push(value);
        }
      });
      values.forEach(value => [...value.childNodes].forEach(node => {
        if (node.nodeType !== 3) return;
        const text = trimFeeZeros(node.nodeValue);
        if (text !== node.nodeValue) node.nodeValue = text;
      }));
    }
    if (location.pathname === '/mining') {
      document.querySelectorAll('.stat').forEach(stat => {
        const label = stat.querySelector('.stat-label'), value = stat.querySelector('.stat-value');
        if (!label || !value || label.textContent.trim() !== 'Block Reward') return;
        // The current 3.13926940 VELD subsidy is shown truncated as requested.
        // Refuse to relabel a future different reward.
        if (!['3.14 VELD', '3.13 VELD'].includes(value.textContent.trim())) return;
        if (value.textContent !== '3.13 VELD') value.textContent = '3.13 VELD';
        value.title = 'Exact block reward: 3.13926940 VELD. This display truncates to two decimals.';
      });
      document.querySelectorAll('.card').forEach(card => {
        const heading = card.querySelector('.card-title');
        if (!heading || heading.textContent.trim() !== 'Coinbase Split') return;
        card.querySelectorAll('tbody tr').forEach(row => {
          const cell = row.querySelector('td');
          if (!cell) return;
          const text = cell.textContent.trim();
          const color = text === 'Miner' ? 'var(--em)' : text === 'Vault' ? 'var(--gold)' : '';
          if (color) {
            cell.style.setProperty('color', color, 'important');
            cell.style.setProperty('-webkit-text-fill-color', color, 'important');
            cell.style.setProperty('font-weight', '600');
          }
        });
      });
    }
  }
  function start() {
    if (!['/mempool', '/mining'].includes(location.pathname)) return;
    paintExplorerDisplay();
    let queued = false;
    const observer = new MutationObserver(() => {
      if (queued) return;
      queued = true;
      requestAnimationFrame(() => { queued = false; paintExplorerDisplay(); });
    });
    observer.observe(document.body, {childList:true,subtree:true,characterData:true});
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, {once:true});
  else start();
})();
