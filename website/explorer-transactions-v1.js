(function () {
  'use strict';
  var txIdPattern = /^[0-9a-f]{64}$/;
  var addressPattern = /^V[1-9A-HJ-NP-Za-km-z]{25,40}$/;
  var pending = [], active = 0, requested = 0, cache = new Map();
  var MAX_REQUESTS = 80;

  function feeText(value) {
    if ((typeof value !== 'number' && typeof value !== 'string') || String(value).trim() === '' || !Number.isFinite(Number(value)) || Number(value) < 0) return null;
    return Number(value).toFixed(8).replace(/\.?0+$/, '') || '0';
  }
  function isConsolidation(entry, tx, address) {
    return !!(entry && entry.type === 'self' && Number(entry.net_veld) === 0 &&
      tx && tx.txid === entry.txid && tx.block_height === entry.block_height &&
      tx.coinbase === false && Array.isArray(tx.vin) && tx.vin.length > 1 &&
      Array.isArray(tx.vout) && tx.vout.length === 1 &&
      tx.vout[0].address === address && Number(tx.vout[0].value) > 0);
  }
  function drain() {
    while (active < 2 && pending.length) {
      var job = pending.shift(); active++;
      (function (item) {
        var controller = new AbortController();
        var timer = setTimeout(function () { controller.abort(); }, 12000);
        fetch(item.path, {cache:'no-store', credentials:'omit', signal:controller.signal})
          .then(function (response) {
            if (!response.ok) throw new Error('Details unavailable');
            return response.text();
          }).then(function (text) {
            if (text.length > 4 * 1024 * 1024) throw new Error('Details exceed display limit');
            var data = JSON.parse(text);
            if (data.error) throw new Error('Details unavailable');
            return data.result || data;
          }).then(item.resolve, item.reject).finally(function () {
            clearTimeout(timer); active--; drain();
          });
      })(job);
    }
  }
  function read(path) {
    if (cache.has(path)) return cache.get(path);
    if (++requested > MAX_REQUESTS) return Promise.reject(new Error('Display request limit reached'));
    var result = new Promise(function (resolve, reject) {
      pending.push({path:path, resolve:resolve, reject:reject}); drain();
    });
    cache.set(path, result);
    return result;
  }
  function transaction(txid, height) {
    if (!txIdPattern.test(txid) || !Number.isSafeInteger(height) || height < 0)
      return Promise.reject(new Error('Invalid transaction reference'));
    return read('/api/v1/transaction?height=' + height + '&txid=' + txid).then(function (tx) {
      if (tx.txid !== txid || tx.block_height !== height) throw new Error('Transaction reference changed');
      return tx;
    });
  }
  function historyEntry(address, txid, height) {
    if (!addressPattern.test(address)) return Promise.reject(new Error('Invalid address'));
    function page(cursor, count) {
      var path = '/api/v1/transaction-history?address=' + address;
      if (cursor) {
        if (!/^ah1:r:[a-f0-9]{50}:[0-9]{20}:[0-9]{10}:[a-f0-9]{64}$/.test(cursor))
          throw new Error('Invalid history cursor');
        path += '&cursor=' + cursor;
      }
      return read(path).then(function (data) {
        if (!Array.isArray(data.entries) || data.entries.length > 50) throw new Error('Invalid history page');
        var entry = data.entries.find(function (row) { return row.txid === txid && row.block_height === height; });
        if (entry) return entry;
        var oldest = data.entries[data.entries.length - 1];
        if (!data.has_more || !oldest || oldest.block_height < height || count >= 10) return null;
        if (data.next_cursor === cursor) throw new Error('History cursor did not advance');
        return page(data.next_cursor, count + 1);
      });
    }
    return page('', 1);
  }
  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }
  function setFee(cell, entry, coinbase) {
    if (coinbase) { cell.textContent = 'Not applicable'; return; }
    var fee = entry ? feeText(entry.fee_veld) : null;
    cell.textContent = fee == null ? 'Unavailable' : fee + ' VELD';
    cell.title = fee == null ? 'The fee could not be verified from transaction history.' : 'Confirmed network fee';
    cell.style.color = fee == null ? 'var(--muted)' : 'var(--text)';
  }
  function blockRows() {
    var title = document.querySelector('.block-detail-header') || document.querySelector('.pheader');
    var match = title && /Block\s*#?(\d[\d,]*)/i.exec(title.textContent);
    if (!match) match = /\/block\/height\/(\d+)/.exec(location.pathname);
    var height = match ? Number(match[1].replace(/,/g, '')) : NaN;
    if (!Number.isSafeInteger(height)) return;
    document.querySelectorAll('.tbl').forEach(function (table) {
      var headers = Array.from(table.querySelectorAll('thead th')).map(function (th) { return th.textContent.trim(); });
      if (headers.join('|') !== 'TXID|Type|Flow|Total|Fee') return;
      table.classList.add('transaction-table');
      table.parentElement.classList.add('transaction-table-wrap');
      table.querySelectorAll('tbody tr').forEach(function (row, ordinal) {
        var cells = row.querySelectorAll('td');
        if (cells.length !== 5) return;
        cells.forEach(function (cell, index) { cell.dataset.label = headers[index] === 'Fee' ? 'Network fee' : headers[index]; });
        var link = cells[0].querySelector('a[href^="/tx/"]');
        var txid = link && link.getAttribute('href').split('/').pop();
        if (!txIdPattern.test(txid || '')) return;
        var badge = cells[1].querySelector('span') || cells[1];
        if (badge.textContent.trim() === 'COINBASE') { setFee(cells[4], null, true); return; }
        var sender = Array.from(cells[2].querySelectorAll('a[href^="/address/"]'))[0];
        var address = sender && sender.getAttribute('href').split('/').pop();
        var initialFee = cells[4].textContent.trim();
        var knownFee = /^[−-]?(\d+(?:\.\d+)?)(?:\s+VELD)?$/.exec(initialFee);
        if (knownFee) {
          cells[4].textContent = feeText(knownFee[1]) + ' VELD';
        } else setFee(cells[4], null, false);
        if (ordinal > 25 || !addressPattern.test(address || '')) return;
        historyEntry(address, txid, height).then(function (entry) {
          if (!row.isConnected || !entry) return;
          setFee(cells[4], entry, false);
          if (entry.type !== 'self' || badge.textContent.trim() !== 'TRANSFER') return;
          badge.textContent = 'SELF-TRANSFER';
          return transaction(txid, height).then(function (tx) {
            if (!row.isConnected || !isConsolidation(entry, tx, address)) return;
            badge.textContent = 'CONSOLIDATION';
            var note = element('div', 'transaction-explanation', tx.vin.length + ' outputs combined into 1 in the same wallet. No new VELD created.');
            cells[2].appendChild(note);
          });
        }).catch(function () {});
      });
    });
  }
  var sourceLabels = {
    staking_distribution:'Staking reward', endorsement_distribution:'Validator reward',
    comine_distribution:'Co-mining payout', stake_lock:'Stake change', stake_unlock:'Unstaked funds'
  };
  function recoverOutput(row, address) {
    var name = row.querySelector('.rl-name'), sub = row.querySelector('.rl-sub');
    if (!name || !sub || !/source unavailable|details unavailable|Loading output details|^Transfer received$/i.test(name.textContent)) return;
    var txid = row.getAttribute('href').split('/').pop();
    var match = /block\s+(\d+)/i.exec(sub.textContent);
    var height = match ? Number(match[1]) : NaN;
    if (!txIdPattern.test(txid) || !Number.isSafeInteger(height)) return;
    name.textContent = 'Loading output details…';
    read('/api/v1/events/' + height).then(function (data) {
      if (data.height !== height || !Array.isArray(data.events)) throw new Error('Block reference changed');
      var event = data.events.find(function (item) { return item.txid === txid; });
      var output = event && Array.isArray(event.credited) && event.credited.find(function (item) { return item.address === address; });
      if (!output) throw new Error('Output reference unavailable');
      if (!row.isConnected) return;
      if (event.type === 'coinbase') name.textContent = output.protocol ? 'Block reward allocation' : 'Mining reward';
      else if (sourceLabels[event.type]) name.textContent = sourceLabels[event.type];
      else return historyEntry(address, txid, height).then(function (entry) {
        if (entry && entry.type === 'self') return transaction(txid, height).then(function (tx) {
          name.textContent = isConsolidation(entry, tx, address) ? 'Consolidated funds' : 'Self-transfer';
        });
        name.textContent = !entry ? 'Wallet output' : entry.type === 'sent' ? 'Change returned' : 'Transfer received';
      });
    }).then(function () {
      var icon = row.querySelector('.rl-ic');
      if (icon) icon.textContent = name.textContent.charAt(0);
    }).catch(function () { if (row.isConnected) name.textContent = 'Output details unavailable'; });
  }
  function addressHistory(address) {
    if (typeof window.expHistRender !== 'function') return;
    var render = window.expHistRender;
    var checks = new Map();
    function enhance() {
      var rows = document.querySelectorAll('#tx-hist .rl-row');
      rows.forEach(function (row) {
        var link = row.matches('a[href]') ? row : row.querySelector('a[href^="/tx/"]');
        var txid = link && link.getAttribute('href').split('/').pop();
        var entry = (window._expHist || []).find(function (item) { return item.txid === txid; });
        if (!entry || entry.type !== 'self') return;
        var name = row.querySelector('.rl-name'), value = row.querySelector('.rl-v'), detail = row.querySelector('.rl-vs');
        if (name) name.textContent = 'Self-transfer';
        if (value) { value.textContent = 'Same wallet'; value.style.color = 'var(--muted)'; }
        if (detail) { var fee = feeText(entry.fee_veld); detail.textContent = fee == null ? 'Fee unavailable' : fee + ' VELD fee'; }
        if (!checks.has(txid)) checks.set(txid, transaction(txid, entry.block_height).then(function (tx) { return isConsolidation(entry, tx, address); }).catch(function () { return false; }));
        checks.get(txid).then(function (yes) { if (yes && row.isConnected && name) name.textContent = 'Consolidation'; });
      });
    }
    window.expHistRender = function () { var result = render.apply(this, arguments); enhance(); return result; };
    enhance();
  }
  function start() {
    if (/^\/(?:block\/|tx\/)/.test(location.pathname)) blockRows();
    var match = /^\/address\/(V[1-9A-HJ-NP-Za-km-z]{25,40})$/.exec(location.pathname);
    if (match) {
      document.querySelectorAll('.card .row-list > a.rl-row').forEach(function (row, i) { if (i < 25) recoverOutput(row, match[1]); });
      addressHistory(match[1]);
    }
  }
  window.VeldTransactionDisplay = Object.freeze({feeText:feeText, isConsolidation:isConsolidation});
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, {once:true});
  else start();
})();
