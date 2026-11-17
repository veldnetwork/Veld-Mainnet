(function () {
  'use strict';
  var txIdPattern = /^[0-9a-f]{64}$/;
  var addressPattern = /^V[1-9A-HJ-NP-Za-km-z]{25,40}$/;
  var pending = [], active = 0, requested = 0, cache = new Map();
  var MAX_REQUESTS = 80;
  // Hosted mainnet display; checked against native_334_activation.h in tests.
  var MINER_FEE_ACTIVATION_HEIGHT = 34750;
  var fundingAddress = {
    'STAKING REWARDS':'VVzm6RG8W1t3U9KQYoD34z49jHcYb1sXdv',
    'STAKING DIST':'VVzm6RG8W1t3U9KQYoD34z49jHcYb1sXdv',
    'ENDORSE REWARD':'VVzm6RG8W1t3U9KQYoD34z49jHcYb1sXdv',
    'VALIDATOR PAYOUT':'VQ3MkHSNrXYXiWQErPfUUu4hWWEVvpfAFT',
    'CO-MINE PAYOUT':'VHkWh9Xfbnp3gCotHSeM9LLN5MwcoXYijZ'
  };

  function feeText(value) {
    if ((typeof value !== 'number' && typeof value !== 'string') || String(value).trim() === '' || !Number.isFinite(Number(value)) || Number(value) < 0) return null;
    return Number(value).toFixed(8).replace(/\.?0+$/, '') || '0';
  }
  function feeUnits(value) {
    var text = feeText(value);
    if (text == null || Number(text) > 21000000 || Number(value) !== Number(text)) return null;
    var parts = text.split('.');
    if (!/^\d+$/.test(parts[0]) || (parts[1] || '').length > 8) return null;
    return BigInt(parts[0]) * 100000000n + BigInt((parts[1] || '').padEnd(8, '0'));
  }
  function minerFeeTotal(block, height, txids, fees) {
    if (!Number.isSafeInteger(height) || height < MINER_FEE_ACTIVATION_HEIGHT ||
        !block || block.height !== height || !Array.isArray(block.tx) ||
        block.tx_count !== block.tx.length || !txids.length ||
        block.tx.length !== txids.length || new Set(txids).size !== txids.length ||
        block.tx.some(function (id, i) { return !txIdPattern.test(id) || id !== txids[i]; })) return null;
    var total = 0n;
    for (var i = 1; i < txids.length; i++) {
      var units = feeUnits(fees.get(txids[i]));
      if (units == null) return null;
      total += units;
      if (total > 2100000000000000n) return null;
    }
    var fraction = String(total % 100000000n).padStart(8, '0').replace(/0+$/, '');
    return String(total / 100000000n) + (fraction ? '.' + fraction : '');
  }
  function indexedFee(entry) {
    var units = entry ? feeUnits(entry.fee_veld) : null;
    if (units == null) return null;
    // The address index records the transaction fee only on input-side rows.
    // A recipient's zero fee is not evidence that the transaction was free.
    if (units === 0n && entry.type !== 'sent' && entry.type !== 'self' &&
        !(Number(entry.net_veld) < 0)) return null;
    return feeText(entry.fee_veld);
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
        if (!/^ah[12]:r:[a-f0-9]{50}:[0-9]{20}:[0-9]{10}:[a-f0-9]{64}$/.test(cursor))
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
  function setFee(cell, entry, coinbase, height) {
    if (coinbase) { cell.textContent = 'Not applicable'; return; }
    var fee = entry ? feeText(entry.fee_veld) : null;
    var toMiner = Number.isSafeInteger(height) && height >= MINER_FEE_ACTIVATION_HEIGHT;
    cell.textContent = fee == null ? 'Unavailable' : fee + ' VELD' + (toMiner ? '\nto miner' : '');
    cell.title = fee == null ? 'The fee could not be verified from transaction history.' :
      toMiner ? 'Confirmed transaction fee paid to the block miner.' : 'Confirmed network fee';
    if (toMiner) cell.style.whiteSpace = 'pre';
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
      var txids = [], fees = new Map(), coinbaseCell = null, block = null;
      function updateMinerFee() {
        if (!coinbaseCell || !coinbaseCell.isConnected) return;
        var total = minerFeeTotal(block, height, txids, fees);
        coinbaseCell.textContent = total == null ? 'Fees unavailable' : total + ' VELD\nto miner';
        coinbaseCell.style.whiteSpace = 'pre';
        coinbaseCell.title = total == null ? 'Every transaction fee must be verified before showing the block total.' :
          'Total transaction fees received by the miner in this block, already included in the coinbase output. This is separate from the block subsidy.';
      }
      table.querySelectorAll('tbody tr').forEach(function (row, ordinal) {
        var cells = row.querySelectorAll('td');
        if (cells.length !== 5) return;
        var link = cells[0].querySelector('a[href^="/tx/"]');
        var txid = link && link.getAttribute('href').split('/').pop();
        if (!txIdPattern.test(txid || '')) return;
        txids.push(txid);
        var badge = cells[1].querySelector('span') || cells[1];
        if (badge.textContent.trim() === 'COINBASE') {
          if (ordinal === 0 && height >= MINER_FEE_ACTIVATION_HEIGHT) {
            coinbaseCell = cells[4];
            coinbaseCell.textContent = 'Checking fees…';
          } else setFee(cells[4], null, true, height);
          return;
        }
        var sender = Array.from(cells[2].querySelectorAll('a[href^="/address/"]'))[0];
        var address = fundingAddress[badge.textContent.trim()] ||
          (sender && sender.getAttribute('href').split('/').pop());
        var initialFee = cells[4].textContent.trim();
        var knownFee = /^[−-]?(\d+(?:\.\d+)?)(?:\s+VELD)?$/.exec(initialFee);
        if (knownFee && feeUnits(knownFee[1]) != null) {
          fees.set(txid, knownFee[1]);
          setFee(cells[4], {fee_veld:knownFee[1]}, false, height);
        } else setFee(cells[4], null, false, height);
        if (ordinal > 25 || !addressPattern.test(address || '')) return;
        historyEntry(address, txid, height).then(function (entry) {
          if (!row.isConnected || !entry) return;
          var verifiedFee = indexedFee(entry);
          if (!fees.has(txid) && verifiedFee != null) {
            fees.set(txid, verifiedFee);
            setFee(cells[4], {fee_veld:verifiedFee}, false, height);
          }
          updateMinerFee();
          if (entry.type !== 'self' || badge.textContent.trim() !== 'TRANSFER') return;
          badge.textContent = 'SELF-TRANSFER';
          return transaction(txid, height).then(function (tx) {
            if (!row.isConnected || !isConsolidation(entry, tx, address)) return;
            badge.textContent = 'CONSOLIDATION';
          });
        }).catch(function () {});
      });
      if (coinbaseCell) read('/api/v1/block/' + height).then(function (data) {
        block = data;
        updateMinerFee();
      }).catch(function () { updateMinerFee(); });
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
  window.VeldTransactionDisplay = Object.freeze({feeText:feeText, feeUnits:feeUnits,
    minerFeeTotal:minerFeeTotal, indexedFee:indexedFee, isConsolidation:isConsolidation});
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, {once:true});
  else start();
})();
