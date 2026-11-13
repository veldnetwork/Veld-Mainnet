// Read-only confirmation lookup for hosted clients on released native binaries.
// Kept identical to the native function by wallet_pending_confirmation_tests.js.
(function () {
  'use strict';
  if (typeof window._veldPendingHistoryHints !== 'function' ||
      typeof window._veldIsConfirmedTransaction !== 'function' ||
      typeof window.rpc !== 'function') return;

async function _veldPendingHistoryHints(address, entries, isCurrent) {
  var wanted = new Set(entries.map(function(e) { return e.txid; }));
  var hints = new Map(), cursors = new Set(), cursor = '';
  // Active validators can produce more history than the bounded window below.
  // Their registration height is a locator, never proof of this transaction.
  var registrations = new Set(entries.filter(function(e) {
    return e.prepare_method === 'prepareregistervalidator' || e.label === 'Validator Register';
  }).map(function(e) { return e.txid; }));
  if (registrations.size && isCurrent()) {
    try {
      var registry = await rpc('getvalidators', []);
      if (!isCurrent()) return hints;
      var matches = registry && Array.isArray(registry.validators)
        ? registry.validators.filter(function(v) { return v && v.address === address; }) : [];
      var registered = matches.length === 1 ? matches[0].registered_height : null;
      if (Number.isSafeInteger(registered) && registered > 0) {
        for (var txid of registrations) {
          if (!isCurrent()) return hints;
          try {
            var registration = await rpc('gettransaction', [txid, String(registered)]);
            if (!isCurrent()) return hints;
            if (_veldIsConfirmedTransaction(registration, txid, registered)) {
              hints.set(txid, registered);
              wanted.delete(txid);
            }
          } catch (_) {}
        }
      }
    } catch (_) {}
  }
  // Indexed, bounded pages avoid repeated whole-chain transaction searches.
  for (var pageNo = 0; wanted.size && pageNo < 20 && isCurrent(); pageNo++) {
    try {
      var params = [address, '50'];
      if (cursor) params.push(cursor);
      var page = await rpc('getaddresshistory', params);
      if (!isCurrent()) break;
      if (!page || !Array.isArray(page.entries) || page.entries.length > 50 ||
          typeof page.has_more !== 'boolean' || typeof page.next_cursor !== 'string') break;
      page.entries.forEach(function(row) {
        if (row && wanted.has(row.txid) && Number.isSafeInteger(row.block_height) && row.block_height >= 0) {
          hints.set(row.txid, row.block_height);
          wanted.delete(row.txid);
        }
      });
      if (!page.has_more) break;
      if (!page.entries.length || !page.next_cursor || page.next_cursor.length > 192 ||
          cursors.has(page.next_cursor)) break;
      cursor = page.next_cursor;
      cursors.add(cursor);
    } catch (_) { break; }
  }
  return hints;
}

  window._veldPendingHistoryHints = _veldPendingHistoryHints;
})();
