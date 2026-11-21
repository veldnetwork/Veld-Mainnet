// Unstake maturity uses the node's stake snapshot, independently of dashboard display.
// Kept identical to the native functions by wallet_unstake_maturity_tests.js.
(function () {
  'use strict';
  if (typeof window.doIncrementalUnstake !== 'function' ||
      typeof window.planIncrementalUnstake !== 'function' ||
      typeof window.rpc !== 'function') return;

function planIncrementalUnstake(matureRecords, totalAmount) {
  // Given sorted mature stake records and a total requested amount, produce
  // exact per-batch amounts. Never submit a partial plan as the full request.
  function units(value) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 ||
        !Number.isSafeInteger(Math.round(value * 100000000)))
      throw new Error('Invalid unstake record amount. Refresh staking and try again.');
    var parsed = _veldParseVeldUnitsExact(value.toFixed(8));
    if (parsed <= 0n)
      throw new Error('Invalid unstake record amount. Refresh staking and try again.');
    return parsed;
  }
  var batches = [];
  var remaining = units(totalAmount);
  for (var i = 0; i < matureRecords.length && remaining > 0n; ++i) {
    var available = units(matureRecords[i].amount_veld);
    var take = available < remaining ? available : remaining;
    batches.push(Number(take) / 100000000);
    remaining -= take;
  }
  if (remaining !== 0n)
    throw new Error('Requested amount exceeds the mature stake records. Refresh staking and try again.');
  return batches;
}

async function doIncrementalUnstake(addr, totalAmount, keyHex, msgEl, unstakeBtn, expectedGeneration) {
  var signerGeneration;
  try { signerGeneration = _veldAssertActiveSignerSeed(keyHex, expectedGeneration); }
  catch (e) {
    msgEl.textContent = e.message;
    if (unstakeBtn) unstakeBtn.disabled = false;
    return;
  }
  // Maturity comes from the node's stake snapshot, not a dashboard label that
  // may be empty, stale or absent when opening Staking directly.
  var history;
  try { history = await rpc('getstakehistory', [addr]); }
  catch (e) {
    msgEl.innerHTML = '<div class="alert alert-err">Unable to load stake records: ' +
      escHtml(e.message || 'Refresh staking and try again.') + '</div>';
    if (unstakeBtn) unstakeBtn.disabled = false;
    return;
  }
  var mature;
  try {
    _veldAssertActiveSignerSeed(keyHex, signerGeneration);
    if (!Array.isArray(history)) throw new Error('Stake records are unavailable. Refresh staking and try again.');
    mature = history.filter(function(r){
      if (!r || typeof r !== 'object') throw new Error('Invalid stake record. Refresh staking and try again.');
      if (r.type !== 'stake' || r.active !== true) return false;
      if ((r.status !== 'locked' && r.status !== 'unlocked') ||
          !Number.isSafeInteger(r.block) || r.block < 0)
        throw new Error('Stake record maturity is unavailable. Refresh staking and try again.');
      return r.status === 'unlocked';
    }).sort(function(a,b){ return a.block - b.block; });
  } catch (e) {
    msgEl.innerHTML = '<div class="alert alert-err">' + escHtml(e.message) + '</div>';
    if (unstakeBtn) unstakeBtn.disabled = false;
    return;
  }
  if (!mature.length) {
    msgEl.innerHTML = '<div class="alert alert-err">No mature stake records available to unstake.</div>';
    if (unstakeBtn) unstakeBtn.disabled = false;
    return;
  }
  var batches;
  try { batches = planIncrementalUnstake(mature, totalAmount); }
  catch (e) {
    msgEl.innerHTML = '<div class="alert alert-err">' + escHtml(e.message) + '</div>';
    if (unstakeBtn) unstakeBtn.disabled = false;
    return;
  }
  var totalBatches = batches.length;
  var estMinutes = Math.ceil((totalBatches - 1) * (UNSTAKE_BATCH_COOLDOWN_MS/1000) / 60);
  if (totalBatches > 1) {
    var ok = confirm('Large unstake will be split into ' + totalBatches + ' batches.\n\n' +
                     'Total amount: ' + fmt(totalAmount,2) + ' VELD\n' +
                     'Estimated time: ~' + estMinutes + ' minute(s)\n\n' +
                     'Continue?');
    if (!ok) {
      msgEl.innerHTML = '<div class="alert alert-info">Unstake cancelled.</div>';
      if (unstakeBtn) unstakeBtn.disabled = false;
      return;
    }
  }
  var completed = 0;
  var failures = [];
  for (var i = 0; i < batches.length; ++i) {
    var batchAmount = batches[i];
    msgEl.innerHTML = '<div class="alert alert-info">Unstaking batch ' + (i+1) + ' of ' + totalBatches +
                      ' \u2014 ' + fmt(batchAmount,2) + ' VELD\u2026</div>';
    try {
      var batchUnits = _veldParseVeldUnitsExact(Number(batchAmount).toFixed(8));
      var batchAmountCanonical = _veldUnitsToAmountString(batchUnits);
      var batchOpHex = _veldBuildProtocolOpReturnHex(
        'VELD_STAKE|UNLOCK|' + addr + '|' + batchUnits.toString());
      // unstake outputs are change-back-to-self
      // (P2PKH to `addr`) + value=0 OP_RETURN. Pass user's hash160 so
      // signAndBroadcast asserts no P2PKH leg redirects to an attacker.
      var r = await signAndBroadcast('prepareunstake', [addr, batchAmountCanonical], keyHex,
                                     null, _veldAddrToKeyCommitmentHex(addr), null, null, batchOpHex, null, signerGeneration);
      completed++;
      var txid = r && r.txid ? r.txid : '';
      msgEl.innerHTML = '<div class="alert alert-ok">\u2713 Batch ' + (i+1) + '/' + totalBatches +
                        ' broadcast (' + fmt(batchAmount,2) + ' VELD).' +
                        (txid ? ' TXID: <a href="https://explorer.veld.network/tx/' + escHtml(txid) + '" target="_blank" rel="noopener noreferrer">' + escHtml(txid.slice(0,10)) + '\u2026</a>' : '') +
                        '</div>';
    } catch (e) {
      failures.push({batch: i+1, amount: batchAmount, error: e.message || String(e)});
      var retryOk = confirm('Batch ' + (i+1) + ' failed: ' + (e.message || 'unknown') + '\n\nRetry this batch?');
      if (retryOk) { i--; await sleepMs(2000); continue; }
      msgEl.innerHTML = '<div class="alert alert-err">\u26A0 Unstake stopped after ' + completed +
                        '/' + totalBatches + ' batches. Failure: ' + escHtml(e.message || 'unknown') +
                        '</div>';
      if (unstakeBtn) unstakeBtn.disabled = false;
      return;
    }
    if (i + 1 < batches.length) {
      msgEl.innerHTML += '<div class="alert alert-info" style="margin-top:6px">Cooldown: waiting ' +
                         Math.ceil(UNSTAKE_BATCH_COOLDOWN_MS/1000) + 's before next batch\u2026</div>';
      await sleepMs(UNSTAKE_BATCH_COOLDOWN_MS);
    }
  }
  msgEl.innerHTML = '<div class="alert alert-ok">Submitted ' + fmt(totalAmount,2) +
                    ' VELD to unstake in ' + totalBatches + ' batch' + (totalBatches===1?'':'es') + '. Waiting for confirmation.</div>';
  if (unstakeBtn) unstakeBtn.disabled = false;
  loadStakingPage();
  onStakeAddrChange();
}

  window.planIncrementalUnstake = planIncrementalUnstake;
  window.doIncrementalUnstake = doIncrementalUnstake;
})();
