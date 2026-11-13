// Native wallet balance reconciliation for hosted clients on released binaries.
// Generated from ui_desktop.h; wallet_bond_balance_tests.js enforces parity.
(function () {
  'use strict';
  if (typeof window.loadWalletAddr !== 'function' || typeof window.rpc !== 'function') return;

function _veldWalletBondBalance(vault, address) {
  if (!vault || !Array.isArray(vault.validators)) throw new Error('Bond balance unavailable');
  var total = 0;
  vault.validators.forEach(function(v) {
    if (!v || v.address !== address) return;
    if (typeof v.principal_held !== 'boolean' || typeof v.bond_veld !== 'number' ||
        !Number.isFinite(v.bond_veld) || v.bond_veld < 0) throw new Error('Invalid bond balance');
    if (v.principal_held) total += v.bond_veld;
  });
  return total;
}

function _veldApplyWalletBondBalance(state) {
  if (!state.isCurrent()) return;
  var bonded = state.bonded == null ? 0 : state.bonded;
  var row = document.getElementById('w-bal-bonded-row');
  var value = document.getElementById('w-bal-bonded');
  if (value) value.textContent = fmt(bonded, 2);
  if (row) row.style.display = bonded > 0.000005 ? '' : 'none';
  if (state.addressTotal == null) return;
  var total = state.addressTotal + bonded;
  var hero = document.getElementById('w-total-bal');
  if (hero) hero.innerHTML = fmt(total, 2) + ' <span>VELD</span>';
  window._statusBalance = total;
}

function _veldLoadWalletBondBalance(state) {
  return rpc('getbondvaultinfo', []).then(function(vault) {
    if (!state.isCurrent()) return;
    state.bonded = _veldWalletBondBalance(vault, state.address);
    _veldApplyWalletBondBalance(state);
  }).catch(function() {
    if (!state.isCurrent()) return;
    state.bonded = null;
    _veldApplyWalletBondBalance(state);
  });
}

function loadWalletAddr(addr) {
  if (!addr) addr = document.getElementById('w-addr-input').value.trim();
  if (!addr) return;
  // reset any cached endorsement history when switching wallets so
  // a new wallet never sees data from the previous one. Also clear the
  // rendered table, stats, pagination, and input field.
  try {
    if (currentAddr !== addr) {
      window._vhEndorsements = [];
      window._vhTab = 'pending';
      var _e = function(id){ return document.getElementById(id); };
      if (_e('val-hist-body'))  _e('val-hist-body').innerHTML = '';
      if (_e('val-hist-table')) _e('val-hist-table').style.display = 'none';
      if (_e('val-hist-stats')) _e('val-hist-stats').style.display = 'none';
      if (_e('val-hist-tabs'))  _e('val-hist-tabs').style.display = 'none';
      if (_e('val-hist-pag'))   _e('val-hist-pag').style.display = 'none';
      if (_e('val-hist-empty'))  _e('val-hist-empty').style.display = '';
      if (_e('val-hist-summary')) _e('val-hist-summary').textContent = '';
      if (_e('vh-total'))    _e('vh-total').textContent = '0';
      if (_e('vh-rewards'))  _e('vh-rewards').textContent = '0 VELD';
      if (_e('vh-paid-status')) _e('vh-paid-status').textContent = '\u2014';
      if (_e('val-hist-addr'))  _e('val-hist-addr').value = '';
    }
  } catch (e) {}
  // validated-write so a poisoned addr ("null"/"undefined"/
  // anything non-V) never lands in localStorage. If it fails the guard
  // the wallet simply stays on the previous selection.
  if (!_setCurrentAddr(addr)) return;
  var balanceRevision = ++walletBalanceRevision;
  var balanceIsCurrent = function() { return balanceRevision === walletBalanceRevision && addr === currentAddr; };
  var bondBalance = {address:addr, isCurrent:balanceIsCurrent, addressTotal:null, bonded:null};
  _veldApplyWalletBondBalance(bondBalance);
  if (savedAddrs.indexOf(addr) === -1) {
    savedAddrs.unshift(addr);
    if (savedAddrs.length > 5) savedAddrs.pop();
    localStorage.setItem('veld_addrs', JSON.stringify(savedAddrs));
  }
  renderSavedChips();
  document.getElementById('wallet-form').style.display = 'none';
  document.getElementById('wallet-hero').style.display = 'block';
  document.getElementById('w-active-addr').textContent = addr;
  // Keep the active address visible in the page subtitle.
  var subEl = document.getElementById('w-active-addr-sub');
  if (subEl) subEl.textContent = addr;
    generateWalletQR(addr);
  rpc('getbalance',[addr]).then(function(r) {
    if (!balanceIsCurrent()) return;
    var total     = typeof r === 'object' ? (r.balance_veld   || 0) : (r || 0);
    var staked    = typeof r === 'object' ? (r.staked_veld    || 0) : 0;
    // ZERO-SPENDABLE FIX. The `||` fallback treats 0 as
    // falsy and fell back to `total`, so when RPC correctly returned
    // spendable_veld=0 (all mature coins already staked, or balance is
    // entirely immature coinbase), the UI showed the full balance as
    // spendable and cascaded wrong numbers into the stake screen.
    // Explicit !=null check preserves a real 0 while still falling
    // back to total for non-object RPC returns.
    var spendable = (typeof r === 'object' && r.spendable_veld != null) ? r.spendable_veld : total;
    var immature  = typeof r === 'object' ? (r.immature_coinbase_veld || 0) : 0;
    // HERO TOTAL FIX (v2). First pass used `spendable + staked`
    // which under-reported by the maturing-coinbase amount (a miner with
    // 41.84 UTXO, 10 staked, 40.91 maturing saw "10" instead of ~50).
    // Second pass "corrected" to `total + staked` which OVER-reported by
    // exactly `staked`: I had assumed the staking ledger was a separate
    // virtual-state table whose units are NOT present in the UTXO set,
    // but rpc.h:1284 shows `balance_veld` sums every UTXO the address
    // owns, INCLUDING the ones the StakingManager has flagged as locked.
    // The stake TX doesn't move coin to a lock address; the UTXO stays
    // put and the lock is just a tag.
    //
    // So `balance_veld` already = spendable + staked + immature_coinbase.
    // The honest headline is just `total`. Leaving the intermediate vars
    // in place (the 3-up grid still uses them) and writing the identity
    // explicitly so a future reader sees the full composition.
    var effective = total;  // == spendable + staked + immature
    document.getElementById('w-total-bal').innerHTML =
      fmt(effective,2) + ' <span>VELD</span>';
    // cache total balance for the enriched status bar.
    window._statusBalance = effective;
    // The vault-held principal is separate from address coins. Reconcile both
    // responses regardless of which finishes first, using this refresh only.
    window._wAddressTotal = effective;
    window._wBalanceAddr  = addr;
    bondBalance.addressTotal = effective;
    _veldApplyWalletBondBalance(bondBalance);
    // backup-nag visibility decision. Three states
    // tracked in localStorage:
    //   veld_backed_up   = '1'   user clicked "I've backed up"
    //   veld_backup_snooze_until = epoch_ms   user clicked "remind later"
    //   (absent)                  show if balance > threshold
    // Threshold 100 VELD = roughly the value where losing the key
    // becomes "actually losing real money" rather than "lost a small
    // pre-activation amount". Re-evaluated on every balance refresh, so the
    // banner appears the FIRST time the user crosses the threshold
    // (no need for the wallet to be open at the exact moment).
    try {
      var bn = document.getElementById('w-backup-nag');
      if (bn) {
        var ackd = localStorage.getItem('veld_backed_up') === '1';
        var snoozeUntil = parseInt(localStorage.getItem('veld_backup_snooze_until') || '0', 10);
        var snoozed = snoozeUntil > Date.now();
        if (!ackd && !snoozed && effective >= 100) {
          var bnBal = document.getElementById('w-backup-nag-bal');
          if (bnBal) bnBal.textContent = fmt(effective, 2);
          bn.style.display = 'block';
        } else {
          bn.style.display = 'none';
        }
      }
    } catch (e) { /* localStorage unavailable in some embedded webviews — fail open (no banner) */ }
    // dedicated cells for Spendable / Staked /
    // Maturing / Pending Out. Replaces the older 3-up grid that
    // tucked Maturing into the hero sub-text and never showed
    // Pending Out at all. Each cell can be zero — formatting stays
    // clean. Pending Out is computed from the mempool below; if
    // the RPC isn't available the field shows 0.
    var liquidEl = document.getElementById('w-bal-liquid');
    if (liquidEl) liquidEl.textContent = fmt(spendable, 2);
    var bsEl = document.getElementById('w-bal-staked');
    if (bsEl) bsEl.textContent = fmt(staked, 2);
    var matEl = document.getElementById('w-bal-maturing');
    if (matEl) matEl.textContent = fmt(immature || 0, 2);
    // Pending-out: sum of mempool TX outflows owned by THIS address.
    // Live RPC call so the value updates as the user sends. Best-
    // effort — on RPC failure the cell stays blank rather than
    // showing a stale or wrong number. Looks up rawmempool, fetches
    // each entry, and counts inputs whose prev_address == us minus
    // any change outputs back to us.
    // server-side pending-out value. getbalance now
    // returns `pending_out_veld` directly (sum of this address's UTXOs
    // being spent by mempool TXs). Replaces the prior client-side
    // heuristic which always rendered 0 because per-input owner data
    // isn't exposed by getmempoolentry. The field is included in every
    // getbalance response so this update lives entirely in-scope of
    // the same RPC round-trip — no second call. Renders red when > 0
    // to draw the eye to in-flight outbound money.
    // Pending Out reads pending_transfer_out_veld
    // (NET outflow to OTHER addresses) instead of pending_out_veld
    // (gross UTXO churn). Consolidation TXs no longer light this up
    // because the change comes back to the same address; only real
    // transfers to a counterparty count. Falls back to pending_out_veld
    // on older nodes that don't ship the new field.
    var pendEl = document.getElementById('w-bal-pending');
    if (pendEl) {
      var pendingOut = 0;
      if (typeof r === 'object') {
        if (r.pending_transfer_out_veld != null)      pendingOut = parseFloat(r.pending_transfer_out_veld);
        else if (r.pending_out_veld != null)           pendingOut = parseFloat(r.pending_out_veld);
      }
      pendEl.textContent = fmt(pendingOut, 2);
      pendEl.style.color = pendingOut > 0 ? 'var(--red, #ff6470)' : '';
    }
    // "Settling" row. Self-churn = gross mempool-locked
    // (pending_out_veld) minus the counterparty outflow already shown as
    // "Pending Out" (pending_transfer_out_veld). This is the user's own
    // coin temporarily locked by their own pending stake / consolidation /
    // endorsement TX, returning to Spendable on confirm.
    // Surfacing it makes the grid reconcile to the hero total exactly:
    //   Spendable + Staked + Maturing + PendingOut + Settling == Total
    // (canonical ComputeWalletState invariant: selectable+immature+
    // pending_out == total, and spendable+staked == selectable). Row
    // collapses when zero so a quiet wallet stays tidy.
    var setRow = document.getElementById('w-bal-settling-row');
    var setEl  = document.getElementById('w-bal-settling');
    if (setRow && setEl) {
      // RECONCILE FIX. Settling MUST be the residual that makes
      // the grid sum exactly to the hero total — not an independent gross-
      // mempool estimate. The old `pending_out_veld - pending_transfer_out_
      // veld` over-counted whenever chained self-consolidation TXs inflated
      // gross pending_out beyond the coin actually locked inside
      // balance_veld (
      // balance"). balance_veld already contains the confirmed coin; the
      // honest, drift-proof definition of "your coin briefly in motion" is
      // exactly what is left after the named buckets:
      //   Settling = Total - Spendable - Staked - Maturing - PendingOut
      // (PendingOut computed identically to the w-bal-pending tile so the
      // two always agree). Tiles now reconcile to the satoshi by build.
      var pOut = 0;
      if (typeof r === 'object') {
        if (r.pending_transfer_out_veld != null) pOut = parseFloat(r.pending_transfer_out_veld) || 0;
        else if (r.pending_out_veld != null)     pOut = parseFloat(r.pending_out_veld) || 0;
      }
      var settling = effective - spendable - staked - (immature || 0) - pOut;
      if (settling < 0) settling = 0;  // never show negative (rounding/edge)
      if (settling > 0.000005) {
        setEl.textContent = fmt(settling, 2);
        setRow.style.display = '';
      } else {
        setRow.style.display = 'none';
      }
    }
    // hero sub-text fix. The earlier version showed only
    // "<spendable> VELD spendable" which left the difference between
    // the hero total and (spendable + staked) unexplained whenever the
    // miner had any maturing coinbase outputs (every 100-block window
    // after a fresh start, there are ~100 immature rewards). Users
    // saw e.g. "1439.59 VELD" / liquid 1295.41 / staked 50 and the
    // numbers didn't add up — because 94.18 VELD was sitting in the
    // 100-block coinbase maturity buffer with no on-screen acknowledgement.
    // Make the breakdown explicit and complete: spendable + staked +
    // (maturing if any). Fields collapse out cleanly when zero, so a
    // wallet with no stake / no maturing coinbase still reads tidy.
    // The detailed Spendable and Maturing values remain in the balance grid;
    // avoid duplicating them below the hero total.
    var spendEl = document.getElementById('w-spendable');
    if (spendEl) { spendEl.textContent = ''; spendEl.style.display = 'none'; }
  });
  // Read actual held principal, including pending returns. The registration
  // minimum can change while an existing validator still holds a larger bond.
  _veldLoadWalletBondBalance(bondBalance);
  // Cache vault-ETA for the enriched status bar
  // (cell removed from balance grid; still surfaced in the top status
  // bar so users see "next draw" countdown there without duplicating
  // the Staking-tab "Next distribution" indicator).
  rpc('getstakinginfo').then(function(si) {
    var rem = (si && si.next_distribution_in != null) ? parseInt(si.next_distribution_in, 10) : null;
    window._statusVaultETA = (rem != null) ? rem : 0;
  }).catch(function(){ window._statusVaultETA = 0; });

  publicAddressHistory(addr, 50).then(function(txs) {
    var el  = document.getElementById('w-bal-lifetime');
    var sub = document.getElementById('w-bal-lifetime-sub');
    var income = (txs || []).reduce(function(total, tx) {
      var n = parseFloat(tx.net_veld || 0) || 0;
      return total + (n > 0 ? n : 0);
    }, 0);
    if (el)  el.textContent  = fmt(income, 2);
    if (sub) sub.textContent = 'recent indexed income';
  }).catch(function() {
    var el = document.getElementById('w-bal-lifetime');
    if (el) el.textContent = '—';
  });
  // \u2014 "Next Draw" cell RESTORED. Original co-mining
  // lottery payout countdown: H % 100 == 0 blocks land the lottery.
  // Source: getpoolinfo.blocks_until_payout.
  rpc('getpoolinfo').then(function(p) {
    var n = (p && typeof p === 'object') ? (p.blocks_until_payout != null ? p.blocks_until_payout : 0) : 0;
    var el = document.getElementById('w-bal-nextdraw');
    if (el) el.textContent = n + ' blocks';
  }).catch(function(){
    var el = document.getElementById('w-bal-nextdraw');
    if (el) el.textContent = '\u2014';
  });
  // Est 24h earnings — computed after mining + staking info arrives.
  //
  // REWRITE — prior version had three bugs:
  //   1. Applied the combined mining×lockup multiplier to the miner coinbase.
  //      The multiplier ONLY affects the vault→staker distribution share;
  //      per-block coinbase is a flat 0.95 VELD (50% of the 1.9 subsidy),
  //      identical for every miner.
  //   2. Treated `w-blocks` as blocks-in-the-last-1095-minutes and scaled
  //      by 1440/1095. In reality GetBlocksMined returns the miner's
  //      LIFETIME block count, so the mining figure was inflated roughly
  //      ~1.3× early and became wildly wrong as the chain aged.
  //   3. Used a hard-coded 0.25 %/day "APR" for staking. The real yield
  //      comes from the vault distribution cycle every
  //      VAULT_DISTRIBUTION_INTERVAL=480 blocks (one cycle per day at the
  //      180-second target). getstakinginfo already reports each staker's
  //      `payout_net_veld` per cycle, so the projection is simply
  //      payout_net × 1.
  //
  // New math:
  //   * Mining/day = lifetime block share × next 480 blocks' miner subsidy.
  //     The node includes subsidy reductions, vault blocks and the supply cap.
  //     Falls back to 0 when chain_height is 0 (pre-genesis guard).
  //   * Staking/day = payout_net_veld × (480 / 480)
  //     — the authoritative per-cycle number from the node × cycles/day.
  //   * Endorsement is not yet projected — it's opportunity-driven and
  //     has no clean per-address pace until we add an RPC for it.
  var _computeEst24h = function() {
    try {
      var mBlocks = parseFloat((document.getElementById('w-blocks')?.textContent||'0').replace(/,/g,''))||0;
      var chainH  = parseFloat((document.getElementById('d-height')?.textContent||'0').replace(/,/g,''))||0;
      var estEl = document.getElementById('w-bal-est24h');
      if (!estEl) return;
      // Mining projection uses lifetime-average: blocks-per-day =
      // mBlocks * (480 / chainH). On very young chains this denominator
      // is tiny and the number spikes (one block on a 10-block chain
      // implies ~140 blocks/day). Require at least 60 blocks of chain
      // history (== post-LWMA-bootstrap window) and at least 1 lifetime
      // block before projecting mining income.
      var miningPerDay = 0;
      var miningReady = (chainH >= 60 && mBlocks >= 1 && walletSubsidy &&
                         walletSubsidy.height === chainH && Date.now() - walletSubsidy.at < 60000);
      if (miningReady) {
        // Lifetime block share applied to the next 480 blocks of actual subsidy.
        miningPerDay = (mBlocks / chainH) * walletSubsidy.minerNext480;
      }
      // Staking: per-cycle net payout from getstakinginfo × 1 cycle/day.
      // 480 blocks/day ÷ VAULT_DISTRIBUTION_INTERVAL (480) = 1.
      // Keyed by address so wallet switches don't bleed.
      var addrNow = (typeof currentAddr === 'string') ? currentAddr : '';
      var stakingPerDay = (window._wStakePerDayByAddr
          && typeof window._wStakePerDayByAddr[addrNow] === 'number')
          ? window._wStakePerDayByAddr[addrNow] : 0;
      var total24h = miningPerDay + stakingPerDay;
      // When no history yet AND no stake, show "—" instead of "+0.00"
      // — avoids the confusing "+0.00 mining + staking" placeholder.
      if (!miningReady && stakingPerDay === 0) {
        estEl.textContent = '—';
        return;
      }
      estEl.textContent = (total24h >= 0.005 ? '+' : '') + fmt(total24h, 2);
      // Honest sub-text: reflect what's actually included in the number.
      var subEl = document.getElementById('w-bal-est24h-sub');
      if (subEl) {
        if (miningReady && stakingPerDay > 0)       subEl.textContent = 'mining (lifetime avg) + staking';
        else if (miningReady)                       subEl.textContent = 'mining (lifetime avg)';
        else if (stakingPerDay > 0)                 subEl.textContent = 'staking only — mining estimate unavailable';
        else                                        subEl.textContent = 'no projection yet';
      }
    } catch (e) {}
  };
  // 5: cancel any pending _computeEst24h timeouts
  // from a previous wallet-switch so we don't paint stale numbers from
  // the prior address, then arm fresh timers bound to THIS addr.
  if (window._wEstTimers) {
    try { window._wEstTimers.forEach(function(t){ clearTimeout(t); }); } catch(e){}
  }
  window._wEstTimers = [];
  window._wEstTimers.push(setTimeout(_computeEst24h, 1200));
  window._wEstTimers.push(setTimeout(_computeEst24h, 3000));
  rpc('listunspent',[addr]).then(function(utxos) {
    window._wUtxoData = utxos || [];
    window._wUtxoPage = 1;
    renderWalletUtxos();
  });
  rpc('getminerinfo',[addr]).then(function(m) {
    // cache "recently mined a block" flag for the
    // enriched status bar. Active when this address's last_block_height
    // is within the last 60 blocks (~3 hours at the 180-second target).
    // Tip pulled from the
    // dashboard's d-height cell so we don't fire a second RPC.
    try {
      var lastH = parseInt(m.last_block_height || 0, 10) || 0;
      var tipH  = parseInt((document.getElementById('d-height')||{}).textContent || '0').toString().replace(/,/g, '');
      tipH = parseInt(tipH, 10) || 0;
      window._statusMiningActive = (lastH > 0 && tipH > 0 && (tipH - lastH) <= 60);
    } catch(_) { window._statusMiningActive = false; }
    document.getElementById('w-blocks').textContent = (m.blocks_mined||0).toLocaleString();
    var tierName = (m.tier > 0) ? (m.tier_name || ['—','Bronze','Silver','Gold','Platinum','Diamond'][m.tier] || '—') : '—';
    var tEl = document.getElementById('w-tier');
    var tierClassNames = ['tier-none','tier-bronze','tier-silver','tier-gold','tier-platinum','tier-diamond'];
    for (var tierClassIndex = 0; tierClassIndex < tierClassNames.length; tierClassIndex++) {
      tEl.classList.remove(tierClassNames[tierClassIndex]);
    }
    var tierKey = String(tierName || '').toLowerCase();
    if (tierClassNames.indexOf('tier-' + tierKey) >= 0) {
      tEl.dataset.tier = tierKey;
      tEl.classList.add('tier-' + tierKey);
    } else {
      delete tEl.dataset.tier;
      tEl.classList.add('tier-none');
    }
    // Diamond renders with the prismatic shimmer
    // instead of a flat colour swap, so it visually stands apart from
    // every other tier and reads as the achievement it represents.
    if (tierName === 'Diamond') {
        tEl.innerHTML = '<span class="diamond-prismatic">Diamond</span>';
        tEl.style.removeProperty('color');
        tEl.style.removeProperty('-webkit-text-fill-color');
    } else {
        tEl.textContent = tierName;
        tEl.style.removeProperty('color');
        tEl.style.removeProperty('-webkit-text-fill-color');
    }
    // wallet UX: replace the static "rolling-window active days"
    // sub-text with a live readout of the address's current and next-tier
    // window-activity counts. This is what the user actually wants to see
    // when they're trying to figure out whether they're about to be promoted
    // (or, more painfully, demoted because an old window slid out).
    var tSubEl = document.getElementById('w-tier-sub');
    if (tSubEl) {
      // This card is assembled with innerHTML, so treat every RPC field as
      // hostile even though the ordinary node emits small integers/names.
      var tierCount = function(v, fallback) {
        var n = Number(v);
        return Number.isSafeInteger(n) && n >= 0 ? String(n) : String(fallback || 0);
      };
      var safeTierName = escHtml(String(tierName || '—'));
      var safeNextTierName = escHtml(String(m.next_tier_name || ''));
      var curLine = '';
      if (m.windows_total && m.windows_required) {
        // Active in window tier — show how comfortably they meet it.
        curLine = tierCount(m.windows_active, 0) + ' of ' + tierCount(m.windows_total, 0) + ' days active'
                + ' &middot; ' + safeTierName + ' needs ' + tierCount(m.windows_required, 0);
      } else {
        // Base tier (no window match yet). Show progress toward Bronze if
        // the next-tier fields are populated (they always are unless we
        // somehow have a tier above Diamond, which we don’t).
        if (m.next_tier_name) {
          curLine = tierCount(m.next_windows_active, 0) + ' of ' + tierCount(m.next_windows_total, 14)
                  + ' days active &middot; ' + safeNextTierName + ' needs '
                  + tierCount(m.next_windows_required, 7);
        } else {
          curLine = 'rolling-window active days';
        }
      }
      var nextLine = '';
      if (m.tier > 0 && m.next_tier_name) {
        // Only show "Next:" if we have both a current tier AND a higher
        // one to climb to. Diamond hits this branch with next_tier_name=""
        // (cleared by RPC) and shows nothing.
        nextLine = '<div style="margin-top:2px;color:var(--muted);font-size:10px">'
                 + 'Next: ' + safeNextTierName + ' &mdash; '
                 + tierCount(m.next_windows_active, 0) + ' of ' + tierCount(m.next_windows_total, 0)
                 + ' (need ' + tierCount(m.next_windows_required, 0) + ')</div>';
      } else if (m.tier === 5) {
        nextLine = '<div style="margin-top:2px;color:var(--muted);font-size:10px">Max tier reached</div>';
      }
      tSubEl.innerHTML = curLine + nextLine;
    }
    var mEl = document.getElementById('w-mult');
    var lmEl = document.getElementById('w-staked');
    var lmSub = document.getElementById('w-staked-sub');
    // the "Reward multiplier" stat shows the COMBINED
    // mining × lockup multiplier that the vault distribution weights
    // each staker by (capped at 3.00×). The "Lockup multiplier" stat
    // below shows the lockup component on its own so the user can see
    // how much of the combined figure comes from their lock term vs.
    // their mining tier. Both come from getstakinginfo which is the
    // authoritative source (rpc.h:2437) — the same JSON the distribute
    // daemon parses.
    rpc('getstakinginfo').then(function(si) {
      var stakers = si.stakers || [];
      var combined = m.multiplier || 1.0;
      var lockup   = 1.0;
      var payoutNet = 0.0;
      // track whether the user actually has a staked
      // position. Previously when the address wasn't found in the
      // stakers list, we defaulted to 1.00×/"7-day (1.00×)", which
      // mislabeled non-stakers as if they had the base lockup tier.
      var hasStake = false;
      for (var i = 0; i < stakers.length; i++) {
        if (stakers[i].address === addr) {
          combined  = stakers[i].multiplier        || combined;
          lockup    = stakers[i].lockup_multiplier || 1.0;
          payoutNet = stakers[i].payout_net_veld   || 0.0;
          hasStake = (stakers[i].staked_veld || 0) > 0;
          break;
        }
      }
      mEl.textContent = combined.toFixed(2) + '×';
      if (lmEl) lmEl.textContent = hasStake ? (lockup.toFixed(2) + '×') : '—';
      if (lmSub) {
        // Actual on-chain LOCKUP_TIERS (consensus/staking.h):
        //   7-day  → 1.00x (Tier 1 / base)
        //   14-day → 1.10x (Tier 2 / short)
        //   30-day → 1.25x (Tier 3 / medium)
        //   90-day → 1.50x (Tier 4 / long)
        var tier;
        if (!hasStake) {
          tier = 'no staked position';
        } else if (lockup >= 1.495) {
          tier = '90-day (1.50×)';
        } else if (lockup >= 1.245) {
          tier = '30-day (1.25×)';
        } else if (lockup >= 1.095) {
          tier = '14-day (1.10×)';
        } else if (lockup >= 1.001) {
          tier = 'partial';
        } else {
          tier = '7-day (1.00×)';
        }
        lmSub.textContent = tier;
      }
      // Cache per-day staking projection for _computeEst24h.
      // 480 blocks/day ÷ VAULT_DISTRIBUTION_INTERVAL (480) = 1 cycle/day.
      // Keyed by address so wallet switches don't pollute.
      if (!window._wStakePerDayByAddr) window._wStakePerDayByAddr = {};
      window._wStakePerDayByAddr[addr] = payoutNet * 1.0;
      // paint est-24h as soon as BOTH getminerinfo (above,
      // sets w-blocks) and getstakinginfo (this promise) resolve, so
      // the user sees real numbers on slow RPC rather than the
      // setTimeout-based placeholder. Wrapped in try so a late
      // _computeEst24h error can't break the staker-table render.
      try { _computeEst24h(); } catch(e){}
    }).catch(function(){
      mEl.textContent = (m.multiplier||1.0).toFixed(2) + '×';
      if (lmEl) lmEl.textContent = '—';
      if (lmSub) lmSub.textContent = 'no staked position';
      if (!window._wStakePerDayByAddr) window._wStakePerDayByAddr = {};
      window._wStakePerDayByAddr[addr] = 0;
      try { _computeEst24h(); } catch(e){}
    });
    mEl.style.color = 'var(--em)';
  }).catch(function(){
    document.getElementById('w-blocks').textContent = '0';
    var tEl2 = document.getElementById('w-tier');
    tEl2.textContent = '—';
    delete tEl2.dataset.tier;
    var tierClassNames2 = ['tier-bronze','tier-silver','tier-gold','tier-platinum','tier-diamond'];
    for (var tierClassIndex2 = 0; tierClassIndex2 < tierClassNames2.length; tierClassIndex2++) {
      tEl2.classList.remove(tierClassNames2[tierClassIndex2]);
    }
    tEl2.classList.add('tier-none');
    tEl2.style.removeProperty('color');
    tEl2.style.removeProperty('-webkit-text-fill-color');
    document.getElementById('w-mult').textContent = '1.0×';
    var lmEl2 = document.getElementById('w-staked');
    if (lmEl2) lmEl2.textContent = '1.00×';
    var lmSub2 = document.getElementById('w-staked-sub');
    if (lmSub2) lmSub2.textContent = 'none';
    var tSub2 = document.getElementById('w-tier-sub');
    if (tSub2) tSub2.textContent = '—';
  });
  // refresh the persistent lock banner for this wallet
  // Recent transactions inline
  var _txh = parseInt((document.getElementById('d-height')?.textContent||'0').replace(/,/g,''))||0;
  var _txfrom = Math.max(0, _txh - 5000);
  publicAddressHistory(addr, 50).then(function(txs) {
    if (!txs || !txs.length) {
      document.getElementById('w-recent-txs').innerHTML = '<div style="color:var(--muted);text-align:center;padding:12px;font-size:11px">No transactions found</div>';
      return;
    }
    // Same friendly label set as the full history panel below
    // (renderHistory). Keeps type names readable: a row shouldn't
    // surface raw protocol identifiers like "near_miss_submission" or
    // "endorsement_payout" — they read as code, not as English. Any
    // unmapped type falls back to a Title-Cased version of the raw
    // identifier with underscores turned into spaces, so future
    // protocol additions remain readable until they're added here.
    var _typeLabel = {
      coinbase:'Block Reward', block_reward:'Block Reward', miner_reward:'Block Reward',
      comine_payout:'Co-Mine Payout',
      staking_distribution:'Staking Reward', vault_distribution:'Staking Reward',
      endorsement_reward:'Validator Rewards', endorsement_payout:'Validator Rewards',
      endorsement:'Block Endorsement',
      stake_lock:'Stake Lock', stake_unlock:'Stake Unlock',
      validator_register:'Validator Registration',
      validator_deregister:'Validator Deregister',
      near_miss_submission:'Near-miss submission',
      gov_proposal:'Governance Proposal',
      gov_vote:'Governance Vote', gov_other:'Governance',
      self:'Self-transfer', consolidation:'Consolidation',
    sent:'Sent', received:'Received'
    };
    var _prettyType = function(s) {
      if (_typeLabel[s]) return _typeLabel[s];
      if (!s) return 'Tx';
      return s.replace(/_/g, ' ').replace(/\b\w/g, function(c){ return c.toUpperCase(); });
    };
    // Recent transactions paginated at 25/page.
    // Replaces the prior hardcoded slice(0,8). Page state lives on
    // window._wRecentPage so navigating across tabs preserves the
    // user's current page.
    window._wRecentTxs = txs;
    renderWalletRecentTxs();
  }).catch(function(){});
  loadActivityFeed();
  // refresh the In-flight TX card next to the
  // balance hero so a still-pending send shows up without needing
  // a manual page reload.
  try { loadPendingSends(); } catch(_){}
  // refresh the Mining session card.
  try { loadMiningSession(); } catch(_){}
  // check for dust UTXOs to surface the
  // Consolidate prompt.
  try { loadDustUtxoCount(); } catch(_){}
  // Automatic cleanup requires an explicit saved opt-in.
  try { autoConsolidateMaybe(); } catch(_){}
}

  window._veldWalletBondBalance = _veldWalletBondBalance;
  window._veldApplyWalletBondBalance = _veldApplyWalletBondBalance;
  window._veldLoadWalletBondBalance = _veldLoadWalletBondBalance;
  window.loadWalletAddr = loadWalletAddr;
})();
