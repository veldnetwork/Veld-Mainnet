(function () {
  'use strict';

  var root = document.documentElement;
  var layoutQuery = window.matchMedia ? window.matchMedia('(max-width: 900px)') : null;
  var coarseQuery = window.matchMedia ? window.matchMedia('(pointer: coarse)') : null;
  var isWallet = window.location.hostname === 'wallet.veld.network';
  var fallbackInstallEvent = null;

  function syncLayout() {
    var compactWidth = window.innerWidth <= 900;
    var touchTablet = !!(coarseQuery && coarseQuery.matches && window.innerWidth <= 1180);
    var mobile = compactWidth || touchTablet;
    root.dataset.deviceLayout = mobile ? 'mobile' : 'desktop';
  }

  function applyWalletAccents(theme) {
    if (!isWallet) return;
    var light = theme === 'light';
    [
      'd-height', 'd-dist-countdown', 'd-supply', 'd-vault', 'sk-active', 'sk-apy',
      'val-mystatus', 'cm-payout-in', 'earn-30d', 'earn-life'
    ].forEach(function (id) {
      var value = document.getElementById(id);
      if (!value) return;
      if (light) {
        value.style.setProperty('color', '#187d37', 'important');
        value.style.setProperty('text-shadow', 'none', 'important');
      } else {
        value.style.removeProperty('color');
        value.style.removeProperty('text-shadow');
      }
    });
  }

  function polishWalletUI() {
    if (!isWallet) return;

    document.querySelectorAll('.theme-tog').forEach(function (button) {
      button.setAttribute('aria-label', 'Toggle light or dark mode');
      button.setAttribute('title', 'Toggle light or dark mode');
    });

    var btcHeader = document.querySelector('#page-btcveld .page-header');
    if (btcHeader) {
      var btcTitle = btcHeader.querySelector('.page-title');
      if (btcTitle) btcTitle.textContent = 'btcVELD';
      var btcSub = btcHeader.querySelector('.page-sub');
      if (!btcSub) {
        btcSub = document.createElement('div');
        btcSub.className = 'page-sub';
        btcHeader.appendChild(btcSub);
      }
      btcSub.textContent = 'Bitcoin, wrapped 1:1';
    }

    document.querySelectorAll('#page-comining div').forEach(function (element) {
      var value = element.textContent.trim();
      if (value.indexOf('five winners below 1,000 eligible miners') !== -1) {
        element.textContent = 'Every 100 blocks, the pool is split equally between randomly drawn eligible miners.';
      }
    });

    applyWalletAccents(root.dataset.theme || 'dark');
  }

  function installStyles() {
    if (document.getElementById('veld-pwa-install-styles')) return;
    var style = document.createElement('style');
    style.id = 'veld-pwa-install-styles';
    style.textContent = [
      '.explorer-install{display:none;position:fixed;top:0;left:0;right:0;z-index:10000;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}',
      '.explorer-install.show{display:flex}.explorer-install .copy{display:grid;gap:2px;min-width:0;flex:1}.explorer-install .copy b{font-size:13px}.explorer-install .copy span{font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.explorer-install .install-btn{border-radius:9px;padding:9px 15px;font:650 13px/1 system-ui,sans-serif;cursor:pointer}.explorer-install .dismiss-btn{width:32px;height:32px;padding:0;border:0;background:transparent;font-size:22px;line-height:1;cursor:pointer}',
      '.explorer-install-sheet{display:none;position:fixed;z-index:10001;inset:0;align-items:flex-end;justify-content:center;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px)}',
      '#pwa-install-banner,.explorer-install{font-family:var(--sans,system-ui),-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif!important;transition:background-color .18s ease,border-color .18s ease,color .18s ease!important}',
      'html:not([data-theme="light"]) #pwa-install-banner,html:not([data-theme="light"]) .explorer-install{background:rgba(16,19,17,.98)!important;border-bottom-color:#303832!important;color:#f4f6f4!important;box-shadow:0 12px 34px rgba(0,0,0,.22)!important}',
      'html[data-theme="light"] #pwa-install-banner,html[data-theme="light"] .explorer-install{background:rgba(244,248,244,.98)!important;border-bottom-color:#c7d1c9!important;color:#172119!important;box-shadow:0 12px 30px rgba(31,58,37,.12)!important}',
      'html:not([data-theme="light"]) #pwa-install-btn,html:not([data-theme="light"]) .explorer-install .install-btn{background:#303832!important;border:1px solid #59645b!important;color:#f5f7f5!important;box-shadow:none!important}',
      'html[data-theme="light"] #pwa-install-btn,html[data-theme="light"] .explorer-install .install-btn{background:#e1e6e2!important;border:1px solid #aeb8b0!important;color:#172119!important;box-shadow:none!important}',
      '#pwa-ios-sheet,.explorer-install-sheet{overflow-y:auto!important;overscroll-behavior:contain!important;padding:max(18px,env(safe-area-inset-top)) 14px max(18px,calc(env(safe-area-inset-bottom) + 12px))!important}',
      '#pwa-ios-sheet.open,.explorer-install-sheet.open{display:flex!important}',
      '.pwa-sheet-card,.explorer-install-card{width:min(100%,500px)!important;max-height:calc(100dvh - 36px - env(safe-area-inset-top) - env(safe-area-inset-bottom))!important;overflow-y:auto!important;overscroll-behavior:contain!important;padding:22px!important;border:1px solid!important;border-radius:20px!important;box-shadow:0 24px 80px rgba(0,0,0,.46)!important}',
      'html:not([data-theme="light"]) #pwa-ios-sheet,html:not([data-theme="light"]) .explorer-install-sheet{background:rgba(0,0,0,.70)!important}',
      'html:not([data-theme="light"]) .pwa-sheet-card,html:not([data-theme="light"]) .explorer-install-card{background:#151815!important;border-color:#3a423b!important;color:#f5f7f5!important}',
      'html[data-theme="light"] #pwa-ios-sheet,html[data-theme="light"] .explorer-install-sheet{background:rgba(20,30,22,.46)!important}',
      'html[data-theme="light"] .pwa-sheet-card,html[data-theme="light"] .explorer-install-card{background:#f8faf8!important;border-color:#bdc8bf!important;color:#172119!important;box-shadow:0 24px 70px rgba(24,40,28,.24)!important}',
      '.pwa-sheet-head,.explorer-install-head{display:grid!important;grid-template-columns:minmax(0,1fr) 40px!important;gap:16px!important;align-items:start!important;margin-bottom:18px!important}',
      '.pwa-sheet-head h2,.explorer-install-head h2{margin:0!important;font:700 22px/1.12 var(--font,ui-monospace),ui-monospace,monospace!important;letter-spacing:-.02em!important}',
      '.pwa-sheet-head p,.explorer-install-head p{margin:8px 0 0!important;font-size:14px!important;line-height:1.45!important}',
      '.pwa-sheet-close,.explorer-install-head .sheet-close{width:40px!important;height:40px!important;display:grid!important;place-items:center!important;padding:0!important;border:1px solid!important;border-radius:11px!important;background:transparent!important;font-size:24px!important;line-height:1!important}',
      '.pwa-sheet-steps,.explorer-install-steps{display:grid!important;gap:10px!important}',
      '.pwa-sheet-step,.explorer-install-step{display:grid!important;grid-template-columns:28px 42px minmax(0,1fr)!important;gap:12px!important;align-items:center!important;padding:12px 14px!important;border:1px solid!important;border-radius:14px!important;font-size:13px!important;line-height:1.45!important;min-height:72px!important}',
      '.pwa-sheet-step::before,.explorer-install-step::before{display:grid!important;place-items:center!important;width:28px!important;height:28px!important;border:1px solid!important;border-radius:50%!important;background:#2e3530!important;border-color:#566158!important;color:#f4f6f4!important;font:750 13px/1 system-ui,sans-serif!important}',
      '.pwa-step-icon,.explorer-install-step-icon{display:grid!important;place-items:center!important;width:40px!important;height:40px!important;border:1px solid!important;border-radius:11px!important}',
      '.pwa-step-icon svg,.explorer-install-step-icon svg{width:21px!important;height:21px!important}',
      '.pwa-step-copy,.explorer-install-step-copy{display:grid!important;gap:3px!important;min-width:0!important;overflow-wrap:anywhere!important}.pwa-step-copy b,.explorer-install-step-copy b{font-size:13px!important}.pwa-step-copy span,.explorer-install-step-copy span{font-size:12px!important;line-height:1.4!important}',
      'html:not([data-theme="light"]) .pwa-sheet-step,html:not([data-theme="light"]) .explorer-install-step{background:#0f120f!important;border-color:#303731!important;color:#f1f4f2!important}',
      'html[data-theme="light"] .pwa-sheet-step,html[data-theme="light"] .explorer-install-step{background:#fff!important;border-color:#ccd5ce!important;color:#172119!important}',
      'html[data-theme="light"] .pwa-sheet-step::before,html[data-theme="light"] .explorer-install-step::before,html[data-theme="light"] .pwa-step-icon,html[data-theme="light"] .explorer-install-step-icon{background:#e7ece8!important;border-color:#bac6bc!important;color:#273329!important}',
      'html:not([data-theme="light"]) .pwa-sheet-head p,html:not([data-theme="light"]) .explorer-install-head p{color:#b3bbb4!important}',
      'html[data-theme="light"] .pwa-sheet-head p,html[data-theme="light"] .explorer-install-head p{color:#5f6a62!important}',
      '@media(min-width:901px){#pwa-install-banner,.explorer-install{left:auto!important;right:22px!important;top:18px!important;width:min(430px,calc(100% - 44px))!important;border:1px solid!important;border-radius:13px!important}#pwa-ios-sheet,.explorer-install-sheet{align-items:center!important;padding:24px!important}.pwa-sheet-card,.explorer-install-card{padding:26px!important}}',
      '@media(max-height:650px){.pwa-sheet-card,.explorer-install-card{padding:18px!important;border-radius:16px!important}.pwa-sheet-head,.explorer-install-head{margin-bottom:13px!important}.pwa-sheet-step,.explorer-install-step{padding:11px!important}}'
    ].join('');
    document.head.appendChild(style);
  }

  function polishInstallUI() {
    var banner = document.querySelector(isWallet ? '#pwa-install-banner' : '#explorer-install');
    if (banner) {
      var title = banner.querySelector(isWallet ? '.pwa-title' : '.copy b');
      var subtitle = banner.querySelector(isWallet ? '.pwa-sub' : '.copy span');
      if (title) title.textContent = isWallet ? 'Install Veld Wallet' : 'Install Veld Explorer';
      if (subtitle) subtitle.textContent = 'Open the app directly from your Home Screen';
    }

    var sheet = document.querySelector(isWallet ? '#pwa-ios-sheet' : '#explorer-install-sheet');
    if (!sheet) return;
    var head = sheet.querySelector(isWallet ? '.pwa-sheet-head' : '.explorer-install-head');
    if (head) {
      var heading = head.querySelector('h2');
      var copy = head.querySelector('p');
      if (heading) heading.textContent = isWallet ? 'Install Veld Wallet' : 'Install Veld Explorer';
      if (copy) copy.textContent = 'Use your browser menu to add the app in four quick steps.';
    }
    var steps = sheet.querySelectorAll(isWallet ? '.pwa-sheet-step' : '.explorer-install-step');
    var labels = [
      ['Open Share','Tap the Share icon in your browser toolbar or menu.'],
      ['Show all actions','Tap View More if the full action list is collapsed.'],
      ['Add to Home Screen','Choose Add to Home Screen from the action list.'],
      ['Confirm','Tap Add. The app will open from your Home Screen.']
    ];
    steps.forEach(function(step, index) {
      if (!labels[index]) return;
      var title = step.querySelector('b');
      var copy = step.querySelector('.pwa-step-copy span,.explorer-install-step-copy span');
      if (title) title.textContent = labels[index][0];
      if (copy) copy.textContent = labels[index][1];
    });
  }

  function ensureExplorerInstallSurface() {
    if (isWallet || document.getElementById('explorer-install')) return;

    var banner = document.createElement('div');
    banner.className = 'explorer-install';
    banner.id = 'explorer-install';
    banner.setAttribute('role', 'region');
    banner.setAttribute('aria-label', 'Install Veld Explorer');
    banner.innerHTML = '<span class="copy"><b>Install Veld Explorer</b><span>Open the app directly from your Home Screen</span></span><button type="button" class="install-btn" id="explorer-install-btn">Install</button><button type="button" class="dismiss-btn" id="explorer-install-dismiss" aria-label="Dismiss install prompt">&times;</button>';

    var sheet = document.createElement('div');
    sheet.className = 'explorer-install-sheet';
    sheet.id = 'explorer-install-sheet';
    sheet.setAttribute('role', 'dialog');
    sheet.setAttribute('aria-modal', 'true');
    sheet.setAttribute('aria-labelledby', 'explorer-install-title');
    var icon = function(path) { return '<span class="explorer-install-step-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + path + '</svg></span>'; };
    var step = function(iconPath, title, copy) { return '<div class="explorer-install-step">' + icon(iconPath) + '<span class="explorer-install-step-copy"><b>' + title + '</b><span>' + copy + '</span></span></div>'; };
    sheet.innerHTML = '<div class="explorer-install-card"><div class="explorer-install-head"><div><h2 id="explorer-install-title">Install Veld Explorer</h2><p>Use your browser menu to add the app in four quick steps.</p></div><button type="button" class="sheet-close" aria-label="Close install instructions">&times;</button></div><div class="explorer-install-steps">' +
      step('<path d="M12 3v12"/><path d="M8 7l4-4 4 4"/><path d="M8 12H6a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5a2 2 0 0 0-2-2h-2"/>','Open Share','Tap the Share icon in your browser toolbar or menu.') +
      step('<path d="m6 9 6 6 6-6"/>','Show all actions','Tap View More if the full action list is collapsed.') +
      step('<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M12 8v8M8 12h8"/>','Add to Home Screen','Choose Add to Home Screen from the action list.') +
      step('<path d="m5 12 4 4L19 6"/>','Confirm','Tap Add. The app will open from your Home Screen.') +
      '</div></div>';

    document.body.appendChild(banner);
    document.body.appendChild(sheet);

    var dismissedKey = 'veld-explorer-install-dismissed';
    var standalone = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || window.navigator.standalone === true;
    var isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);

    function dismissed() {
      try { return sessionStorage.getItem(dismissedKey) === '1'; } catch (_) { return false; }
    }
    function show() {
      if (!standalone && !dismissed()) {
        banner.classList.add('show');
        document.body.classList.add('has-explorer-install');
      }
    }
    function hide() {
      banner.classList.remove('show');
      document.body.classList.remove('has-explorer-install');
      sheet.classList.remove('open');
    }
    function openSheet() {
      polishInstallUI();
      sheet.classList.add('open');
      var close = sheet.querySelector('.sheet-close');
      if (close) close.focus();
    }

    banner.querySelector('.install-btn').addEventListener('click', function () {
      if (fallbackInstallEvent) {
        fallbackInstallEvent.prompt();
        fallbackInstallEvent.userChoice.then(function () {
          fallbackInstallEvent = null;
          hide();
        });
      } else if (isIOS) {
        openSheet();
      }
    });
    banner.querySelector('.dismiss-btn').addEventListener('click', function () {
      try { sessionStorage.setItem(dismissedKey, '1'); } catch (_) {}
      hide();
    });
    sheet.querySelector('.sheet-close').addEventListener('click', function () { sheet.classList.remove('open'); });
    sheet.addEventListener('click', function (event) { if (event.target === sheet) sheet.classList.remove('open'); });

    window.addEventListener('beforeinstallprompt', function (event) {
      event.preventDefault();
      fallbackInstallEvent = event;
      show();
    });
    window.addEventListener('appinstalled', function () {
      standalone = true;
      fallbackInstallEvent = null;
      hide();
    });
    if (isIOS && !standalone) window.setTimeout(show, 1200);
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js?ui=20260907-current-web', { scope: '/', updateViaCache: 'none' }).catch(function () {});
  }

  function initialize() {
    syncLayout();
    installStyles();
    ensureExplorerInstallSurface();
    polishWalletUI();
    polishInstallUI();
  }

  if (layoutQuery) {
    if (layoutQuery.addEventListener) layoutQuery.addEventListener('change', syncLayout);
    else if (layoutQuery.addListener) layoutQuery.addListener(syncLayout);
  }
  if (coarseQuery) {
    if (coarseQuery.addEventListener) coarseQuery.addEventListener('change', syncLayout);
    else if (coarseQuery.addListener) coarseQuery.addListener(syncLayout);
  }
  window.addEventListener('resize', syncLayout);
  window.addEventListener('orientationchange', syncLayout);
  document.addEventListener('click', function (event) {
    if (event.target.closest && event.target.closest('.theme-tog')) {
      window.setTimeout(function () {
        polishWalletUI();
        polishInstallUI();
      }, 0);
    }
    if (event.target.closest && event.target.closest('#pwa-install-btn,#explorer-install-btn')) {
      window.setTimeout(polishInstallUI, 0);
    }
  });

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize);
  else initialize();

  if (isWallet) window.veldApplyDashAccents = applyWalletAccents;
})();
