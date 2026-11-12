(() => {
  'use strict';
  if (typeof HTMLDialogElement === 'undefined' || !HTMLDialogElement.prototype.showModal) return;

  const dialog = document.createElement('dialog');
  dialog.className = 'info-dialog';
  dialog.id = 'homepage-info';
  dialog.setAttribute('aria-labelledby', 'homepage-info-title');
  dialog.innerHTML = '<div class="info-dialog-header"><h2 id="homepage-info-title"></h2><button type="button" class="info-close" aria-label="Close explanation" autofocus><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div><div class="info-dialog-body"></div>';
  document.body.append(dialog);
  const title = dialog.querySelector('h2');
  const body = dialog.querySelector('.info-dialog-body');
  let opener = null;
  let previousOverflow = '';
  const close = () => dialog.close();
  dialog.querySelector('.info-close').addEventListener('click', close);
  dialog.addEventListener('keydown', event => {
    if (event.key !== 'Tab') return;
    const items = Array.from(dialog.querySelectorAll('button, a[href]')).filter(item => !item.disabled && item.getClientRects().length);
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
  let backdropDown = false;
  const outside = event => {
    const rect = dialog.getBoundingClientRect();
    return event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom;
  };
  dialog.addEventListener('pointerdown', event => { backdropDown = event.target === dialog && outside(event); });
  dialog.addEventListener('click', event => {
    if (backdropDown && event.target === dialog && outside(event)) close();
    backdropDown = false;
  });
  dialog.addEventListener('close', () => {
    document.documentElement.style.overflow = previousOverflow;
    body.replaceChildren();
    if (opener && opener.isConnected) opener.focus({ preventScroll: true });
    opener = null;
  });

  document.querySelectorAll('.info-content').forEach(content => {
    const card = content.closest('.hc, .wc, .dl');
    const heading = card && card.querySelector('h3');
    if (!heading) return;
    const download = card.classList.contains('dl');
    const label = download ? heading.textContent + ' — Checksums and source' : heading.textContent;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = download ? 'info-trigger info-trigger-text' : 'info-trigger';
    button.setAttribute('aria-label', download ? label : 'About ' + label);
    button.setAttribute('aria-haspopup', 'dialog');
    button.setAttribute('aria-controls', dialog.id);
    button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M12 11v6"/><circle class="info-dot" cx="12" cy="7.5" r=".8"/></svg>';
    if (download) {
      const text = document.createElement('span');
      text.textContent = 'Checksums and source';
      button.append(text);
      content.before(button);
    } else {
      const row = document.createElement('div');
      row.className = 'info-heading';
      heading.before(row);
      row.append(heading, button);
    }
    button.addEventListener('click', () => {
      if (dialog.open) return;
      title.textContent = label;
      body.replaceChildren(...Array.from(content.childNodes, node => node.cloneNode(true)));
      opener = button;
      previousOverflow = document.documentElement.style.overflow;
      dialog.showModal();
      document.documentElement.style.overflow = 'hidden';
    });
    content.hidden = true;
  });
})();
