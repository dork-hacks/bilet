/* Update only text and visibility: keep the page and keyboard focus in place. */
(() => {
  const page = document.querySelector('[data-scan-status]');
  if (!page || page.dataset.running !== 'true') return;
  const message = document.getElementById('scan-message');
  const cancel = document.getElementById('scan-cancel');
  const result = document.getElementById('scan-result');
  const retry = document.getElementById('scan-retry');
  const hint = document.getElementById('scan-auth-hint');
  const error = document.getElementById('scan-refresh-error');
  async function poll() {
    try {
      const response = await fetch(page.dataset.scanStatus, {cache: 'no-store', credentials: 'same-origin'});
      if (!response.ok) throw new Error('Status unavailable');
      const status = await response.json();
      if (message.textContent !== status.message) message.textContent = status.message;
      const cancelFocused = cancel.contains(document.activeElement);
      cancel.hidden = !status.running;
      hint.hidden = !status.running;
      result.hidden = !status.done;
      retry.hidden = status.running;
      error.hidden = true;
      if (!status.running) {
        if (cancelFocused) {
          const next = status.done ? result.querySelector('a') : retry.querySelector('button');
          if (next) next.focus();
        }
        return;
      }
      setTimeout(poll, 3000);
    } catch {
      error.hidden = false;
      // Manual refresh stays available without repeated failures or a page reload.
    }
  }
  setTimeout(poll, 3000);
})();
