// Content script: makes sqrl:// links work in the browser.
//
// Most SQRL-enabled pages render the login link as <a href="sqrl://host/cli.sqrl?nut=…">
// (and usually a QR code of the same URL). Browsers have no handler for the sqrl: scheme,
// so clicks are intercepted here and handed to the extension, which opens the
// authentication window. Links pointing at http://localhost:25519/… (the CPS form that
// sites switch to after their probe succeeds) are left alone: the background script's
// declarativeNetRequest rule turns that navigation into the in-tab authentication page.

(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  if (!api || !api.runtime || !api.runtime.id) return;

  const SQRL_RE = /^s?qrl:\/\//i;

  function sqrlHref(el) {
    const a = el && el.closest ? el.closest('a[href]') : null;
    if (!a) return null;
    const href = a.getAttribute('href') || '';
    return SQRL_RE.test(href.trim()) ? href.trim() : null;
  }

  document.addEventListener(
    'click',
    (ev) => {
      if (ev.defaultPrevented || ev.button !== 0) return;
      const href = sqrlHref(ev.target);
      if (!href) return;
      ev.preventDefault();
      ev.stopImmediatePropagation();
      api.runtime.sendMessage({ type: 'sqrl-link-clicked', url: href }).catch(() => {});
    },
    true
  );

  // Also support the "sqrl:" links found inside QR-code <img> alt text or data attributes
  // that some sites use: a middle-click / keyboard activation goes through the same path.
  document.addEventListener(
    'auxclick',
    (ev) => {
      if (ev.button !== 1) return;
      const href = sqrlHref(ev.target);
      if (!href) return;
      ev.preventDefault();
      api.runtime.sendMessage({ type: 'sqrl-link-clicked', url: href }).catch(() => {});
    },
    true
  );

  let lastReport = '';
  function report() {
    const urls = [];
    for (const a of document.querySelectorAll('a[href]')) {
      const href = (a.getAttribute('href') || '').trim();
      if (SQRL_RE.test(href) && !urls.includes(href)) urls.push(href);
      if (urls.length >= 10) break;
    }
    const key = urls.join('\n');
    if (key === lastReport) return;
    lastReport = key;
    if (urls.length) api.runtime.sendMessage({ type: 'sqrl-links-found', urls }).catch(() => {});
  }

  report();
  const observer = new MutationObserver(() => {
    clearTimeout(report.t);
    report.t = setTimeout(report, 300);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['href'] });
})();
