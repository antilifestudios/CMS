/* CMS Detector AI — shared Turnstile token helper (no dependencies).
 * Exposes window.cmsDetectorToken(): Promise<string>.
 * Returns '' when the challenge is not configured, keeping the tool
 * working out of the box; the API decides whether to enforce. */
(function () {
  'use strict';
  async function token() {
    try {
      var meta = document.querySelector('meta[name="turnstile-sitekey"]');
      var key = (meta && meta.getAttribute('content')) || '';
      var t = window.turnstile;
      if (key && t && typeof t.execute === 'function') {
        return await t.execute(key, { action: 'detect' });
      }
    } catch (e) {
      /* challenge unavailable — fall through */
    }
    return '';
  }
  window.cmsDetectorToken = token;
})();
