/**
 * Bot-protection handling tests (CMS Detector AI).
 *
 * Covers the bot_protected scan state for /api/detect + shared scanners:
 * - Provider identification per protection system (headers/cookies/scripts)
 * - No identification from a single generic word
 * - Challenge HTML never feeds technology detection (header-only context)
 * - Headers/cookies are still analyzed (hosting-level hints survive)
 * - Challenge trigger semantics (any-status markers, 429/403/503/401/407)
 * - buildBotProtection payload shape (status, provider, headers, limits)
 *
 * Fixture-based, no network. Run with: npm test (node --test, no deps).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  isChallengeResponse,
  selectScanHtml,
  identifyProtection,
  buildBotProtection,
  pickRelevantHeaders,
} from '../src/lib/detect/protection.ts';
import { runSignatureEngine } from '../src/lib/detect/signatures.ts';
import { applyConfidenceModel } from '../src/lib/detect/confidence.ts';

const CF_CHALLENGE_HTML = `<html><head><title>Just a moment...</title></head><body>
  <div id="cf-challenge">Verifying you are human. This may take a few seconds.</div>
  <script src="/cdn-cgi/challenge-platform/h/b/scripts/jsd/abc.js"></script>
  <script src="https://www.youtube.com/iframe_api"></script>
  <script src="https://www.google.com/recaptcha/api.js?render=abc123XYZ456"></script>
  <script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC123"></script>
  <meta name="generator" content="WordPress 6.4.1">
  </body></html>`;

// ----------------------------------------------------------------
// 1. Challenge trigger semantics
// ----------------------------------------------------------------

describe('challenge detection', () => {
  it('flags challenge copy on any status (WAFs sometimes answer 200)', () => {
    assert.equal(isChallengeResponse(200, CF_CHALLENGE_HTML), true);
  });

  it('flags access-control statuses', () => {
    for (const s of [401, 403, 407, 429, 503]) {
      assert.equal(isChallengeResponse(s, '<html><body>hi</body></html>'), true, `status ${s}`);
    }
  });

  it('leaves normal pages alone', () => {
    assert.equal(isChallengeResponse(200, '<html><body><p>Hello world</p></body></html>'), false);
    assert.equal(isChallengeResponse(301, '', ), false);
  });

  it('selectScanHtml blanks challenge HTML, keeps normal HTML', () => {
    assert.equal(selectScanHtml(200, CF_CHALLENGE_HTML), '');
    assert.equal(selectScanHtml(403, '<html>whatever</html>'), '');
    assert.equal(selectScanHtml(200, '<html><p>real site</p></html>'), '<html><p>real site</p></html>');
  });
});

// ----------------------------------------------------------------
// 2. Provider identification
// ----------------------------------------------------------------

describe('provider identification', () => {
  it('identifies Cloudflare from ray + server + challenge script', () => {
    const p = identifyProtection(
      403,
      { server: 'cloudflare', 'cf-ray': 'abc123-IAD', 'content-type': 'text/html' },
      ['__cf_bm'],
      CF_CHALLENGE_HTML
    );
    assert.ok(p, 'expected a provider');
    assert.equal(p.name, 'Cloudflare');
    assert.ok(p.confidence >= 0.4 && p.confidence <= 0.98, `confidence ${p.confidence}`);
    assert.ok(p.evidence.length >= 2, 'multiple evidence lines');
  });

  it('identifies Cloudflare Turnstile from widget markers alone', () => {
    const html = `<html><body><div class="cf-turnstile" data-sitekey="0x4AAAAAAAabc"></div>
      <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script></body></html>`;
    const p = identifyProtection(200, {}, [], html);
    assert.ok(p, 'expected a provider');
    assert.equal(p.name, 'Cloudflare Turnstile');
  });

  it('identifies Akamai from Bot Manager cookies', () => {
    const p = identifyProtection(403, { server: 'AkamaiGHost' }, ['ak_bmsc', '_abck'], '<html><body>Access Denied. Reference #18.abc</body></html>');
    assert.ok(p);
    assert.equal(p.name, 'Akamai');
  });

  it('identifies Imperva from incap cookies + X-Iinfo', () => {
    const p = identifyProtection(403, { 'x-iinfo': '1-2-3' }, ['incap_ses_123', 'visid_incap_123'], '<html><body>Incapsula incident ID</body></html>');
    assert.ok(p);
    assert.equal(p.name, 'Imperva');
  });

  it('identifies DataDome from device cookie', () => {
    const p = identifyProtection(403, {}, ['datadome'], '<html><body><script src="https://captcha.datadome.co/captcha.js"></script></body></html>');
    assert.ok(p);
    assert.equal(p.name, 'DataDome');
  });

  it('identifies PerimeterX/HUMAN from px cookies', () => {
    const p = identifyProtection(403, {}, ['px3', '_pxvid'], '<html><body><script src="https://collector.px-cdn.net/x.js"></script></body></html>');
    assert.ok(p);
    assert.equal(p.name, 'PerimeterX / HUMAN');
  });

  it('identifies AWS WAF from token cookie', () => {
    const p = identifyProtection(403, {}, ['aws-waf-token'], '<html><body>Request blocked by AWS WAF</body></html>');
    assert.ok(p);
    assert.equal(p.name, 'AWS WAF');
  });

  it('identifies Fastly from server + served-by headers', () => {
    const p = identifyProtection(503, { server: 'Fastly', 'x-served-by': 'cache-iad1' }, [], '<html><body>Fastly error: unknown domain</body></html>');
    assert.ok(p);
    assert.equal(p.name, 'Fastly');
  });

  it('identifies a reCAPTCHA challenge page', () => {
    const p = identifyProtection(200, {}, [], '<html><body><script src="https://www.google.com/recaptcha/api.js"></script><div class="g-recaptcha" data-sitekey="abc123XYZ456"></div></body></html>');
    assert.ok(p);
    assert.equal(p.name, 'Google reCAPTCHA');
  });

  it('identifies an hCaptcha challenge page', () => {
    const p = identifyProtection(200, {}, [], '<html><body><script src="https://js.hcaptcha.com/1.js"></script></body></html>');
    assert.ok(p);
    assert.equal(p.name, 'hCaptcha');
  });

  it('never identifies from a single generic word', () => {
    assert.equal(identifyProtection(200, {}, [], '<html><body><p>Take the coding challenge today</p></body></html>'), null);
  });

  it('returns null for a plain block with no provider markers', () => {
    assert.equal(identifyProtection(403, { server: 'nginx' }, [], '<html><body><h1>403 Forbidden</h1></body></html>'), null);
  });

  it('caps confidence below absolute certainty', () => {
    const p = identifyProtection(
      403,
      { server: 'cloudflare', 'cf-ray': 'x', 'cf-mitigated': 'challenge' },
      ['__cf_bm', 'cf_clearance'],
      CF_CHALLENGE_HTML
    );
    assert.ok(p);
    assert.ok(p.confidence <= 0.98, `confidence ${p.confidence} must never claim 100%`);
  });
});

// ----------------------------------------------------------------
// 3. Challenge HTML never feeds technology detection
// ----------------------------------------------------------------

describe('header-only detection on blocked responses', () => {
  // What the pipeline now runs: empty HTML + real headers/cookies.
  const headerOnly = (headers: Record<string, string>, cookies: string[] = []) =>
    applyConfidenceModel(runSignatureEngine({ html: '', headers, cookies }));

  it('challenge-page scripts are NOT reported as site technologies', () => {
    const found = headerOnly({ 'content-type': 'text/html', server: 'cloudflare', 'cf-ray': 'x' }, []);
    const ids = found.map((r) => r.id);
    for (const banned of ['youtube-embed', 'recaptcha', 'google-tag-manager', 'wordpress']) {
      const hit = found.find((r) => r.id === banned);
      assert.ok(!hit || (hit.score ?? 0) < 40, `"${banned}" must not surface from challenge HTML`);
    }
    assert.ok(!ids.includes('youtube-embed'), 'challenge YouTube script is invisible with empty HTML');
  });

  it('header-level evidence is still analyzed', () => {
    const found = headerOnly({ server: 'cloudflare', 'cf-ray': 'x' }, []);
    assert.ok(found.some((r) => r.id === 'cloudflare'), 'Cloudflare hosting hint survives via headers');
  });

  it('full-context scan of the same page WOULD have been fooled (guard proof)', () => {
    // Sanity: with the challenge HTML present, the engine fires — which
    // is exactly why the pipeline must blank it first.
    const full = runSignatureEngine({ html: CF_CHALLENGE_HTML, headers: {}, cookies: [] });
    assert.ok(full.some((r) => r.id === 'youtube-embed'), 'challenge HTML contains detectable scripts');
  });
});

// ----------------------------------------------------------------
// 4. Payload shape
// ----------------------------------------------------------------

describe('bot_protected payload', () => {
  it('builds the documented shape', () => {
    const info = buildBotProtection(
      403,
      { server: 'cloudflare', 'cf-ray': 'abc', 'set-cookie': '__cf_bm=x', 'x-powered-by': 'PHP/8.1' },
      ['__cf_bm'],
      CF_CHALLENGE_HTML
    );
    assert.equal(info.status, 'bot_protected');
    assert.equal(info.httpStatus, 403);
    assert.ok(info.provider && info.provider.name === 'Cloudflare');
    assert.ok(Array.isArray(info.limitations) && info.limitations.length >= 1);
    assert.ok(info.responseHeaders['server'] === 'cloudflare');
    assert.ok(info.responseHeaders['cf-ray'] === 'abc');
    assert.ok(!('set-cookie' in info.responseHeaders), 'cookies are not echoed in headers');
    assert.ok(!('x-powered-by' in info.responseHeaders), 'only relevant headers preserved');
  });

  it('keeps provider null when evidence is insufficient', () => {
    const info = buildBotProtection(403, { server: 'nginx' }, [], '<html>Forbidden</html>');
    assert.equal(info.status, 'bot_protected');
    assert.equal(info.provider, null);
  });

  it('pickRelevantHeaders is case-insensitive and capped', () => {
    const out = pickRelevantHeaders({ Server: 'cloudflare', 'CF-RAY': 'x'.repeat(500), 'X-Custom': '1' });
    assert.equal(out['server'], 'cloudflare');
    assert.ok((out['cf-ray'] ?? '').length <= 200);
    assert.ok(!('x-custom' in out));
  });
});
