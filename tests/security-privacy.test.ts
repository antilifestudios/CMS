/**
 * Security & privacy detector tests (CMS Detector AI).
 *
 * Evidence-based regression suite for /security-privacy-detector:
 * - Privacy CMP true positives (Didomi, Osano, CookieYes, Termly, Quantcast)
 * - Security true positives (Turnstile, Fingerprint, Datadog, New Relic,
 *   Bugsnag, Rollbar, expanded Sentry / reCAPTCHA)
 * - Expanded "other" techs (Maps embed, YouTube/Vimeo players, FA kit)
 * - False positives: prose mentions, watch links, placeholder sitekeys
 * - Resource-URL channel: img/link/iframe src scanned, not just <script>
 *
 * Fixture-based, no network. Run with: npm test (node --test, no deps).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runSignatureEngine, type MatchContext } from '../src/lib/detect/signatures.ts';
import { applyConfidenceModel, explainDetection } from '../src/lib/detect/confidence.ts';

const ctx = (html: string, headers: Record<string, string> = {}, cookies: string[] = []): MatchContext => ({ html, headers, cookies });
const hit = (id: string, c: MatchContext) => {
  const all = applyConfidenceModel(runSignatureEngine(c));
  const h = all.find((r) => r.id === id);
  assert.ok(h, `expected "${id}" detected, got [${all.map((r) => r.id).join(',')}]`);
  return h;
};
const miss = (id: string, c: MatchContext) => {
  const all = applyConfidenceModel(runSignatureEngine(c));
  const h = all.find((r) => r.id === id);
  assert.ok(!h || (h.score ?? 0) < 40, `expected "${id}" NOT detected (score ${h?.score})`);
};

describe('new privacy CMPs', () => {
  it('Didomi SDK + token cookie', () => {
    const h = hit('didomi', ctx(`<script src="https://sdk.didomi.io/didomi-loader/abc.js"></script><script>Didomi.notice.show();</script>`, {}, ['didomi_token']));
    assert.ok((h.families ?? 0) >= 2);
  });
  it('Osano SDK + uuid cookie', () => {
    hit('osano', ctx(`<script src="https://cmp.osano.com/dist/osano.js?customerId=abc"></script>`, {}, ['osano_consentmanager_uuid']));
  });
  it('CookieYes client_data + cky cookie', () => {
    hit('cookieyes', ctx(`<script src="https://cdn-cookieyes.com/client_data/abc/script.js"></script>`, {}, ['cky-consent']));
  });
  it('Termly blocker', () => {
    hit('termly', ctx(`<script src="https://app.termly.io/resource-blocker/abc.min.js"></script>`));
  });
  it('Quantcast choice SDK', () => {
    hit('quantcast-choice', ctx(`<script src="https://cmp.quantcast.com/choice/abc/__tcf.js"></script><script>__tcfapi('addEventListener',2,function(){});</script>`));
  });
});

describe('new security techs', () => {
  it('Turnstile api.js + widget', () => {
    hit('cloudflare-turnstile', ctx(`<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script><div class="cf-turnstile" data-sitekey="0x4AAAAAAAabc123"></div>`));
  });
  it('FingerprintJS', () => {
    hit('fingerprint', ctx(`<script src="https://cdn.fingerprintjs.com/fp.min.js"></script><script>FingerprintJS.load().then();</script>`));
  });
  it('Datadog RUM', () => {
    hit('datadog', ctx(`<script src="https://browser-intake-datadoghq.com/sdk/datadog-rum.js"></script><script>DD_RUM.init({});</script>`));
  });
  it('New Relic', () => {
    hit('new-relic', ctx(`<script src="https://js-agent.newrelic.com/nr-spa-123.min.js"></script><script>NREUM.init();</script>`));
  });
  it('Bugsnag', () => {
    hit('bugsnag', ctx(`<script src="https://d2wy8f7a9ursnm.cloudfront.net/v7/bugsnag.min.js"></script><script>Bugsnag.start({apiKey:'x'});</script>`));
  });
  it('Rollbar', () => {
    hit('rollbar', ctx(`<script src="https://cdn.rollbar.com/rollbarjs/refs/head/master/rollbar.min.js"></script><script>_rollbarConfig={accessToken:'x'};</script>`));
  });
  it('Sentry ingest envelope + init', () => {
    const h = hit('sentry', ctx(`<script src="https://browser.sentry-cdn.com/7.0.0/bundle.min.js"></script><script>Sentry.init({dsn:'https://abc@o1.ingest.sentry.io/1'});</script>`));
    const ex = explainDetection(h.evidence);
    assert.ok(ex.score >= 40);
  });
  it('reCAPTCHA via recaptcha.net + _GRECAPTCHA cookie', () => {
    hit('recaptcha', ctx(`<script src="https://www.recaptcha.net/recaptcha/api.js?render=abc123XYZ456"></script>`, {}, ['_GRECAPTCHA']));
  });
});

describe('expanded other techs', () => {
  it('Maps iframe embed', () => {
    hit('google-maps', ctx(`<iframe src="https://www.google.com/maps/embed?pb=!1m18!abc"></iframe>`));
  });
  it('Maps enterprise client param in JSON config', () => {
    hit('google-maps', ctx(`<script>var cfg={"googleMapsUrl":"https://maps.googleapis.com/maps/api/js?v=3&client=gme-example&libraries=places"};</script>`));
  });
  it('YouTube player API', () => {
    hit('youtube-embed', ctx(`<script src="https://www.youtube.com/iframe_api"></script><script>new YT.Player('p');</script>`));
  });
  it('Vimeo new Player', () => {
    hit('vimeo-embed', ctx(`<iframe src="https://player.vimeo.com/video/123456"></iframe><script>new Vimeo.Player('v');</script>`));
  });
  it('Font Awesome kit + icon class', () => {
    hit('font-awesome', ctx(`<script src="https://kit.fontawesome.com/abc.js"></script><i class="fa-solid fa-user"></i>`));
  });
});

describe('false positives still blocked', () => {
  it('marketing CSS mentioning CookieDeclaration is NOT usage', () => {
    miss('cookiebot', ctx(`<html><head><style>#CookieDeclarationContainer a{color:#0063ab}.cb-anchor-scroll{color:red}</style></head><body><p>Cookiebot CMP by Usercentrics for GDPR compliance. Try Cookiebot free.</p></body></html>`));
  });
  it('docs <code> snippets quoting SDKs are NOT usage', () => {
    miss('sentry', ctx(`<html><body><article><p>Install Sentry:</p><pre><code>import * as Sentry from '@sentry/browser'; Sentry.init({ dsn: '___' });</code></pre></article></body></html>`));
    miss('didomi', ctx(`<html><body><pre><code>&lt;script src="https://sdk.didomi.io/didomi-loader/x.js"&gt;&lt;/script&gt;</code></pre></body></html>`));
  });
  it('bare cookie-doc text (OptanonConsent) is NOT usage', () => {
    miss('onetrust', ctx(`<html><body><article><p>The OptanonConsent cookie stores consent. OneTrust alternatives include Cookiebot.</p></article></body></html>`));
  });
  it('prose comparing vendors does NOT detect usage', () => {
    const c = ctx(`<html><body><article><p>We compare Sentry vs Rollbar vs Bugsnag for error tracking, and Didomi vs Osano for consent. Turnstile and Fingerprint are bot options.</p></article></body></html>`);
    for (const id of ['sentry', 'rollbar', 'bugsnag', 'didomi', 'osano', 'cloudflare-turnstile', 'fingerprint', 'datadog', 'new-relic']) miss(id, c);
  });
  it('youtube watch link is NOT an embed', () => {
    miss('youtube-embed', ctx(`<html><body><a href="https://www.youtube.com/watch?v=dQw4w9WgXcQ">watch this</a><p>youtube is great</p></body></html>`));
  });
  it('generic google link is NOT Maps', () => {
    miss('google-maps', ctx(`<html><body><a href="https://www.google.com/search?q=x">google</a><script src="https://www.google.com/js/g.js"></script></body></html>`));
  });
  it('placeholder recaptcha sitekey is vetoed', () => {
    miss('recaptcha', ctx(`<script src="https://www.google.com/recaptcha/api.js"></script><div class="g-recaptcha" data-sitekey="YOUR_SITE_KEY"></div>`));
  });
  it('resource URLs beyond <script> are scanned (img/link/iframe)', () => {
    // No <script> at all — Cloudinary <img> must fire the resource-URL channel
    const h = hit('cloudinary', ctx(`<html><body><img src="https://res.cloudinary.com/demo/image/upload/sample.jpg"></body></html>`));
    assert.ok(h.evidence.some((e) => e.artifact.startsWith('img')), `expected img evidence, got ${JSON.stringify(h.evidence.map((e) => e.artifact))}`);
    // nocookie embed fires with zero scripts
    hit('youtube-embed', ctx(`<html><body><iframe src="https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ"></iframe></body></html>`));
  });
});
