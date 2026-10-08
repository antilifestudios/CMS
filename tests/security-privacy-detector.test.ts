/**
 * Security & Privacy detector tests (v1: 26 technologies).
 *
 * Fixture-based, no network. Run with: npm test (node --test, no deps).
 *
 * Per technology: one positive fixture, one negative (empty page),
 * one near-miss (looks related but must NOT detect).
 * Plus: scoring-model unit tests, Quantcast __tcfapi guard, Turnstile /
 * generic-Cloudflare guard, bundled-JS detection, category grouping.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  detectSecurityPrivacy,
  groupByCategory,
  type SecurityPrivacyInput,
} from '../src/lib/detect/security-privacy.ts';
import { SECURITY_PRIVACY_SIGNATURES } from '../src/data/security-privacy-signatures.ts';

const inp = (html: string, extra: Partial<SecurityPrivacyInput> = {}): SecurityPrivacyInput => ({
  html,
  ...extra,
});

function hit(id: string, input: SecurityPrivacyInput) {
  const all = detectSecurityPrivacy(input);
  const h = all.find((r) => r.id === id);
  assert.ok(h, `expected "${id}" detected, got [${all.map((r) => r.id).join(',')}]`);
  assert.ok(h.score >= 0.35, `score ${h.score} must clear the 0.35 floor`);
  assert.ok(Array.isArray(h.evidence) && h.evidence.length > 0, 'evidence array required');
  return h;
}

function miss(id: string, input: SecurityPrivacyInput) {
  const all = detectSecurityPrivacy(input);
  const h = all.find((r) => r.id === id);
  assert.ok(!h, `expected "${id}" NOT detected (score ${h?.score}, evidence ${JSON.stringify(h?.evidence)})`);
}

const EMPTY = inp('<html><head><title>Nothing here</title></head><body><p>Hello world</p></body></html>');

// ----------------------------------------------------------------
// Positive fixtures (one per technology)
// ----------------------------------------------------------------

const POSITIVES: Array<{ id: string; html: string; extra?: Partial<SecurityPrivacyInput> }> = [
  {
    id: 'onetrust',
    html: `<script src="https://cdn.cookielaw.org/consent/abc/otSDKStub.js"></script><script>function OptanonWrapper(){}</script><div id="onetrust-banner-sdk"></div>`,
    extra: { cookies: ['OptanonConsent'] },
  },
  {
    id: 'cookiebot',
    html: `<script src="https://consent.cookiebot.com/uc.js?cbid=abcdef12-3456-7890-abcd-ef1234567890"></script><script>Cookiebot.consent.necessary;</script><div id="CybotCookiebotDialog"></div>`,
    extra: { cookies: ['CookieConsent'] },
  },
  {
    id: 'usercentrics',
    html: `<script src="https://app.usercentrics.eu/browser-ui/latest/loader.js"></script><script>UC_UI.showSecondLayer();</script><div id="usercentrics-root"></div>`,
    extra: { cookies: ['uc_settings'] },
  },
  {
    id: 'trustarc',
    html: `<script src="https://consent.trustarc.com/notice?domain=example.com"></script><script>truste.eu;</script><div id="truste-consent-track"></div>`,
    extra: { cookies: ['notice_gdpr_prefs'] },
  },
  {
    id: 'iubenda',
    html: `<script src="https://cdn.iubenda.com/cs/iubenda_cs.js"></script><script>_iub.cs.consent;</script><div class="iubenda-cs-container"></div>`,
    extra: { cookies: ['_iub_cs-123456'] },
  },
  {
    id: 'complianz',
    html: `<script src="https://example.com/wp-content/plugins/complianz-gdpr/assets/js/complianz.min.js"></script><script>cmplz_set_cookie();</script><div id="cmplz-cookiebanner-container"></div>`,
    extra: { cookies: ['cmplz_choice'] },
  },
  {
    id: 'didomi',
    html: `<script src="https://sdk.privacy-center.org/abc.js"></script><script>Didomi.notice.show();</script><div id="didomi-host"></div>`,
    extra: { cookies: ['didomi_token'] },
  },
  {
    id: 'osano',
    html: `<script src="https://cmp.osano.com/dist/osano.js?customerId=abc"></script><script>Osano.cm.showDrawer();</script><div class="osano-cm-window"></div>`,
    extra: { cookies: ['osano_consentmanager'] },
  },
  {
    id: 'cookieyes',
    html: `<script src="https://cdn-cookieyes.com/client_data/abc/script.js"></script><script>getCkyConsent();</script><div class="cky-consent-container"></div>`,
    extra: { cookies: ['cookieyes-consent'] },
  },
  {
    id: 'termly',
    html: `<script src="https://app.termly.io/resource-blocker/abc.min.js"></script><script>Termly.getConsentState();</script><div id="termly-code-snippet-support"></div>`,
  },
  {
    id: 'quantcast-choice',
    html: `<script src="https://cmp.quantcast.com/choice/abc/__tcf.js"></script><div class="qc-cmp2-container"></div>`,
  },
  {
    id: 'recaptcha',
    html: `<script src="https://www.google.com/recaptcha/api.js?render=6AbcDEFghiJKLmnoP"></script><script>grecaptcha.execute("6AbcDEFghiJKLmnoP");</script><div class="g-recaptcha" data-sitekey="6AbcDEFghiJKLmnoP"></div>`,
  },
  {
    id: 'hcaptcha',
    html: `<script src="https://js.hcaptcha.com/1/api.js"></script><script>hcaptcha.execute();</script><div class="h-captcha" data-sitekey="abc123def456"></div>`,
  },
  {
    id: 'sentry',
    html: `<script src="https://browser.sentry-cdn.com/7.0.0/bundle.min.js"></script><script>Sentry.init({dsn:"https://abc@o1.ingest.sentry.io/1"});</script>`,
  },
  {
    id: 'cloudflare-turnstile',
    html: `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script><script>turnstile.render("#t");</script><div class="cf-turnstile" data-sitekey="0x4AAAAAAAabc123def456"></div>`,
  },
  {
    id: 'fingerprint',
    html: `<script src="https://fpjs.io/v3/abc"></script><script>FingerprintJS.load().then();</script>`,
  },
  {
    id: 'datadog',
    html: `<script src="https://browser-intake-datadoghq.com/sdk/datadog-rum.js"></script><script>DD_RUM.init({});</script>`,
    extra: { cookies: ['_dd_s'] },
  },
  {
    id: 'new-relic',
    html: `<script src="https://js-agent.newrelic.com/nr-spa-123.min.js"></script><script>newrelic.addPageAction("x");</script>`,
  },
  {
    id: 'bugsnag',
    html: `<script src="https://d2wy8f7a9ursnm.cloudfront.net/v7/bugsnag.min.js"></script><script>Bugsnag.start({apiKey:"x"});</script>`,
  },
  {
    id: 'rollbar',
    html: `<script src="https://cdn.rollbar.com/rollbarjs/refs/head/master/rollbar.min.js"></script><script>_rollbarConfig={accessToken:"x"};</script>`,
  },
  {
    id: 'cloudinary',
    html: `<html><body><img src="https://res.cloudinary.com/demo/image/upload/sample.jpg"></body></html>`,
  },
  {
    id: 'algolia',
    html: `<script src="https://cdn.jsdelivr.net/npm/algoliasearch@4/dist/algoliasearch.min.js"></script><script>algoliasearch("APP","KEY");</script>`,
  },
  {
    id: 'google-maps',
    html: `<script src="https://maps.googleapis.com/maps/api/js?key=AIzaFakeKey123"></script><script>new google.maps.Map(document.getElementById("m"));</script>`,
  },
  {
    id: 'youtube',
    html: `<html><body><iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ"></iframe></body></html>`,
  },
  {
    id: 'vimeo',
    html: `<html><body><iframe src="https://player.vimeo.com/video/123456"></iframe></body></html>`,
  },
  {
    id: 'font-awesome',
    html: `<script src="https://kit.fontawesome.com/abc.js"></script><i class="fa-solid fa-user"></i>`,
  },
];

describe('positives — every technology detected with evidence', () => {
  for (const p of POSITIVES) {
    it(`${p.id}: positive fixture`, () => {
      hit(p.id, inp(p.html, p.extra ?? {}));
    });
  }
  it('covers exactly the 26 supported technologies', () => {
    assert.equal(SECURITY_PRIVACY_SIGNATURES.length, 26);
    assert.equal(POSITIVES.length, 26);
    assert.deepEqual(
      new Set(POSITIVES.map((p) => p.id)),
      new Set(SECURITY_PRIVACY_SIGNATURES.map((s) => s.id)),
    );
  });
});

describe('negatives — empty page detects nothing', () => {
  it('empty page yields zero technologies (honest empty state)', () => {
    assert.deepEqual(detectSecurityPrivacy(EMPTY), []);
  });
  it('categories still render with zero counts', () => {
    const groups = groupByCategory(detectSecurityPrivacy(EMPTY));
    assert.equal(groups.length, 3);
    assert.ok(groups.every((g) => g.count === 0 && g.technologies.length === 0));
  });
});

// ----------------------------------------------------------------
// Near-miss fixtures (must NOT detect)
// ----------------------------------------------------------------

describe('near-miss — lookalikes that must NOT detect', () => {
  it('onetrust: prose + vendor link are not integration', () => {
    miss('onetrust', inp(`<html><body><article><p>OneTrust alternatives and the OptanonConsent cookie explained.</p><a href="https://www.onetrust.com/products/">OneTrust</a></article></body></html>`));
  });
  it('cookiebot: marketing CSS + prose are not usage', () => {
    miss('cookiebot', inp(`<html><head><style>#CookieDeclarationContainer a{color:#0063ab}</style></head><body><p>Cookiebot CMP by Usercentrics for GDPR compliance.</p></body></html>`));
  });
  it('usercentrics: prose mention is not usage', () => {
    miss('usercentrics', inp(`<html><body><p>We compare Usercentrics vs Didomi for consent.</p></body></html>`));
  });
  it('didomi/osano: docs <code> snippets are not usage', () => {
    miss('didomi', inp(`<html><body><pre><code>&lt;script src="https://sdk.didomi.io/didomi-loader/x.js"&gt;&lt;/script&gt;</code></pre></body></html>`));
    miss('osano', inp(`<html><body><pre><code>Osano.cm.showDrawer(); // docs example</code></pre></body></html>`));
  });
  it('sentry: docs code sample is not usage', () => {
    miss('sentry', inp(`<html><body><article><pre><code>import * as Sentry from '@sentry/browser'; Sentry.init({ dsn: '___' });</code></pre></article></body></html>`));
  });
  it('youtube: watch link is NOT an embed', () => {
    miss('youtube', inp(`<html><body><a href="https://www.youtube.com/watch?v=dQw4w9WgXcQ">watch this</a><p>youtube is great</p></body></html>`));
  });
  it('youtube: nocookie embed IS detected', () => {
    hit('youtube', inp(`<html><body><iframe src="https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ"></iframe></body></html>`));
  });
  it('google-maps: generic google link is NOT Maps', () => {
    miss('google-maps', inp(`<html><body><a href="https://www.google.com/search?q=x">google</a><script src="https://www.google.com/js/g.js"></script></body></html>`));
  });
  it('google-maps: embed iframe IS detected', () => {
    hit('google-maps', inp(`<iframe src="https://www.google.com/maps/embed?pb=!1m18!abc"></iframe>`));
  });
  it('vimeo: vimeo.com link is NOT an embed', () => {
    miss('vimeo', inp(`<html><body><a href="https://vimeo.com/123456">watch on vimeo</a></body></html>`));
  });
  it('font-awesome: lone generic "fa" class is NOT enough', () => {
    miss('font-awesome', inp(`<html><body><i class="fa fa-user"></i></body></html>`));
  });
  it('recaptcha: placeholder sitekey is vetoed', () => {
    miss('recaptcha', inp(`<script src="https://www.google.com/recaptcha/api.js"></script><div class="g-recaptcha" data-sitekey="YOUR_SITE_KEY"></div>`));
  });
  it('cloudinary: cloudinary.com marketing link is NOT usage', () => {
    miss('cloudinary', inp(`<html><body><a href="https://cloudinary.com/pricing">Cloudinary pricing</a></body></html>`));
  });
  it('algolia: prose mention is NOT usage', () => {
    miss('algolia', inp(`<html><body><p>We migrated from Algolia to Elasticsearch.</p></body></html>`));
  });
});

describe('targeted false-positive guards', () => {
  it('Quantcast is NOT reported from __tcfapi alone', () => {
    miss('quantcast-choice', inp(`<script>__tcfapi('addEventListener',2,function(){});</script>`));
    miss('quantcast-choice', inp(`<html></html>`, { cookies: ['euconsent-v2'] }));
  });
  it('Quantcast IS reported with its SDK host', () => {
    hit('quantcast-choice', inp(`<script src="https://cmp.quantcast.com/choice/abc/__tcf.js"></script><script>__tcfapi('addEventListener',2,function(){});</script>`));
  });
  it('Turnstile is NOT reported for generic Cloudflare sites', () => {
    miss(
      'cloudflare-turnstile',
      inp(
        `<script src="https://cdnjs.cloudflare.com/ajax/libs/alpinejs/3.0.0/cdn.min.js"></script><script src="/cdn-cgi/challenge-platform/h/b/scripts/invisible.js"></script>`,
        { headers: { 'cf-ray': 'abc123', server: 'cloudflare' }, cookies: ['cf_clearance'] },
      ),
    );
  });
  it('Turnstile IS reported with its exact SDK path', () => {
    hit('cloudflare-turnstile', inp(`<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script><div class="cf-turnstile" data-sitekey="0x4AAAAAAAabc123def456ghi789"></div>`));
  });
});

describe('scoring model', () => {
  it('noisy-OR over distinct types: host (0.9) + dom (0.65) = 0.97', () => {
    const h = hit(
      'recaptcha',
      inp(`<script src="https://www.google.com/recaptcha/api.js"></script><div class="g-recaptcha" data-sitekey="6AbcDEFghiJKLmnoPqrSTUvwx"></div>`),
    );
    assert.equal(h.score, 0.97);
    assert.equal(h.confidence, 'high');
  });
  it('each evidence TYPE counts once (repeated matches do not inflate)', () => {
    const once = detectSecurityPrivacy(
      inp(`<script src="https://fpjs.io/v3/a"></script><script>FingerprintJS.load();</script>`),
    ).find((r) => r.id === 'fingerprint')!;
    const repeated = detectSecurityPrivacy(
      inp(`<script src="https://fpjs.io/v3/a"></script><script src="https://fpjs.io/v3/b"></script><script src="https://fpjs.io/v3/c"></script><script>FingerprintJS.load();FingerprintJS.load();</script>`),
    ).find((r) => r.id === 'fingerprint')!;
    assert.equal(repeated.score, once.score);
  });
  it('High requires strong evidence (dom + cookie alone never reach High)', () => {
    const h = hit(
      'cookieyes',
      inp(`<div class="cky-consent-container"></div>`, { cookies: ['cookieyes-consent'] }),
    );
    assert.ok(h.score <= 0.84, `weak-only score ${h.score} must be capped below High`);
    assert.notEqual(h.confidence, 'high');
  });
  it('below 0.35 is never reported', () => {
    // A lone weak TCF hint (0.2) must not surface.
    miss('quantcast-choice', inp(`<script>var x = "__tcfapi";</script>`));
  });
  it('CSP-only vendor mention caps at Low', () => {
    const h = detectSecurityPrivacy(
      inp(`<html><head></head><body><p>hi</p></body></html>`, {
        headers: { 'content-security-policy': "script-src 'self' https://cdn.cookielaw.org" },
      }),
    ).find((r) => r.id === 'onetrust');
    assert.ok(!h || h.score <= 0.59, `CSP-only mention must cap at Low (got ${h?.score})`);
  });
});

describe('bundled SDK detection (Pass 1b)', () => {
  it('Sentry init inside a first-party bundle is detected', () => {
    const h = hit(
      'sentry',
      inp(`<script src="https://example.com/assets/app.abc123.js"></script>`, {
        bundleJs: [`!function(){Sentry.init({dsn:"https://abc@o1.ingest.sentry.io/1"});}();`],
      }),
    );
    assert.ok(h.evidence.some((e) => e.type === 'sdk-init'));
  });
  it('Datadog init inside a first-party bundle is detected', () => {
    hit(
      'datadog',
      inp(`<script src="https://example.com/main.js"></script>`, {
        bundleJs: [`DD_RUM.init({applicationId:"x"});`],
      }),
    );
  });
});

describe('output grouping', () => {
  it('groups into privacy / security / other with counts', () => {
    const all = detectSecurityPrivacy(
      inp(
        `<script src="https://cdn.cookielaw.org/consent/a/otSDKStub.js"></script><script src="https://browser.sentry-cdn.com/7.0.0/bundle.min.js"></script><iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ"></iframe>`,
      ),
    );
    const groups = groupByCategory(all);
    assert.deepEqual(groups.map((g) => g.id), ['privacy', 'security', 'other']);
    assert.equal(groups[0].technologies[0].id, 'onetrust');
    assert.equal(groups[1].technologies[0].id, 'sentry');
    assert.equal(groups[2].technologies[0].id, 'youtube');
    for (const g of groups) assert.equal(g.count, g.technologies.length);
  });
  it('every result carries typed evidence with details', () => {
    for (const p of POSITIVES) {
      const h = hit(p.id, inp(p.html, p.extra ?? {}));
      for (const e of h.evidence) {
        assert.ok(typeof e.type === 'string' && e.type.length > 0);
        assert.ok(typeof e.detail === 'string' && e.detail.length > 0);
      }
    }
  });
});
