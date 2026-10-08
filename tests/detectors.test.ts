/**
 * Detector expansion tests (CMS Detector AI).
 *
 * Covers the website-intelligence detectors without network access:
 * - Growth & marketing true positives (analytics, ads, payments, chat)
 * - Security & privacy true positives (consent, security, other)
 * - False positives: brand mentions in prose must NOT detect usage
 * - Evidence families: duplicated signals in one family don't inflate
 * - Confidence model: deterministic 0–100 scores, labels, thresholds
 * - Conflict handling: strong WordPress vs weak Shopify
 * - Coverage penalty for multi-page evidence
 * - SSRF guards unchanged, theme catalog annotation
 *
 * Fixture-based, no network. Run with: npm test (node --test, no deps).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  runSignatureEngine,
  type MatchContext,
} from '../src/lib/detect/signatures.ts';
import {
  applyConfidenceModel,
  passesThreshold,
  scoreDetection,
  scoreForCoverage,
  scoreToLabel5,
  MIN_DISPLAY_SCORE,
  MIN_PRIMARY_SCORE,
} from '../src/lib/detect/confidence.ts';
import { validateUrl, validateRedirect } from '../src/lib/detect/ssrf.ts';
import { isKnownShopifyTheme, isKnownWpTheme } from '../src/data/themes.ts';

// ----------------------------------------------------------------
// Fixture builders
// ----------------------------------------------------------------

function ctx(
  html: string,
  headers: Record<string, string> = {},
  cookies: string[] = []
): MatchContext {
  return { html, headers, cookies };
}

function scored(id: string, c: MatchContext) {
  const all = applyConfidenceModel(runSignatureEngine(c));
  const hit = all.find((r) => r.id === id);
  assert.ok(hit, `expected "${id}" to be detected`);
  return hit;
}

function ids(c: MatchContext): string[] {
  return runSignatureEngine(c).map((r) => r.id);
}

// ----------------------------------------------------------------
// 1. Growth & marketing true positives
// ----------------------------------------------------------------

describe('growth & marketing detection', () => {
  it('detects Google Analytics from gtag SDK + config call', () => {
    const html = `
      <script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123DEF"></script>
      <script>gtag('config', 'G-ABC123DEF');</script>`;
    const hit = scored('google-analytics', ctx(html));
    assert.ok((hit.score ?? 0) >= 40, `score ${hit.score} should clear display threshold`);
    assert.ok((hit.families ?? 0) >= 2, 'script + html corroboration');
  });

  it('detects Google Tag Manager from gtm.js + noscript', () => {
    const html = `
      <script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC123"></script>
      <noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-ABC123"></iframe></noscript>`;
    scored('google-tag-manager', ctx(html));
  });

  it('detects Meta Pixel from fbevents SDK + init call', () => {
    const html = `
      <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
      <script>fbq('init', '123456789012345'); fbq('track', 'PageView');</script>`;
    const hit = scored('meta-pixel', ctx(html));
    assert.ok((hit.score ?? 0) >= 40, `score ${hit.score} should clear display threshold`);
  });

  it('detects Stripe from the Stripe.js SDK', () => {
    const html = `<script src="https://js.stripe.com/v3/"></script>
      <script>var stripe = window.Stripe('pk_live_123');</script>`;
    const hit = scored('stripe', ctx(html));
    assert.ok((hit.score ?? 0) >= 40, `score ${hit.score} should clear display threshold`);
  });

  it('detects Intercom from the widget SDK', () => {
    const html = `
      <script>window.intercomSettings = { app_id: "abc123" };</script>
      <script src="https://widget.intercom.io/widget/abc123"></script>`;
    scored('intercom', ctx(html));
  });

  it('detects Klaviyo from onsite SDK with company id', () => {
    const html = `<script src="https://static.klaviyo.com/onsite/js/klaviyo.js?company_id=ABC123"></script>`;
    scored('klaviyo', ctx(html));
  });

  it('detects PayPal from the checkout SDK', () => {
    const html = `<script src="https://www.paypal.com/sdk/js?client-id=abc123&currency=USD"></script>
      <script>paypal.Buttons.render('#paypal-button');</script>`;
    scored('paypal', ctx(html));
  });
});

// ----------------------------------------------------------------
// 2. Security & privacy true positives
// ----------------------------------------------------------------

describe('security & privacy detection', () => {
  it('detects OneTrust from the consent SDK + cookie', () => {
    const html = `<script src="https://cdn.cookielaw.org/consent/abc123/otSDKStub.js"></script>`;
    const hit = scored('onetrust', ctx(html, {}, ['OptanonConsent']));
    assert.ok((hit.families ?? 0) >= 2, 'script + cookie corroboration');
  });

  it('detects Cookiebot from uc.js with cbid', () => {
    const html = `<script src="https://consent.cookiebot.com/uc.js?cbid=abcdef12-3456-7890-abcd-ef1234567890"></script>`;
    scored('cookiebot', ctx(html));
  });

  it('detects reCAPTCHA from api.js with render key', () => {
    const html = `<script src="https://www.google.com/recaptcha/api.js?render=6AbcDEF123"></script>
      <div class="g-recaptcha" data-sitekey="6AbcDEF123"></div>`;
    scored('recaptcha', ctx(html));
  });

  it('detects Google Maps from the maps API SDK', () => {
    const html = `<script src="https://maps.googleapis.com/maps/api/js?key=AIzaFakeKey123&callback=init"></script>
      <script>new google.maps.Map(document.getElementById('map'));</script>`;
    scored('google-maps', ctx(html));
  });

  it('detects Font Awesome from a stylesheet link', () => {
    const html = `<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">`;
    const hit = scored('font-awesome', ctx(html));
    assert.ok(
      hit.evidence.some((e) => e.type === 'stylesheet-url'),
      'stylesheet-url evidence type should fire'
    );
  });

  it('detects a YouTube embed from the iframe URL', () => {
    const html = `<iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ" allowfullscreen></iframe>`;
    scored('youtube-embed', ctx(html));
  });
});

// ----------------------------------------------------------------
// 3. False positives: prose mentions are NOT usage
// ----------------------------------------------------------------

describe('false-positive protection', () => {
  const prose = ctx(`
    <html><head><title>Stripe vs PayPal for your Shopify store</title></head>
    <body><article>
      <p>Stripe and PayPal are popular. This Shopify vs WordPress comparison
      mentions React, Google Analytics pricing, and OneTrust alternatives.</p>
    </article></body></html>`);

  it('does not detect Stripe from a prose mention', () => {
    assert.ok(!ids(prose).includes('stripe'), 'bare "Stripe" text must not detect');
  });

  it('does not detect PayPal from a prose mention', () => {
    assert.ok(!ids(prose).includes('paypal'), 'bare "PayPal" text must not detect');
  });

  it('does not detect Shopify from a prose mention', () => {
    assert.ok(!ids(prose).includes('shopify'), 'bare "Shopify" text must not detect');
  });

  it('does not detect WordPress from a prose mention', () => {
    assert.ok(!ids(prose).includes('wordpress'), 'bare "WordPress" text must not detect');
  });

  it('does not detect Google Analytics from a prose mention', () => {
    assert.ok(!ids(prose).includes('google-analytics'), 'bare "Google Analytics" text must not detect');
  });

  it('does not detect OneTrust from a prose mention', () => {
    assert.ok(!ids(prose).includes('onetrust'), 'bare "OneTrust" text must not detect');
  });

  it('a lone _ga cookie is INSUFFICIENT, never a confident finding', () => {
    const all = applyConfidenceModel(runSignatureEngine(ctx('<html></html>', {}, ['_ga'])));
    const hit = all.find((r) => r.id === 'google-analytics');
    assert.ok(hit, 'weak cookie evidence may still surface as a candidate');
    assert.ok((hit.score ?? 100) < MIN_DISPLAY_SCORE, `cookie-only score ${hit.score} must stay below ${MIN_DISPLAY_SCORE}`);
    assert.equal(hit.scoreLabel, 'INSUFFICIENT');
    assert.equal(passesThreshold(hit), false);
  });
});

// ----------------------------------------------------------------
// 4. Evidence families & confidence model
// ----------------------------------------------------------------

describe('confidence model', () => {
  it('labels follow the 90/75/60/40 bands', () => {
    assert.equal(scoreToLabel5(100), 'VERY HIGH');
    assert.equal(scoreToLabel5(90), 'VERY HIGH');
    assert.equal(scoreToLabel5(89), 'HIGH');
    assert.equal(scoreToLabel5(75), 'HIGH');
    assert.equal(scoreToLabel5(74), 'MEDIUM');
    assert.equal(scoreToLabel5(60), 'MEDIUM');
    assert.equal(scoreToLabel5(59), 'LOW');
    assert.equal(scoreToLabel5(40), 'LOW');
    assert.equal(scoreToLabel5(39), 'INSUFFICIENT');
    assert.equal(scoreToLabel5(0), 'INSUFFICIENT');
  });

  it('one definitive signal scores VERY HIGH', () => {
    const { score, families } = scoreDetection([
      { type: 'header', artifact: 'x', weight: 95, name: 'cf-ray', value: 'v', strength: 'definitive', family: 'NETWORK', specificity: 1 },
    ]);
    // Evidence-weighted: a single 95-weight definitive signal scores 95 —
    // one very strong signature is enough for VERY HIGH, with no need for
    // corroborating families.
    assert.ok(score >= 90, `single definitive signal must reach VERY HIGH, got ${score}`);
    assert.equal(families, 1);
    assert.equal(scoreToLabel5(score), 'VERY HIGH');
  });

  it('does not reward duplicated signals inside one family', () => {
    const mk = (name: string) => ({
      type: 'script-host', artifact: name, weight: 80, name, value: name,
      strength: 'strong', family: 'SCRIPT', specificity: 0.7,
    });
    const single = scoreDetection([mk('a') as never]);
    const triple = scoreDetection([mk('a') as never, mk('b') as never, mk('c') as never]);
    assert.equal(triple.score, single.score, 'same-CDN echoes must not inflate the score');
    assert.equal(triple.families, 1);
  });

  it('rewards independent corroboration across families', () => {
    const fam = (family: 'SCRIPT' | 'HTML' | 'META') => ({
      type: 'html-regex', artifact: 'x', weight: 80, name: family, value: 'x',
      strength: 'strong', family, specificity: 0.7,
    });
    const one = scoreDetection([fam('SCRIPT') as never]).score;
    const two = scoreDetection([fam('SCRIPT') as never, fam('HTML') as never]).score;
    const three = scoreDetection([fam('SCRIPT') as never, fam('HTML') as never, fam('META') as never]).score;
    assert.ok(two > one, `two families (${two}) must outscore one (${one})`);
    assert.ok(three > two, `three families (${three}) must outscore two (${two})`);
  });

  it('weak-only evidence stays INSUFFICIENT', () => {
    const { score } = scoreDetection([
      { type: 'cookie-name', artifact: 'x', weight: 40, name: '_ga', value: '_ga', strength: 'weak', family: 'COOKIE', specificity: 0.3 },
    ]);
    assert.ok(score < MIN_DISPLAY_SCORE, `weak-only score ${score} must stay below threshold`);
    assert.equal(scoreToLabel5(score), 'INSUFFICIENT');
  });

  it('coverage penalty: minority presence caps at INSUFFICIENT', () => {
    assert.ok(scoreForCoverage(95, 2, 15) <= 39, 'minority presence must cap');
    const partial = scoreForCoverage(90, 9, 15);
    assert.ok(partial < 90 && partial >= 40, `partial presence ${partial} is discounted but displayable`);
    assert.equal(scoreForCoverage(90, 15, 15), 90, 'full coverage is untouched');
  });

  it('primary platform findings need the conservative threshold', () => {
    assert.equal(MIN_PRIMARY_SCORE, 60);
    assert.equal(passesThreshold({ score: 59 } as never, true), false);
    assert.equal(passesThreshold({ score: 60 } as never, true), true);
    assert.equal(passesThreshold({ score: 40 } as never, false), true);
    assert.equal(passesThreshold({ score: 39 } as never, false), false);
  });
});

// ----------------------------------------------------------------
// 5. Conflict handling: strong WordPress vs weak Shopify
// ----------------------------------------------------------------

describe('conflict handling', () => {
  it('reports the strong platform and demotes the weak contradiction', () => {
    const c = ctx(`
      <html><head>
        <meta name="generator" content="WordPress 6.4.1">
        <link rel="stylesheet" href="/wp-content/themes/astra/style.css">
      </head><body>
        <p>We migrated off myshopify.com last year.</p>
      </body></html>`);
    const all = applyConfidenceModel(runSignatureEngine(c));
    const wp = all.find((r) => r.id === 'wordpress');
    const shop = all.find((r) => r.id === 'shopify');
    assert.ok(wp && (wp.score ?? 0) >= MIN_PRIMARY_SCORE, `WordPress should be confident (${wp?.score})`);
    if (shop) {
      assert.ok(
        (shop.score ?? 100) < MIN_DISPLAY_SCORE,
        `Shopify contradiction (${shop.score}) must fall below display threshold`
      );
      assert.ok(
        (shop.conflicting ?? []).includes('wordpress'),
        'demoted result records the winner'
      );
      assert.equal(passesThreshold(shop), false, 'demoted result is not displayable as confirmed');
    }
  });

  it('does not resolve contests when no candidate is confident', () => {
    const c = ctx(`<html><body><p>nothing distinctive here</p></body></html>`);
    const all = applyConfidenceModel(runSignatureEngine(c));
    assert.ok(all.every((r) => (r.conflicting ?? []).length === 0), 'no confident winner → no penalties');
  });
});

// ----------------------------------------------------------------
// 6. SSRF guards unchanged
// ----------------------------------------------------------------

describe('ssrf protection', () => {
  it('still rejects private, loopback, and metadata targets', () => {
    for (const raw of [
      'http://localhost/',
      'http://localhost:3000/',
      'http://127.0.0.1/',
      'http://10.0.0.5/',
      'http://192.168.1.1/',
      'http://169.254.169.254/latest/meta-data/',
      'http://[::1]/',
      'http://2130706433/',
    ]) {
      assert.equal(validateUrl(raw).ok, false, `${raw} must be rejected`);
    }
  });

  it('still rejects non-standard ports and validates redirects', () => {
    assert.equal(validateUrl('http://example.com:8080/').ok, false);
    assert.equal(validateUrl('https://example.com/').ok, true);
    assert.equal(validateRedirect('http://127.0.0.1/', 'https://example.com/').ok, false);
    assert.equal(validateRedirect('/pricing', 'https://example.com/').ok, true);
  });
});

// ----------------------------------------------------------------
// 7. Theme catalog annotation
// ----------------------------------------------------------------

describe('theme catalog', () => {
  it('recognises known WordPress theme slugs without guessing', () => {
    assert.equal(isKnownWpTheme('astra'), true);
    assert.equal(isKnownWpTheme('hello-elementor'), true);
    assert.equal(isKnownWpTheme('twentytwentyfour'), true);
    assert.equal(isKnownWpTheme('my-custom-client-theme'), false);
    assert.equal(isKnownWpTheme(undefined), false);
  });

  it('recognises known Shopify theme names without guessing', () => {
    assert.equal(isKnownShopifyTheme('Dawn'), true);
    assert.equal(isKnownShopifyTheme('Prestige'), true);
    assert.equal(isKnownShopifyTheme('Totally Custom Theme 2024'), false);
    assert.equal(isKnownShopifyTheme(undefined), false);
  });
});
