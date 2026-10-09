/**
 * Growth & Marketing detector tests (v1: 38 technologies).
 *
 * Fixture-based, no network. Run with: npm test (node --test, no deps).
 *
 * Per technology: one positive fixture; negatives via the empty page;
 * near-misses for every mandated lookalike. Plus: noisy-OR scoring,
 * extractedIds, Salesforce/UA sub-notes, Adobe Launch cap, GTM
 * container expansion, and category grouping.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  detectGrowthMarketing,
  groupGrowthByCategory,
  serverSideWarning,
  type GrowthInput,
} from '../src/lib/detect/growth-marketing.ts';
import { GROWTH_MARKETING_SIGNATURES } from '../src/data/growth-marketing-signatures.ts';

const inp = (html: string, extra: Partial<GrowthInput> = {}): GrowthInput => ({ html, ...extra });

function hit(id: string, input: GrowthInput) {
  const all = detectGrowthMarketing(input);
  const h = all.find((r) => r.id === id);
  assert.ok(h, `expected "${id}" detected, got [${all.map((r) => r.id).join(',')}]`);
  assert.ok(h.score >= 40, `score ${h.score} must clear the 40 floor`);
  assert.ok(Array.isArray(h.evidence) && h.evidence.length > 0, 'evidence array required');
  return h;
}

function miss(id: string, input: GrowthInput) {
  const all = detectGrowthMarketing(input);
  const h = all.find((r) => r.id === id);
  assert.ok(!h, `expected "${id}" NOT detected (score ${h?.score}, evidence ${JSON.stringify(h?.evidence)})`);
}

const EMPTY = inp('<html><head><title>Nothing here</title></head><body><p>Hello world</p></body></html>');

// ----------------------------------------------------------------
// Positive fixtures (one per technology — all 38)
// ----------------------------------------------------------------

const POSITIVES: Array<{ id: string; html: string; extra?: Partial<GrowthInput> }> = [
  { id: 'google-analytics', html: `<script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123DEF"></script><script>gtag('config','G-ABC123DEF');</script>`, extra: { cookies: ['_ga', '_gid'] } },
  { id: 'google-tag-manager', html: `<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC123"></script><noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-ABC123"></iframe></noscript><script>window.google_tag_manager["GTM-ABC123"]={};</script>` },
  { id: 'microsoft-clarity', html: `<script src="https://www.clarity.ms/tag/abc123xyz"></script><script>clarity('set','x','y');</script>`, extra: { cookies: ['_clck', '_clsk'] } },
  { id: 'hotjar', html: `<script src="https://static.hotjar.com/c/hotjar-1234567.js?sv=6"></script><script>hj('trigger','x');</script>`, extra: { cookies: ['_hjSessionUser_abc'] } },
  { id: 'matomo', html: `<script src="https://example.matomo.cloud/matomo.js"></script><script>_paq.push(['trackPageView']);</script>`, extra: { cookies: ['_pk_id.1.fff'] } },
  { id: 'plausible', html: `<script src="https://plausible.io/js/script.js" data-domain="example.com"></script><script>plausible('pageview');</script>` },
  { id: 'mixpanel', html: `<script src="https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js"></script><script>mixpanel.init('a1b2c3d4e5f60718293a4b5c6d7e8f90');</script>`, extra: { cookies: ['mp_a1b2c3d4e5f60718293a4b5c6d7e8f90_mixpanel'] } },
  { id: 'posthog', html: `<script src="https://us.i.posthog.com/static/array.js"></script><script>posthog.init('phc_x');</script>`, extra: { cookies: ['ph_phc_x_posthog'] } },
  { id: 'segment', html: `<script src="https://cdn.segment.com/analytics.js/v1/AbC123XyZ/analytics.min.js"></script><script>analytics.SNIPPET_VERSION='4.15.3';</script>`, extra: { cookies: ['ajs_anonymous_id'] } },
  { id: 'adobe-analytics', html: `<script src="https://example.com/AppMeasurement.js"></script><script>s_account="x";var s=s_gi(s_account);</script>`, extra: { cookies: ['s_cc', 'AMCV_ABC123'] } },
  { id: 'google-ads', html: `<script src="https://www.googletagmanager.com/gtag/js?id=AW-123456789"></script><script>gtag('config','AW-123456789/AbC123');</script>`, extra: { cookies: ['_gcl_au'] } },
  { id: 'google-adsense', html: `<script src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-123456789"></script><script>(adsbygoogle=window.adsbygoogle||[]).push({});</script><ins class="adsbygoogle"></ins>` },
  { id: 'meta-pixel', html: `<script src="https://connect.facebook.net/en_US/fbevents.js"></script><script>fbq('init','123456789012345');</script><noscript><img src="https://www.facebook.com/tr?id=123456789012345&ev=PageView&noscript=1"></noscript>`, extra: { cookies: ['_fbp'] } },
  { id: 'tiktok-pixel', html: `<script src="https://analytics.tiktok.com/i18n/pixel/events.js"></script><script>ttq.load('C123ABC456DEF');ttq.page();</script>`, extra: { cookies: ['_ttp'] } },
  { id: 'linkedin-insight', html: `<script src="https://snap.licdn.com/li.lms-analytics/insight.min.js"></script><script>_linkedin_partner_id = "1234567";</script>` },
  { id: 'pinterest-tag', html: `<script src="https://s.pinimg.com/ct/core.js"></script><script>pintrk('load','1234567');pintrk('page');</script>`, extra: { cookies: ['_pin_unauth'] } },
  { id: 'reddit-pixel', html: `<script src="https://www.redditstatic.com/ads/pixel.js"></script><script>rdt('init','t2_abc123');</script>`, extra: { cookies: ['_rdt_uuid'] } },
  { id: 'snapchat-pixel', html: `<script src="https://sc-static.net/scevent.min.js"></script><script>snaptr('init','abc-def-123');</script>`, extra: { cookies: ['_scid'] } },
  { id: 'hubspot', html: `<script src="https://js.hs-scripts.com/12345678.js"></script><script>_hsq.push(['setPath','/']);</script>`, extra: { cookies: ['hubspotutk'] } },
  { id: 'klaviyo', html: `<script src="https://static.klaviyo.com/onsite/js/klaviyo.js?company_id=ABC123"></script><script>klaviyo.identify({});</script>`, extra: { cookies: ['__kla_id'] } },
  { id: 'mailchimp', html: `<script src="https://chimpstatic.com/mcjs-connected/js/users/abc.js"></script><div id="mc_embed_signup"><form action="https://x.list-manage.com/subscribe/post"></form></div>` },
  { id: 'activecampaign', html: `<script src="https://trackcmp.net/visit.js"></script><script>vgo('setAccount','123');</script>` },
  { id: 'marketo', html: `<script src="https://munchkin.marketo.net/munchkin.js"></script><script>Munchkin.init('ABC-123-XYZ');</script>`, extra: { cookies: ['_mkto_trk'] } },
  { id: 'salesforce', html: `<script src="https://pi.pardot.com/pd.js"></script><script>var piAId='12345';</script>` },
  { id: 'stripe', html: `<script src="https://js.stripe.com/v3/"></script><script>var s=Stripe('pk_test_123');</script><stripe-buy-button></stripe-buy-button>`, extra: { cookies: ['__stripe_mid'] } },
  { id: 'paypal', html: `<script src="https://www.paypal.com/sdk/js?client-id=ABC123xyz"></script><script>paypal.Buttons.render('#x');</script>` },
  { id: 'razorpay', html: `<script src="https://checkout.razorpay.com/v1/checkout.js"></script><script>var r=new Razorpay({});</script><script data-payment_button_id="pl_123"></script>` },
  { id: 'square', html: `<script src="https://web.squarecdn.com/v1/square.js"></script><script>Square.payments('appId');</script>` },
  { id: 'adyen', html: `<script src="https://checkoutshopper-live.adyen.com/checkoutshopper/sdk/5.0.0/adyen.js"></script><script>AdyenCheckout({environment:'live'});</script><div class="adyen-checkout__payment-methods"></div>` },
  { id: 'apple-pay', html: `<script src="https://applepay.cdn-apple.com/jsapi/v1/apple-pay-sdk.js"></script><script>var s=new ApplePaySession(3,req);</script><apple-pay-button></apple-pay-button>` },
  { id: 'google-pay', html: `<script src="https://pay.google.com/gp/p/js/pay.js"></script><script>var c=new google.payments.api.PaymentsClient({});</script><div class="gpay-button"></div>` },
  { id: 'intercom', html: `<script src="https://widget.intercom.io/widget/abc123"></script><script>Intercom('boot',{app_id:'abc123'});</script><div id="intercom-container"></div>`, extra: { cookies: ['intercom-id-abc'] } },
  { id: 'zendesk', html: `<script src="https://static.zdassets.com/ekr/snippet.js?key=abc-def-123"></script><script>zE('webWidget','show');</script>`, extra: { cookies: ['__zlcmid'] } },
  { id: 'crisp', html: `<script src="https://client.crisp.chat/l.js"></script><script>CRISP_WEBSITE_ID = "abc-def-123";$crisp.push(['do','chat:show']);</script><div class="crisp-client"></div>` },
  { id: 'tawkto', html: `<script src="https://embed.tawk.to/abc123def/def456abc"></script><script>var Tawk_API=Tawk_API||{};</script>`, extra: { cookies: ['twk_uuid_abc'] } },
  { id: 'drift', html: `<script src="https://js.driftt.com/include/abc123/def.js"></script><script>drift.load('abc123');</script><div id="drift-widget"></div>`, extra: { cookies: ['drift_aid'] } },
  { id: 'livechat', html: `<script src="https://cdn.livechatinc.com/tracking.js"></script><script>LiveChatWidget.on('ready',function(){});</script>`, extra: { cookies: ['__lc_cid'] } },
  { id: 'hubspot-chat', html: `<script src="https://js.usemessages.com/conversations-embed.js"></script><script>HubSpotConversations.widget.load();</script><div id="hubspot-messages-iframe-container"></div>` },
];

describe('positives — every technology detected with evidence', () => {
  for (const p of POSITIVES) {
    it(`${p.id}: positive fixture`, () => {
      hit(p.id, inp(p.html, p.extra ?? {}));
    });
  }
  it('covers exactly the 38 supported technologies', () => {
    assert.equal(GROWTH_MARKETING_SIGNATURES.length, 38);
    assert.equal(POSITIVES.length, 38);
    assert.deepEqual(
      new Set(POSITIVES.map((p) => p.id)),
      new Set(GROWTH_MARKETING_SIGNATURES.map((s) => s.id)),
    );
  });
});

describe('negatives — empty page detects nothing', () => {
  it('empty page yields zero technologies (honest empty state)', () => {
    assert.deepEqual(detectGrowthMarketing(EMPTY), []);
  });
  it('categories still render with zero counts', () => {
    const groups = groupGrowthByCategory(detectGrowthMarketing(EMPTY));
    assert.deepEqual(groups.map((g) => g.id), ['analytics', 'advertising', 'marketing', 'payments', 'chat']);
    assert.ok(groups.every((g) => g.count === 0 && g.technologies.length === 0));
  });
});

// ----------------------------------------------------------------
// Mandated near-misses (must NOT detect)
// ----------------------------------------------------------------

describe('near-miss — lookalikes that must NOT detect', () => {
  it('Meta Pixel: link to facebook.com is not the pixel', () => {
    miss('meta-pixel', inp(`<html><body><a href="https://www.facebook.com/brand">Follow us on facebook</a><p>Meta Pixel helps advertisers.</p></body></html>`));
  });
  it('Segment: lone `analytics` global is generic', () => {
    miss('segment', inp(`<html><body><script>var analytics={track:function(e){console.log(e);}};analytics.track('x');</script></body></html>`));
  });
  it('Segment IS detected with the snippet marker', () => {
    hit('segment', inp(`<script src="https://cdn.segment.com/analytics.js/v1/KEY/analytics.min.js"></script><script>analytics.SNIPPET_VERSION='4.15.3';</script>`));
  });
  it('GTM: lone dataLayer is NOT enough', () => {
    miss('google-tag-manager', inp(`<html><body><script>var dataLayer=[{page:'x'}];</script></body></html>`));
  });
  it('Apple Pay: bare window.ApplePaySession is NEVER evidence', () => {
    miss('apple-pay', inp(`<html><body><script>if(window.ApplePaySession&&ApplePaySession.canMakePayments()){}</script></body></html>`));
  });
  it('HubSpot Chat: plain HubSpot script is HubSpot, not Chat', () => {
    const all = detectGrowthMarketing(inp(`<script src="https://js.hs-scripts.com/123.js"></script><script>_hsq.push([]);</script>`));
    assert.ok(all.some((r) => r.id === 'hubspot'), 'generic HubSpot script detects HubSpot');
    miss('hubspot-chat', inp(`<script src="https://js.hs-scripts.com/123.js"></script><script>_hsq.push([]);</script>`));
  });
  it('PayPal: plain paypal.me link is IGNORED', () => {
    miss('paypal', inp(`<html><body><a href="https://paypal.me/brand/5">Tip us via paypal.me</a><p>We accept PayPal.</p></body></html>`));
  });
  it('Adobe Analytics: Launch loader alone caps at Low', () => {
    const all = detectGrowthMarketing(inp(`<script src="https://assets.adobedtm.com/abc/satelliteLib-xyz.js"></script>`));
    const h = all.find((r) => r.id === 'adobe-analytics');
    assert.ok(!h || h.score <= 59, `Launch-only must be Low at most (got ${h?.score})`);
  });
  it('Adobe Analytics IS detected with AppMeasurement', () => {
    hit('adobe-analytics', inp(`<script src="https://example.com/AppMeasurement.js"></script><script>var s=s_gi("x");</script>`));
  });
  it('Stripe: buy.stripe.com link alone is not the SDK', () => {
    miss('stripe', inp(`<html><body><a href="https://buy.stripe.com/test_x">Buy now</a></body></html>`));
  });
  it('Zendesk: help-center link alone is not the widget', () => {
    miss('zendesk', inp(`<html><body><a href="https://brand.zendesk.com/hc/en-us">Help center</a></body></html>`));
  });
  it('Square: #card-container alone is supporting evidence only', () => {
    miss('square', inp(`<html><body><div id="card-container"></div></body></html>`));
  });
  it('Plausible: generic script.js alone is not Plausible', () => {
    miss('plausible', inp(`<html><body><script src="https://example.com/assets/script.js"></script></body></html>`));
  });
  it('Plausible: data-domain + proxied script.js reaches Medium', () => {
    const h = hit('plausible', inp(`<html><body><script src="https://example.com/js/script.js" data-domain="example.com"></script></body></html>`));
    assert.ok(h.score >= 60 && h.score < 90, `proxied pair should be Medium (got ${h.score})`);
  });
});

// ----------------------------------------------------------------
// Scoring model
// ----------------------------------------------------------------

describe('scoring model', () => {
  it('noisy-OR over distinct types: host (0.9) + dom (0.6) = 96', () => {
    const h = hit(
      'google-adsense',
      inp(`<script src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-1"></script><ins class="adsbygoogle"></ins>`),
    );
    assert.equal(h.score, 96);
    assert.equal(h.band, 'very-high');
  });
  it('each evidence TYPE counts once (repeated matches do not inflate)', () => {
    const once = detectGrowthMarketing(inp(`<script src="https://connect.facebook.net/en_US/fbevents.js"></script><script>fbq('init','1');</script>`)).find((r) => r.id === 'meta-pixel')!;
    const repeated = detectGrowthMarketing(inp(`<script src="https://connect.facebook.net/en_US/fbevents.js"></script><script src="https://connect.facebook.net/en_US/fbevents.js"></script><script>fbq('init','1');fbq('init','1');</script>`)).find((r) => r.id === 'meta-pixel')!;
    assert.equal(repeated.score, once.score);
  });
  it('no strong evidence caps below High (dom + cookie only)', () => {
    const h = hit(
      'mailchimp',
      inp(`<div id="mc_embed_signup"></div>`, { cookies: ['mailchimp_landing_site'] }),
    );
    // dom-only 0.6 → 60 Medium; dom+cookie must stay below High (75).
    assert.ok(h.score < 75, `weak-only score ${h.score} must be capped below High`);
  });
  it('below 40 is never reported (weak 0.3 supporting rule alone)', () => {
    miss('square', inp(`<html><body><div id="card-container"></div></body></html>`));
    miss('adobe-analytics', inp(`<html><body><script src="https://x.demdex.net/event"></script></body></html>`));
  });
  it('scores are integers 0-100 (round(p*100))', () => {
    for (const p of POSITIVES) {
      const h = hit(p.id, inp(p.html, p.extra ?? {}));
      assert.ok(Number.isInteger(h.score) && h.score >= 40 && h.score <= 100, `${p.id}: ${h.score}`);
      assert.equal(h.score100, h.score);
    }
  });
});

// ----------------------------------------------------------------
// extractedIds + sub-notes
// ----------------------------------------------------------------

describe('extractedIds — the exact evidence behind every finding', () => {
  it('extracts GA4 + GTM ids', () => {
    const ga = hit('google-analytics', inp(POSITIVES[0].html));
    assert.ok(ga.extractedIds.some((e) => e.kind === 'GA4 measurement ID' && e.value === 'G-ABC123DEF'), JSON.stringify(ga.extractedIds));
    const gtm = hit('google-tag-manager', inp(POSITIVES[1].html));
    assert.ok(gtm.extractedIds.some((e) => e.kind === 'GTM container ID' && e.value === 'GTM-ABC123'));
  });
  it('extracts ad + chat + crm ids', () => {
    assert.ok(hit('meta-pixel', inp(POSITIVES[12].html)).extractedIds.some((e) => e.value === '123456789012345'));
    assert.ok(hit('hubspot', inp(POSITIVES[18].html)).extractedIds.some((e) => e.kind === 'HubSpot portal ID' && e.value === '12345678'));
    assert.ok(hit('klaviyo', inp(POSITIVES[19].html)).extractedIds.some((e) => e.kind === 'Klaviyo company ID' && e.value === 'ABC123'));
    assert.ok(hit('google-adsense', inp(POSITIVES[11].html)).extractedIds.some((e) => e.value === 'ca-pub-123456789'));
  });
  it('Salesforce names the matched product in a sub-note', () => {
    const h = hit('salesforce', inp(`<script src="https://pi.pardot.com/pd.js"></script><script>var piAId='1';</script>`));
    assert.ok(h.subNote?.includes('Pardot'), `subNote: ${h.subNote}`);
  });
  it('UA-only GA reports Universal Analytics (legacy)', () => {
    const h = hit('google-analytics', inp(`<script src="https://www.google-analytics.com/ga.js"></script><script>var _gaq=_gaq||[];_gaq.push(['_setAccount','UA-12345-1']);</script>`));
    assert.ok(h.subNote?.includes('legacy'), `subNote: ${h.subNote}`);
  });
});

// ----------------------------------------------------------------
// GTM container expansion
// ----------------------------------------------------------------

const GTM_PAGE = `<html><head><script src="https://www.googletagmanager.com/gtm.js?id=GTM-PAGE1"></script></head><body><p>hi</p></body></html>`;
const GTM_CONTAINER_JS = `
function gtm() {
  var s = document.createElement('script');
  s.src = 'https://connect.facebook.net/en_US/fbevents.js';
  fbq('init', '999000111222333');
  ttq.load('GTMTTQ123');
  var l = document.createElement('script');
  l.src = 'https://snap.licdn.com/li.lms-analytics/insight.min.js';
}`;

describe('GTM container expansion', () => {
  it('page with only gtm.js detects pixels found in the (mocked) container', () => {
    miss('meta-pixel', inp(GTM_PAGE));
    const all = detectGrowthMarketing(inp(GTM_PAGE, { gtmContainers: [{ id: 'GTM-PAGE1', js: GTM_CONTAINER_JS }] }));
    for (const id of ['meta-pixel', 'tiktok-pixel', 'linkedin-insight']) {
      const h = all.find((r) => r.id === id);
      assert.ok(h, `expected "${id}" via GTM, got [${all.map((r) => r.id).join(',')}]`);
      assert.ok(h.evidence.some((e) => e.type === 'via-gtm' && e.detail.includes('GTM-PAGE1')), 'container evidence labelled');
    }
  });
  it('GTM-only evidence never reaches the top band', () => {
    const all = detectGrowthMarketing(inp(GTM_PAGE, { gtmContainers: [{ id: 'GTM-PAGE1', js: GTM_CONTAINER_JS }] }));
    for (const h of all) {
      // google-tag-manager itself is DIRECT evidence (the page loads
      // gtm.js) — everything else here is container-only.
      if (h.id === 'google-tag-manager') continue;
      assert.ok(h.score < 90, `${h.id}: GTM-only score ${h.score} must stay below VERY HIGH`);
    }
  });
  it('direct + GTM evidence merge into a higher score with both entries', () => {
    const direct = detectGrowthMarketing(inp(`<script src="https://connect.facebook.net/en_US/fbevents.js"></script>`)).find((r) => r.id === 'meta-pixel')!;
    const merged = detectGrowthMarketing(
      inp(`<script src="https://connect.facebook.net/en_US/fbevents.js"></script>`, {
        gtmContainers: [{ id: 'GTM-M1', js: `fbq('init','1');` }],
      }),
    ).find((r) => r.id === 'meta-pixel')!;
    assert.ok(merged.score >= direct.score, `${merged.score} >= ${direct.score}`);
    assert.ok(merged.evidence.some((e) => e.type === 'via-gtm'), 'merged evidence keeps the container entry');
  });
  it('a tag NAME containing a vendor word is not detection', () => {
    const all = detectGrowthMarketing(
      inp(GTM_PAGE, { gtmContainers: [{ id: 'GTM-N1', js: `{"name":"Meta Pixel - Homepage","html":"<div>promo</div>"}` }] }),
    );
    assert.ok(!all.some((r) => r.id === 'meta-pixel'), `tag name must not detect (got ${all.map((r) => r.id).join(',')})`);
  });
});

// ----------------------------------------------------------------
// Output grouping + blind-spot warnings
// ----------------------------------------------------------------

describe('output grouping + warnings', () => {
  it('groups into the five growth categories with counts', () => {
    const all = detectGrowthMarketing(
      inp(`<script src="https://www.googletagmanager.com/gtag/js?id=G-X1"></script><script src="https://connect.facebook.net/en_US/fbevents.js"></script><script src="https://js.stripe.com/v3/"></script><script src="https://widget.intercom.io/widget/a1"></script><script src="https://js.hs-scripts.com/1.js"></script>`),
    );
    const groups = groupGrowthByCategory(all);
    assert.deepEqual(groups.map((g) => g.id), ['analytics', 'advertising', 'marketing', 'payments', 'chat']);
    for (const g of groups) assert.equal(g.count, g.technologies.length);
    assert.ok(groups.every((g) => g.count === 1), JSON.stringify(groups.map((g) => [g.id, g.count])));
  });
  it('every result carries typed evidence with details + extractedIds array', () => {
    for (const p of POSITIVES) {
      const h = hit(p.id, inp(p.html, p.extra ?? {}));
      for (const e of h.evidence) {
        assert.ok(typeof e.type === 'string' && e.type.length > 0);
        assert.ok(typeof e.detail === 'string' && e.detail.length > 0);
      }
      assert.ok(Array.isArray(h.extractedIds), 'extractedIds array required');
    }
  });
  it('Zaraz / server-side tagging raises a warning', () => {
    assert.ok(serverSideWarning(`<script src="/cdn-cgi/zaraz/s.js"></script>`, []), 'zaraz warning');
    assert.equal(serverSideWarning(`<p>plain</p>`, []), null);
  });
});
