/**
 * Shared GTM container expansion tests (both detectors import the same
 * module — no duplicated logic).
 *
 * Uses mocked container sources (no network): fetchGtmContainers accepts
 * an injected fetch impl, and detectSecurityPrivacy / detectGrowthMarketing
 * accept pre-fetched gtmContainers.
 *
 * Spec cases: (a) OneTrust in container → Medium/High, never VERY HIGH;
 * (b) Sentry DSN in container → detected; (c) vendor word in a tag NAME
 * only → no detection; (d) fetch failure → warning + normal results.
 * Plus: merge behavior, redirect pinning, TTL cache, id extraction.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  extractGtagIds,
  extractGtmIds,
  fetchGtmContainers,
  sanitizeContainerJs,
  clearGtmCache,
  GTM_CONTAINER_HOST,
} from '../src/lib/detect/gtm-expansion.ts';
import { createBudget } from '../src/lib/detect/static-collect.ts';
import { detectSecurityPrivacy } from '../src/lib/detect/security-privacy.ts';
import { detectGrowthMarketing } from '../src/lib/detect/growth-marketing.ts';

function containerResponse(js: string, status = 200): Response {
  return new Response(js, { status, headers: { 'Content-Type': 'application/javascript' } });
}

/** Mock fetch serving canned GTM containers by id. */
function mockFetch(containers: Record<string, string>, seen: string[] = []): typeof fetch {
  return (async (url: unknown) => {
    const u = String(url);
    seen.push(u);
    const m = /gtm\.js\?id=(GTM-[A-Z0-9]+)/.exec(u);
    const js = m ? containers[m[1]] : undefined;
    if (js === undefined) return new Response('not found', { status: 404 });
    return containerResponse(js);
  }) as typeof fetch;
}

const ONETRUST_CONTAINER = `
(function(){var s=document.createElement('script');
s.src='https://cdn.cookielaw.org/consent/abc/otSDKStub.js';
function OptanonWrapper(){}
document.head.appendChild(s);})();`;

const SENTRY_CONTAINER = `
!function(){Sentry.init({dsn:"https://abc123@o1.ingest.sentry.io/456"});}();`;

const TAGNAME_ONLY_CONTAINER = `{"tags":[{"name":"OneTrust - Homepage Banner","html":"<div>promo</div>"}]}`;

describe('id extraction', () => {
  it('extracts GTM ids from HTML, bundles and noscript iframes (deduped)', () => {
    const html = `<script src="https://www.googletagmanager.com/gtm.js?id=GTM-AAA111"></script>
      <noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-BBB222"></iframe></noscript>`;
    const ids = extractGtmIds(html, [`var x="GTM-AAA111";var y="GTM-CCC333";`]);
    assert.deepEqual(ids, ['GTM-AAA111', 'GTM-BBB222', 'GTM-CCC333']);
  });
  it('extracts gtag ids by product prefix (G-/AW-/GT-/UA-)', () => {
    const html = `<script src="https://www.googletagmanager.com/gtag/js?id=G-X1"></script>
      <script src="https://www.googletagmanager.com/gtag/js?id=AW-123/x"></script>`;
    const ids = extractGtagIds(html, []);
    assert.deepEqual(ids.ga4, ['G-X1']);
    assert.deepEqual(ids.ads, ['AW-123/x']);
    assert.deepEqual(ids.generic, []);
    assert.deepEqual(ids.legacy, []);
  });
});

describe('sanitizeContainerJs', () => {
  it('strips tag names and comments but keeps hosts and init calls', () => {
    const out = sanitizeContainerJs(`{"name":"OneTrust"}/* cdn.cookielaw.org */var a=1;// Sentry.init(
Sentry.init({});`);
    assert.ok(!out.includes('"OneTrust"'), 'tag name removed');
    assert.ok(out.includes('Sentry.init({})'), 'init call kept');
  });
});

describe('security-privacy via GTM container', () => {
  it('(a) OneTrust in container → Medium/High but not VERY HIGH', () => {
    const all = detectSecurityPrivacy({
      html: `<script src="https://www.googletagmanager.com/gtm.js?id=GTM-T1"></script>`,
      gtmContainers: [{ id: 'GTM-T1', js: ONETRUST_CONTAINER }],
    });
    const h = all.find((r) => r.id === 'onetrust');
    assert.ok(h, `OneTrust via GTM expected, got [${all.map((r) => r.id).join(',')}]`);
    assert.ok(h.score100 < 90, `GTM-only must stay below VERY HIGH (got ${h.score100})`);
    assert.ok(['high', 'medium'].includes(h.confidence), `confidence ${h.confidence}`);
    assert.ok(h.evidence.some((e) => e.type === 'via-gtm' && e.detail.includes('GTM-T1')));
  });
  it('(b) Sentry DSN in container → detected', () => {
    const all = detectSecurityPrivacy({
      html: `<script src="https://www.googletagmanager.com/gtm.js?id=GTM-T2"></script>`,
      gtmContainers: [{ id: 'GTM-T2', js: SENTRY_CONTAINER }],
    });
    assert.ok(all.some((r) => r.id === 'sentry'), 'Sentry via GTM expected');
  });
  it('(c) vendor word in a tag NAME only → no detection', () => {
    const all = detectSecurityPrivacy({
      html: `<script src="https://www.googletagmanager.com/gtm.js?id=GTM-T3"></script>`,
      gtmContainers: [{ id: 'GTM-T3', js: TAGNAME_ONLY_CONTAINER }],
    });
    assert.ok(!all.some((r) => r.id === 'onetrust'), `tag name must not detect (got ${all.map((r) => r.id).join(',')})`);
  });
  it('generic __tcfapi in a container stays weak (no Quantcast)', () => {
    const all = detectSecurityPrivacy({
      html: `<p>x</p>`,
      gtmContainers: [{ id: 'GTM-T4', js: `__tcfapi('addEventListener',2,function(){});` }],
    });
    assert.ok(!all.some((r) => r.id === 'quantcast-choice'), 'lone __tcfapi must not report Quantcast');
  });
  it('merge: direct + GTM evidence scores higher with merged evidence', () => {
    const direct = detectSecurityPrivacy({
      html: `<script src="https://browser.sentry-cdn.com/7.0.0/bundle.min.js"></script>`,
    }).find((r) => r.id === 'sentry')!;
    const merged = detectSecurityPrivacy({
      html: `<script src="https://browser.sentry-cdn.com/7.0.0/bundle.min.js"></script>`,
      gtmContainers: [{ id: 'GTM-M', js: SENTRY_CONTAINER }],
    }).find((r) => r.id === 'sentry')!;
    assert.ok(merged.score >= direct.score, `${merged.score} >= ${direct.score}`);
    assert.ok(merged.evidence.some((e) => e.type === 'via-gtm'), 'merged evidence keeps container entry');
  });
});

describe('growth via GTM container', () => {
  it('detects pixels via container expansion', () => {
    const all = detectGrowthMarketing({
      html: `<script src="https://www.googletagmanager.com/gtm.js?id=GTM-G1"></script>`,
      gtmContainers: [{
        id: 'GTM-G1',
        js: `s.src='https://connect.facebook.net/en_US/fbevents.js';fbq('init','1');`,
      }],
    });
    assert.ok(all.some((r) => r.id === 'meta-pixel'), 'Meta Pixel via GTM expected');
  });
});

describe('fetchGtmContainers (mocked fetch)', () => {
  it('(d) fetch failure → warning, empty containers (fail soft)', async () => {
    clearGtmCache();
    const failing = (async () => {
      throw new Error('boom');
    }) as typeof fetch;
    const r = await fetchGtmContainers(['GTM-FAIL1'], new AbortController().signal, createBudget(), failing);
    assert.equal(r.containers.length, 0);
    assert.ok(r.warnings.length > 0, 'warning required');
  });
  it('fetches containers and caches by id (short TTL)', async () => {
    clearGtmCache();
    const seen: string[] = [];
    const f = mockFetch({ 'GTM-C1': ONETRUST_CONTAINER }, seen);
    const signal = new AbortController().signal;
    const first = await fetchGtmContainers(['GTM-C1'], signal, createBudget(), f);
    assert.equal(first.containers.length, 1);
    assert.equal(first.containers[0].js, ONETRUST_CONTAINER);
    const second = await fetchGtmContainers(['GTM-C1'], signal, createBudget(), f);
    assert.equal(second.containers.length, 1);
    assert.equal(seen.length, 1, 'second call served from cache');
  });
  it('caps at 3 containers per scan (deduplicated)', async () => {
    clearGtmCache();
    const seen: string[] = [];
    const f = mockFetch({ 'GTM-A1': 'a', 'GTM-A2': 'b', 'GTM-A3': 'c', 'GTM-A4': 'd' }, seen);
    const r = await fetchGtmContainers(
      ['GTM-A1', 'GTM-A2', 'GTM-A3', 'GTM-A4', 'GTM-A1'],
      new AbortController().signal,
      createBudget(),
      f,
    );
    assert.equal(r.containers.length, 3);
    assert.ok(!seen.some((u) => u.includes('GTM-A4')), '4th container never fetched');
  });
  it('never follows redirects off googletagmanager.com', async () => {
    clearGtmCache();
    const redirecting = (async () => new Response(null, {
      status: 302,
      headers: { location: 'https://malicious-tracker.com/gtm.js?id=GTM-E1' },
    })) as typeof fetch;
    const r = await fetchGtmContainers(['GTM-E1'], new AbortController().signal, createBudget(), redirecting);
    assert.equal(r.containers.length, 0);
    assert.ok(r.warnings.length > 0, 'off-host redirect becomes a warning');
    assert.ok(r.warnings.some((w) => w.includes('googletagmanager.com')));
  });
  it('respects the subrequest budget', async () => {
    clearGtmCache();
    const seen: string[] = [];
    const f = mockFetch({ 'GTM-B1': 'a' }, seen);
    const spent = createBudget();
    spent.remaining = 0;
    const r = await fetchGtmContainers(['GTM-B1'], new AbortController().signal, spent, f);
    assert.equal(r.containers.length, 0);
    assert.equal(seen.length, 0, 'no fetch when budget spent');
  });
});
