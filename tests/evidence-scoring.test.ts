/**
 * Evidence-weighted scoring regression suite (CMS Detector AI).
 *
 * Locks in the fixed confidence architecture for
 * /security-privacy-detector:
 * - One very strong signature (official SDK, unique init, DSN) is
 *   enough for HIGH / VERY HIGH — a single evidence family is NOT
 *   weak evidence.
 * - Families and confidence are separate: the family count is
 *   descriptive corroboration, never the score.
 * - Weak signals stay weak: many weak hints can never reach HIGH.
 * - Same URL seen through two channels is deduplicated, not double
 *   counted.
 * - Domain names alone never establish a detection (the engine takes
 *   no hostname input — only fetched HTML/headers/cookies).
 * - Every detection carries a human-readable evidence trail.
 *
 * Fixture-based, no network. Run with: npm test (node --test, no deps).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runSignatureEngine, type MatchContext } from '../src/lib/detect/signatures.ts';
import {
  applyConfidenceModel,
  explainDetection,
  passesThreshold,
  scoreDetection,
  scoreToLabel5,
} from '../src/lib/detect/confidence.ts';

const ctx = (html: string, headers: Record<string, string> = {}, cookies: string[] = []): MatchContext => ({ html, headers, cookies });

const scored = (id: string, c: MatchContext) => {
  const all = applyConfidenceModel(runSignatureEngine(c));
  const hit = all.find((r) => r.id === id);
  assert.ok(hit, `expected "${id}" detected, got [${all.map((r) => r.id).join(',')}]`);
  return hit;
};

// ----------------------------------------------------------------
// 1. Single very-strong signature => HIGH / VERY HIGH (the reported bug)
// ----------------------------------------------------------------

describe('single strong signature is enough', () => {
  it('Sentry SDK script alone is HIGH or better (1 family is fine)', () => {
    const h = scored('sentry', ctx(`<script src="https://browser.sentry-cdn.com/7.0.0/bundle.min.js"></script>`));
    assert.ok((h.score ?? 0) >= 75, `Sentry SDK-only score ${h.score} must be HIGH+`);
    assert.ok(h.families === 1, 'one family must not prevent HIGH confidence');
    assert.ok(h.scoreLabel === 'HIGH' || h.scoreLabel === 'VERY HIGH');
  });

  it('Sentry init + DSN inline (no script tag) is HIGH or better', () => {
    const h = scored('sentry', ctx(`<script>Sentry.init({dsn:'https://abc@o1.ingest.sentry.io/1'});</script>`));
    assert.ok((h.score ?? 0) >= 75, `Sentry init-only score ${h.score} must be HIGH+`);
  });

  it('Algolia SDK script alone is HIGH or better (1 family is fine)', () => {
    const h = scored('algolia', ctx(`<script src="https://cdn.jsdelivr.net/npm/algoliasearch@4/dist/algoliasearch.min.js"></script>`));
    assert.ok((h.score ?? 0) >= 75, `Algolia SDK-only score ${h.score} must be HIGH+`);
    assert.ok(h.families === 1, 'one family must not prevent HIGH confidence');
  });

  it('Algolia init/API signature alone is HIGH or better', () => {
    const h = scored('algolia', ctx(`<script>const client = algoliasearch('APP123', 'key'); client.initIndex('products');</script><script>fetch('https://app123.algolia.net/1/indexes/products/query');</script>`));
    assert.ok((h.score ?? 0) >= 75, `Algolia init-only score ${h.score} must be HIGH+`);
  });

  it('Cookiebot SDK script alone is HIGH or better', () => {
    const h = scored('cookiebot', ctx(`<script src="https://consent.cookiebot.com/uc.js?cbid=abcdef12-3456-7890-abcd-ef1234567890"></script>`));
    assert.ok((h.score ?? 0) >= 75, `Cookiebot SDK-only score ${h.score} must be HIGH+`);
  });
});

// ----------------------------------------------------------------
// 2. Weak signals stay weak — count never becomes quality
// ----------------------------------------------------------------

describe('weak signals stay weak', () => {
  it('a lone consent cookie never reaches HIGH', () => {
    const h = scored('onetrust', ctx(`<html></html>`, {}, ['OptanonConsent']));
    assert.ok((h.score ?? 0) < 75, `cookie-only score ${h.score} must stay below HIGH`);
    assert.ok(h.scoreLabel === 'LOW' || h.scoreLabel === 'MEDIUM' || h.scoreLabel === 'INSUFFICIENT');
  });

  it('multiple weak-only families can never reach HIGH', () => {
    const { score } = scoreDetection([
      { type: 'cookie-name', artifact: 'a', weight: 40, name: 'c1', value: 'https://x.example/c1', strength: 'weak', family: 'COOKIE', specificity: 0.3, description: 'd', signalId: 's1' },
      { type: 'html-regex', artifact: 'b', weight: 35, name: 'c2', value: 'https://y.example/c2', strength: 'weak', family: 'HTML', specificity: 0.3, description: 'd', signalId: 's2' },
      { type: 'header', artifact: 'c', weight: 30, name: 'c3', value: 'v3', strength: 'weak', family: 'NETWORK', specificity: 0.3, description: 'd', signalId: 's3' },
    ] as never);
    assert.ok(score < 75, `weak-only score ${score} must stay below HIGH however many families`);
    assert.ok(score < 60, `weak-only must cap at LOW or below, got ${score}`);
  });

  it('strong corroboration without a definitive signature caps below VERY HIGH', () => {
    const { score } = scoreDetection([
      { type: 'script-host', artifact: 'a', weight: 92, name: 'h1', value: 'https://a.example/sdk.js', strength: 'strong', family: 'SCRIPT', specificity: 0.7, description: 'd', signalId: 's1' },
      { type: 'html-regex', artifact: 'b', weight: 88, name: 'h2', value: 'initCall()', strength: 'strong', family: 'HTML', specificity: 0.7, description: 'd', signalId: 's2' },
      { type: 'cookie-name', artifact: 'c', weight: 72, name: 'ck', value: 'ck', strength: 'strong', family: 'COOKIE', specificity: 0.7, description: 'd', signalId: 's3' },
    ] as never);
    assert.ok(score >= 75, `three strong families (${score}) should reach HIGH`);
    assert.ok(score < 90, `no definitive signature (${score}) must not reach VERY HIGH`);
  });
});

// ----------------------------------------------------------------
// 3. Deduplication: one resource, two channels => one signal
// ----------------------------------------------------------------

describe('evidence deduplication', () => {
  it('same SDK URL in resource scan + HTML pattern does not inflate', () => {
    const url = 'https://consent.cookiebot.com/uc.js?cbid=abcdef12-3456-7890-abcd-ef1234567890';
    const single = scoreDetection([
      { type: 'script-host', artifact: `script[src]: "${url}"`, weight: 92, name: 'consent.cookiebot.com', value: url, strength: 'definitive', family: 'SCRIPT', specificity: 1, description: 'd', signalId: 's1' },
    ] as never);
    const doubled = scoreDetection([
      { type: 'script-host', artifact: `script[src]: "${url}"`, weight: 92, name: 'consent.cookiebot.com', value: url, strength: 'definitive', family: 'SCRIPT', specificity: 1, description: 'd', signalId: 's1' },
      { type: 'html-regex', artifact: `html: "${url.slice(0, 40)}"`, weight: 88, name: url.slice(0, 40), value: `src="${url}" data-cbid=`, strength: 'definitive', family: 'HTML', specificity: 1, description: 'd', signalId: 's2' },
    ] as never);
    assert.equal(doubled.score, single.score, `same URL twice (${doubled.score}) must equal once (${single.score})`);
    assert.equal(doubled.families, 1, 'same resource is one family, not two');
  });

  it('genuinely different integrations on one host still corroborate', () => {
    const one = scoreDetection([
      { type: 'html-regex', artifact: 'embed', weight: 90, name: 'e', value: 'https://www.youtube.com/embed/ABC123', strength: 'definitive', family: 'HTML', specificity: 1, description: 'd', signalId: 's1' },
    ] as never);
    const two = scoreDetection([
      { type: 'html-regex', artifact: 'embed', weight: 90, name: 'e', value: 'https://www.youtube.com/embed/ABC123', strength: 'definitive', family: 'HTML', specificity: 1, description: 'd', signalId: 's1' },
      { type: 'script-host', artifact: 'sdk', weight: 85, name: 'h', value: 'https://www.youtube.com/iframe_api', strength: 'strong', family: 'SCRIPT', specificity: 0.7, description: 'd', signalId: 's2' },
    ] as never);
    assert.ok(two.score >= one.score, 'embed + player SDK must score at least as well as embed alone');
    assert.equal(two.families, 2);
  });
});

// ----------------------------------------------------------------
// 4. Domain names and generic words are NOT proof
// ----------------------------------------------------------------

describe('no domain-name or keyword proof', () => {
  it('mentioning sentry.io / algolia.com domains in prose detects nothing', () => {
    const c = ctx(`<html><body><article><p>Visit sentry.io for errors and algolia.com for search. We love sentry and algolia services.</p></article></body></html>`);
    const all = applyConfidenceModel(runSignatureEngine(c));
    assert.ok(!all.some((r) => r.id === 'sentry'), 'domain prose must not detect Sentry');
    assert.ok(!all.some((r) => r.id === 'algolia'), 'domain prose must not detect Algolia');
  });

  it('generic words (cloud, security, google) detect nothing', () => {
    const c = ctx(`<html><body><p>Cloud security with Google-scale infrastructure. YouTube-famous vimeo alternatives.</p></body></html>`);
    const all = applyConfidenceModel(runSignatureEngine(c));
    for (const id of ['cloudinary', 'sentry', 'google-maps', 'youtube-embed', 'vimeo-embed']) {
      assert.ok(!all.some((r) => r.id === id), `"${id}" must not fire on generic words`);
    }
  });

  it('a minimal example.com-style page yields zero detections', () => {
    const c = ctx(`<html><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p></body></html>`, { 'content-type': 'text/html' });
    const all = applyConfidenceModel(runSignatureEngine(c));
    assert.equal(all.length, 0, `minimal page must yield nothing, got [${all.map((r) => r.id).join(',')}]`);
  });

  it('a tutorial page with fenced + highlighted SDK samples detects nothing', () => {
    // No live usage anywhere: highlighted samples (no <pre>/<code> tags,
    // like real syntax highlighters emit) plus fenced code blocks,
    // including fences embedded in a JSON data blob with escaped newlines.
    const fence = '```';
    const c = ctx(`<html><body><article><h1>How to install Sentry</h1>
      <div class="highlight"><span>src="https://browser.sentry-cdn.com/7.0.0/bundle.min.js"</span></div>
      <div class="code-wrapper"><span>Sentry.init({ dsn: 'https://abc123@o1.ingest.sentry.io/1' });</span>
      <span>Sentry.captureException(new Error('oops'));</span></div>
      <script type="application/json">{"snippet":"Configure it:\\n\\n${fence}javascript\\nSentry.init({ dsn: 'https://abc123@o1.ingest.sentry.io/1' });\\n${fence}"}</script>
      </article></body></html>`);
    const all = applyConfidenceModel(runSignatureEngine(c));
    assert.ok(!all.some((r) => r.id === 'sentry'), `docs samples must not detect Sentry, got ${JSON.stringify(all.map((r) => ({ id: r.id, score: r.score })))}`);
  });

  it('live usage beside docs samples scores from the live signals only', () => {
    const fence = '```';
    const live = `<script>if(window.Sentry){window.Sentry.getCurrentHub();}</script>`;
    const c = ctx(`<html><head>${live}</head><body><article>
      <div class="highlight"><span>Sentry.init({ dsn: 'https://docs@example.com/1' });</span></div>
      <div>${fence}javascript\nSentry.init({ dsn: 'https://docs@example.com/1' });\n${fence}</div>
      </article></body></html>`);
    const h = scored('sentry', c);
    assert.ok((h.score ?? 0) >= 75, `live window.Sentry usage must stay HIGH, got ${h.score}`);
    for (const e of h.evidence) {
      assert.ok(!e.value.includes('docs@example.com'), 'recorded evidence must be live code, not docs samples');
    }
  });

  it('a marketing "highlight-section" class never strips live code', () => {
    const c = ctx(`<html><body><div class="highlight-section"><script src="https://browser.sentry-cdn.com/7.0.0/bundle.min.js"></script></div></body></html>`);
    const h = scored('sentry', c);
    assert.ok((h.score ?? 0) >= 75, 'live SDK inside highlight-section must still score HIGH');
  });

  it('JSON-LD metadata mentioning a vendor detects nothing without usage', () => {
    const c = ctx(`<html><head><script type="application/ld+json">{"@context":"https://schema.org","@type":"WebPage","name":"Sentry tutorial using plausible analytics"}</script></head><body><p>hello</p></body></html>`);
    const all = applyConfidenceModel(runSignatureEngine(c));
    assert.ok(!all.some((r) => r.id === 'sentry'), 'JSON-LD prose must not detect Sentry');
  });
});

// ----------------------------------------------------------------
// 5. Evidence trail: every detection explains itself
// ----------------------------------------------------------------

describe('evidence trail', () => {
  it('every detection carries human-readable evidence descriptions', () => {
    const h = scored('sentry', ctx(`<script src="https://browser.sentry-cdn.com/7.0.0/bundle.min.js"></script>`));
    assert.ok(h.evidence.length > 0);
    for (const e of h.evidence) {
      assert.ok(typeof e.description === 'string' && e.description.length > 5, 'evidence needs a description');
      assert.ok(typeof e.signalId === 'string' && e.signalId.length > 0, 'evidence needs a stable signal id');
      assert.ok(typeof e.weight === 'number' && typeof e.specificity === 'number', 'evidence needs weight + specificity');
    }
    assert.ok(h.evidence.some((e) => /sentry/i.test(e.description)), 'trail names the technology');
  });

  it('debug explanation exposes per-signal weight math', () => {
    const h = scored('algolia', ctx(`<script src="https://cdn.jsdelivr.net/npm/algoliasearch@4/dist/algoliasearch.min.js"></script>`));
    const ex = explainDetection(h.evidence);
    assert.equal(ex.score, h.score, 'debug score mirrors the detection score');
    assert.equal(ex.families, h.families, 'debug families mirror the detection');
    assert.ok(ex.signals.length > 0);
    assert.ok(ex.signals.some((s) => s.familyWinner), 'a winning signal is identified');
  });

  it('LOW detections stay displayable-but-flagged, INSUFFICIENT stays hidden', () => {
    const low = scored('onetrust', ctx(`<html></html>`, {}, ['OptanonConsent']));
    assert.ok((low.score ?? 0) >= 40 || !passesThreshold(low), 'LOW either shows with a hint or is hidden');
    const weak = applyConfidenceModel(runSignatureEngine(ctx(`<html></html>`, {}, ['_ga']))).find((r) => r.id === 'google-analytics');
    assert.ok(weak && !passesThreshold(weak), 'weak cookie-only hint must not pass the display threshold');
  });
});
