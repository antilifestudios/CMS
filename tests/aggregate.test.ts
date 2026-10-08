/**
 * Regression tests for per-technology detection (CMS Detector AI).
 *
 * - Evidence must never leak across detections: each card shows only
 *   its own techId's signals.
 * - Confidence is per technology, from fingerprint STRENGTH (union
 *   across pages) — one weak page never downgrades the tech, and a
 *   partial presence caps at Medium.
 * - Evidence is deduplicated by signal with page counts, strongest
 *   signal first.
 *
 * Fixture-based, no network. Run with: npm test (node --test, no deps).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  aggregateTechs,
  confidenceForTech,
  pageTechConfidence,
  toTechItems,
} from '../src/lib/scan/aggregate.ts';
import type { PageScanResult, TechEvidenceItem } from '../src/lib/scan/types.ts';
import frameworksJson from '../src/data/signatures/frameworks.json' with { type: 'json' };
import hostingJson from '../src/data/signatures/hosting.json' with { type: 'json' };
import cmsJson from '../src/data/signatures/cms.json' with { type: 'json' };
import buildersJson from '../src/data/signatures/builders.json' with { type: 'json' };
import ecommerceJson from '../src/data/signatures/ecommerce.json' with { type: 'json' };

// ----------------------------------------------------------------
// Fixture builders: an Astro site behind Cloudflare.
// ----------------------------------------------------------------

function cfItems(pageUrl: string, ray: string): TechEvidenceItem[] {
  return [
    { techId: 'cloudflare', signalType: 'header', name: 'cf-ray', value: ray, pageUrl, strength: 'definitive' },
    { techId: 'cloudflare', signalType: 'header', name: 'server', value: 'cloudflare', pageUrl, strength: 'definitive' },
  ];
}

function astroItems(pageUrl: string, cid: string, asset: string): TechEvidenceItem[] {
  return [
    { techId: 'astro', signalType: 'html-regex', name: cid, value: cid, pageUrl, strength: 'strong' },
    { techId: 'astro', signalType: 'html-path', name: '/_astro/', value: asset, pageUrl, strength: 'strong' },
  ];
}

function cfAstroPage(i: number): PageScanResult {
  const url = `https://getdnstools.com/page-${i}/`;
  return {
    url,
    finalUrl: url,
    redirectChain: [],
    crossDomainRedirect: false,
    framework: 'Astro',
    frameworkId: 'astro',
    frameworkSlug: 'astro',
    provider: 'Cloudflare',
    providerId: 'cloudflare',
    providerSlug: 'cloudflare',
    confidence: 'High',
    evidence: ['legacy flat list (matrix only)'],
    techEvidence: [
      ...cfItems(url, `ray-${i}-HKG`),
      ...astroItems(url, 'data-astro-cid', `/_astro/page-${i}.js`),
    ],
    frameworkConfidence: 'High',
    providerConfidence: 'High',
  };
}

function techById(techs: ReturnType<typeof aggregateTechs>, id: string) {
  const t = techs.find((x) => x.techId === id);
  assert.ok(t, `expected tech "${id}" in aggregation`);
  return t;
}

// ----------------------------------------------------------------
// 1. Separation: neither detection contains the other's signals.
// ----------------------------------------------------------------

describe('evidence separation', () => {
  it("Cloudflare card shows only header evidence; Astro card only html/asset evidence", () => {
    const pages = [cfAstroPage(1), cfAstroPage(2), cfAstroPage(3)];
    const techs = aggregateTechs(pages);

    const cf = techById(techs, 'cloudflare');
    const astro = techById(techs, 'astro');

    assert.deepEqual(
      new Set(cf.evidence.map((e) => e.signalType)),
      new Set(['header']),
      'cloudflare must have header evidence only'
    );
    assert.deepEqual(
      new Set(cf.evidence.map((e) => e.name)),
      new Set(['cf-ray', 'server'])
    );
    assert.ok(
      cf.evidence.every((e) => !/astro/i.test(e.name) && !/astro/i.test(e.sampleValue)),
      'no Astro signal may appear under Cloudflare'
    );

    assert.deepEqual(
      new Set(astro.evidence.map((e) => e.signalType)),
      new Set(['html-regex', 'html-path']),
      'astro must have html/asset evidence only'
    );
    assert.ok(
      astro.evidence.every((e) => !/cf-ray|cloudflare/i.test(e.name)),
      'no Cloudflare signal may appear under Astro'
    );
  });

  it('toTechItems tags every line with its own technology id and strength', () => {
    const astroResult = {
      id: 'astro',
      name: 'Astro',
      category: 'framework',
      confidence: 97,
      confidenceLabel: 'confirmed',
      evidence: [
        { type: 'html-regex', artifact: 'html: "data-astro-cid"', weight: 85, name: 'data-astro-cid', value: 'data-astro-cid', strength: 'strong' },
        { type: 'html-path', artifact: 'html: "/_astro/"', weight: 80, name: '/_astro/', value: '/_astro/a.css', strength: 'strong' },
      ],
    } as const;
    const items = toTechItems(astroResult as never, 'https://getdnstools.com/');
    assert.equal(items.length, 2);
    assert.ok(items.every((i) => i.techId === 'astro'));
    assert.ok(items.every((i) => i.strength === 'strong'));
  });

  it('page slugs travel through to the tech rollup for card links', () => {
    const techs = aggregateTechs([cfAstroPage(1)]);
    assert.equal(techById(techs, 'astro').pageSlug, 'astro');
    assert.equal(techById(techs, 'cloudflare').pageSlug, 'cloudflare');
  });
});

// ----------------------------------------------------------------
// 2. Multi-page merge of 15 pages: separated + deduplicated.
// ----------------------------------------------------------------

describe('multi-page merge', () => {
  it('merges 15 pages into one line per signal with page counts', () => {
    const pages = Array.from({ length: 15 }, (_, i) => cfAstroPage(i + 1));
    const techs = aggregateTechs(pages);

    const cf = techById(techs, 'cloudflare');
    assert.equal(cf.detectedOn, 15);
    assert.equal(cf.checkedPages, 15);
    // cf-ray values differ per page but collapse to one line.
    assert.equal(cf.evidence.length, 2);
    const ray = cf.evidence.find((e) => e.name === 'cf-ray');
    assert.ok(ray);
    assert.equal(ray.pagesSeen, 15);

    const astro = techById(techs, 'astro');
    assert.equal(astro.detectedOn, 15);
    assert.equal(astro.checkedPages, 15);
    assert.equal(astro.evidence.length, 2);
    assert.ok(astro.evidence.every((e) => e.pagesSeen === 15));
  });

  it('orders evidence strongest signal first', () => {
    const url = 'https://example.com/';
    const pages: PageScanResult[] = [{
      ...cfAstroPage(1),
      url,
      finalUrl: url,
      techEvidence: [
        { techId: 'x', signalType: 'html-regex', name: 'generic', value: 'generic', pageUrl: url, strength: 'weak' },
        { techId: 'x', signalType: 'header', name: 'x-vendor', value: 'yes', pageUrl: url, strength: 'definitive' },
        { techId: 'x', signalType: 'html-path', name: '/vendor/', value: '/vendor/a.js', pageUrl: url, strength: 'strong' },
      ],
      framework: 'X', frameworkId: 'x', provider: 'Unknown', providerId: null,
    }];
    const order = techById(aggregateTechs(pages), 'x').evidence.map((e) => e.strength);
    assert.deepEqual(order, ['definitive', 'strong', 'weak']);
  });

  it('ignores error pages in both evidence and page counts', () => {
    const pages = [cfAstroPage(1), cfAstroPage(2)];
    pages.push({
      url: 'https://getdnstools.com/broken/',
      finalUrl: 'https://getdnstools.com/broken/',
      redirectChain: [],
      crossDomainRedirect: false,
      framework: 'Unknown',
      frameworkId: null,
      provider: 'Unknown',
      providerId: null,
      confidence: 'Low',
      evidence: ['Timeout'],
      techEvidence: [],
      error: 'Timeout',
    });
    const techs = aggregateTechs(pages);
    assert.equal(techById(techs, 'astro').checkedPages, 2);
    assert.equal(techById(techs, 'astro').detectedOn, 2);
  });
});

// ----------------------------------------------------------------
// 3. Confidence from signal strength (single definition under test).
// ----------------------------------------------------------------

describe('confidence', () => {
  it('is High for one definitive signal', () => {
    assert.equal(
      confidenceForTech({ signals: [{ strength: 'definitive' }], coverage: 1 }),
      'High'
    );
  });

  it('is High for two or more strong signals', () => {
    assert.equal(
      confidenceForTech({ signals: [{ strength: 'strong' }, { strength: 'strong' }], coverage: 1 }),
      'High'
    );
    assert.equal(
      confidenceForTech({ signals: [{ strength: 'strong' }, { strength: 'strong' }, { strength: 'weak' }], coverage: 1 }),
      'High'
    );
  });

  it('is Medium for exactly one strong signal', () => {
    assert.equal(
      confidenceForTech({ signals: [{ strength: 'strong' }], coverage: 1 }),
      'Medium'
    );
  });

  it('is Medium for multiple weak signals', () => {
    assert.equal(
      confidenceForTech({ signals: [{ strength: 'weak' }, { strength: 'weak' }], coverage: 1 }),
      'Medium'
    );
  });

  it('is Low for a single weak signal', () => {
    assert.equal(
      confidenceForTech({ signals: [{ strength: 'weak' }], coverage: 1 }),
      'Low'
    );
    assert.equal(confidenceForTech({ signals: [], coverage: 1 }), 'Low');
  });

  it('is Low for a minority presence however strong', () => {
    assert.equal(
      confidenceForTech({ signals: [{ strength: 'definitive' }], coverage: 1 / 15 }),
      'Low'
    );
  });

  it('caps a partial presence at Medium and reports the fraction', () => {
    // Definitive headers on 9 of 15 pages: earned High, capped Medium.
    const pages = Array.from({ length: 15 }, (_, i) => cfAstroPage(i + 1));
    for (let i = 9; i < 15; i++) {
      const p = pages[i];
      pages[i] = {
        ...p,
        provider: 'Unknown',
        providerId: null,
        techEvidence: (p.techEvidence ?? []).filter((e) => e.techId !== 'cloudflare'),
      };
    }
    const cf = techById(aggregateTechs(pages), 'cloudflare');
    assert.equal(cf.detectedOn, 9);
    assert.equal(cf.checkedPages, 15);
    assert.equal(cf.confidence, 'Medium');
  });

  it('is not downgraded by one weaker page at full coverage', () => {
    const pages = Array.from({ length: 14 }, (_, i) => cfAstroPage(i + 1));
    // 15th page: truncated HTML, only the html marker survived.
    const weakUrl = 'https://getdnstools.com/page-15/';
    pages.push({
      url: weakUrl,
      finalUrl: weakUrl,
      redirectChain: [],
      crossDomainRedirect: false,
      framework: 'Astro',
      frameworkId: 'astro',
      provider: 'Cloudflare',
      providerId: 'cloudflare',
      confidence: 'Medium',
      evidence: [],
      techEvidence: [
        ...cfItems(weakUrl, 'ray-15-HKG'),
        { techId: 'astro', signalType: 'html-regex', name: 'data-astro-cid', value: 'data-astro-cid', pageUrl: weakUrl, strength: 'strong' },
      ],
      frameworkConfidence: 'Medium',
      providerConfidence: 'High',
    });
    const techs = aggregateTechs(pages);
    assert.equal(techById(techs, 'astro').confidence, 'High');
    assert.equal(techById(techs, 'cloudflare').confidence, 'High');
  });

  it('earns High for the getdnstools.com shape: definitive provider headers + strong framework markers', () => {
    const techs = aggregateTechs(Array.from({ length: 15 }, (_, i) => cfAstroPage(i + 1)));
    assert.equal(techById(techs, 'astro').confidence, 'High');
    assert.equal(techById(techs, 'cloudflare').confidence, 'High');
  });

  it('pageTechConfidence follows the same rule on a single page', () => {
    const def = { id: 'x', evidence: [{ type: 'header', strength: 'definitive' }] } as never;
    assert.equal(pageTechConfidence(def), 'High');
    const twoStrong = { id: 'x', evidence: [{ type: 'html-regex', strength: 'strong' }, { type: 'html-path', strength: 'strong' }] } as never;
    assert.equal(pageTechConfidence(twoStrong), 'High');
    const oneStrong = { id: 'x', evidence: [{ type: 'header', strength: 'strong' }] } as never;
    assert.equal(pageTechConfidence(oneStrong), 'Medium');
    const oneWeak = { id: 'x', evidence: [{ type: 'header', strength: 'weak' }] } as never;
    assert.equal(pageTechConfidence(oneWeak), 'Low');
  });
});

// ----------------------------------------------------------------
// 4. Signatures: every rule carries a valid strength, and the key
//    real-world signals are tagged so High is earned, not hardcoded.
// ----------------------------------------------------------------

type SigFile = Array<{ id: string; signals: Array<{ type: string; name?: string; pattern: string; strength?: string }> }>;

describe('signatures', () => {
  it('every signal in every rules file has a valid strength', () => {
    const files: SigFile[] = [cmsJson as SigFile, buildersJson as SigFile, ecommerceJson as SigFile, frameworksJson as SigFile, hostingJson as SigFile];
    let count = 0;
    for (const file of files) {
      for (const tech of file) {
        for (const sig of tech.signals) {
          count++;
          assert.ok(
            sig.strength === 'definitive' || sig.strength === 'strong' || sig.strength === 'weak',
            `${tech.id}: signal ${sig.type}/${sig.name ?? sig.pattern} has no valid strength`
          );
        }
      }
    }
    assert.ok(count > 100, `expected >100 tagged signals, saw ${count}`);
  });

  it('astro earns High from strong marker + asset-path signals', () => {
    const astro = (frameworksJson as SigFile).find((s) => s.id === 'astro');
    assert.ok(astro, 'astro signature exists');
    const byType = new Map(astro.signals.map((s) => [s.type, s.strength]));
    assert.equal(byType.get('html-regex'), 'strong');
    assert.ok(astro.signals.some((s) => s.type === 'html-path' && s.pattern.includes('/_astro/') && s.strength === 'strong'));
  });

  it('cloudflare earns High from definitive provider headers', () => {
    const cf = (hostingJson as SigFile).find((s) => s.id === 'cloudflare');
    assert.ok(cf, 'cloudflare signature exists');
    const headers = new Map(cf.signals.filter((s) => s.type === 'header').map((s) => [s.name, s.strength]));
    assert.equal(headers.get('cf-ray'), 'definitive');
    assert.equal(headers.get('server'), 'definitive');
  });
});
