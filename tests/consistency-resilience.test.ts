/**
 * Multi-URL Consistency Analysis Resilience Tests
 *
 * Verifies:
 * - A failed or skipped page marks that URL "unscanned", NEVER "consistent"
 * - 1 successful page + 14 failed pages yields "mixed", not "consistent"
 * - All matching pages yield "consistent"
 * - Coverage metadata tracks checked, unscanned, and truncated properly
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeConsistency } from '../src/lib/scan/analyze.ts';
import type { PageScanResult, ScanCoverage } from '../src/lib/scan/types.ts';

describe('Consistency Analysis Resilience', () => {
  const rootUrl = 'https://example.com/';
  const rootHost = 'example.com';

  it('marks scan consistent ONLY when all attempted pages succeeded and match', () => {
    const pages: PageScanResult[] = [
      {
        url: 'https://example.com/',
        path: '/',
        framework: 'Next.js',
        provider: 'Vercel',
        confidence: 'High',
        evidence: [],
        crossDomainRedirect: false,
        status: 200,
        timingMs: 50,
      },
      {
        url: 'https://example.com/about',
        path: '/about',
        framework: 'Next.js',
        provider: 'Vercel',
        confidence: 'High',
        evidence: [],
        crossDomainRedirect: false,
        status: 200,
        timingMs: 52,
      },
      {
        url: 'https://example.com/pricing',
        path: '/pricing',
        framework: 'Next.js',
        provider: 'Vercel',
        confidence: 'High',
        evidence: [],
        crossDomainRedirect: false,
        status: 200,
        timingMs: 48,
      },
    ];

    const coverage: ScanCoverage = {
      checked: 3,
      foundApprox: 3,
      truncated: false,
    };

    const res = analyzeConsistency({ rootUrl, rootHost, pages, coverage });
    assert.equal(res.verdict, 'consistent');
    assert.equal(res.coverage.checked, 3);
    assert.equal(res.baselineFramework, 'Next.js');
    assert.equal(res.baselineProvider, 'Vercel');
    assert.equal(res.frontDoorNote, true);
  });

  it('NEVER declares consistent when 14 pages fail and only 1 succeeds', () => {
    const pages: PageScanResult[] = [
      {
        url: 'https://example.com/',
        path: '/',
        framework: 'WordPress',
        provider: 'Cloudflare',
        confidence: 'High',
        evidence: [],
        crossDomainRedirect: false,
        status: 200,
        timingMs: 120,
      },
    ];

    // 14 failed/timed-out pages
    for (let i = 1; i <= 14; i++) {
      pages.push({
        url: `https://example.com/page-${i}`,
        path: `/page-${i}`,
        error: 'TIMEOUT',
        framework: 'Unscanned',
        provider: 'Unscanned',
        confidence: 'Low',
        evidence: [],
        crossDomainRedirect: false,
        status: 0,
        timingMs: 0,
      });
    }

    const coverage: ScanCoverage = {
      checked: 1,
      foundApprox: 15,
      truncated: false,
    };

    const res = analyzeConsistency({ rootUrl, rootHost, pages, coverage });
    assert.equal(res.verdict, 'mixed');
    assert.equal(res.coverage.checked, 1);
    assert.equal(res.coverage.truncated, true); // Flagged because 14 pages were unscanned
    assert.ok(res.verdictLine.includes('1 of 15 pages scanned'));
    assert.ok(res.verdictLine.includes('14 unscanned or failed'));
  });

  it('handles 0 successful pages gracefully', () => {
    const pages: PageScanResult[] = [
      {
        url: 'https://example.com/',
        path: '/',
        error: 'DNS_FAILED',
        framework: 'Unscanned',
        provider: 'Unscanned',
        confidence: 'Low',
        evidence: [],
        crossDomainRedirect: false,
        status: 0,
        timingMs: 0,
      },
    ];

    const coverage: ScanCoverage = {
      checked: 0,
      foundApprox: 1,
      truncated: false,
    };

    const res = analyzeConsistency({ rootUrl, rootHost, pages, coverage });
    assert.equal(res.verdict, 'mixed');
    assert.equal(res.coverage.checked, 0);
    assert.equal(res.verdictLine, '0 of 1 pages could be scanned');
  });

  it('flags different stacks as mixed with accurate odd count', () => {
    const pages: PageScanResult[] = [
      {
        url: 'https://example.com/',
        path: '/',
        framework: 'Next.js',
        provider: 'Vercel',
        confidence: 'High',
        evidence: [],
        crossDomainRedirect: false,
        status: 200,
        timingMs: 40,
      },
      {
        url: 'https://example.com/blog',
        path: '/blog',
        framework: 'WordPress',
        provider: 'WP Engine',
        confidence: 'High',
        evidence: [],
        crossDomainRedirect: false,
        status: 200,
        timingMs: 90,
      },
    ];

    const coverage: ScanCoverage = {
      checked: 2,
      foundApprox: 2,
      truncated: false,
    };

    const res = analyzeConsistency({ rootUrl, rootHost, pages, coverage });
    assert.equal(res.verdict, 'mixed');
    assert.equal(res.frontDoorNote, false); // Vercel vs WP Engine
    assert.ok(pages.some((p) => p.isOddOneOut));
  });
});
