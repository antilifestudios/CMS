/**
 * Consistency analysis — pure function.
 * Baseline = most common (framework, provider) pair across scanned pages.
 *
 * Reliability rule: A failed or skipped page marks that URL "unscanned",
 * NEVER "consistent". A multi-page scan can ONLY be declared "consistent"
 * when every attempted page completed successfully without differences.
 */
import type { PageScanResult, ScanCoverage, ScanResult } from './types.ts';
import { aggregateTechs } from './aggregate.ts';

function mode(values: string[]): string {
  const counts = new Map<string, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  let best = values[0] ?? 'Unknown';
  let bestN = -1;
  for (const [v, n] of counts) {
    if (n > bestN) {
      best = v;
      bestN = n;
    }
  }
  return best;
}

export function analyzeConsistency(opts: {
  rootUrl: string;
  rootHost: string;
  pages: PageScanResult[];
  coverage: ScanCoverage;
}): ScanResult {
  const { rootUrl, rootHost, pages, coverage } = opts;

  const ok = pages.filter((p) => !p.error && !p.skippedByRobots);
  const baselineFramework = ok.length > 0 ? mode(ok.map((p) => p.framework)) : 'Unknown';
  const baselineProvider = ok.length > 0 ? mode(ok.map((p) => p.provider)) : 'Unknown';

  let oddCount = 0;
  for (const p of pages) {
    if (p.error || p.skippedByRobots) {
      p.differsFramework = false;
      p.differsProvider = false;
      p.isOddOneOut = false;
      continue;
    }
    p.differsFramework = p.framework !== baselineFramework;
    p.differsProvider = p.provider !== baselineProvider;
    p.isOddOneOut = p.differsFramework || p.differsProvider || p.crossDomainRedirect;
    if (p.isOddOneOut) oddCount += 1;
  }

  const unscannedCount = pages.length - ok.length;

  // A scan is only consistent when:
  // 1. At least 1 page completed successfully.
  // 2. No attempted pages failed or were skipped (unscannedCount === 0).
  // 3. No differences were observed across pages (oddCount === 0).
  const isConsistent = ok.length > 0 && unscannedCount === 0 && oddCount === 0;
  const verdict: 'consistent' | 'mixed' = isConsistent ? 'consistent' : 'mixed';

  let verdictLine: string;
  if (isConsistent) {
    verdictLine = `${ok.length}/${pages.length} pages run ${baselineFramework} + ${baselineProvider}`;
  } else if (ok.length === 0) {
    verdictLine = `0 of ${pages.length} pages could be scanned`;
  } else if (unscannedCount > 0) {
    const diffSuffix = oddCount > 0 ? `, ${oddCount} differ` : '';
    verdictLine = `${ok.length} of ${pages.length} pages scanned (${unscannedCount} unscanned or failed${diffSuffix})`;
  } else {
    verdictLine = `${oddCount} of ${pages.length} path${pages.length === 1 ? '' : 's'} differ${oddCount === 1 ? '' : ''}`;
  }

  // Front-door note: every successful page behind the same named CDN.
  const namedProviders = ok.map((p) => p.provider).filter((p) => p !== 'Unknown' && p !== 'Unscanned');
  const frontDoorNote =
    namedProviders.length > 0 &&
    namedProviders.length === ok.length &&
    new Set(namedProviders).size === 1;

  return {
    rootUrl,
    rootHost,
    verdict,
    baselineFramework,
    baselineProvider,
    verdictLine,
    coverage: {
      ...coverage,
      checked: ok.length,
      truncated: coverage.truncated || unscannedCount > 0,
    },
    pages,
    techs: aggregateTechs(pages),
    frontDoorNote,
    scannedAt: new Date().toISOString(),
  };
}
