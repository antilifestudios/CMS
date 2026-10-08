/**
 * Consistency analysis — pure function.
 * Baseline = most common (framework, provider) pair across scanned pages.
 */
import type { PageScanResult, ScanCoverage, ScanResult } from './types';
import { aggregateTechs } from './aggregate';

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
    if (p.error || p.skippedByRobots) continue;
    p.differsFramework = p.framework !== baselineFramework;
    // Cross-domain redirect counts as a provider-level difference signal
    // but the flag stays precise: provider differs OR bounced off-domain.
    p.differsProvider = p.provider !== baselineProvider;
    p.isOddOneOut = p.differsFramework || p.differsProvider || p.crossDomainRedirect;
    if (p.isOddOneOut) oddCount += 1;
  }

  const verdict = oddCount === 0 ? 'consistent' : 'mixed';
  const n = ok.length;
  // Verdict line carries no leading label — presentation layers render the
  // "Consistent"/"Mixed stack" label once from locale copy.
  const verdictLine =
    verdict === 'consistent'
      ? `${n}/${pages.length} pages run ${baselineFramework} + ${baselineProvider}`
      : `${oddCount} of ${pages.length} path${pages.length === 1 ? '' : 's'} differ${oddCount === 1 ? 's' : ''}`;

  // Front-door note: every successful page behind the same named CDN.
  const namedProviders = ok.map((p) => p.provider).filter((p) => p !== 'Unknown');
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
    coverage,
    pages,
    // Per-technology rollups: evidence grouped by techId, confidence
    // per technology. Cards render from this, never from pooled lists.
    techs: aggregateTechs(pages),
    frontDoorNote,
    scannedAt: new Date().toISOString(),
  };
}
