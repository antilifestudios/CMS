/**
 * Multi-path scan types.
 * Workers-runtime compatible — plain data, no Node APIs.
 */

export type ConfidenceLevel = 'High' | 'Medium' | 'Low';

export interface RedirectHop {
  url: string;
  status: number;
}

export interface StackSignal {
  /** e.g. "Astro", "Next.js", "WordPress", "Unknown" */
  framework: string;
  frameworkId: string | null;
  /** e.g. "Cloudflare", "Vercel", "Unknown" */
  provider: string;
  providerId: string | null;
  confidence: ConfidenceLevel;
  evidence: string[];
}

export interface PageScanResult extends StackSignal {
  url: string;
  finalUrl: string;
  redirectChain: RedirectHop[];
  /** True when final host differs from scanned host. */
  crossDomainRedirect: boolean;
  skippedByRobots?: boolean;
  error?: string;
  /** Why this row differs from the site baseline, if it does. */
  differsFramework?: boolean;
  differsProvider?: boolean;
  isOddOneOut?: boolean;
}

export interface ScanCoverage {
  checked: number;
  foundApprox: number;
  truncated: boolean;
}

export interface ScanResult {
  rootUrl: string;
  rootHost: string;
  verdict: 'consistent' | 'mixed';
  baselineFramework: string;
  baselineProvider: string;
  /** e.g. "Consistent: 12/12 pages run Astro + Cloudflare" */
  verdictLine: string;
  coverage: ScanCoverage;
  pages: PageScanResult[];
  /** Shown when every page sits behind the same CDN. */
  frontDoorNote: boolean;
  scannedAt: string;
}

export interface ScanInput {
  rootUrl: string;
  extraUrls: string[];
}
