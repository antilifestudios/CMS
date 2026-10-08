/**
 * Multi-path scan types.
 * Workers-runtime compatible — plain data, no Node APIs.
 */

export type ConfidenceLevel = 'High' | 'Medium' | 'Low';

export interface RedirectHop {
  url: string;
  status: number;
}

/**
 * One piece of evidence, always owned by the technology whose rule
 * produced it. `techId` is the grouping key — evidence must never be
 * pooled into a shared list and shown under a different technology.
 */
export interface TechEvidenceItem {
  /** Technology id, e.g. "astro", "cloudflare" */
  techId: string;
  /** Display name, e.g. "Google Analytics" (falls back to techId) */
  techName?: string;
  /** Slug for /cms/[slug] links, when the tech has a content page. */
  pageSlug?: string;
  /** Signal channel, e.g. "header", "html-regex", "html-path" */
  signalType: string;
  /**
   * Stable signal name used for dedupe across pages, e.g. "cf-ray"
   * for headers or the matched pattern for HTML signals.
   */
  name: string;
  /** One sample value for display (values differ per page) */
  value: string;
  /** Page this evidence was observed on */
  pageUrl: string;
  /** Fingerprint strength of the rule that produced this evidence. */
  strength: 'definitive' | 'strong' | 'weak';
}

/**
 * One deduplicated evidence line for display: a single signal seen
 * on one or more pages, with a sample value and a page count.
 */
export interface AggregatedEvidence {
  signalType: string;
  name: string;
  sampleValue: string;
  /** Distinct pages where this signal was seen */
  pagesSeen: number;
  /** Strongest rule strength observed for this signal. */
  strength: 'definitive' | 'strong' | 'weak';
}

/**
 * Site-level rollup for one technology: detected when seen on any
 * sampled page; confidence is computed from this tech's own signals.
 */
export interface AggregatedTech {
  techId: string;
  name: string;
  kind: 'framework' | 'hosting' | 'other';
  confidence: ConfidenceLevel;
  /** Deterministic 0–100 evidence score (see lib/detect/confidence). */
  score?: number;
  scoreLabel?: 'VERY HIGH' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT';
  /** Distinct successful pages where this tech was detected */
  detectedOn: number;
  /** Successful pages checked (denominator for detectedOn) */
  checkedPages: number;
  /** Deduplicated, strongest signal first */
  evidence: AggregatedEvidence[];
  /** Slug for /cms/[slug] links, when the tech has a content page. */
  pageSlug?: string;
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
  /**
   * Per-technology evidence for this page, tagged with techId.
   * Cards must aggregate from this (grouped by techId), never from
   * the legacy flat `evidence` list below.
   */
  techEvidence?: TechEvidenceItem[];
  /** This page's own confidence per technology (not shared). */
  frameworkConfidence?: ConfidenceLevel;
  providerConfidence?: ConfidenceLevel;
  /** Slugs for /cms/[slug] links, when the techs have content pages. */
  frameworkSlug?: string | null;
  providerSlug?: string | null;
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
  /** e.g. "12/12 pages run Astro + Cloudflare" (no leading label) */
  verdictLine: string;
  coverage: ScanCoverage;
  pages: PageScanResult[];
  /**
   * Per-technology rollups (grouped by techId, deduplicated).
   * Summary cards must render from this — one card per technology,
   * showing only that technology's own evidence and confidence.
   */
  techs?: AggregatedTech[];
  /** Shown when every page sits behind the same CDN. */
  frontDoorNote: boolean;
  scannedAt: string;
}

export interface ScanInput {
  rootUrl: string;
  extraUrls: string[];
}
