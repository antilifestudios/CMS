/**
 * Multi-path scan budget — single config for free-tier safety.
 *
 * Workers Free: 50 subrequests/invocation, 10ms CPU, 6 concurrent
 * connections. Every redirect hop counts as a subrequest.
 *
 * Typical budget:
 *   1 robots.txt + 1 sitemap.xml
 *   + N pages × ~1.3 fetches (initial + occasional redirect)
 *   + 2 probes + 1 DoH (homepage only)
 * ≈ 35 subrequests for 15 pages. Hard-stop at 50 with honest coverage.
 */

export const SCAN_CONFIG = {
  /** Max sampled paths per scan (brief §2 default 15). */
  MAX_PAGES_PER_SCAN: 15,
  /** Redirect hops followed per page in scan mode (single-detect keeps 5). */
  MAX_REDIRECT_HOPS: 3,
  /** HTML bytes kept per secondary page (homepage keeps 400KB). */
  PER_PAGE_HTML_CAP: 100_000,
  /** Sitemap URLs parsed (hard cap before diversity sampling). */
  SITEMAP_URL_CAP: 500,
  /** Extra user-pasted URLs accepted. */
  MAX_EXTRA_URLS: 5,
  /** Homepage-only probes per scan (never per page). */
  PROBES_PER_SCAN: 2,
  /** Homepage-only DNS hints per scan. */
  DOH_LOOKUPS_PER_SCAN: 1,
  /** Max concurrent page fetches (under the 6-connection cap). */
  CONCURRENCY: 5,
  /** Per-page fetch timeout (ms). */
  PER_PAGE_TIMEOUT_MS: 6_000,
  /** Overall scan wall-clock budget (ms). */
  SCAN_TIMEOUT_MS: 25_000,
  /** Hard subrequest ceiling — stop sampling, don't error. */
  SUBREQUEST_CEILING: 50,
  /** Crawler identity (must match pipeline UA family). */
  USER_AGENT: 'CMSDetector-AI/1.0 (+https://cmsdetectorai.com/blog/how-it-works)',
} as const;

export type ScanConfig = typeof SCAN_CONFIG;
