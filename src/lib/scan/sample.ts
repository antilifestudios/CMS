/**
 * Page sampler — pure functions, no network.
 * Priority: homepage → diverse sitemap prefixes → homepage links → extra URLs.
 */
import { SCAN_CONFIG } from './config';

function sameOrigin(u: string, origin: string): boolean {
  try {
    const a = new URL(u);
    const b = new URL(origin);
    return a.protocol.startsWith('http') && a.hostname.toLowerCase() === b.hostname.toLowerCase();
  } catch {
    return false;
  }
}

function normalisePath(url: string): string {
  try {
    const u = new URL(url);
    u.hash = '';
    // Strip trailing slash except root
    if (u.pathname.length > 1) u.pathname = u.pathname.replace(/\/+$/, '');
    return u.toString();
  } catch {
    return url;
  }
}

function firstSegment(pathname: string): string {
  const seg = pathname.split('/').filter(Boolean)[0] ?? '/';
  return `/${seg}`;
}

/** Extract <loc> URLs from a sitemap (or sitemap index — nested indexes resolved by caller). */
export function parseSitemapLocs(xml: string, cap = SCAN_CONFIG.SITEMAP_URL_CAP): string[] {
  const out: string[] = [];
  const rx = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(xml)) !== null) {
    // Skip nested sitemap indexes (*.xml) — page URLs only
    const loc = m[1].trim();
    if (/sitemap.*\.xml$/i.test(loc)) continue;
    out.push(loc);
    if (out.length >= cap) break;
  }
  return out;
}

/** Pick at most one URL per path prefix, round-robin, to maximise diversity. */
export function pickDiverse(urls: string[], limit: number): string[] {
  const byPrefix = new Map<string, string[]>();
  for (const u of urls) {
    let prefix = '/';
    try {
      prefix = firstSegment(new URL(u).pathname);
    } catch {
      continue;
    }
    if (!byPrefix.has(prefix)) byPrefix.set(prefix, []);
    byPrefix.get(prefix)!.push(u);
  }
  const groups = [...byPrefix.values()];
  const picked: string[] = [];
  let round = 0;
  while (picked.length < limit && groups.length > 0) {
    let progressed = false;
    for (const g of groups) {
      if (picked.length >= limit) break;
      if (round < g.length) {
        picked.push(g[round]);
        progressed = true;
      }
    }
    if (!progressed) break;
    round++;
  }
  return picked;
}

const ASSET_EXT = /\.(css|js|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|map|json|xml|txt|pdf|zip)$/i;

/** Extract same-origin HTML page links from homepage HTML (regex only, no DOM). */
export function extractInternalLinks(html: string, origin: string, cap = 100): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const rx = /<a[^>]+href=["']([^"'#]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(html)) !== null) {
    const raw = m[1].trim();
    if (!raw || raw.startsWith('mailto:') || raw.startsWith('tel:') || raw.startsWith('javascript:')) continue;
    let abs: string;
    try {
      abs = new URL(raw, origin).toString();
    } catch {
      continue;
    }
    if (!sameOrigin(abs, origin)) continue;
    if (ASSET_EXT.test(abs.split('?')[0])) continue;
    const n = normalisePath(abs);
    if (seen.has(n)) continue;
    seen.add(n);
    out.push(n);
    if (out.length >= cap) break;
  }
  return out;
}

export interface SamplePlan {
  sample: string[];
  unscannedUrls: string[];
  foundApprox: number;
}

/**
 * Build the capped page sample.
 * Homepage is always sample[0].
 */
export function buildSample(opts: {
  origin: string;
  homepageUrl: string;
  sitemapXml?: string;
  homepageHtml?: string;
  extraUrls?: string[];
  maxPages?: number;
}): SamplePlan {
  const maxPages = opts.maxPages ?? SCAN_CONFIG.MAX_PAGES_PER_SCAN;
  const seen = new Set<string>();
  const sample: string[] = [];

  const push = (u: string) => {
    const n = normalisePath(u);
    if (seen.has(n) || sample.length >= maxPages) return;
    seen.add(n);
    sample.push(n);
  };

  push(opts.homepageUrl);

  const sitemapLocs = opts.sitemapXml
    ? parseSitemapLocs(opts.sitemapXml).filter((u) => sameOrigin(u, opts.origin))
    : [];
  const diverse = pickDiverse(sitemapLocs, maxPages);
  for (const u of diverse) {
    if (sample.length >= maxPages) break;
    push(u);
  }

  const homepageLinks = opts.homepageHtml
    ? extractInternalLinks(opts.homepageHtml, opts.origin, 1000)
    : [];

  if (sample.length < maxPages) {
    for (const u of homepageLinks) {
      if (sample.length >= maxPages) break;
      push(u);
    }
  }

  // User-pasted extras: same-host only (cross-host would break the
  // per-domain consistency story; they surface as redirect findings instead).
  const extras = (opts.extraUrls ?? []).slice(0, SCAN_CONFIG.MAX_EXTRA_URLS);
  for (const raw of extras) {
    if (sample.length >= maxPages) break;
    try {
      const abs = new URL(raw, opts.origin).toString();
      if (!sameOrigin(abs, opts.origin)) continue;
      push(abs);
    } catch {
      continue;
    }
  }

  // Collect discovered unscanned URLs (preview of up to 15 additional discovered URLs)
  const unscannedUrls: string[] = [];
  const unscannedSeen = new Set<string>(seen);
  const addUnscanned = (u: string) => {
    const n = normalisePath(u);
    if (unscannedSeen.has(n) || unscannedUrls.length >= 15) return;
    unscannedSeen.add(n);
    unscannedUrls.push(n);
  };

  for (const u of sitemapLocs) {
    addUnscanned(u);
    if (unscannedUrls.length >= 15) break;
  }
  for (const u of homepageLinks) {
    addUnscanned(u);
    if (unscannedUrls.length >= 15) break;
  }

  const foundApprox = Math.max(sitemapLocs.length, homepageLinks.length, sample.length);

  return { sample, unscannedUrls, foundApprox };
}
