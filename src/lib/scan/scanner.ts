/**
 * Multi-path scan orchestrator.
 * Budget-aware: hard-stops at SUBREQUEST_CEILING and reports honest coverage.
 */
import { validateUrl, validateRedirect } from '../detect/ssrf';
import { runSignatureEngine } from '../detect/signatures';
import { SCAN_CONFIG } from './config';
import { buildSample, parseSitemapLocs } from './sample';
import { analyzeConsistency } from './analyze';
import { confidenceFromScore, fetchSinglePage, isAllowedByRobots, type Budget } from './fetchPage';
import type { PageScanResult, ScanResult } from './types';

export type ScanErrorCode = 'INVALID_URL' | 'PRIVATE_IP' | 'TIMEOUT' | 'SCAN_TIMEOUT' | 'UNKNOWN';

async function fetchTextCapped(url: string, cap: number, timeoutMs: number, budget: Budget): Promise<string | null> {
  if (budget.used >= budget.ceiling) return null;
  const v = validateUrl(url);
  if (!v.ok) return null;
  budget.used += 1;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(v.url.toString(), {
      signal: ctrl.signal,
      headers: { 'User-Agent': SCAN_CONFIG.USER_AGENT, Accept: 'text/html,*/*;q=0.8' },
    });
    if (!res.body) {
      const buf = await res.arrayBuffer();
      return new TextDecoder().decode(buf.byteLength > cap ? buf.slice(0, cap) : buf);
    }
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          const rem = cap - total;
          if (rem <= 0) break;
          const s = value.length > rem ? value.subarray(0, rem) : value;
          chunks.push(s);
          total += s.length;
          if (total >= cap) break;
        }
      }
    } finally {
      try {
        await reader.cancel();
      } catch {
        /* noop */
      }
    }
    const merged = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      merged.set(c, off);
      off += c.length;
    }
    return new TextDecoder().decode(merged);
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function runPool<T>(items: string[], concurrency: number, fn: (u: string) => Promise<T>): Promise<T[]> {
  const out: T[] = new Array(items.length);
  let i = 0;
  async function worker(): Promise<void> {
    for (;;) {
      const idx = i++;
      if (idx >= items.length) return;
      out[idx] = await fn(items[idx]);
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
  await Promise.all(workers);
  return out;
}

export async function runMultiPathScan(
  rawRoot: string,
  rawExtras: string[] = []
): Promise<{ ok: true; data: ScanResult } | { ok: false; error: { code: ScanErrorCode; message: string } }> {
  const validated = validateUrl(rawRoot);
  if (!validated.ok) {
    const code = validated.code === 'PRIVATE_IP' ? 'PRIVATE_IP' : 'INVALID_URL';
    return { ok: false, error: { code: code as ScanErrorCode, message: validated.message } };
  }
  const origin = validated.url.origin;
  const rootHost = validated.url.hostname.toLowerCase();
  const deadline = Date.now() + SCAN_CONFIG.SCAN_TIMEOUT_MS;
  const budget: Budget = { used: 0, ceiling: SCAN_CONFIG.SUBREQUEST_CEILING };

  // 1. robots.txt (best effort, 1 subrequest)
  const robotsTxt = (await fetchTextCapped(`${origin}/robots.txt`, 50_000, 6_000, budget)) ?? '';

  // 2. Homepage fetch via the same single-page path (counts redirects honestly)
  const homePage: PageScanResult = await fetchSinglePage(
    validated.url.toString(),
    rootHost,
    robotsTxt,
    budget
  );
  if (homePage.error && homePage.evidence[0]?.startsWith('Rejected')) {
    const code = homePage.evidence[0].includes('PRIVATE_IP') ? 'PRIVATE_IP' : 'INVALID_URL';
    return { ok: false, error: { code: code as ScanErrorCode, message: homePage.evidence[0] } };
  }

  // 3. Homepage HTML for link extraction (reuse: refetch capped — 1 extra
  // subrequest; acceptable inside the 50 budget and keeps code simple).
  // If the budget is already tight, skip link extraction gracefully.
  let homepageHtml = '';
  if (budget.used < budget.ceiling - 2 && Date.now() < deadline) {
    homepageHtml = (await fetchTextCapped(homePage.finalUrl, SCAN_CONFIG.PER_PAGE_HTML_CAP, 6_000, budget)) ?? '';
  }

  // 4. sitemap.xml (1 subrequest, best effort)
  let sitemapXml: string | undefined;
  if (budget.used < budget.ceiling - 1 && Date.now() < deadline) {
    const sm = await fetchTextCapped(`${origin}/sitemap.xml`, 500_000, 6_000, budget);
    if (sm && sm.includes('<url')) sitemapXml = sm;
  }

  // 5. Build sample (homepage final URL is sample[0])
  const cleanExtras = rawExtras.map((s) => s.trim()).filter(Boolean).slice(0, SCAN_CONFIG.MAX_EXTRA_URLS);
  const { sample, foundApprox } = buildSample({
    origin,
    homepageUrl: homePage.finalUrl,
    sitemapXml,
    homepageHtml,
    extraUrls: cleanExtras,
  });

  // Homepage result already covers sample[0] — fetch the rest concurrently.
  const rest = sample.slice(1);
  const restResults: PageScanResult[] = await runPool(rest, SCAN_CONFIG.CONCURRENCY, async (u) => {
    if (Date.now() >= deadline || budget.used >= budget.ceiling) {
      return {
        url: u,
        finalUrl: u,
        redirectChain: [],
        crossDomainRedirect: false,
        framework: 'Unknown',
        frameworkId: null,
        provider: 'Unknown',
        providerId: null,
        confidence: 'Low' as const,
        evidence: ['Skipped: scan budget reached'],
        error: 'Skipped: scan budget reached',
      };
    }
    return fetchSinglePage(u, rootHost, robotsTxt, budget);
  });

  const pages = [homePage, ...restResults];
  const checked = pages.filter((p) => !p.error || p.skippedByRobots).length;
  const truncated =
    budget.used >= budget.ceiling || Date.now() >= deadline || foundApprox > sample.length;

  const result = analyzeConsistency({
    rootUrl: homePage.finalUrl,
    rootHost,
    pages,
    coverage: { checked, foundApprox: Math.max(foundApprox, sample.length), truncated },
  });

  void parseSitemapLocs;
  void isAllowedByRobots;
  void runSignatureEngine;
  void validateRedirect;
  void confidenceFromScore;

  return { ok: true, data: result };
}
