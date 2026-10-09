/**
 * POST /api/growth-detect
 *
 * Request body (JSON):  { url: string }
 * Response body (JSON):
 *   { url, finalUrl, scannedAt, mode: "static",
 *     categories: [{ id, name, count,
 *       technologies: [{ id, name, website, band, confidence,
 *         score: 0-100, score100: 0-100,
 *         evidence: [{ type, detail }], extractedIds: [{ kind, value }],
 *         subNote?, variantNote? }] }],
 *     warnings: [] }
 *
 * Static scan only (same passes as the security-privacy detector):
 * HTML fetch (SSRF guard, redirects, caps) → first-party JS bundles →
 * GTM container expansion (shared module; container evidence weighs
 * 0.70 and never reaches the top band alone). All fetch/SSRF/budget
 * logic is REUSED from static-collect.ts / gtm-expansion.ts; all vendor
 * knowledge lives in growth-marketing-signatures.ts.
 *
 * "Not detected" never means "not used": consent-gated tags,
 * server-side tagging, first-party proxies and Zaraz can hide vendor
 * hosts — surfaced as warnings, never as revenue/business language.
 */

import type { APIRoute } from 'astro';
import { validateUrl } from '../../lib/detect/ssrf';
import {
  detectGrowthMarketing,
  groupGrowthByCategory,
  serverSideWarning,
} from '../../lib/detect/growth-marketing';
import {
  BUNDLE_TIMEOUT_MS,
  FETCH_TIMEOUT_MS,
  MAX_BUNDLE_BYTES,
  MAX_BUNDLES,
  MAX_HTML_BYTES,
  PARTIAL_SCAN_WARNING,
  clientIp,
  createBudget,
  extractCookieNames,
  extractHeaders,
  fetchBundles,
  fetchWithRedirects,
  json,
  rateLimited,
  readCappedText,
  sameOriginScriptUrls,
} from '../../lib/detect/static-collect';
import { extractGtmIds, fetchGtmContainers } from '../../lib/detect/gtm-expansion';

export const prerender = false;

const CACHE_TTL_SECONDS = 600;
const DETECTOR_REVISION = 1;

const STATIC_ONLY_WARNING =
  'Static scan including GTM container contents. Tools loaded after user consent or via server-side tagging may not be detected.';

const memoryCache = new Map<string, { body: string; expires: number }>();

function cacheKeyFor(rawUrl: string): string | undefined {
  try {
    const trimmed = rawUrl.trim();
    const parsed = new URL(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    const host = parsed.hostname.toLowerCase();
    const path = parsed.pathname.replace(/\/+$/, '') || '/';
    return `https://cmsdetectorai.com/api/growth-detect?rev=${DETECTOR_REVISION}&u=${encodeURIComponent(host + path + parsed.search)}`;
  } catch {
    return undefined;
  }
}

export const OPTIONS: APIRoute = () => new Response(null, { status: 204 });

export const POST: APIRoute = async ({ request }) => {
  if (rateLimited(clientIp(request))) {
    return json({ ok: false, error: { code: 'RATE_LIMITED', message: 'Too many requests — please wait a minute and try again.' } }, 429);
  }

  let body: { url?: unknown };
  try {
    const text = await request.text();
    if (text.length > 8192) return json({ ok: false, error: { code: 'INVALID_URL', message: 'Invalid URL.' } }, 400);
    body = JSON.parse(text) as typeof body;
  } catch {
    return json({ ok: false, error: { code: 'INVALID_URL', message: 'Invalid request body.' } }, 400);
  }

  const rawUrl = typeof body.url === 'string' ? body.url.trim() : '';
  if (!rawUrl || rawUrl.length > 2048) {
    return json({ ok: false, error: { code: 'INVALID_URL', message: 'Enter a valid website URL (e.g. https://example.com).' } }, 400);
  }

  const validated = validateUrl(rawUrl);
  if (!validated.ok) {
    const code = validated.code === 'PRIVATE_IP' ? 'PRIVATE_IP' : 'INVALID_URL';
    return json({ ok: false, error: { code, message: validated.message } }, 400);
  }

  const cacheKey = cacheKeyFor(rawUrl);
  try {
    const cache = await caches.default;
    if (cacheKey) {
      const cached = await cache.match(cacheKey);
      if (cached) return json(JSON.parse(await cached.text()), 200, { 'X-Cache': 'HIT' });
    }
  } catch {
    const mem = cacheKey ? memoryCache.get(cacheKey) : undefined;
    if (mem && mem.expires > Date.now()) {
      return json(JSON.parse(mem.body), 200, { 'X-Cache': 'HIT' });
    }
  }

  const budget = createBudget();
  const warnings: string[] = [STATIC_ONLY_WARNING];

  // Pass 1: fetch HTML.
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let res: Response;
  let finalUrl: string;
  try {
    const fetched = await fetchWithRedirects(
      validated.url,
      controller.signal,
      'text/html,application/xhtml+xml,*/*;q=0.8',
      budget,
    );
    if ('error' in fetched) {
      return json({ ok: false, error: { code: 'FETCH_FAILED', message: fetched.error } }, 502);
    }
    res = fetched.res;
    finalUrl = fetched.finalUrl;
  } finally {
    clearTimeout(timeoutId);
  }

  const headers = extractHeaders(res);
  const cookies = extractCookieNames(res, headers);
  const contentType = (headers['content-type'] ?? '').toLowerCase();
  if (contentType && !contentType.includes('text/html') && !contentType.includes('application/xhtml')) {
    return json(
      { ok: false, error: { code: 'NON_HTML', message: 'The URL returned a non-HTML response (e.g. an image, PDF, or API endpoint).' } },
      422,
    );
  }

  let html: string;
  try {
    const { text, truncated } = await readCappedText(res, MAX_HTML_BYTES);
    html = text;
    if (truncated) warnings.push(PARTIAL_SCAN_WARNING);
  } catch {
    return json({ ok: false, error: { code: 'TIMEOUT', message: 'The request timed out while reading the page.' } }, 504);
  }
  try {
    if (res.body) await res.arrayBuffer().catch(() => undefined);
  } catch {
    /* noop */
  }

  // Pass 2: largest first-party JS bundles (bounded).
  let bundleJs: string[] = [];
  try {
    const bundleUrls = sameOriginScriptUrls(html, finalUrl);
    if (bundleUrls.length > 0) {
      const bCtrl = new AbortController();
      const bTimeout = setTimeout(() => bCtrl.abort(), 8_000);
      try {
        const { bodies, truncated } = await fetchBundles(bundleUrls, bCtrl.signal, budget, fetch, {
          maxBundles: MAX_BUNDLES,
          maxBytes: MAX_BUNDLE_BYTES,
          timeoutMs: BUNDLE_TIMEOUT_MS,
        });
        bundleJs = bodies;
        if (truncated) warnings.push(PARTIAL_SCAN_WARNING);
      } finally {
        clearTimeout(bTimeout);
      }
    }
  } catch {
    bundleJs = [];
  }

  // Pass 3: GTM container expansion (shared module, fail-soft).
  let gtmContainers: Array<{ id: string; js: string }> = [];
  try {
    const gtmIds = extractGtmIds(html, bundleJs);
    if (gtmIds.length > 0) {
      const gCtrl = new AbortController();
      const gTimeout = setTimeout(() => gCtrl.abort(), 8_000);
      try {
        const { containers, warnings: gtmWarnings } = await fetchGtmContainers(gtmIds, gCtrl.signal, budget);
        gtmContainers = containers;
        warnings.push(...gtmWarnings);
        if (containers.some((c) => c.truncated)) warnings.push(PARTIAL_SCAN_WARNING);
      } finally {
        clearTimeout(gTimeout);
      }
    }
  } catch {
    warnings.push('GTM container expansion unavailable; kept normal results.');
  }

  const serverWarning = serverSideWarning(html, bundleJs);
  if (serverWarning) warnings.push(serverWarning);
  if (budget.truncated) warnings.push(PARTIAL_SCAN_WARNING);

  const technologies = detectGrowthMarketing({ html, headers, cookies, bundleJs, gtmContainers });
  const categories = groupGrowthByCategory(technologies);

  const payload = {
    ok: true,
    url: rawUrl,
    finalUrl,
    scannedAt: new Date().toISOString(),
    mode: 'static' as const,
    categories,
    warnings: [...new Set(warnings)],
  };

  if (cacheKey) {
    try {
      const cache = await caches.default;
      await cache.put(
        new Request(cacheKey),
        new Response(JSON.stringify(payload), {
          headers: { 'Content-Type': 'application/json', 'Cache-Control': `public, max-age=${CACHE_TTL_SECONDS}` },
        }),
      );
    } catch {
      memoryCache.set(cacheKey, { body: JSON.stringify(payload), expires: Date.now() + CACHE_TTL_SECONDS * 1000 });
    }
  }

  return json(payload, 200, { 'X-Cache': 'MISS' });
};

export const GET: APIRoute = () => {
  return json({ ok: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Use POST with { url }.' } }, 405);
};
