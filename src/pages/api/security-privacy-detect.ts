/**
 * POST /api/security-privacy-detect
 *
 * Request body (JSON):  { url: string }
 * Response body (JSON): { url, finalUrl, scannedAt, mode, categories, warnings }
 *   categories: [{ id, name, count, technologies: [{ id, name, website,
 *                 confidence: "high"|"medium"|"low", score: 0-1,
 *                 evidence: [{ type, detail }] }] }]
 *
 * Architecture (v1):
 * - Pass 1 (static): fetch HTML (≤5 redirects, 10s timeout, 3MB cap,
 *   realistic User-Agent), channel-parse it, then fetch up to 10
 *   same-origin JS bundles (size-capped) for bundled SDK init strings.
 * - Pass 2 (rendered headless browser): NOT available in this runtime —
 *   mode is always "static" and a visible warning is returned. The
 *   detector accepts a Pass-2 seam (globals / networkRequests /
 *   storageKeys) so rendering can be plugged in without touching logic.
 *
 * Security: SSRF guard (validateUrl + validateRedirect on every hop and
 * bundle URL; Workers egress blocks private ranges as backstop),
 * in-memory per-IP rate limit, strict timeouts, response-size caps,
 * fetched JS is scanned as text and never executed. Short-TTL result
 * cache keyed by normalized URL.
 */

import type { APIRoute } from 'astro';
import { validateUrl, validateRedirect } from '../../lib/detect/ssrf';
import {
  detectSecurityPrivacy,
  extractChannels,
  groupByCategory,
} from '../../lib/detect/security-privacy';

export const prerender = false;

// ----------------------------------------------------------------
// Tuning
// ----------------------------------------------------------------

const MAX_HTML_BYTES = 3_000_000; // 3 MB cap
const MAX_REDIRECTS = 5;
const FETCH_TIMEOUT_MS = 10_000;
const BUNDLE_TIMEOUT_MS = 5_000;
const MAX_BUNDLES = 10;
const BUNDLE_CANDIDATES = 20;
const MAX_BUNDLE_BYTES = 300_000; // per-bundle cap
const CACHE_TTL_SECONDS = 600; // short TTL: 10 min
const DETECTOR_REVISION = 1;

/** Rate limit: max requests per window per client IP. */
const RATE_MAX = 20;
const RATE_WINDOW_MS = 60_000;
const rateHits = new Map<string, number[]>();

/** Dev fallback when the Cache API is unavailable. */
const memoryCache = new Map<string, { body: string; expires: number }>();

const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 CMSDetector-AI/1.0 (+https://cmsdetectorai.com/methodology)';

const STATIC_ONLY_WARNING =
  'Static scan only: tools injected via tag managers may be missed.';

// ----------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------

function json(body: unknown, status = 200, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      ...extra,
    },
  });
}

function clientIp(request: Request): string {
  return (
    request.headers.get('cf-connecting-ip') ??
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    'unknown'
  );
}

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const hits = (rateHits.get(ip) ?? []).filter((t) => now - t < RATE_WINDOW_MS);
  hits.push(now);
  rateHits.set(ip, hits);
  if (rateHits.size > 10_000) rateHits.clear();
  return hits.length > RATE_MAX;
}

function cacheKeyFor(rawUrl: string): string | undefined {
  try {
    const trimmed = rawUrl.trim();
    const parsed = new URL(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    const host = parsed.hostname.toLowerCase();
    const path = parsed.pathname.replace(/\/+$/, '') || '/';
    return `https://cmsdetectorai.com/api/security-privacy-detect?rev=${DETECTOR_REVISION}&u=${encodeURIComponent(host + path + parsed.search)}`;
  } catch {
    return undefined;
  }
}

async function readCappedText(res: Response, maxBytes: number): Promise<string> {
  if (!res.body) {
    const buf = await res.arrayBuffer();
    return new TextDecoder().decode(buf.byteLength > maxBytes ? buf.slice(0, maxBytes) : buf);
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        const remaining = maxBytes - total;
        if (remaining <= 0) break;
        const slice = value.length > remaining ? value.subarray(0, remaining) : value;
        chunks.push(slice);
        total += slice.length;
        if (total >= maxBytes) break;
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
}

function extractHeaders(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

function extractCookieNames(res: Response, headers: Record<string, string>): string[] {
  let rawCookies: string[] = [];
  const getter = (res.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getter === 'function') {
    try {
      rawCookies = getter.call(res.headers);
    } catch {
      rawCookies = [];
    }
  }
  if (rawCookies.length === 0) {
    const raw = headers['set-cookie'] ?? '';
    if (!raw) return [];
    rawCookies = raw.split(/,(?=[^;,=\s]+\s*=)/);
  }
  return rawCookies
    .map((s) => s.split(';')[0].split('=')[0].trim())
    .filter(Boolean);
}

// ----------------------------------------------------------------
// Fetch with redirect following + per-hop SSRF re-validation
// ----------------------------------------------------------------

async function fetchWithRedirects(
  startUrl: URL,
  signal: AbortSignal,
  accept: string,
): Promise<{ res: Response; finalUrl: string } | { error: string }> {
  let current = startUrl.toString();
  let hops = 0;

  while (hops <= MAX_REDIRECTS) {
    let res: Response;
    try {
      res = await fetch(current, {
        redirect: 'manual',
        signal,
        headers: { 'User-Agent': USER_AGENT, Accept: accept, 'Accept-Language': 'en-US,en;q=0.9' },
      });
    } catch (e: unknown) {
      const msg = String(e);
      if (msg.includes('abort')) return { error: 'The request timed out. The site may be slow or blocking automated access.' };
      if (msg.includes('certificate') || msg.includes('SSL') || msg.includes('TLS')) {
        return { error: 'The site has a TLS certificate error.' };
      }
      return { error: 'Could not fetch the site. Check the URL and try again.' };
    }

    if (res.status >= 301 && res.status <= 308) {
      const location = res.headers.get('location');
      try {
        await res.arrayBuffer();
      } catch {
        /* noop */
      }
      if (!location) return { error: 'The site returned a broken redirect.' };
      const validated = validateRedirect(location, current);
      if (!validated.ok) return { error: 'The site redirected to a blocked address.' };
      current = validated.url.toString();
      hops++;
      continue;
    }

    return { res, finalUrl: current };
  }

  return { error: 'Too many redirects — stopped after 5 hops.' };
}

// ----------------------------------------------------------------
// First-party JS bundles (Pass 1b): HEAD-size the same-origin scripts,
// fetch the largest MAX_BUNDLES as text (never executed).
// ----------------------------------------------------------------

function sameOriginScriptUrls(html: string, pageUrl: string): string[] {
  const origin = new URL(pageUrl).origin;
  const out: string[] = [];
  const rx = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(html)) !== null) {
    const src = m[1];
    if (!src || src.startsWith('data:') || src.startsWith('blob:')) continue;
    try {
      const abs = new URL(src, pageUrl).toString();
      if (new URL(abs).origin !== origin) continue; // first-party only
      if (validateUrl(abs).ok && !out.includes(abs)) out.push(abs);
      if (out.length >= BUNDLE_CANDIDATES) break;
    } catch {
      /* skip unresolvable */
    }
  }
  return out;
}

async function fetchBundles(urls: string[], signal: AbortSignal): Promise<string[]> {
  // Size candidates with HEAD so we fetch the LARGEST same-origin bundles.
  const sized = await Promise.all(
    urls.map(async (u) => {
      try {
        const head = await fetch(u, {
          method: 'HEAD',
          signal,
          headers: { 'User-Agent': USER_AGENT },
        });
        const len = Number(head.headers.get('content-length') ?? '0');
        try {
          await head.arrayBuffer();
        } catch {
          /* noop */
        }
        return { url: u, size: Number.isFinite(len) ? len : 0 };
      } catch {
        return { url: u, size: 0 };
      }
    }),
  );
  sized.sort((a, b) => b.size - a.size);
  const top = sized.slice(0, MAX_BUNDLES);

  const bodies: string[] = [];
  // Small concurrency pool — bounded time, bounded bytes.
  const workers = 3;
  let i = 0;
  async function worker(): Promise<void> {
    for (;;) {
      const idx = i++;
      if (idx >= top.length) return;
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), BUNDLE_TIMEOUT_MS);
      try {
        const res = await fetch(top[idx].url, {
          signal: ctrl.signal,
          headers: { 'User-Agent': USER_AGENT, Accept: '*/*' },
        });
        const ct = (res.headers.get('content-type') ?? '').toLowerCase();
        if (res.ok && (ct.includes('javascript') || ct.includes('ecmascript') || ct === '' || ct.includes('text/plain'))) {
          bodies.push(await readCappedText(res, MAX_BUNDLE_BYTES));
        } else {
          try {
            await res.arrayBuffer();
          } catch {
            /* noop */
          }
        }
      } catch {
        /* bundle failed — skip silently */
      } finally {
        clearTimeout(t);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(workers, top.length) }, () => worker()));
  void signal;
  return bodies;
}

// ----------------------------------------------------------------
// Route
// ----------------------------------------------------------------

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

  // Short-TTL cache (Cache API, in-memory fallback for local dev).
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
    html = await readCappedText(res, MAX_HTML_BYTES);
  } catch {
    return json({ ok: false, error: { code: 'TIMEOUT', message: 'The request timed out while reading the page.' } }, 504);
  }
  try {
    if (res.body) await res.arrayBuffer().catch(() => undefined);
  } catch {
    /* noop */
  }

  // Pass 1b: first-party JS bundles (bounded).
  let bundleJs: string[] = [];
  try {
    const bundleUrls = sameOriginScriptUrls(html, finalUrl);
    if (bundleUrls.length > 0) {
      const bCtrl = new AbortController();
      const bTimeout = setTimeout(() => bCtrl.abort(), 8_000);
      try {
        bundleJs = await fetchBundles(bundleUrls, bCtrl.signal);
      } finally {
        clearTimeout(bTimeout);
      }
    }
  } catch {
    bundleJs = [];
  }

  // Detect (Pass 2 seam left empty → static mode).
  const ch = extractChannels(html, headers);
  void ch;
  const technologies = detectSecurityPrivacy({ html, headers, cookies, bundleJs });
  const categories = groupByCategory(technologies);

  const payload = {
    ok: true,
    url: rawUrl,
    finalUrl,
    scannedAt: new Date().toISOString(),
    mode: 'static' as const,
    categories,
    warnings: [STATIC_ONLY_WARNING],
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
