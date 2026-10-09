/**
 * Shared static-scan collection — the single seam both family detectors
 * (security-privacy and growth-marketing) import. No detector duplicates
 * fetch/SSRF/budget/cap logic; all vendor knowledge stays in the
 * per-detector signature data files.
 *
 * Workers Free-tier budgets (enforced here, not in each route):
 * - HTML cap 1 MB, JS bundles 5 x 250 KB, GTM containers 3 x 400 KB.
 * - Max 40 external subrequests per scan invocation (incl. redirects,
 *   HEAD sizings, bundle + container fetches). When the budget truncates
 *   the scan, callers surface a "Partial scan" warning.
 * - Streams are cancelled as soon as the cap is reached so a huge
 *   response can never OOM the Worker. Fetched JS is scanned as text
 *   and never executed.
 *
 * SSRF: every URL (page, redirect hop, bundle, container) goes through
 * validateUrl()/validateRedirect() — non-http(s) schemes, credentials,
 * non-standard ports, localhost and IP literals are blocked. Workers
 * cannot resolve DNS, so private hostnames that resolve to private IPs
 * are additionally blocked by Cloudflare egress guards (documented in
 * /methodology). No DNS-over-HTTPS here: it would burn the subrequest
 * budget for no detection value.
 */

import { validateRedirect, validateUrl } from './ssrf.ts';

export const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 CMSDetector-AI/1.0 (+https://cmsdetectorai.com/methodology)';

export const MAX_HTML_BYTES = 1_000_000;
export const MAX_BUNDLES = 5;
export const MAX_BUNDLE_BYTES = 250_000;
export const BUNDLE_CANDIDATES = 20;
export const BUNDLE_TIMEOUT_MS = 5_000;
export const FETCH_TIMEOUT_MS = 10_000;
export const MAX_REDIRECTS = 5;
export const MAX_SUBREQUESTS = 40;

export const PARTIAL_SCAN_WARNING =
  'Partial scan: large files were only partly scanned.';

/** Mutable subrequest budget shared across every fetch in one scan. */
export interface ScanBudget {
  remaining: number;
  truncated: boolean;
}

export function createBudget(max = MAX_SUBREQUESTS): ScanBudget {
  return { remaining: max, truncated: false };
}

/** Consume one subrequest; returns false (and marks truncated) when spent. */
export function takeBudget(b: ScanBudget): boolean {
  if (b.remaining <= 0) {
    b.truncated = true;
    return false;
  }
  b.remaining -= 1;
  return true;
}

export function extractHeaders(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

export function extractCookieNames(res: Response, headers: Record<string, string>): string[] {
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
    // Never split on ',' — Expires dates contain commas.
    rawCookies = raw.split(/,(?=[^;,=\s]+\s*=)/);
  }
  return rawCookies
    .map((s) => s.split(';')[0].split('=')[0].trim())
    .filter(Boolean);
}

/** Stream a body as text, stopping at maxBytes. Reports truncation. */
export async function readCappedText(
  res: Response,
  maxBytes: number,
): Promise<{ text: string; truncated: boolean }> {
  if (!res.body) {
    const buf = await res.arrayBuffer();
    const cut = buf.byteLength > maxBytes;
    return {
      text: new TextDecoder().decode(cut ? buf.slice(0, maxBytes) : buf),
      truncated: cut,
    };
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        const remaining = maxBytes - total;
        if (remaining <= 0) {
          truncated = true;
          break;
        }
        const slice = value.length > remaining ? value.subarray(0, remaining) : value;
        chunks.push(slice);
        total += slice.length;
        if (total >= maxBytes) {
          // Peek: if the stream is not actually done, we truncated.
          const next = await reader.read();
          if (!next.done) truncated = true;
          if (next.value) {
            /* dropped — over the cap */
          }
          break;
        }
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
  return { text: new TextDecoder().decode(merged), truncated };
}

export type FetchFn = typeof fetch;

export async function fetchWithRedirects(
  startUrl: URL,
  signal: AbortSignal,
  accept: string,
  budget: ScanBudget,
  fetchImpl: FetchFn = fetch,
  opts: { maxRedirects?: number; pinHost?: string } = {},
): Promise<{ res: Response; finalUrl: string } | { error: string }> {
  const maxRedirects = opts.maxRedirects ?? MAX_REDIRECTS;
  let current = startUrl.toString();
  let hops = 0;

  while (hops <= maxRedirects) {
    if (!takeBudget(budget)) return { error: 'Subrequest budget exhausted.' };
    let res: Response;
    try {
      res = await fetchImpl(current, {
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
      if (opts.pinHost && validated.url.hostname.toLowerCase() !== opts.pinHost) {
        return { error: 'Container fetch must not follow redirects off googletagmanager.com.' };
      }
      current = validated.url.toString();
      hops++;
      continue;
    }

    return { res, finalUrl: current };
  }

  return { error: 'Too many redirects — stopped after 5 hops.' };
}

/** First-party (same-origin) script URLs, SSRF-validated, capped. */
export function sameOriginScriptUrls(html: string, pageUrl: string, max = BUNDLE_CANDIDATES): string[] {
  const origin = new URL(pageUrl).origin;
  const out: string[] = [];
  const rx = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(html)) !== null) {
    const src = m[1];
    if (!src || src.startsWith('data:') || src.startsWith('blob:')) continue;
    try {
      const abs = new URL(src, pageUrl).toString();
      if (new URL(abs).origin !== origin) continue;
      if (validateUrl(abs).ok && !out.includes(abs)) out.push(abs);
      if (out.length >= max) break;
    } catch {
      /* skip unresolvable */
    }
  }
  return out;
}

export interface BundleResult {
  bodies: string[];
  truncated: boolean;
}

/**
 * Fetch the largest same-origin JS bundles as text (never executed).
 * HEAD-sizes candidates so bandwidth goes to the largest bundles first.
 */
export async function fetchBundles(
  urls: string[],
  signal: AbortSignal,
  budget: ScanBudget,
  fetchImpl: FetchFn = fetch,
  opts: { maxBundles?: number; maxBytes?: number; timeoutMs?: number } = {},
): Promise<BundleResult> {
  const maxBundles = opts.maxBundles ?? MAX_BUNDLES;
  const maxBytes = opts.maxBytes ?? MAX_BUNDLE_BYTES;
  const timeoutMs = opts.timeoutMs ?? BUNDLE_TIMEOUT_MS;
  let truncated = false;

  const sized = await Promise.all(
    urls.map(async (u) => {
      if (!takeBudget(budget)) {
        truncated = true;
        return { url: u, size: 0 };
      }
      try {
        const head = await fetchImpl(u, { method: 'HEAD', signal, headers: { 'User-Agent': USER_AGENT } });
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
  const top = sized.slice(0, maxBundles);
  if (urls.length > maxBundles) truncated = true;

  const bodies: string[] = [];
  const workers = 3;
  let i = 0;
  async function worker(): Promise<void> {
    for (;;) {
      const idx = i++;
      if (idx >= top.length) return;
      if (!takeBudget(budget)) {
        truncated = true;
        return;
      }
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const res = await fetchImpl(top[idx].url, {
          signal: ctrl.signal,
          headers: { 'User-Agent': USER_AGENT, Accept: '*/*' },
        });
        const ct = (res.headers.get('content-type') ?? '').toLowerCase();
        if (res.ok && (ct.includes('javascript') || ct.includes('ecmascript') || ct === '' || ct.includes('text/plain'))) {
          const { text, truncated: cut } = await readCappedText(res, maxBytes);
          bodies.push(text);
          if (cut) truncated = true;
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
  return { bodies, truncated };
}

// ----------------------------------------------------------------
// Per-IP rate limit + short-TTL cache key helpers (in-memory; the
// routes layer the Cache API on top where available).
// ----------------------------------------------------------------

const rateHits = new Map<string, number[]>();

export function rateLimited(ip: string, max = 20, windowMs = 60_000): boolean {
  const now = Date.now();
  const hits = (rateHits.get(ip) ?? []).filter((t) => now - t < windowMs);
  hits.push(now);
  rateHits.set(ip, hits);
  if (rateHits.size > 10_000) rateHits.clear();
  return hits.length > max;
}

export function clientIp(request: Request): string {
  return (
    request.headers.get('cf-connecting-ip') ??
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    'unknown'
  );
}

export function json(body: unknown, status = 200, extra?: Record<string, string>): Response {
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
