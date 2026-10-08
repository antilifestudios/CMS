/**
 * POST /api/scan — multi-path consistency scan.
 *
 * Request:  { url: string; extraUrls?: string[]; token?: string }
 * Response: { ok: true, data: ScanResult }
 *         | { ok: false, error: { code: string } }
 *
 * Free-tier abuse layers (same as /api/detect):
 *   1. Turnstile when TURNSTILE_SECRET is set.
 *   2. Cache API 1h on normalised (root + extras) key.
 *   3. Edge rate limiting via a WAF rate-limit rule on /api/scan*
 *      (dashboard — free plan). Body caps enforced here.
 */
import type { APIRoute } from 'astro';
import { runMultiPathScan } from '../../lib/scan/scanner';
import { SCAN_CONFIG } from '../../lib/scan/config';

export const prerender = false;

const TURNSTILE_SECRET = (import.meta.env?.TURNSTILE_SECRET as string | undefined) ?? '';

async function verifyTurnstile(token: string): Promise<boolean> {
  if (!TURNSTILE_SECRET) return true;
  if (!token) return false;
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: TURNSTILE_SECRET, response: token }),
    });
    const data = (await res.json()) as { success: boolean };
    return data.success === true;
  } catch {
    return false;
  }
}

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

function cacheKeyFor(root: string, extras: string[]): string | undefined {
  try {
    const t = root.trim();
    const parsed = new URL(/^https?:\/\//i.test(t) ? t : `https://${t}`);
    const host = parsed.hostname.toLowerCase();
    const ex = extras
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, SCAN_CONFIG.MAX_EXTRA_URLS)
      .sort()
      .join(',');
    return `https://cmsdetectorai.com/api/scan?u=${encodeURIComponent(host)}&x=${encodeURIComponent(ex)}`;
  } catch {
    return undefined;
  }
}

export const OPTIONS: APIRoute = () => new Response(null, { status: 204 });

export const POST: APIRoute = async ({ request }) => {
  let body: { url?: unknown; extraUrls?: unknown; token?: unknown };
  try {
    const text = await request.text();
    if (text.length > 16_384) {
      return json({ ok: false, error: { code: 'INVALID_URL' } }, 400);
    }
    body = JSON.parse(text) as typeof body;
  } catch {
    return json({ ok: false, error: { code: 'INVALID_URL' } }, 400);
  }

  const rawUrl = typeof body.url === 'string' ? body.url.trim() : '';
  const rawExtras = Array.isArray(body.extraUrls)
    ? body.extraUrls.filter((u): u is string => typeof u === 'string').slice(0, SCAN_CONFIG.MAX_EXTRA_URLS)
    : [];
  const cfToken = typeof body.token === 'string' ? body.token : '';

  if (!rawUrl || rawUrl.length > 2048) {
    return json({ ok: false, error: { code: 'INVALID_URL' } }, 400);
  }

  if (!(await verifyTurnstile(cfToken))) {
    return json({ ok: false, error: { code: 'TURNSTILE_FAILED' } }, 403);
  }

  let cache: Cache | undefined;
  const cacheKey = cacheKeyFor(rawUrl, rawExtras);
  try {
    cache = await caches.default;
    if (cacheKey) {
      const cached = await cache.match(cacheKey);
      if (cached) return json(JSON.parse(await cached.text()), 200, { 'X-Cache': 'HIT' });
    }
  } catch {
    cache = undefined;
  }

  const result = await runMultiPathScan(rawUrl, rawExtras);

  if (cache && cacheKey && result.ok) {
    try {
      await cache.put(
        new Request(cacheKey),
        new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600' },
        })
      );
    } catch {
      /* non-fatal */
    }
  }

  return json(result, 200, { 'X-Cache': 'MISS' });
};

export const GET: APIRoute = () => json({ ok: false, error: { code: 'UNKNOWN' } }, 405);
