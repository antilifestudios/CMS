/**
 * POST /api/detect
 *
 * Request body (JSON):
 *   { url: string; token?: string }
 *
 * Response body (JSON):
 *   { ok: true, data: PipelineSuccess }
 *   | { ok: false, error: { code: string, partialResults: DetectionResult[] } }
 *
 * Cloudflare Workers runtime — no Node APIs.
 * Never logs the submitted URL.
 *
 * Abuse layers (free tier):
 *   1. Cloudflare Turnstile (managed) when TURNSTILE_SECRET is configured.
 *   2. 1-hour Cache API result cache — repeat scans never refetch.
 *   3. For edge rate limiting, add a Cloudflare WAF rate-limit rule on
 *      /api/detect in the dashboard (free plan includes 1 rule slot usage
 *      via Rate Limiting Rules). See wrangler + methodology notes.
 */

import type { APIRoute } from 'astro';
import { runDetectionPipeline } from '../../lib/detect/pipeline';
import { explainDetections } from '../../lib/detect/confidence';

export const prerender = false;

// Turnstile secret (set via CF environment variable, empty in dev = skip verify)
const TURNSTILE_SECRET = (import.meta.env?.TURNSTILE_SECRET as string | undefined) ?? '';

async function verifyTurnstile(token: string): Promise<boolean> {
  // Dev / unconfigured: skip verification so the tool works out of the box.
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

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
} as const;

function json(body: unknown, status = 200, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...SECURITY_HEADERS,
      ...extra,
    },
  });
}

/** Normalise a cache key: lowercase host, strip trailing slash + fragment. */
function cacheKeyFor(rawUrl: string): string | undefined {
  try {
    const trimmed = rawUrl.trim();
    const parsed = new URL(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    const host = parsed.hostname.toLowerCase();
    const path = parsed.pathname.replace(/\/+$/, '') || '/';
    return `https://cmsdetectorai.com/api/detect?u=${encodeURIComponent(host + path)}`;
  } catch {
    return undefined;
  }
}

export const OPTIONS: APIRoute = () => {
  return new Response(null, {
    status: 204,
    headers: { ...SECURITY_HEADERS, 'Cache-Control': 'no-store' },
  });
};

export const POST: APIRoute = async ({ request }) => {
  // Parse body (with a sanity size cap — the URL itself is ≤ 2048 chars)
  let body: { url?: unknown; token?: unknown; debug?: unknown };
  try {
    const text = await request.text();
    if (text.length > 8192) {
      return json({ ok: false, error: { code: 'INVALID_URL', partialResults: [] } }, 400);
    }
    body = JSON.parse(text) as typeof body;
  } catch {
    return json({ ok: false, error: { code: 'INVALID_URL', partialResults: [] } }, 400);
  }

  const rawUrl = typeof body.url === 'string' ? body.url.trim() : '';
  const cfToken = typeof body.token === 'string' ? body.token : '';
  const wantDebug = body.debug === true;

  if (!rawUrl || rawUrl.length > 2048) {
    return json({ ok: false, error: { code: 'INVALID_URL', partialResults: [] } }, 400);
  }

  // Turnstile verification
  const turnstileOk = await verifyTurnstile(cfToken);
  if (!turnstileOk) {
    return json({ ok: false, error: { code: 'TURNSTILE_FAILED', partialResults: [] } }, 403);
  }

  // Check cache (Cache API — same-zone synthetic key, 1h TTL)
  let cache: Cache | undefined;
  const cacheKey = cacheKeyFor(rawUrl);

  try {
    cache = await caches.default;
    if (cacheKey) {
      const cached = await cache.match(cacheKey);
      if (cached) {
        const cachedBody = await cached.text();
        return json(JSON.parse(cachedBody), 200, { 'X-Cache': 'HIT' });
      }
    }
  } catch {
    cache = undefined; // Cache API unavailable (local dev) — continue uncached
  }

  // Run pipeline (never logs the URL)
  const result = await runDetectionPipeline(rawUrl);

  // Dev/debug: explain WHY each technology scored what it did.
  // Opt-in via { debug: true } — never cached, never logged.
  // Shape: { id, name, score, families, corroborationBonus, signals[] }
  // where each signal shows baseWeight × specificity = adjusted.
  if (wantDebug && result.ok) {
    const debug = explainDetections(result.data.results);
    return json({ ...result, debug }, 200, { 'X-Cache': 'MISS' });
  }

  // Cache successful results for 1 hour. put() needs a Request key in some
  // runtimes, so build one from the synthetic URL.
  if (cache && cacheKey && result.ok) {
    try {
      await cache.put(
        new Request(cacheKey),
        new Response(JSON.stringify(result), {
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'public, max-age=3600',
          },
        })
      );
    } catch {
      /* cache write failure is non-fatal */
    }
  }

  return json(result, 200, { 'X-Cache': 'MISS' });
};

// Reject non-POST requests
export const GET: APIRoute = () => {
  return json({ ok: false, error: { code: 'UNKNOWN', partialResults: [] } }, 405);
};
