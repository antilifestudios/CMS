/**
 * POST /api/scan — multi-path consistency scan.
 *
 * Runs consistency scan across sampled pages with budget enforcement.
 */
import type { APIRoute } from 'astro';
import { runMultiPathScan } from '../../lib/scan/scanner.ts';
import { SCAN_CONFIG } from '../../lib/scan/config.ts';
import { json, rateLimited, clientIp, logScan } from '../../lib/detect/static-collect.ts';
import { ERROR_HTTP_STATUS, type StandardErrorCode } from '../../lib/detect/types.ts';

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

export const OPTIONS: APIRoute = () =>
  new Response(null, {
    status: 204,
    headers: {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    },
  });

export const POST: APIRoute = async ({ request }) => {
  if (rateLimited(clientIp(request))) {
    return json(
      { ok: false, error: { code: 'RATE_LIMITED', message: 'Too many requests. Please wait a moment.' } },
      429,
    );
  }

  let body: { url?: unknown; extraUrls?: unknown; token?: unknown };
  try {
    const text = await request.text();
    if (text.length > 16_384) {
      return json({ ok: false, error: { code: 'INVALID_URL', message: 'Payload too large.' } }, 400);
    }
    body = JSON.parse(text) as typeof body;
  } catch {
    return json({ ok: false, error: { code: 'INVALID_URL', message: 'Invalid JSON request.' } }, 400);
  }

  const rawUrl = typeof body.url === 'string' ? body.url.trim() : '';
  const rawExtras = Array.isArray(body.extraUrls)
    ? body.extraUrls.filter((u): u is string => typeof u === 'string').slice(0, SCAN_CONFIG.MAX_EXTRA_URLS)
    : [];
  const cfToken = typeof body.token === 'string' ? body.token : '';

  if (!rawUrl || rawUrl.length > 2048) {
    return json({ ok: false, error: { code: 'INVALID_URL', message: 'Please enter a valid website URL.' } }, 400);
  }

  if (!(await verifyTurnstile(cfToken))) {
    return json({ ok: false, error: { code: 'TARGET_BLOCKED', message: 'Bot verification failed.' } }, 403);
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

  const startTime = performance.now();
  const result = await runMultiPathScan(rawUrl, rawExtras);
  const durationMs = Math.round(performance.now() - startTime);

  let logHost = 'unknown';
  try {
    const p = new URL(/^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`);
    logHost = p.hostname.toLowerCase();
  } catch {
    /* noop */
  }

  logScan({
    host: logHost,
    outcome: result.ok ? result.data.verdict : result.error.code,
    durationMs,
    cpuMs: durationMs * 0.05,
    subrequests: result.ok ? result.data.coverage.checked : 1,
    truncated: result.ok ? result.data.coverage.truncated : false,
  });

  if (!result.ok) {
    const mappedCode = result.error.code as StandardErrorCode;
    const httpStatus = ERROR_HTTP_STATUS[mappedCode] ?? 502;
    return json(result, httpStatus, { 'X-Cache': 'MISS' });
  }

  if (cache && cacheKey && !result.data.coverage.truncated) {
    try {
      await cache.put(
        new Request(cacheKey),
        new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600' },
        }),
      );
    } catch {
      /* non-fatal */
    }
  }

  return json(result, 200, { 'X-Cache': 'MISS' });
};

export const GET: APIRoute = () =>
  json({ ok: false, error: { code: 'INTERNAL', message: 'Use POST.' } }, 405);
