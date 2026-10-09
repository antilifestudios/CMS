/**
 * POST /api/detect — Technology (CMS, framework, hosting, builder, theme) detector.
 *
 * Request body (JSON):
 *   { url: string; token?: string; debug?: boolean }
 *
 * Response body (JSON):
 *   {
 *     ok: boolean,
 *     status: 'complete' | 'partial' | 'failed',
 *     coverage: CoverageMetadata,
 *     data?: PipelineSuccess,
 *     error?: StandardApiError
 *   }
 */

import type { APIRoute } from 'astro';
import { runDetectionPipeline } from '../../lib/detect/pipeline.ts';
import { explainDetections } from '../../lib/detect/confidence.ts';
import { rateLimited, clientIp, json, logScan } from '../../lib/detect/static-collect.ts';
import { ERROR_HTTP_STATUS } from '../../lib/detect/types.ts';

export const prerender = false;

const TURNSTILE_SECRET = (import.meta.env?.TURNSTILE_SECRET as string | undefined) ?? '';
const CACHE_TTL_SECONDS = 3600;
const DETECTOR_REVISION = 3;

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

function cacheKeyFor(rawUrl: string): string | undefined {
  try {
    const trimmed = rawUrl.trim();
    const parsed = new URL(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    const host = parsed.hostname.toLowerCase();
    const path = parsed.pathname.replace(/\/+$/, '') || '/';
    return `https://cmsdetectorai.com/api/detect?rev=${DETECTOR_REVISION}&u=${encodeURIComponent(host + path)}`;
  } catch {
    return undefined;
  }
}

const EMPTY_COVERAGE = {
  htmlBytes: 0,
  bundlesScanned: 0,
  bundlesSkipped: 0,
  gtmContainersFetched: 0,
  truncated: false,
  subrequests: 0,
  durationMs: 0,
};

export const OPTIONS: APIRoute = () => {
  return new Response(null, {
    status: 204,
    headers: {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    },
  });
};

export const POST: APIRoute = async ({ request }) => {
  const ip = clientIp(request);
  if (rateLimited(ip)) {
    return json(
      {
        ok: false,
        status: 'failed',
        coverage: EMPTY_COVERAGE,
        error: {
          code: 'RATE_LIMITED',
          message: 'Too many requests — please wait a minute and try again.',
          retryable: true,
        },
      },
      429,
    );
  }

  let body: { url?: unknown; token?: unknown; debug?: unknown };
  try {
    const text = await request.text();
    if (text.length > 8192) {
      return json(
        {
          ok: false,
          status: 'failed',
          coverage: EMPTY_COVERAGE,
          error: { code: 'INVALID_URL', message: 'Request payload too large.', retryable: false },
        },
        400,
      );
    }
    body = JSON.parse(text) as typeof body;
  } catch {
    return json(
      {
        ok: false,
        status: 'failed',
        coverage: EMPTY_COVERAGE,
        error: { code: 'INVALID_URL', message: 'Invalid JSON body.', retryable: false },
      },
      400,
    );
  }

  const rawUrl = typeof body.url === 'string' ? body.url.trim() : '';
  const cfToken = typeof body.token === 'string' ? body.token : '';
  const wantDebug = body.debug === true;

  if (!rawUrl || rawUrl.length > 2048) {
    return json(
      {
        ok: false,
        status: 'failed',
        coverage: EMPTY_COVERAGE,
        error: { code: 'INVALID_URL', message: 'Enter a valid website URL (e.g. https://example.com).', retryable: false },
      },
      400,
    );
  }

  // Turnstile verification
  const turnstileOk = await verifyTurnstile(cfToken);
  if (!turnstileOk) {
    return json(
      {
        ok: false,
        status: 'failed',
        coverage: EMPTY_COVERAGE,
        error: { code: 'TARGET_BLOCKED', message: 'Bot verification failed. Please try again.', retryable: true },
      },
      403,
    );
  }

  // Cache lookup
  let cache: Cache | undefined;
  const cacheKey = cacheKeyFor(rawUrl);
  try {
    cache = await caches.default;
    if (cacheKey) {
      const cached = await cache.match(cacheKey);
      if (cached) {
        return json(JSON.parse(await cached.text()), 200, { 'X-Cache': 'HIT' });
      }
    }
  } catch {
    cache = undefined;
  }

  const startTime = performance.now();
  const result = await runDetectionPipeline(rawUrl);
  const durationMs = Math.round(performance.now() - startTime);

  // Extract host only for logging (never log full query/path)
  let logHost = 'unknown';
  try {
    const p = new URL(/^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`);
    logHost = p.hostname.toLowerCase();
  } catch {
    /* noop */
  }

  logScan({
    host: logHost,
    outcome: result.ok ? result.status : result.error?.code ?? 'ERROR',
    durationMs,
    cpuMs: durationMs * 0.08,
    subrequests: result.coverage?.subrequests ?? 1,
    truncated: result.coverage?.truncated ?? false,
  });

  if (!result.ok) {
    const httpStatus = result.error?.code ? ERROR_HTTP_STATUS[result.error.code] ?? 502 : 502;
    return json(result, httpStatus, { 'X-Cache': 'MISS' });
  }

  if (wantDebug) {
    const debug = explainDetections(result.data.results);
    return json({ ...result, debug }, 200, { 'X-Cache': 'MISS' });
  }

  // Cache complete successful results
  if (cache && cacheKey && result.status === 'complete') {
    try {
      await cache.put(
        new Request(cacheKey),
        new Response(JSON.stringify(result), {
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': `public, max-age=${CACHE_TTL_SECONDS}`,
          },
        }),
      );
    } catch {
      /* non-fatal */
    }
  }

  return json(result, 200, { 'X-Cache': 'MISS' });
};

export const GET: APIRoute = () => {
  return json(
    {
      ok: false,
      status: 'failed',
      coverage: EMPTY_COVERAGE,
      error: { code: 'INTERNAL', message: 'Use POST with { url }.', retryable: false },
    },
    405,
  );
};
