/**
 * POST /api/security-privacy-detect — Security & Privacy detector.
 *
 * Uses the unified `collectEvidence` seam. Cloudflare Workers Free runtime.
 */

import type { APIRoute } from 'astro';
import {
  detectSecurityPrivacy,
  groupByCategory,
} from '../../lib/detect/security-privacy.ts';
import { analyzeWebsiteSafety } from '../../lib/detect/website-safety.ts';
import {
  collectEvidence,
  rateLimited,
  clientIp,
  json,
  logScan,
} from '../../lib/detect/static-collect.ts';
import { ERROR_HTTP_STATUS } from '../../lib/detect/types.ts';

export const prerender = false;

const CACHE_TTL_SECONDS = 600;
const DETECTOR_REVISION = 4;

const memoryCache = new Map<string, { body: string; expires: number }>();

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

const EMPTY_COVERAGE = {
  htmlBytes: 0,
  bundlesScanned: 0,
  bundlesSkipped: 0,
  gtmContainersFetched: 0,
  truncated: false,
  subrequests: 0,
  durationMs: 0,
};

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

  let body: { url?: unknown };
  try {
    const text = await request.text();
    if (text.length > 8192) {
      return json(
        {
          ok: false,
          status: 'failed',
          coverage: EMPTY_COVERAGE,
          error: { code: 'INVALID_URL', message: 'Invalid URL payload.', retryable: false },
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
        error: { code: 'INVALID_URL', message: 'Invalid request body.', retryable: false },
      },
      400,
    );
  }

  const rawUrl = typeof body.url === 'string' ? body.url.trim() : '';
  if (!rawUrl || rawUrl.length > 2048) {
    return json(
      {
        ok: false,
        status: 'failed',
        coverage: EMPTY_COVERAGE,
        error: {
          code: 'INVALID_URL',
          message: 'Enter a valid website URL (e.g. https://example.com).',
          retryable: false,
        },
      },
      400,
    );
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

  const startTime = performance.now();
  const collected = await collectEvidence(rawUrl);
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
    outcome: collected.ok ? collected.status : collected.code,
    durationMs,
    cpuMs: durationMs * 0.08,
    subrequests: collected.coverage?.subrequests ?? 1,
    truncated: collected.coverage?.truncated ?? false,
  });

  if (!collected.ok) {
    const httpStatus = ERROR_HTTP_STATUS[collected.code] ?? 502;
    return json(
      {
        ok: false,
        status: 'failed',
        coverage: collected.coverage,
        error: {
          code: collected.code,
          message: collected.message,
          retryable: collected.retryable,
          httpStatus: collected.httpStatus,
          botProtection: collected.botProtection,
        },
      },
      httpStatus,
      { 'X-Cache': 'MISS' },
    );
  }

  const technologies = detectSecurityPrivacy({
    html: collected.html,
    headers: collected.headers,
    cookies: collected.cookies,
    bundleJs: collected.bundleJs,
    gtmContainers: collected.gtmContainers,
  });
  const categories = groupByCategory(technologies);

  const safety = await analyzeWebsiteSafety({
    rawUrl,
    finalUrl: collected.finalUrl,
    redirectChain: collected.redirectChain,
    headers: collected.headers,
    html: collected.html,
  });

  const payloadData = {
    url: rawUrl,
    finalUrl: collected.finalUrl,
    scannedAt: new Date().toISOString(),
    mode: 'static' as const,
    safety,
    categories,
    warnings: collected.warnings,
  };

  const responsePayload = {
    ok: true,
    status: collected.status,
    coverage: collected.coverage,
    safety,
    categories,
    data: payloadData,
    // Preserve top-level fields for backwards compatibility with UI
    ...payloadData,
  };

  if (cacheKey && collected.status === 'complete') {
    try {
      const cache = await caches.default;
      await cache.put(
        new Request(cacheKey),
        new Response(JSON.stringify(responsePayload), {
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': `public, max-age=${CACHE_TTL_SECONDS}`,
          },
        }),
      );
    } catch {
      memoryCache.set(cacheKey, {
        body: JSON.stringify(responsePayload),
        expires: Date.now() + CACHE_TTL_SECONDS * 1000,
      });
    }
  }

  return json(responsePayload, 200, { 'X-Cache': 'MISS' });
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
