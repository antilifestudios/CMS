/**
 * POST /api/scan/step — Step 2 of client-orchestrated multi-path consistency scan.
 *
 * Scans a single URL within its own Worker invocation (1-3 subrequests max).
 * Returns the typed PageScanResult. If it fails, caller marks this URL "unscanned".
 */

import type { APIRoute } from 'astro';
import { fetchSinglePage } from '../../../lib/scan/fetchPage.ts';
import { createBudget } from '../../../lib/detect/static-collect.ts';
import { json, rateLimited, clientIp } from '../../../lib/detect/static-collect.ts';

export const prerender = false;

export const OPTIONS: APIRoute = () =>
  new Response(null, {
    status: 204,
    headers: {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });

export const POST: APIRoute = async ({ request }) => {
  if (rateLimited(clientIp(request), 60)) {
    return json(
      { ok: false, error: { code: 'RATE_LIMITED', message: 'Rate limit reached. Please wait a moment.' } },
      429,
    );
  }

  let body: { pageUrl?: unknown; rootHost?: unknown; robotsTxt?: unknown };
  try {
    const text = await request.text();
    body = JSON.parse(text) as typeof body;
  } catch {
    return json({ ok: false, error: { code: 'INVALID_URL', message: 'Invalid JSON body.' } }, 400);
  }

  const pageUrl = typeof body.pageUrl === 'string' ? body.pageUrl.trim() : '';
  const rootHost = typeof body.rootHost === 'string' ? body.rootHost.trim().toLowerCase() : '';
  const robotsTxt = typeof body.robotsTxt === 'string' ? body.robotsTxt : '';

  if (!pageUrl || !rootHost) {
    return json({ ok: false, error: { code: 'INVALID_URL', message: 'Missing pageUrl or rootHost.' } }, 400);
  }

  const budget = { used: 0, ceiling: 6 };
  const pageResult = await fetchSinglePage(pageUrl, rootHost, robotsTxt, budget);

  return json({
    ok: !pageResult.error,
    status: pageResult.error ? 'failed' : 'complete',
    data: pageResult,
  });
};
