/**
 * POST /api/scan/complete — Step 3 of client-orchestrated consistency scan.
 *
 * Merges and analyzes PageScanResult items collected across client-driven steps.
 * Consumes 0 subrequests and executes in <1ms CPU.
 */
import type { APIRoute } from 'astro';
import { analyzeConsistency } from '../../../lib/scan/analyze.ts';
import { json } from '../../../lib/detect/static-collect.ts';
import type { PageScanResult, ScanCoverage } from '../../../lib/scan/types.ts';

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
  let body: {
    rootUrl?: unknown;
    rootHost?: unknown;
    pages?: unknown;
    coverage?: unknown;
  };
  try {
    const text = await request.text();
    body = JSON.parse(text);
  } catch {
    return json({ ok: false, error: { code: 'INVALID_URL', message: 'Invalid JSON body.' } }, 400);
  }

  const rootUrl = typeof body.rootUrl === 'string' ? body.rootUrl : '';
  const rootHost = typeof body.rootHost === 'string' ? body.rootHost : '';
  const pages = Array.isArray(body.pages) ? (body.pages as PageScanResult[]) : [];
  const coverage = (body.coverage as ScanCoverage) ?? {
    checked: pages.filter((p) => !p.error && !p.skippedByRobots).length,
    foundApprox: pages.length,
    truncated: false,
  };

  if (!rootUrl || !rootHost || pages.length === 0) {
    return json({ ok: false, error: { code: 'INVALID_URL', message: 'Missing rootUrl, rootHost, or pages.' } }, 400);
  }

  const result = analyzeConsistency({ rootUrl, rootHost, pages, coverage });
  return json({
    ok: true,
    status: 'complete',
    data: result,
  });
};
