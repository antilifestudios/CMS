/**
 * GET /api/health — Health check endpoint for uptime monitors and observability.
 */

import type { APIRoute } from 'astro';
import { ALL_SIGNATURES } from '../../lib/detect/signatures.ts';
import { GROWTH_MARKETING_SIGNATURES } from '../../data/growth-marketing-signatures.ts';
import { SECURITY_PRIVACY_SIGNATURES } from '../../data/security-privacy-signatures.ts';

export const prerender = false;

export const GET: APIRoute = () => {
  const body = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: typeof process !== 'undefined' && process.uptime ? Math.round(process.uptime()) : 0,
    version: '1.0.0',
    signatures: {
      core: ALL_SIGNATURES.length,
      growth: GROWTH_MARKETING_SIGNATURES.length,
      security: SECURITY_PRIVACY_SIGNATURES.length,
      total: ALL_SIGNATURES.length + GROWTH_MARKETING_SIGNATURES.length + SECURITY_PRIVACY_SIGNATURES.length,
    },
    limits: {
      maxSubrequestsPerScan: 40,
      maxHtmlBytes: 500_000,
      maxBundleBytes: 250_000,
    },
  };

  return new Response(JSON.stringify(body, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'X-Content-Type-Options': 'nosniff',
    },
  });
};
