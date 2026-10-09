/**
 * POST /api/scan/plan — Step 1 of client-orchestrated multi-path consistency scan.
 *
 * Discovers candidate URLs from sitemap.xml, robots.txt, and homepage links.
 * Returns the planned URL sample without executing heavy scans.
 * Budget: 2-3 subrequests max.
 */

import type { APIRoute } from 'astro';
import { validateUrl } from '../../../lib/detect/ssrf.ts';
import { SCAN_CONFIG } from '../../../lib/scan/config.ts';
import { buildSample } from '../../../lib/scan/sample.ts';
import { json, rateLimited, clientIp } from '../../../lib/detect/static-collect.ts';

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

async function fetchCappedText(url: string, maxBytes: number, timeoutMs = 5000): Promise<string> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { 'User-Agent': SCAN_CONFIG.USER_AGENT, Accept: '*/*' },
    });
    if (!res.ok) return '';
    const text = await res.text();
    return text.slice(0, maxBytes);
  } catch {
    return '';
  } finally {
    clearTimeout(t);
  }
}

export const OPTIONS: APIRoute = () =>
  new Response(null, {
    status: 204,
    headers: {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
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
    if (text.length > 8192) {
      return json({ ok: false, error: { code: 'INVALID_URL', message: 'Payload too large.' } }, 400);
    }
    body = JSON.parse(text) as typeof body;
  } catch {
    return json({ ok: false, error: { code: 'INVALID_URL', message: 'Invalid JSON body.' } }, 400);
  }

  const rawUrl = typeof body.url === 'string' ? body.url.trim() : '';
  const rawExtras = Array.isArray(body.extraUrls)
    ? body.extraUrls.filter((u): u is string => typeof u === 'string').slice(0, SCAN_CONFIG.MAX_EXTRA_URLS)
    : [];
  const cfToken = typeof body.token === 'string' ? body.token : '';

  if (!rawUrl || rawUrl.length > 2048) {
    return json({ ok: false, error: { code: 'INVALID_URL', message: 'Enter a valid URL.' } }, 400);
  }

  if (!(await verifyTurnstile(cfToken))) {
    return json({ ok: false, error: { code: 'TARGET_BLOCKED', message: 'Bot verification failed.' } }, 403);
  }

  const validated = validateUrl(rawUrl);
  if (!validated.ok) {
    return json({ ok: false, error: { code: validated.code, message: validated.message } }, 400);
  }

  const origin = validated.url.origin;
  const rootHost = validated.url.hostname.toLowerCase();

  // Discover robots.txt, sitemap.xml, homepage HTML in parallel (3 subrequests max)
  const [robotsTxt, sitemapXml, homepageHtml] = await Promise.all([
    fetchCappedText(`${origin}/robots.txt`, 50_000),
    fetchCappedText(`${origin}/sitemap.xml`, 200_000),
    fetchCappedText(validated.url.toString(), 100_000),
  ]);

  const { sample, foundApprox } = buildSample({
    origin,
    homepageUrl: validated.url.toString(),
    sitemapXml: sitemapXml.includes('<url') ? sitemapXml : undefined,
    homepageHtml,
    extraUrls: rawExtras,
  });

  return json({
    ok: true,
    data: {
      rootUrl: validated.url.toString(),
      rootHost,
      sampleUrls: sample,
      foundApprox: Math.max(foundApprox, sample.length),
      robotsTxt,
    },
  });
};
