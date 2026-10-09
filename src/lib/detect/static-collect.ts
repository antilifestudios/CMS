/**
 * Shared static evidence collection seam (`collectEvidence`).
 *
 * Workers Free-tier limits enforced here:
 * - HTML cap 500 KB, JS bundles 5 x 250 KB, GTM containers 3 x 400 KB.
 * - Max 40 external subrequests per invocation.
 * - CPU discipline: hard byte caps, cheap candidate pre-checks, early exit.
 * - Bot-block detection: immediately returns TARGET_BLOCKED without running
 *   detection on challenge pages.
 * - Single collection seam: used across /api/detect, /api/growth-detect,
 *   and /api/security-privacy-detect.
 */

import { validateRedirect, validateUrl } from './ssrf.ts';
import { isChallengeResponse, buildBotProtection, type BotProtectionInfo } from './protection.ts';
import { extractGtmIds, fetchGtmContainers } from './gtm-expansion.ts';
import type { CoverageMetadata, ScanStatus, StandardErrorCode } from './types.ts';

export const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 CMSDetector-AI/1.0 (+https://cmsdetectorai.com/blog/how-it-works)';

export const MAX_HTML_BYTES = 500_000;
export const MAX_BUNDLES = 5;
export const MAX_BUNDLE_BYTES = 250_000;
export const BUNDLE_CANDIDATES = 20;
export const BUNDLE_TIMEOUT_MS = 5_000;
export const FETCH_TIMEOUT_MS = 8_000;
export const TOTAL_DEADLINE_MS = 14_000;
export const MAX_REDIRECTS = 5;
export const MAX_SUBREQUESTS = 40;

export const PARTIAL_SCAN_WARNING =
  'Partial scan: subrequest or file size budget limit reached.';

export interface ScanBudget {
  remaining: number;
  used: number;
  truncated: boolean;
}

export function createBudget(max = MAX_SUBREQUESTS): ScanBudget {
  return { remaining: max, used: 0, truncated: false };
}

export function takeBudget(b: ScanBudget): boolean {
  if (b.remaining <= 0) {
    b.truncated = true;
    return false;
  }
  b.remaining -= 1;
  b.used += 1;
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
          const next = await reader.read().catch(() => ({ done: true, value: undefined }));
          if (!next.done) truncated = true;
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
): Promise<
  | { res: Response; finalUrl: string; redirectChain: string[] }
  | { error: StandardErrorCode; message: string; httpStatus?: number; res?: Response }
> {
  const maxRedirects = opts.maxRedirects ?? MAX_REDIRECTS;
  let current = startUrl.toString();
  const visited = new Set<string>([current]);
  const redirectChain: string[] = [current];
  let hops = 0;

  while (hops <= maxRedirects) {
    if (!takeBudget(budget)) {
      return { error: 'BUDGET_EXCEEDED', message: 'Subrequest budget exhausted.' };
    }
    let res: Response;
    try {
      res = await fetchImpl(current, {
        redirect: 'manual',
        signal,
        headers: { 'User-Agent': USER_AGENT, Accept: accept, 'Accept-Language': 'en-US,en;q=0.9' },
      });
    } catch (e: unknown) {
      const msg = String(e);
      if (msg.includes('abort')) {
        return { error: 'TIMEOUT', message: 'The request timed out.' };
      }
      if (msg.includes('DNS') || msg.includes('ENOTFOUND') || msg.includes('EAI_AGAIN')) {
        return { error: 'DNS_FAILED', message: 'Could not resolve domain name.' };
      }
      if (msg.includes('certificate') || msg.includes('SSL') || msg.includes('TLS')) {
        return { error: 'TLS_ERROR', message: 'TLS certificate verification failed.' };
      }
      return { error: 'HTTP_ERROR', message: 'Network connection failed.' };
    }

    if (res.status >= 301 && res.status <= 308) {
      const location = res.headers.get('location');
      try {
        await res.arrayBuffer();
      } catch {
        /* noop */
      }
      if (!location) {
        return { error: 'HTTP_ERROR', message: 'Redirect response missing Location header.', httpStatus: res.status };
      }
      const validated = validateRedirect(location, current);
      if (!validated.ok) {
        return { error: 'BLOCKED_TARGET', message: validated.message, httpStatus: res.status };
      }
      if (opts.pinHost && validated.url.hostname.toLowerCase() !== opts.pinHost) {
        return { error: 'BLOCKED_TARGET', message: `Container fetch must not follow redirects off ${opts.pinHost}.`, httpStatus: res.status };
      }
      const nextUrl = validated.url.toString();
      if (visited.has(nextUrl)) {
        return { error: 'HTTP_ERROR', message: 'Redirect loop detected.', httpStatus: res.status };
      }
      visited.add(nextUrl);
      redirectChain.push(nextUrl);
      current = nextUrl;
      hops++;
      continue;
    }

    if (res.status >= 500) {
      return { error: 'HTTP_ERROR', message: `Server returned HTTP status ${res.status}.`, httpStatus: res.status };
    }

    return { res, finalUrl: current, redirectChain };
  }

  return { error: 'HTTP_ERROR', message: `Exceeded maximum redirect limit (${maxRedirects}).` };
}

/** Extract base href if defined */
function extractBaseHref(html: string, pageUrl: string): string {
  const m = /<base\s+[^>]*href=["']([^"']+)["']/i.exec(html);
  if (!m) return pageUrl;
  try {
    return new URL(m[1], pageUrl).toString();
  } catch {
    return pageUrl;
  }
}

/** First-party (same-origin) script URLs, SSRF-validated, capped. */
export function sameOriginScriptUrls(html: string, pageUrl: string, max = BUNDLE_CANDIDATES): string[] {
  const baseUrl = extractBaseHref(html, pageUrl);
  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return [];
  }

  const out: string[] = [];
  const addUrl = (raw: string) => {
    if (!raw || raw.startsWith('data:') || raw.startsWith('blob:') || raw.startsWith('javascript:')) return;
    try {
      const abs = new URL(raw, baseUrl).toString();
      if (new URL(abs).origin !== origin) return;
      if (validateUrl(abs).ok && !out.includes(abs)) out.push(abs);
    } catch {
      /* skip */
    }
  };

  // 1. <script src="...">
  const scriptRx = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = scriptRx.exec(html)) !== null) {
    addUrl(m[1]);
    if (out.length >= max) return out;
  }

  // 2. <link rel="modulepreload" href="..."> and <link rel="preload" as="script" href="...">
  const linkRx = /<link\s+[^>]*>/gi;
  while ((m = linkRx.exec(html)) !== null) {
    const tag = m[0];
    const isModulePreload = /rel=["'](?:[^"']*\s+)?modulepreload(?:\s+[^"']*)?["']/i.test(tag);
    const isScriptPreload =
      /rel=["'](?:[^"']*\s+)?preload(?:\s+[^"']*)?["']/i.test(tag) &&
      /as=["']script["']/i.test(tag);
    if (isModulePreload || isScriptPreload) {
      const hrefMatch = /href=["']([^"']+)["']/i.exec(tag);
      if (hrefMatch) addUrl(hrefMatch[1]);
      if (out.length >= max) return out;
    }
  }

  return out;
}

export interface BundleResult {
  bodies: string[];
  scannedCount: number;
  skippedCount: number;
  truncated: boolean;
}

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

  const headSettled = await Promise.allSettled(
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

  const sized = headSettled
    .map((res, i) => (res.status === 'fulfilled' ? res.value : { url: urls[i], size: 0 }))
    .sort((a, b) => b.size - a.size);

  const top = sized.slice(0, maxBundles);
  const skippedCount = Math.max(0, urls.length - top.length);
  if (urls.length > maxBundles) truncated = true;

  const bodies: string[] = [];
  const fetchSettled = await Promise.allSettled(
    top.map(async (item) => {
      if (!takeBudget(budget)) {
        truncated = true;
        return null;
      }
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const res = await fetchImpl(item.url, {
          signal: ctrl.signal,
          headers: { 'User-Agent': USER_AGENT, Accept: '*/*' },
        });
        const ct = (res.headers.get('content-type') ?? '').toLowerCase();
        if (res.ok && (ct.includes('javascript') || ct.includes('ecmascript') || ct === '' || ct.includes('text/plain'))) {
          const { text, truncated: cut } = await readCappedText(res, maxBytes);
          if (cut) truncated = true;
          return text;
        } else {
          try {
            await res.arrayBuffer();
          } catch {
            /* noop */
          }
          return null;
        }
      } catch {
        return null;
      } finally {
        clearTimeout(t);
      }
    }),
  );

  for (const outcome of fetchSettled) {
    if (outcome.status === 'fulfilled' && outcome.value) {
      bodies.push(outcome.value);
    }
  }

  return { bodies, scannedCount: bodies.length, skippedCount, truncated };
}

/** Extract inline framework data (e.g. Next.js, Nuxt, Remix) */
export function extractInlineFrameworkData(html: string): Record<string, string> {
  const data: Record<string, string> = {};

  const nextMatch = /<script\s+[^>]*id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i.exec(html);
  if (nextMatch) {
    data['__NEXT_DATA__'] = nextMatch[1].slice(0, 10_000);
  }

  const nuxtMatch = /window\.__NUXT__\s*=\s*(\{[\s\S]*?\});/i.exec(html);
  if (nuxtMatch) {
    data['__NUXT__'] = nuxtMatch[1].slice(0, 10_000);
  }

  const remixMatch = /window\.__remixContext\s*=\s*(\{[\s\S]*?\});/i.exec(html);
  if (remixMatch) {
    data['__remixContext'] = remixMatch[1].slice(0, 10_000);
  }

  return data;
}

/** Check meta refresh tag */
export function extractMetaRefresh(html: string): string | undefined {
  const m = /<meta\s+[^>]*http-equiv=["']refresh["'][^>]*content=["']\d+;\s*url=([^"']+)["']/i.exec(html);
  return m ? m[1].trim() : undefined;
}

/** Check for client-rendered SPA shell */
export function isClientRendered(html: string): boolean {
  const stripped = html.replace(/<script[\s\S]*?<\/script>/gi, '');
  const textLength = stripped.replace(/<[^>]+>/g, '').trim().length;
  if (textLength < 200) return true;
  return (
    /<div[^>]+id=["']root["']>\s*<\/div>/i.test(html) ||
    /<div[^>]+id=["']app["']>\s*<\/div>/i.test(html) ||
    /<body>\s*<\/body>/i.test(html)
  );
}

// ----------------------------------------------------------------
// The Single Seam: collectEvidence
// ----------------------------------------------------------------

export interface CollectEvidenceOptions {
  fetchImpl?: FetchFn;
  maxSubrequests?: number;
  skipBundles?: boolean;
  skipGtm?: boolean;
}

export type CollectEvidenceResult =
  | {
      ok: true;
      status: ScanStatus;
      url: string;
      finalUrl: string;
      redirectChain: string[];
      headers: Record<string, string>;
      cookies: string[];
      html: string;
      bundleJs: string[];
      gtmContainers: Array<{ id: string; js: string; truncated: boolean }>;
      inlineFrameworkData: Record<string, string>;
      metaRefresh?: string;
      isClientRendered: boolean;
      warnings: string[];
      coverage: CoverageMetadata;
    }
  | {
      ok: false;
      status: 'failed';
      code: StandardErrorCode;
      message: string;
      retryable: boolean;
      httpStatus: number;
      coverage: CoverageMetadata;
      partialHeaders?: Record<string, string>;
      partialCookies?: string[];
      botProtection?: BotProtectionInfo;
    };

export async function collectEvidence(
  rawUrl: string,
  opts: CollectEvidenceOptions = {},
): Promise<CollectEvidenceResult> {
  const startTime = performance.now();
  const budget = createBudget(opts.maxSubrequests ?? MAX_SUBREQUESTS);
  const fetchImpl = opts.fetchImpl ?? fetch;
  const warnings: string[] = [];

  const coverageBase: CoverageMetadata = {
    htmlBytes: 0,
    bundlesScanned: 0,
    bundlesSkipped: 0,
    gtmContainersFetched: 0,
    truncated: false,
    subrequests: 0,
    durationMs: 0,
  };

  const finalizeCoverage = (): CoverageMetadata => {
    coverageBase.subrequests = budget.used;
    coverageBase.durationMs = Math.round(performance.now() - startTime);
    coverageBase.truncated = coverageBase.truncated || budget.truncated;
    return { ...coverageBase };
  };

  // 1. URL validation
  const validated = validateUrl(rawUrl);
  if (!validated.ok) {
    const code: StandardErrorCode =
      validated.code === 'BLOCKED_TARGET' ? 'BLOCKED_TARGET' : 'INVALID_URL';
    return {
      ok: false,
      status: 'failed',
      code,
      message: validated.message,
      retryable: false,
      httpStatus: code === 'BLOCKED_TARGET' ? 403 : 400,
      coverage: finalizeCoverage(),
    };
  }

  // 2. Fetch HTML with timeout and retry (retry once on network error or 5xx)
  const ctrl = new AbortController();
  const overallTimeout = setTimeout(() => ctrl.abort(), TOTAL_DEADLINE_MS);

  let fetchedRes: Response;
  let finalUrl: string;
  let redirectChain: string[];

  try {
    let attempt = await fetchWithRedirects(
      validated.url,
      ctrl.signal,
      'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      budget,
      fetchImpl,
    );

    // Safe retry: retry once on 5xx or network errors (never 4xx)
    if ('error' in attempt && (attempt.error === 'HTTP_ERROR' || (attempt.httpStatus && attempt.httpStatus >= 500))) {
      if (budget.remaining > 0 && !ctrl.signal.aborted) {
        await new Promise((r) => setTimeout(r, 250));
        attempt = await fetchWithRedirects(
          validated.url,
          ctrl.signal,
          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          budget,
          fetchImpl,
        );
      }
    }

    if ('error' in attempt) {
      return {
        ok: false,
        status: 'failed',
        code: attempt.error,
        message: attempt.message,
        retryable: attempt.error === 'TIMEOUT' || attempt.error === 'HTTP_ERROR' || attempt.error === 'DNS_FAILED',
        httpStatus: attempt.httpStatus ?? 502,
        coverage: finalizeCoverage(),
      };
    }

    fetchedRes = attempt.res;
    finalUrl = attempt.finalUrl;
    redirectChain = attempt.redirectChain;
  } finally {
    clearTimeout(overallTimeout);
  }

  // 3. Extract headers and cookies
  const headers = extractHeaders(fetchedRes);
  const cookies = extractCookieNames(fetchedRes, headers);

  // 4. Bot protection check before reading whole body or running detection
  if (isChallengeResponse(fetchedRes.status, '')) {
    return {
      ok: false,
      status: 'failed',
      code: 'TARGET_BLOCKED',
      message: 'Target site presented a bot challenge or access protection wall.',
      retryable: false,
      httpStatus: 403,
      coverage: finalizeCoverage(),
      partialHeaders: headers,
      partialCookies: cookies,
      botProtection: buildBotProtection(fetchedRes.status, headers, cookies, ''),
    };
  }

  // 5. Verify Content-Type is HTML
  const contentType = (headers['content-type'] ?? '').toLowerCase();
  const isHtmlType = contentType.includes('text/html') || contentType.includes('application/xhtml');

  // 6. Read capped HTML
  let html = '';
  try {
    const { text, truncated } = await readCappedText(fetchedRes, MAX_HTML_BYTES);
    html = text;
    coverageBase.htmlBytes = new TextEncoder().encode(html).length;
    if (truncated) {
      coverageBase.truncated = true;
      warnings.push(PARTIAL_SCAN_WARNING);
    }
  } catch (e: unknown) {
    const msg = String(e);
    const code: StandardErrorCode = msg.includes('abort') ? 'TIMEOUT' : 'HTTP_ERROR';
    return {
      ok: false,
      status: 'failed',
      code,
      message: 'Failed while reading response stream.',
      retryable: code === 'TIMEOUT',
      httpStatus: code === 'TIMEOUT' ? 504 : 502,
      coverage: finalizeCoverage(),
      partialHeaders: headers,
      partialCookies: cookies,
    };
  }

  // Check if non-HTML
  if (!isHtmlType) {
    const sniff = html.slice(0, 1024).toLowerCase();
    const looksLikeHtml = sniff.includes('<!doctype html') || sniff.includes('<html');
    if (!looksLikeHtml) {
      return {
        ok: false,
        status: 'failed',
        code: 'NOT_HTML',
        message: 'The URL returned a non-HTML response (e.g. image, PDF, or API endpoint).',
        retryable: false,
        httpStatus: 422,
        coverage: finalizeCoverage(),
        partialHeaders: headers,
        partialCookies: cookies,
      };
    }
  }

  // Check bot challenge on HTML content
  if (isChallengeResponse(fetchedRes.status, html)) {
    return {
      ok: false,
      status: 'failed',
      code: 'TARGET_BLOCKED',
      message: 'Target site presented a bot challenge or access protection wall.',
      retryable: false,
      httpStatus: 403,
      coverage: finalizeCoverage(),
      partialHeaders: headers,
      partialCookies: cookies,
      botProtection: buildBotProtection(fetchedRes.status, headers, cookies, html),
    };
  }

  // 7. Extract inline framework data & meta refresh
  const inlineFrameworkData = extractInlineFrameworkData(html);
  const metaRefresh = extractMetaRefresh(html);
  const clientRendered = isClientRendered(html);

  // 8. Fetch first-party JS bundles (fail soft)
  let bundleJs: string[] = [];
  if (!opts.skipBundles) {
    try {
      const scriptUrls = sameOriginScriptUrls(html, finalUrl);
      if (scriptUrls.length > 0) {
        const bCtrl = new AbortController();
        const bTimeout = setTimeout(() => bCtrl.abort(), BUNDLE_TIMEOUT_MS);
        try {
          const bundleResult = await fetchBundles(scriptUrls, bCtrl.signal, budget, fetchImpl, {
            maxBundles: MAX_BUNDLES,
            maxBytes: MAX_BUNDLE_BYTES,
            timeoutMs: BUNDLE_TIMEOUT_MS,
          });
          bundleJs = bundleResult.bodies;
          coverageBase.bundlesScanned = bundleResult.scannedCount;
          coverageBase.bundlesSkipped = bundleResult.skippedCount;
          if (bundleResult.truncated) {
            coverageBase.truncated = true;
            warnings.push(PARTIAL_SCAN_WARNING);
          }
        } finally {
          clearTimeout(bTimeout);
        }
      }
    } catch {
      bundleJs = [];
    }
  }

  // 9. GTM container expansion (fail soft)
  let gtmContainers: Array<{ id: string; js: string; truncated: boolean }> = [];
  if (!opts.skipGtm) {
    try {
      const gtmIds = extractGtmIds(html, bundleJs);
      if (gtmIds.length > 0) {
        const gCtrl = new AbortController();
        const gTimeout = setTimeout(() => gCtrl.abort(), 6_000);
        try {
          const { containers, warnings: gtmWarnings } = await fetchGtmContainers(
            gtmIds,
            gCtrl.signal,
            budget,
            fetchImpl,
          );
          gtmContainers = containers;
          coverageBase.gtmContainersFetched = containers.length;
          warnings.push(...gtmWarnings);
          if (containers.some((c) => c.truncated)) {
            coverageBase.truncated = true;
            warnings.push(PARTIAL_SCAN_WARNING);
          }
        } finally {
          clearTimeout(gTimeout);
        }
      }
    } catch {
      warnings.push('GTM container expansion unavailable; kept normal results.');
    }
  }

  const status: ScanStatus = coverageBase.truncated || budget.truncated ? 'partial' : 'complete';

  return {
    ok: true,
    status,
    url: rawUrl,
    finalUrl,
    redirectChain,
    headers,
    cookies,
    html,
    bundleJs,
    gtmContainers,
    inlineFrameworkData,
    metaRefresh,
    isClientRendered: clientRendered,
    warnings: [...new Set(warnings)],
    coverage: finalizeCoverage(),
  };
}

// ----------------------------------------------------------------
// Per-IP Rate Limiting & Utility Helpers
// ----------------------------------------------------------------

const rateHits = new Map<string, number[]>();

export function rateLimited(ip: string, max = 30, windowMs = 60_000): boolean {
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

/** Structured logging for observability */
export function logScan(meta: {
  requestId?: string;
  host: string;
  outcome: string;
  durationMs: number;
  cpuMs: number;
  subrequests: number;
  truncated: boolean;
}): void {
  const isHighCpu = meta.cpuMs >= 8;
  const payload = {
    timestamp: new Date().toISOString(),
    id: meta.requestId ?? crypto.randomUUID().slice(0, 8),
    host: meta.host,
    outcome: meta.outcome,
    durationMs: meta.durationMs,
    cpuMs: Math.round(meta.cpuMs * 100) / 100,
    subrequests: meta.subrequests,
    truncated: meta.truncated,
    highCpu: isHighCpu,
  };
  console.log(JSON.stringify(payload));
}
