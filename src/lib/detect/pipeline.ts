/**
 * Detection pipeline — the heart of the Worker.
 *
 * Steps:
 *  1. Validate URL (SSRF guard)
 *  2. Fetch HTML (max 400 KB, follow up to 5 redirects, 8s timeout)
 *  3. Extract headers, cookies, HTML
 *  4. Run signature engine
 *  5. Targeted secondary probes (max 4 total)
 *  6. Re-run engine with probe results
 *  7. Return typed JSON result
 *
 * All network code uses the Fetch API — no Node-only APIs.
 */

import { validateUrl, validateRedirect } from './ssrf';
import { runSignatureEngine, type DetectionResult, type MatchContext } from './signatures';
import { applyConfidenceModel } from './confidence';
import { isKnownShopifyTheme, isKnownWpTheme } from '../../data/themes';

// ----------------------------------------------------------------
// Constants
// ----------------------------------------------------------------

const MAX_HTML_BYTES  = 400_000;   // 400 KB cap
const MAX_REDIRECTS   = 5;
const FETCH_TIMEOUT   = 8_000;     // ms
const MAX_PROBES      = 4;
const USER_AGENT      = 'CMSDetector-AI/1.0 (+https://cmsdetectorai.com/methodology)';

// ----------------------------------------------------------------
// Types
// ----------------------------------------------------------------

export type PipelineErrorCode =
  | 'INVALID_URL'
  | 'PRIVATE_IP'
  | 'BLOCKED'
  | 'TIMEOUT'
  | 'DNS_FAILURE'
  | 'INVALID_TLS'
  | 'NON_HTML'
  | 'CLIENT_RENDERED'
  | 'REDIRECT_LOOP'
  | 'UNKNOWN';

export interface PipelineError {
  code: PipelineErrorCode;
  /** Technology IDs detected despite the error (e.g. from headers) */
  partialResults: DetectionResult[];
}

export interface PipelineSuccess {
  /** Final URL after redirects */
  finalUrl: string;
  results: DetectionResult[];
  /** Whether HTML appeared to be a client-rendered shell */
  isClientRendered: boolean;
  /** Structured WordPress extras (also present as probe evidence) */
  wordpressTheme?: { name?: string; author?: string; version?: string; slug?: string; known?: boolean };
  wordpressPlugins?: string[];
  /** Structured Shopify extras (also present as probe evidence) */
  shopifyTheme?: { name?: string; id?: string; known?: boolean };
}

export type PipelineResult =
  | { ok: true;  data: PipelineSuccess }
  | { ok: false; error: PipelineError };

// ----------------------------------------------------------------
// Header / cookie extraction
// ----------------------------------------------------------------

function extractHeaders(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

function extractCookieNames(res: Response, headers: Record<string, string>): string[] {
  // Prefer getSetCookie() (splits correctly); fall back to parsing the
  // raw header. Never split on ',' — Expires dates contain commas.
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
    // Split on commas that precede a cookie-name= token (not Expires dates)
    rawCookies = raw.split(/,(?=[^;,=\s]+\s*=)/);
  }
  return rawCookies
    .map((s) => s.split(';')[0].split('=')[0].trim())
    .filter(Boolean);
}

// ----------------------------------------------------------------
// Bounded body reader — streams and stops at maxBytes so a huge
// response can never OOM the Worker. Decodes incrementally as UTF-8.
// ----------------------------------------------------------------

async function readCappedText(res: Response, maxBytes: number): Promise<string> {
  if (!res.body) {
    const buf = await res.arrayBuffer();
    const capped = buf.byteLength > maxBytes ? buf.slice(0, maxBytes) : buf;
    return new TextDecoder().decode(capped);
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        const remaining = maxBytes - total;
        if (remaining <= 0) break;
        const slice = value.length > remaining ? value.subarray(0, remaining) : value;
        chunks.push(slice);
        total += slice.length;
        if (total >= maxBytes) break;
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
  return new TextDecoder().decode(merged);
}

// ----------------------------------------------------------------
// SPA / client-render detection
// ----------------------------------------------------------------

const CLIENT_RENDER_SIGNALS = [
  /<div[^>]+id=["']root["']>\s*<\/div>/i,
  /<div[^>]+id=["']app["']>\s*<\/div>/i,
  /<body>\s*<\/body>/i,
];

function isClientRendered(html: string): boolean {
  const stripped = html.replace(/<script[\s\S]*?<\/script>/gi, '');
  const textLength = stripped.replace(/<[^>]+>/g, '').trim().length;
  if (textLength < 200) return true;
  for (const rx of CLIENT_RENDER_SIGNALS) {
    if (rx.test(html)) return true;
  }
  return false;
}

// ----------------------------------------------------------------
// Bot protection detection
// ----------------------------------------------------------------

function isBlocked(status: number, html: string): boolean {
  const sample = html.slice(0, 8000);
  const challengeMarkers =
    /challenge|captcha|security check|ddos protection|just a moment|verify you are human|access denied|request blocked|perimeterx|datadome|kasada|shape\.sh|incapsula/i;
  // Challenge copy on any status (some WAFs answer 200) means a block.
  if (challengeMarkers.test(sample)) return true;
  // 429 is always rate-limiting; 403/503 without readable content are blocks.
  if (status === 429) return true;
  if (status === 403 || status === 503 || status === 401 || status === 407) return true;
  return false;
}

// ----------------------------------------------------------------
// Fetch with redirect following & SSRF re-validation
// ----------------------------------------------------------------

async function fetchWithRedirects(
  startUrl: URL,
  signal: AbortSignal
): Promise<{ res: Response; finalUrl: string } | { error: PipelineErrorCode }> {
  let current = startUrl.toString();
  let hops = 0;

  while (hops <= MAX_REDIRECTS) {
    let res: Response;
    try {
      res = await fetch(current, {
        redirect: 'manual',
        signal,
        headers: {
          'User-Agent': USER_AGENT,
          Accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
        },
      });
    } catch (e: unknown) {
      const msg = String(e);
      if (msg.includes('abort')) return { error: 'TIMEOUT' };
      if (msg.includes('DNS') || msg.includes('ENOTFOUND') || msg.includes('EAI_AGAIN')) {
        return { error: 'DNS_FAILURE' };
      }
      if (msg.includes('certificate') || msg.includes('SSL') || msg.includes('TLS')) {
        return { error: 'INVALID_TLS' };
      }
      return { error: 'UNKNOWN' };
    }

    // Follow redirect with SSRF validation
    if (res.status >= 301 && res.status <= 308) {
      const location = res.headers.get('location');
      if (!location) return { error: 'UNKNOWN' };

      const validated = validateRedirect(location, current);
      if (!validated.ok) return { error: validated.code as PipelineErrorCode };

      current = validated.url.toString();
      hops++;
      continue;
    }

    return { res, finalUrl: current };
  }

  return { error: 'REDIRECT_LOOP' };
}

// ----------------------------------------------------------------
// Targeted secondary probes
// ----------------------------------------------------------------

const PROBE_PATHS: Array<{ forId: string; path: string }> = [
  { forId: 'wordpress', path: '/wp-json/' },
  { forId: 'shopify',   path: '' }, // Shopify has no reliable probe path
];

async function runProbes(
  baseUrl: URL,
  detectedIds: Set<string>,
  signal: AbortSignal
): Promise<Record<string, string>> {
  const results: Record<string, string> = {};
  let probeCount = 0;

  for (const { forId, path } of PROBE_PATHS) {
    if (!detectedIds.has(forId) || !path) continue;
    if (probeCount >= MAX_PROBES) break;

    const probeUrl = `${baseUrl.origin}${path}`;
    const validated = validateUrl(probeUrl);
    if (!validated.ok) continue;

    try {
      const res = await fetch(probeUrl, {
        signal,
        headers: { 'User-Agent': USER_AGENT },
      });
      const text = await res.text();
      results[path] = text.slice(0, 50_000);
      probeCount++;
    } catch {
      // Probe failed — skip silently
    }
  }

  // WordPress theme probe — look for /wp-content/themes/<slug>/style.css
  if (detectedIds.has('wordpress') && probeCount < MAX_PROBES) {
    // Extract theme slug from already-collected HTML (caller passes as context)
    // This is handled in the pipeline after collecting html
  }

  return results;
}

// ----------------------------------------------------------------
// WordPress extras: theme name from style.css
// ----------------------------------------------------------------

async function fetchWpThemeMeta(
  origin: string,
  html: string,
  signal: AbortSignal
): Promise<{ themeName?: string; themeAuthor?: string; themeVersion?: string }> {
  // Extract theme slug from HTML
  const slugMatch = /\/wp-content\/themes\/([^/]+)\//i.exec(html);
  if (!slugMatch) return {};

  const slug = slugMatch[1];
  const cssUrl = `${origin}/wp-content/themes/${slug}/style.css`;
  const validated = validateUrl(cssUrl);
  if (!validated.ok) return {};

  try {
    const res = await fetch(cssUrl, { signal, headers: { 'User-Agent': USER_AGENT } });
    const css = await res.text().then((t) => t.slice(0, 10_000));

    const themeName    = /^Theme Name:\s*(.+)$/mi.exec(css)?.[1]?.trim();
    const themeAuthor  = /^Author:\s*(.+)$/mi.exec(css)?.[1]?.trim();
    const themeVersion = /^Version:\s*(.+)$/mi.exec(css)?.[1]?.trim();

    return { themeName, themeAuthor, themeVersion };
  } catch {
    return {};
  }
}

// ----------------------------------------------------------------
// Shopify theme from JS embed
// ----------------------------------------------------------------

function extractShopifyTheme(html: string): { name?: string; id?: string } {
  const nameMatch = /Shopify\.theme\s*=\s*\{[^}]*["']name["']\s*:\s*["']([^"']+)["']/i.exec(html);
  const idMatch =
    /Shopify\.theme\s*=\s*\{[^}]*["']id["']\s*:\s*(\d+)/i.exec(html) ??
    /["']theme_id["']\s*:\s*(\d+)/i.exec(html);
  return { name: nameMatch?.[1], id: idMatch?.[1] };
}

// ----------------------------------------------------------------
// WordPress plugins from asset paths (/wp-content/plugins/<slug>/)
// ----------------------------------------------------------------

const WP_PLUGIN_IGNORE = new Set(['cache', 'uploads', 'upgrade', 'languages']);

export function extractWpPlugins(html: string, limit = 8): string[] {
  const seen: string[] = [];
  const rx = /\/wp-content\/plugins\/([^/"'\s?#]+)/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(html)) !== null) {
    const slug = m[1].replace(/\/$/, '');
    if (!slug || WP_PLUGIN_IGNORE.has(slug) || seen.includes(slug)) continue;
    seen.push(slug);
    if (seen.length >= limit) break;
  }
  return seen;
}

// ----------------------------------------------------------------
// Hosting hint via DNS-over-HTTPS (CNAME chain, best effort).
// One subrequest; failure is silent. Maps known provider suffixes.
// ----------------------------------------------------------------

const CNAME_PROVIDER_MAP: Array<{ suffix: string; id: string; name: string }> = [
  { suffix: '.cloudfront.net', id: 'aws-cloudfront', name: 'AWS CloudFront' },
  { suffix: '.fastly.net', id: 'fastly', name: 'Fastly' },
  { suffix: '.fastlylb.net', id: 'fastly', name: 'Fastly' },
  { suffix: '.vercel-dns.com', id: 'vercel', name: 'Vercel' },
  { suffix: '.vercel.app', id: 'vercel', name: 'Vercel' },
  { suffix: '.netlify.app', id: 'netlify', name: 'Netlify' },
  { suffix: '.netlify.com', id: 'netlify', name: 'Netlify' },
  { suffix: '.wpengine.com', id: 'wp-engine', name: 'WP Engine' },
  { suffix: '.wpenginepowered.com', id: 'wp-engine', name: 'WP Engine' },
  { suffix: '.kinsta.cloud', id: 'kinsta', name: 'Kinsta' },
  { suffix: '.kinsta.com', id: 'kinsta', name: 'Kinsta' },
  { suffix: '.github.io', id: 'github-pages', name: 'GitHub Pages' },
  { suffix: '.wixdns.net', id: 'wix', name: 'Wix' },
  { suffix: '.squarespace.com', id: 'squarespace', name: 'Squarespace' },
  { suffix: '.shopify.com', id: 'shopify', name: 'Shopify' },
  { suffix: '.myshopify.com', id: 'shopify', name: 'Shopify' },
  { suffix: '.hubspot.net', id: 'hubspot-cms', name: 'HubSpot CMS' },
];

async function dohCnameHint(
  hostname: string,
  signal: AbortSignal
): Promise<{ id: string; name: string; cname: string } | null> {
  try {
    const q = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=CNAME`,
      { signal, headers: { Accept: 'application/dns-json', 'User-Agent': USER_AGENT } }
    );
    if (!q.ok) return null;
    const data = (await q.json()) as {
      Answer?: Array<{ type: number; data: string }>;
    };
    const answers = Array.isArray(data.Answer) ? data.Answer : [];
    for (const a of answers) {
      if (a.type !== 5 || typeof a.data !== 'string') continue;
      const target = a.data.replace(/\.$/, '').toLowerCase();
      for (const p of CNAME_PROVIDER_MAP) {
        if (target.endsWith(p.suffix)) {
          return { id: p.id, name: p.name, cname: target };
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}

// ----------------------------------------------------------------
// Main pipeline entry point
// ----------------------------------------------------------------

export async function runDetectionPipeline(
  rawUrl: string
): Promise<PipelineResult> {
  // 1. Validate
  const validated = validateUrl(rawUrl);
  if (!validated.ok) {
    return {
      ok: false,
      error: { code: validated.code as PipelineErrorCode, partialResults: [] },
    };
  }

  const url = validated.url;

  // 2. Fetch with timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

  let res: Response;
  let finalUrl: string;

  try {
    const fetchResult = await fetchWithRedirects(url, controller.signal);
    if ('error' in fetchResult) {
      return {
        ok: false,
        error: { code: fetchResult.error, partialResults: [] },
      };
    }
    res = fetchResult.res;
    finalUrl = fetchResult.finalUrl;
  } finally {
    clearTimeout(timeoutId);
  }

  // 3. Extract headers + cookies from initial fetch (headers always available)
  const headers = extractHeaders(res);
  const cookies = extractCookieNames(res, headers);

  // Check content type — anything that isn't HTML/XHTML is a NON_HTML
  // failure (except bot-block statuses, which report BLOCKED instead so the
  // UI can explain and still show header-derived hints).
  const contentType = (headers['content-type'] ?? '').toLowerCase();
  const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml');
  // Missing content-type with a 200: sniff the body start for "<html".
  if (!isHtml) {
    const ctx: MatchContext = { html: '', headers, cookies };
    const partialResults = runSignatureEngine(ctx);
    if (isBlocked(res.status, '')) {
      return { ok: false, error: { code: 'BLOCKED', partialResults } };
    }
    return { ok: false, error: { code: 'NON_HTML', partialResults } };
  }

  // 4. Read capped HTML via a reader — never buffer an unbounded body
  // (a malicious 100 MB page must not OOM the Worker).
  let html: string;
  try {
    html = await readCappedText(res, MAX_HTML_BYTES);
  } catch (e: unknown) {
    if (String(e).includes('abort')) {
      return { ok: false, error: { code: 'TIMEOUT', partialResults: [] } };
    }
    return { ok: false, error: { code: 'UNKNOWN', partialResults: [] } };
  }

  // Check for bot block
  if (isBlocked(res.status, html)) {
    const ctx: MatchContext = { html: html.slice(0, 5000), headers, cookies };
    const partialResults = runSignatureEngine(ctx);
    return { ok: false, error: { code: 'BLOCKED', partialResults } };
  }

  // 5. First pass signature matching
  const ctx: MatchContext = { html, headers, cookies };
  const firstPass = runSignatureEngine(ctx);
  const detectedIds = new Set(firstPass.map((r) => r.id));

  // 6. Secondary probes (bounded: 1 page fetch + DoH + at most MAX_PROBES
  // extra fetches, all under a 5s budget)
  const controller2 = new AbortController();
  const probeTimeout = setTimeout(() => controller2.abort(), 5_000);

  let probeResults: Record<string, string> = {};
  let wpThemeMeta: { themeName?: string; themeAuthor?: string; themeVersion?: string } = {};
  let shopifyTheme: { name?: string; id?: string } = {};
  let wpPlugins: string[] = [];
  let dnsHint: { id: string; name: string; cname: string } | null = null;

  try {
    const baseUrl = new URL(finalUrl);
    const isWordPress = detectedIds.has('wordpress');

    [probeResults, wpThemeMeta, dnsHint] = await Promise.all([
      runProbes(baseUrl, detectedIds, controller2.signal),
      isWordPress
        ? fetchWpThemeMeta(baseUrl.origin, html, controller2.signal)
        : Promise.resolve({}),
      dohCnameHint(baseUrl.hostname, controller2.signal),
    ]);

    if (isWordPress) {
      wpPlugins = extractWpPlugins(html);
    }
    if (detectedIds.has('shopify')) {
      shopifyTheme = extractShopifyTheme(html);
    }
  } finally {
    clearTimeout(probeTimeout);
  }

  // 7. Second pass with probe results
  const ctx2: MatchContext = { html, headers, cookies, probeResults };
  let results = runSignatureEngine(ctx2);

  // 8. Augment WordPress result with theme metadata
  if (wpThemeMeta.themeName) {
    results = results.map((r) => {
      if (r.id === 'wordpress') {
        return {
          ...r,
          evidence: [
            ...r.evidence,
            {
              type: 'probe' as const,
              artifact: `theme: "${wpThemeMeta.themeName}"${wpThemeMeta.themeVersion ? ` v${wpThemeMeta.themeVersion}` : ''}${wpThemeMeta.themeAuthor ? ` by ${wpThemeMeta.themeAuthor}` : ''}`,
              weight: 85,
              name: 'theme',
              value: wpThemeMeta.themeName ?? '',
              strength: 'strong' as const,
              family: 'PLATFORM_IDENTIFIER' as const,
              specificity: 0.7,
            },
          ],
        };
      }
      return r;
    });
  }

  // 9. Augment Shopify result with theme name / ID
  if (shopifyTheme.name || shopifyTheme.id) {
    const label = `theme: "${shopifyTheme.name ?? 'unknown'}"${shopifyTheme.id ? ` (id ${shopifyTheme.id})` : ''}`;
    results = results.map((r) => {
      if (r.id === 'shopify') {
        return {
          ...r,
          evidence: [
            ...r.evidence,
            { type: 'probe' as const, artifact: label, weight: 80, name: 'theme', value: shopifyTheme.name ?? shopifyTheme.id ?? '', strength: 'strong' as const, family: 'PLATFORM_IDENTIFIER' as const, specificity: 0.7 },
          ],
        };
      }
      return r;
    });
  }

  // 9b. Append detected WordPress plugins as their own result group
  if (wpPlugins.length > 0) {
    results.push({
      id: 'wordpress-plugins',
      name: `WordPress plugins (${wpPlugins.length} detected)`,
      category: 'plugin',
      confidence: 90,
      confidenceLabel: 'confirmed',
      evidence: wpPlugins.map((slug) => ({
        type: 'html-path' as const,
        artifact: `html: "/wp-content/plugins/${slug}/"`,
        weight: 90,
        name: `/wp-content/plugins/${slug}/`,
        value: `/wp-content/plugins/${slug}/`,
        strength: 'strong' as const,
        family: 'ASSET' as const,
        specificity: 0.7,
      })),
    });
  }

  // 9c. DNS CNAME hint — only when no hosting provider was detected
  // from headers (headers win; DNS is corroboration, never a guess).
  if (dnsHint && !results.some((r) => r.category === 'hosting')) {
    results.push({
      id: dnsHint.id,
      name: dnsHint.name,
      category: 'hosting',
      confidence: 70,
      confidenceLabel: 'likely',
      evidence: [
        { type: 'probe' as const, artifact: `dns[cname]: "${dnsHint.cname}"`, weight: 70, name: 'cname', value: dnsHint.cname, strength: 'weak' as const, family: 'PLATFORM_IDENTIFIER' as const, specificity: 0.3 },
      ],
    });
  }

  // 10. Evidence-model scoring: deterministic 0–100 scores, platform
  // conflict resolution. Legacy confidence fields are left untouched.
  results = applyConfidenceModel(results);

  // 11. Client-rendered check
  const clientRendered = isClientRendered(html);

  const themeSlug = /\/wp-content\/themes\/([^/]+)\//i.exec(html)?.[1];

  return {
    ok: true,
    data: {
      finalUrl,
      results,
      isClientRendered: clientRendered,
      ...(wpThemeMeta.themeName || themeSlug
        ? {
            wordpressTheme: {
              name: wpThemeMeta.themeName,
              author: wpThemeMeta.themeAuthor,
              version: wpThemeMeta.themeVersion,
              slug: themeSlug,
              known: isKnownWpTheme(themeSlug),
            },
          }
        : {}),
      ...(wpPlugins.length > 0 ? { wordpressPlugins: wpPlugins } : {}),
      ...(shopifyTheme.name || shopifyTheme.id
        ? { shopifyTheme: { ...shopifyTheme, known: isKnownShopifyTheme(shopifyTheme.name) } }
        : {}),
    },
  };
}
