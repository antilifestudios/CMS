/**
 * Detection pipeline — the core technology detector for CMS Detector AI.
 *
 * Uses the unified `collectEvidence` seam for HTML, headers, cookies, redirects,
 * and bot-protection checks. Workers-runtime compatible (no Node APIs).
 */

import { validateUrl } from './ssrf.ts';
import { runSignatureEngine, type DetectionResult, type MatchContext } from './signatures.ts';
import { applyConfidenceModel } from './confidence.ts';
import { isKnownShopifyTheme, isKnownWpTheme } from '../../data/themes.ts';
import { collectEvidence, type CollectEvidenceOptions } from './static-collect.ts';
import type { StandardApiResponse, StandardErrorCode, CoverageMetadata, ScanStatus } from './types.ts';
import type { BotProtectionInfo } from './protection.ts';

// ----------------------------------------------------------------
// Constants
// ----------------------------------------------------------------

const USER_AGENT = 'CMSDetector-AI/1.0 (+https://cmsdetectorai.com/blog/how-it-works)';
const MAX_PROBES = 3;

// ----------------------------------------------------------------
// Types
// ----------------------------------------------------------------

export interface PipelineSuccess {
  finalUrl: string;
  results: DetectionResult[];
  isClientRendered: boolean;
  wordpressTheme?: { name?: string; author?: string; version?: string; slug?: string; known?: boolean };
  wordpressPlugins?: string[];
  shopifyTheme?: { name?: string; id?: string; known?: boolean };
}

export interface PipelineError {
  code: StandardErrorCode;
  message: string;
  retryable: boolean;
  partialResults: DetectionResult[];
  httpStatus?: number;
  botProtection?: BotProtectionInfo;
}

export type PipelineResult = StandardApiResponse<PipelineSuccess>;

// ----------------------------------------------------------------
// Targeted secondary probes
// ----------------------------------------------------------------

const PROBE_PATHS: Array<{ forId: string; path: string }> = [
  { forId: 'wordpress', path: '/wp-json/' },
];

async function runProbes(
  baseUrl: URL,
  detectedIds: Set<string>,
  signal: AbortSignal,
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
      if (res.ok) {
        const text = await res.text();
        results[path] = text.slice(0, 50_000);
      }
      probeCount++;
    } catch {
      // Probe failed — fail soft
    }
  }

  return results;
}

// ----------------------------------------------------------------
// WordPress extras: theme name from style.css
// ----------------------------------------------------------------

async function fetchWpThemeMeta(
  origin: string,
  html: string,
  signal: AbortSignal,
): Promise<{ themeName?: string; themeAuthor?: string; themeVersion?: string }> {
  const slugMatch = /\/wp-content\/themes\/([^/]+)\//i.exec(html);
  if (!slugMatch) return {};

  const slug = slugMatch[1];
  const cssUrl = `${origin}/wp-content/themes/${slug}/style.css`;
  const validated = validateUrl(cssUrl);
  if (!validated.ok) return {};

  try {
    const res = await fetch(cssUrl, { signal, headers: { 'User-Agent': USER_AGENT } });
    if (!res.ok) return {};
    const css = await res.text().then((t) => t.slice(0, 10_000));

    const themeName = /^Theme Name:\s*(.+)$/im.exec(css)?.[1]?.trim();
    const themeAuthor = /^Author:\s*(.+)$/im.exec(css)?.[1]?.trim();
    const themeVersion = /^Version:\s*(.+)$/im.exec(css)?.[1]?.trim();

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
  signal: AbortSignal,
): Promise<{ id: string; name: string; cname: string } | null> {
  try {
    const q = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=CNAME`,
      { signal, headers: { Accept: 'application/dns-json', 'User-Agent': USER_AGENT } },
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
  rawUrl: string,
  opts: CollectEvidenceOptions = {},
): Promise<PipelineResult> {
  // 1. Collect evidence using the shared collection seam
  const collected = await collectEvidence(rawUrl, {
    skipBundles: true,
    skipGtm: true,
    ...opts,
  });

  if (!collected.ok) {
    let partialResults: DetectionResult[] = [];
    if (collected.code === 'TARGET_BLOCKED' && collected.partialHeaders) {
      partialResults = applyConfidenceModel(
        runSignatureEngine({
          html: '',
          headers: collected.partialHeaders,
          cookies: collected.partialCookies ?? [],
        }),
      );
    }
    return {
      ok: false,
      status: 'failed',
      coverage: collected.coverage,
      error: {
        code: collected.code,
        message: collected.message,
        retryable: collected.retryable,
        httpStatus: collected.httpStatus,
        partialResults,
        botProtection: collected.botProtection,
      },
    };
  }

  const { finalUrl, html, headers, cookies } = collected;

  // 2. First pass signature matching
  const ctx: MatchContext = { html, headers, cookies };
  const firstPass = runSignatureEngine(ctx);
  const detectedIds = new Set(firstPass.map((r) => r.id));

  // 3. Secondary probes (WordPress theme, Shopify theme, DNS CNAME hint)
  const probeCtrl = new AbortController();
  const probeTimeout = setTimeout(() => probeCtrl.abort(), 4_000);

  let probeResults: Record<string, string> = {};
  let wpThemeMeta: { themeName?: string; themeAuthor?: string; themeVersion?: string } = {};
  let shopifyTheme: { name?: string; id?: string } = {};
  let wpPlugins: string[] = [];
  let dnsHint: { id: string; name: string; cname: string } | null = null;

  try {
    const baseUrl = new URL(finalUrl);
    const isWordPress = detectedIds.has('wordpress');

    const probeFetches = [
      runProbes(baseUrl, detectedIds, probeCtrl.signal),
      isWordPress ? fetchWpThemeMeta(baseUrl.origin, html, probeCtrl.signal) : Promise.resolve({}),
      dohCnameHint(baseUrl.hostname, probeCtrl.signal),
    ] as const;

    [probeResults, wpThemeMeta, dnsHint] = await Promise.all(probeFetches);

    if (isWordPress) {
      wpPlugins = extractWpPlugins(html);
    }
    if (detectedIds.has('shopify')) {
      shopifyTheme = extractShopifyTheme(html);
    }
  } catch {
    // Probes fail soft
  } finally {
    clearTimeout(probeTimeout);
  }

  // 4. Second pass with probe results
  const ctx2: MatchContext = { html, headers, cookies, probeResults };
  let results = runSignatureEngine(ctx2);

  // 5. Augment WordPress result with theme metadata
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
              description: 'WordPress theme stylesheet identified',
              signalId: 'wordpress#probe:theme',
            },
          ],
        };
      }
      return r;
    });
  }

  // 6. Augment Shopify result with theme name / ID
  if (shopifyTheme.name || shopifyTheme.id) {
    const label = `theme: "${shopifyTheme.name ?? 'unknown'}"${shopifyTheme.id ? ` (id ${shopifyTheme.id})` : ''}`;
    results = results.map((r) => {
      if (r.id === 'shopify') {
        return {
          ...r,
          evidence: [
            ...r.evidence,
            {
              type: 'probe' as const,
              artifact: label,
              weight: 80,
              name: 'theme',
              value: shopifyTheme.name ?? shopifyTheme.id ?? '',
              strength: 'strong' as const,
              family: 'PLATFORM_IDENTIFIER' as const,
              specificity: 0.7,
              description: 'Shopify theme identified',
              signalId: 'shopify#probe:theme',
            },
          ],
        };
      }
      return r;
    });
  }

  // 7. Append detected WordPress plugins
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
        description: `WordPress plugin asset path detected (${slug})`,
        signalId: `wordpress-plugins#html-path:${slug}`,
      })),
    });
  }

  // 8. DNS CNAME hint (only if no hosting provider already detected)
  if (dnsHint && !results.some((r) => r.category === 'hosting')) {
    results.push({
      id: dnsHint.id,
      name: dnsHint.name,
      category: 'hosting',
      confidence: 70,
      confidenceLabel: 'likely',
      evidence: [
        {
          type: 'probe' as const,
          artifact: `dns[cname]: "${dnsHint.cname}"`,
          weight: 70,
          name: 'cname',
          value: dnsHint.cname,
          strength: 'weak' as const,
          family: 'PLATFORM_IDENTIFIER' as const,
          specificity: 0.3,
          description: 'Hosting provider inferred from DNS',
          signalId: 'hosting#probe:cname',
        },
      ],
    });
  }

  // 9. Apply evidence confidence model & filter out analytics (CMS detector does not detect analytics)
  results = applyConfidenceModel(results).filter((r) => r.category !== 'analytics');

  const themeSlug = /\/wp-content\/themes\/([^/]+)\//i.exec(html)?.[1];

  return {
    ok: true,
    status: collected.status,
    coverage: collected.coverage,
    data: {
      finalUrl,
      results,
      isClientRendered: collected.isClientRendered,
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
