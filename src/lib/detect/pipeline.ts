/**
 * Detection pipeline — the core technology detector for CMS Detector AI.
 *
 * Uses the unified `collectEvidence` seam for HTML, headers, cookies, redirects,
 * and bot-protection checks. Workers-runtime compatible (no Node APIs).
 */

import { validateUrl } from './ssrf.ts';
import { runSignatureEngine, type DetectionResult, type MatchContext } from './signatures.ts';
import { applyConfidenceModel } from './confidence.ts';
import {
  isKnownShopifyTheme,
  isKnownWpTheme,
  getKnownWpThemeMeta,
  getShopifyThemeStoreName,
  getShopifyThemeStoreUrl,
} from '../../data/themes.ts';
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
  wordpressTheme?: {
    name?: string;
    author?: string;
    authorUri?: string;
    themeUri?: string;
    version?: string;
    parentTheme?: string;
    slug?: string;
    isChild?: boolean;
    known?: boolean;
  };
  wordpressPlugins?: string[];
  shopifyTheme?: {
    name?: string;
    id?: string;
    themeStoreId?: number;
    themeStoreName?: string;
    themeStoreUrl?: string;
    version?: string;
    role?: string;
    known?: boolean;
  };
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
// WordPress extras: theme name, author, version, parent/child
// ----------------------------------------------------------------

export interface WpThemeMetaResult {
  themeName?: string;
  themeAuthor?: string;
  themeAuthorUri?: string;
  themeUri?: string;
  themeVersion?: string;
  parentTheme?: string;
  slug?: string;
  isChild?: boolean;
}

export async function fetchWpThemeMeta(
  origin: string,
  html: string,
  signal?: AbortSignal,
): Promise<WpThemeMetaResult> {
  const themeMatches = [...html.matchAll(/\/wp-content\/themes\/([^/"'\s?#]+)\//gi)].map((m) => m[1]);
  if (themeMatches.length === 0) return {};

  const slugs = [...new Set(themeMatches)];
  const childSlug = slugs.find((s) => s.toLowerCase().endsWith('-child'));
  const primarySlug = childSlug || slugs[0];
  const parentCandidateSlug = slugs.find((s) => s !== primarySlug);

  const cssUrl = `${origin}/wp-content/themes/${primarySlug}/style.css`;
  const validated = validateUrl(cssUrl);
  let css = '';
  if (validated.ok) {
    try {
      const res = await fetch(cssUrl, { signal, headers: { 'User-Agent': USER_AGENT } });
      if (res.ok) {
        css = await res.text().then((t) => t.slice(0, 15_000));
      }
    } catch {
      // Fail soft
    }
  }

  let themeName = /^Theme Name:\s*(.+)$/im.exec(css)?.[1]?.trim();
  let themeAuthor = /^Author:\s*(.+)$/im.exec(css)?.[1]?.trim();
  let themeAuthorUri = /^(?:Author URI|Author Uri):\s*(https?:\/\/[^\s]+)$/im.exec(css)?.[1]?.trim();
  let themeUri = /^(?:Theme URI|Theme Uri):\s*(https?:\/\/[^\s]+)$/im.exec(css)?.[1]?.trim();
  let themeVersion = /^Version:\s*(.+)$/im.exec(css)?.[1]?.trim();
  let templateSlug = /^Template:\s*(.+)$/im.exec(css)?.[1]?.trim();

  const isChild = Boolean(templateSlug || primarySlug.toLowerCase().endsWith('-child'));
  let parentTheme = templateSlug || (isChild ? parentCandidateSlug : undefined);

  // If style.css could not be read or themeName is missing, fall back to known catalog or clean slug
  const baseSlug = primarySlug.toLowerCase().replace(/-child$/, '');
  const known = getKnownWpThemeMeta(baseSlug);

  if (!themeName) {
    if (known) {
      themeName = isChild ? `${known.name} Child` : known.name;
      if (!themeAuthor && known.author) themeAuthor = known.author;
      if (!themeUri && known.url) themeUri = known.url;
    } else {
      themeName = primarySlug
        .split(/[-_]+/)
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
        .join(' ');
    }
  }

  if (parentTheme) {
    const parentKnown = getKnownWpThemeMeta(parentTheme.toLowerCase());
    if (parentKnown) parentTheme = parentKnown.name;
  }

  return {
    themeName,
    themeAuthor,
    themeAuthorUri,
    themeUri,
    themeVersion,
    parentTheme,
    slug: primarySlug,
    isChild,
  };
}

// ----------------------------------------------------------------
// Shopify theme from JS embed and BOOMR analytics
// ----------------------------------------------------------------

export interface ShopifyThemeInfo {
  name?: string;
  id?: string;
  themeStoreId?: number;
  themeStoreName?: string;
  themeStoreUrl?: string;
  version?: string;
  role?: string;
  known?: boolean;
}

export function extractShopifyTheme(html: string): ShopifyThemeInfo {
  let name: string | undefined;
  let id: string | undefined;
  let themeStoreId: number | undefined;
  let version: string | undefined;
  let role: string | undefined;

  // 1. Shopify.theme object in storefront scripts
  const themeObjMatch = /Shopify\.theme\s*=\s*(\{[^;]+?\});/i.exec(html);
  if (themeObjMatch) {
    try {
      const parsed = JSON.parse(themeObjMatch[1]);
      if (typeof parsed.name === 'string') name = parsed.name.trim();
      if (parsed.id != null) id = String(parsed.id);
      if (typeof parsed.theme_store_id === 'number') themeStoreId = parsed.theme_store_id;
      if (typeof parsed.role === 'string') role = parsed.role;
    } catch {
      const nameM = /["']name["']\s*:\s*["']([^"']+)["']/i.exec(themeObjMatch[1]);
      if (nameM) name = nameM[1].trim();
      const idM = /["']id["']\s*:\s*(\d+)/i.exec(themeObjMatch[1]);
      if (idM) id = idM[1];
      const storeIdM = /["']theme_store_id["']\s*:\s*(\d+)/i.exec(themeObjMatch[1]);
      if (storeIdM) themeStoreId = parseInt(storeIdM[1], 10);
      const roleM = /["']role["']\s*:\s*["']([^"']+)["']/i.exec(themeObjMatch[1]);
      if (roleM) role = roleM[1];
    }
  }

  // 2. Direct assignment or BOOMR theme variables
  if (!name) {
    const directName = /Shopify\.theme\.name\s*=\s*["']([^"']+)["']/i.exec(html);
    if (directName) name = directName[1].trim();
  }
  if (!name) {
    const boomrName = /BOOMR\.themeName\s*=\s*["']([^"']+)["']/i.exec(html);
    if (boomrName) name = boomrName[1].trim();
  }
  if (!version) {
    const boomrVer = /BOOMR\.themeVersion\s*=\s*["']([^"']+)["']/i.exec(html);
    if (boomrVer) version = boomrVer[1].trim();
  }
  if (!id) {
    const boomrId = /BOOMR\.themeId\s*=\s*(\d+)/i.exec(html);
    if (boomrId) id = boomrId[1];
  }
  if (!id) {
    const idMatch =
      /["']theme_id["']\s*:\s*(\d+)/i.exec(html) ??
      /data-theme-id=["'](\d+)["']/i.exec(html);
    if (idMatch) id = idMatch[1];
  }

  const themeStoreName = getShopifyThemeStoreName(themeStoreId);
  const effectiveName = name || themeStoreName;
  const themeStoreUrl = getShopifyThemeStoreUrl(themeStoreName || effectiveName);
  const known = isKnownShopifyTheme(effectiveName) || Boolean(themeStoreName);

  return {
    name: effectiveName,
    id,
    themeStoreId,
    themeStoreName,
    themeStoreUrl,
    version,
    role,
    known,
  };
}

// ----------------------------------------------------------------
// WordPress plugins from asset paths (/wp-content/plugins/<slug>/)
// ----------------------------------------------------------------

const WP_PLUGIN_IGNORE = new Set([
  'cache',
  'uploads',
  'upgrade',
  'languages',
  'dist',
  'build',
  'assets',
  'vendor',
  'node_modules',
  'tmp',
  'temp',
]);

const VALID_PLUGIN_SLUG = /^[a-z0-9][a-z0-9_-]{1,60}$/i;

export function extractWpPlugins(html: string, limit = 8): string[] {
  const seen: string[] = [];
  const rx = /\/wp-content\/plugins\/([^/"'\s?#]+)/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(html)) !== null) {
    const slug = m[1].replace(/\/$/, '').toLowerCase();
    if (!slug || !VALID_PLUGIN_SLUG.test(slug) || WP_PLUGIN_IGNORE.has(slug) || seen.includes(slug)) {
      continue;
    }
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
  let wpThemeMeta: WpThemeMetaResult = {};
  let shopifyTheme: ShopifyThemeInfo = {};
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
  if (wpThemeMeta.themeName || wpThemeMeta.slug) {
    const themeDisplay = wpThemeMeta.themeName ?? wpThemeMeta.slug;
    const authorPart = wpThemeMeta.themeAuthor ? ` by ${wpThemeMeta.themeAuthor}` : '';
    const versionPart = wpThemeMeta.themeVersion ? ` v${wpThemeMeta.themeVersion}` : '';
    const childPart = wpThemeMeta.parentTheme ? ` (child of ${wpThemeMeta.parentTheme})` : '';
    results = results.map((r) => {
      if (r.id === 'wordpress') {
        return {
          ...r,
          evidence: [
            ...r.evidence,
            {
              type: 'probe' as const,
              artifact: `theme: "${themeDisplay}"${versionPart}${authorPart}${childPart}`,
              weight: 85,
              name: 'theme',
              value: themeDisplay ?? '',
              strength: 'strong' as const,
              family: 'PLATFORM_IDENTIFIER' as const,
              specificity: 0.7,
              description: 'WordPress theme identified',
              signalId: 'wordpress#probe:theme',
            },
          ],
        };
      }
      return r;
    });
  }

  // 6. Augment Shopify result with theme name / ID
  if (shopifyTheme.name || shopifyTheme.id || shopifyTheme.themeStoreName) {
    const displayName = shopifyTheme.name || shopifyTheme.themeStoreName || 'Custom';
    const storePart = shopifyTheme.themeStoreName && shopifyTheme.themeStoreName !== displayName
      ? ` [Store: ${shopifyTheme.themeStoreName}]`
      : '';
    const idPart = shopifyTheme.id ? ` (id ${shopifyTheme.id})` : '';
    const label = `theme: "${displayName}"${storePart}${idPart}`;
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
              value: displayName,
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
      ...(wpThemeMeta.themeName || wpThemeMeta.slug || themeSlug
        ? {
            wordpressTheme: {
              name: wpThemeMeta.themeName,
              author: wpThemeMeta.themeAuthor,
              authorUri: wpThemeMeta.themeAuthorUri,
              themeUri: wpThemeMeta.themeUri,
              version: wpThemeMeta.themeVersion,
              slug: wpThemeMeta.slug ?? themeSlug,
              parentTheme: wpThemeMeta.parentTheme,
              isChild: wpThemeMeta.isChild,
              known: isKnownWpTheme(wpThemeMeta.slug ?? themeSlug),
            },
          }
        : {}),
      ...(wpPlugins.length > 0 ? { wordpressPlugins: wpPlugins } : {}),
      ...(shopifyTheme.name || shopifyTheme.id || shopifyTheme.themeStoreName
        ? {
            shopifyTheme: {
              ...shopifyTheme,
              known: shopifyTheme.known ?? isKnownShopifyTheme(shopifyTheme.name),
            },
          }
        : {}),
    },
  };
}
