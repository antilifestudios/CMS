/**
 * Shared GTM container expansion — imported by BOTH family detectors
 * (security-privacy and growth-marketing). No duplicated logic.
 *
 * Many tools are injected through Google Tag Manager, so a plain HTML
 * scan misses them. GTM container files (gtm.js?id=GTM-XXXXXXX) are
 * public JavaScript and can be scanned with the same signatures.
 *
 * Evidence from a container gets weight 0.70 ("via GTM container"): the
 * tag may be paused, consent-gated, or conditionally fired, so it is not
 * proof the tool runs. Container-only evidence therefore combines to at
 * most 0.70 and can never reach the top band on its own.
 *
 * Rules:
 * - Max 3 containers per scan, deduplicated, short-TTL cache by id.
 * - Same SSRF protection as other fetches; fetches are pinned to
 *   www.googletagmanager.com and must NOT follow redirects off-host.
 * - 5 s timeout, 400 KB size cap. Fail soft: on fetch failure return a
 *   warning and let the caller keep its normal results.
 * - Never report a technology just because its NAME appears in a GTM tag
 *   name or comment: callers must match hosts / SDK init strings / ids
 *   only (the detectors already do this — they never scan prose).
 */

import { validateUrl } from './ssrf.ts';
import {
  createBudget,
  fetchWithRedirects,
  readCappedText,
  type FetchFn,
  type ScanBudget,
} from './static-collect.ts';

export const GTM_CONTAINER_HOST = 'www.googletagmanager.com';
export const MAX_GTM_CONTAINERS = 3;
export const GTM_CONTAINER_TIMEOUT_MS = 5_000;
export const MAX_GTM_CONTAINER_BYTES = 400_000;
const GTM_CACHE_TTL_MS = 5 * 60_000;

const GTM_ID_RX = /GTM-[A-Z0-9]+/g;
/** gtag.js loader ids: G- (GA4), AW- (Ads), GT- (generic tag), UA- (legacy). */
const GTAG_ID_RX =
  /googletagmanager\.com\/gtag\/js\?id=(G-[A-Z0-9]+|AW-[A-Z0-9/_-]+|GT-[A-Z0-9]+|UA-\d+-\d+)/gi;

export interface GtmFetchResult {
  containers: Array<{ id: string; js: string; truncated: boolean }>;
  warnings: string[];
}

/** Extract GTM-XXXXXXX ids from HTML, bundles and noscript iframes. */
export function extractGtmIds(html: string, bundles: string[] = []): string[] {
  const out: string[] = [];
  const push = (src: string) => {
    GTM_ID_RX.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = GTM_ID_RX.exec(src)) !== null) {
      if (!out.includes(m[0])) out.push(m[0]);
    }
  };
  push(html);
  for (const b of bundles) push(b);
  return out;
}

export interface GtagIds {
  ga4: string[];
  ads: string[];
  generic: string[];
  legacy: string[];
}

/**
 * Extract gtag.js ids by product prefix. Used for disambiguation
 * (G- = Analytics, AW- = Ads) and extractedIds — NOT fetched as
 * containers (gtag.js is a generic loader with no per-id content).
 */
export function extractGtagIds(html: string, bundles: string[] = []): GtagIds {
  const ids: GtagIds = { ga4: [], ads: [], generic: [], legacy: [] };
  const push = (src: string) => {
    GTAG_ID_RX.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = GTAG_ID_RX.exec(src)) !== null) {
      const id = m[1];
      const bucket = id.startsWith('G-')
        ? ids.ga4
        : id.startsWith('AW-')
          ? ids.ads
          : id.startsWith('GT-')
            ? ids.generic
            : ids.legacy;
      if (!bucket.includes(id)) bucket.push(id);
    }
  };
  push(html);
  for (const b of bundles) push(b);
  return ids;
}

const containerCache = new Map<string, { js: string; expires: number }>();

export function clearGtmCache(): void {
  containerCache.clear();
}

/**
 * Strip GTM tag NAMES and JS comments before signature matching: a
 * technology must never be reported just because its name appears in a
 * tag name or comment. Hosts, SDK init strings, DSNs and ids live in
 * code/URLs and survive this sanitisation.
 */
export function sanitizeContainerJs(js: string): string {
  return js
    .replace(/"name"\s*:\s*"([^"\\]|\\.)*"/g, '"name":""')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:/])\/\/[^\n]*/g, '$1 ');
}

async function fetchOneContainer(
  id: string,
  signal: AbortSignal,
  budget: ScanBudget,
  fetchImpl: FetchFn,
): Promise<{ id: string; js: string; truncated: boolean } | { warning: string }> {
  const cached = containerCache.get(id);
  if (cached && cached.expires > Date.now()) {
    return { id, js: cached.js, truncated: false };
  }
  const target = `https://${GTM_CONTAINER_HOST}/gtm.js?id=${encodeURIComponent(id)}`;
  const validated = validateUrl(target);
  if (!validated.ok) return { warning: `Skipped GTM container ${id}: blocked address.` };

  const ctrl = new AbortController();
  const onAbort = () => ctrl.abort();
  signal.addEventListener('abort', onAbort, { once: true });
  const t = setTimeout(() => ctrl.abort(), GTM_CONTAINER_TIMEOUT_MS);
  try {
    const fetched = await fetchWithRedirects(validated.url, ctrl.signal, '*/*', budget, fetchImpl, {
      pinHost: GTM_CONTAINER_HOST,
    });
    if ('error' in fetched) {
      const detail = fetched.message || fetched.error;
      return { warning: `GTM container ${id} unavailable (${detail})` };
    }
    const ct = (fetched.res.headers.get('content-type') ?? '').toLowerCase();
    if (!fetched.res.ok || !(ct.includes('javascript') || ct.includes('ecmascript') || ct === '' || ct.includes('text'))) {
      try {
        await fetched.res.arrayBuffer();
      } catch {
        /* noop */
      }
      return { warning: `GTM container ${id} returned an unexpected response.` };
    }
    const { text, truncated } = await readCappedText(fetched.res, MAX_GTM_CONTAINER_BYTES);
    containerCache.set(id, { js: text, expires: Date.now() + GTM_CACHE_TTL_MS });
    if (containerCache.size > 500) {
      const first = containerCache.keys().next();
      if (!first.done) containerCache.delete(first.value);
    }
    return { id, js: text, truncated };
  } catch {
    return { warning: `GTM container ${id} fetch failed; kept normal results.` };
  } finally {
    clearTimeout(t);
    signal.removeEventListener('abort', onAbort);
  }
}

/**
 * Fetch up to MAX_GTM_CONTAINERS container files. Never throws —
 * failures become warnings and the caller keeps its normal results.
 */
export async function fetchGtmContainers(
  ids: string[],
  signal: AbortSignal,
  budget?: ScanBudget,
  fetchImpl: FetchFn = fetch,
): Promise<GtmFetchResult> {
  const containers: GtmFetchResult['containers'] = [];
  const warnings: string[] = [];
  const unique = [...new Set(ids)].slice(0, MAX_GTM_CONTAINERS);
  // Share the caller's scan budget so containers count against the same
  // 40-subrequest cap; fall back to a fresh budget in tests.
  const local = budget ?? createBudget();
  for (const id of unique) {
    const r = await fetchOneContainer(id, signal, local, fetchImpl);
    if ('warning' in r) warnings.push(r.warning);
    else containers.push(r);
  }
  return { containers, warnings };
}
