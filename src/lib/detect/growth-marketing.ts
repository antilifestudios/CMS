/**
 * Growth & Marketing detector module (v1: 38 technologies).
 *
 * Pure functions, no network, Workers-runtime compatible.
 * Fully data-driven: all vendor knowledge lives in
 * src/data/growth-marketing-signatures.ts — this file never names a
 * vendor. Channel extraction is REUSED from the security-privacy
 * detector (imported, not duplicated); only growth-specific channels
 * (data-* attributes, custom elements, style hooks) are added here.
 *
 * Channels inspected (attributes, code, headers, structure ONLY):
 * - resource URLs: script[src], link[href], iframe[src], img[src/srcset],
 *   source/video/audio/embed/track src, form[action], data-src
 *   (never <a href>, never visible text)
 * - inline <script> bodies (+ fetched first-party bundle JS bodies)
 * - GTM container JS (script-host + sdk-init rules only — hosts, init
 *   strings, ids; tag names and comments can never match)
 * - meta tags, DOM ids/classes, data-* attributes, custom-element tags,
 *   <style> hooks (for -apple-pay-button-style)
 * - Set-Cookie names (+ storage keys on the rendered seam)
 *
 * Scoring: noisy-OR over distinct evidence TYPES in 0-1, then
 * score100 = round(p*100). Bands follow the shared confidence.ts scale
 * (VERY HIGH >= 90, HIGH >= 75, MEDIUM >= 60, LOW >= 40); below 40 is
 * never reported. GTM-only evidence collapses to the single `via-gtm`
 * type (0.70), so it can never reach the top band on its own.
 */

import {
  GROWTH_MARKETING_SIGNATURES,
  GROWTH_STRONG_TYPES,
  type GrowthEvidenceType,
  type GrowthSignature,
} from '../../data/growth-marketing-signatures.ts';
import { extractChannels } from './security-privacy.ts';
import { sanitizeContainerJs } from './gtm-expansion.ts';

// ----------------------------------------------------------------
// Public types (mirror the API output schema)
// ----------------------------------------------------------------

export interface GrowthEvidence {
  type: GrowthEvidenceType;
  /** Human-readable "why" line for the UI. */
  detail: string;
  /** The exact matched snippet (verbatim evidence, truncated). */
  value?: string;
  /** Display family for the shared result-card UI. */
  family?: string;
}

export type GrowthBand = 'very-high' | 'high' | 'medium' | 'low';

export interface GrowthTechnology {
  id: string;
  name: string;
  website: string;
  band: GrowthBand;
  /** Lowercase twin of `band` for the shared result-card UI. */
  confidence: 'high' | 'medium' | 'low';
  /** 0–100 score (noisy-OR in 0-1, then round(p*100)). */
  score: number;
  score100: number;
  evidence: GrowthEvidence[];
  extractedIds: Array<{ kind: string; value: string }>;
  subNote?: string;
  variantNote?: string;
}

export interface GrowthCategoryGroup {
  id: 'analytics' | 'advertising' | 'marketing' | 'payments' | 'chat';
  name: string;
  count: number;
  technologies: GrowthTechnology[];
}

export interface GrowthInput {
  html: string;
  headers?: Record<string, string>;
  cookies?: string[];
  /** Bodies of fetched first-party JS bundles. */
  bundleJs?: string[];
  /** Fetched GTM container sources (Pass: container expansion). */
  gtmContainers?: Array<{ id: string; js: string }>;
  /** Rendered-pass extras (empty in static mode). */
  globals?: string[];
  networkRequests?: string[];
  storageKeys?: string[];
}

// ----------------------------------------------------------------
// Thresholds (shared confidence.ts bands; report floor = LOW floor)
// ----------------------------------------------------------------

export const VERY_HIGH_MIN = 90;
export const HIGH_MIN = 75;
export const MEDIUM_MIN = 60;
export const REPORT_MIN_POINTS = 40;
/** No strong evidence → cap below High. */
export const NO_STRONG_CAP = 0.74;
/** Seen only in CSP header / comments → cap at Low. */
export const HEADER_ONLY_CAP = 0.59;
/** Launch-only (tag manager, not the product) → cap at Low. */
export const LAUNCH_ONLY_CAP = 0.59;
/** GTM-only (no direct evidence) → cap below High. */
export const GTM_ONLY_CAP = 0.74;

export function bandForScore100(score100: number): GrowthBand {
  if (score100 >= VERY_HIGH_MIN) return 'very-high';
  if (score100 >= HIGH_MIN) return 'high';
  if (score100 >= MEDIUM_MIN) return 'medium';
  return 'low';
}

// Family labels for the shared result-card UI.
const FAMILY_FOR_TYPE: Record<GrowthEvidenceType, string> = {
  'script-host': 'SCRIPT',
  'sdk-init': 'SCRIPT',
  dom: 'HTML',
  'cookie-storage': 'COOKIE',
  'via-gtm': 'VIA_GTM',
};

// ----------------------------------------------------------------
// Growth-specific channels (data attrs, custom elements, style hooks)
// ----------------------------------------------------------------

export interface GrowthChannels {
  resourceHay: string;
  codeHay: string;
  domHay: string;
  attrHay: string;
  cookieHay: string;
  globalHay: string;
  commentHay: string;
  csp: string;
}

export function extractGrowthChannels(input: GrowthInput): GrowthChannels {
  const ch = extractChannels(input.html, input.headers ?? {});
  const bundles = input.bundleJs ?? [];

  const resourceHay = [...ch.resourceUrls, ...(input.networkRequests ?? [])].join('\n');
  const codeHay = [...ch.inlineScripts, ...bundles].join('\n');
  const domHay = ch.idsAndClasses.join(' ');
  const cookieHay = [...(input.cookies ?? []), ...(input.storageKeys ?? [])].join(' ');
  const globalHay = [...(input.globals ?? []), codeHay].join('\n');

  // data-* attributes (data-domain, data-payment_button_id …),
  // custom-element tags (<apple-pay-button>), and <style> hooks
  // (-apple-pay-button-style). Prose is never included.
  const attrs: string[] = [];
  const dataAttrRx = /\bdata-[a-z-]+\s*=\s*["'][^"']*["']/gi;
  let m: RegExpExecArray | null;
  while ((m = dataAttrRx.exec(input.html)) !== null) attrs.push(m[0]);
  const customElRx = /<([a-z]+-[a-z0-9-]+)(?=[\s/>])/gi;
  while ((m = customElRx.exec(input.html)) !== null) attrs.push(m[1]);
  const styleRx = /<style[^>]*>([\s\S]*?)<\/style\s*>/gi;
  while ((m = styleRx.exec(input.html)) !== null) attrs.push(m[1].slice(0, 20_000));

  return {
    resourceHay,
    codeHay,
    domHay,
    attrHay: [...attrs, domHay].join('\n'),
    cookieHay,
    globalHay,
    commentHay: ch.comments.join('\n'),
    csp: ch.csp,
  };
}

// ----------------------------------------------------------------
// Core detection
// ----------------------------------------------------------------

interface TypeHit {
  type: GrowthEvidenceType;
  weight: number;
  detail: string;
  value: string;
  headerOnly: boolean;
  launchOnly: boolean;
  product?: string;
}

const regexCache = new Map<string, RegExp>();
function rx(pattern: string): RegExp {
  let r = regexCache.get(pattern);
  if (!r) {
    r = new RegExp(pattern, 'i');
    regexCache.set(pattern, r);
  }
  r.lastIndex = 0;
  return r;
}

function snippetFor(re: RegExp, hay: string): string {
  re.lastIndex = 0;
  const m = re.exec(hay);
  if (!m) return '';
  const s = m[0].replace(/\s+/g, ' ').trim();
  return s.length > 140 ? `${s.slice(0, 137)}…` : s;
}

function matchDirect(sig: GrowthSignature, bags: GrowthChannels): TypeHit[] {
  const hits: TypeHit[] = [];
  for (const rule of sig.evidence) {
    const re = rx(rule.pattern);
    let matched = false;
    let headerOnly = false;
    let value = '';

    switch (rule.type) {
      case 'script-host': {
        if (re.test(bags.resourceHay)) {
          matched = true;
          value = snippetFor(re, bags.resourceHay);
        } else if (re.test(bags.csp) || re.test(bags.commentHay)) {
          // Vendor domain visible ONLY inside CSP / comments → weak.
          matched = true;
          headerOnly = true;
          value = snippetFor(re, `${bags.csp}\n${bags.commentHay}`);
        }
        break;
      }
      case 'sdk-init': {
        if (re.test(bags.globalHay)) {
          matched = true;
          value = snippetFor(re, bags.globalHay);
        }
        break;
      }
      case 'dom': {
        const hay = `${bags.domHay}\n${bags.attrHay}\n${bags.codeHay}`;
        if (re.test(hay)) {
          matched = true;
          value = snippetFor(re, hay);
        }
        break;
      }
      case 'cookie-storage': {
        if (re.test(bags.cookieHay)) {
          matched = true;
          value = snippetFor(re, bags.cookieHay);
        }
        break;
      }
    }

    if (matched) {
      hits.push({
        type: rule.type,
        weight: rule.weight,
        detail: rule.description,
        value,
        headerOnly,
        launchOnly: rule.launchOnly ?? false,
        product: rule.product,
      });
    }
  }
  return hits;
}

/**
 * Scan GTM container sources with script-host + sdk-init rules ONLY
 * (hosts, SDK init strings, ids — never DOM ids, cookies, tag names or
 * comments). Every match becomes `via-gtm` evidence at 0.70 for that
 * container; scoring counts the type once.
 */
function matchContainers(
  sig: GrowthSignature,
  containers: Array<{ id: string; js: string }>,
): TypeHit[] {
  const hits: TypeHit[] = [];
  const eligible = sig.evidence.filter((r) => r.type === 'script-host' || r.type === 'sdk-init');
  for (const c of containers) {
    // Tag names and comments are stripped first: a name match is not
    // integration evidence (hosts / init strings / ids only).
    const js = sanitizeContainerJs(c.js);
    for (const rule of eligible) {
      // Generic weak hints stay weak: they can never become container
      // evidence on their own.
      if (rule.weight < 0.35) continue;
      const re = rx(rule.pattern);
      if (re.test(js)) {
        hits.push({
          type: 'via-gtm',
          weight: 0.7,
          detail: `Found in GTM container ${c.id}: ${rule.description}`,
          value: snippetFor(re, js),
          headerOnly: false,
          launchOnly: rule.launchOnly ?? false,
          product: rule.product,
        });
        break; // one entry per container per technology
      }
    }
  }
  return hits;
}

const idRegexCache = new Map<string, RegExp>();
function idRx(pattern: string): RegExp {
  let r = idRegexCache.get(pattern);
  if (!r) {
    r = new RegExp(pattern, 'gi');
    idRegexCache.set(pattern, r);
  }
  r.lastIndex = 0;
  return r;
}

function extractIds(
  sig: GrowthSignature,
  bags: GrowthChannels,
  containers: Array<{ id: string; js: string }>,
): Array<{ kind: string; value: string }> {
  if (!sig.ids?.length) return [];
  const hay = `${bags.resourceHay}\n${bags.codeHay}\n${containers.map((c) => c.js).join('\n')}`;
  const out: Array<{ kind: string; value: string }> = [];
  for (const rule of sig.ids) {
    const re = idRx(rule.pattern);
    let m: RegExpExecArray | null;
    while ((m = re.exec(hay)) !== null && out.length < 10) {
      const v = (m[1] ?? '').trim();
      if (!v || v.length > 128) continue;
      // Known GTM-internal placeholder, not a real container id.
      if (/^gtm-webtemplate$/i.test(v)) continue;
      if (!out.some((o) => o.kind === rule.kind && o.value === v)) out.push({ kind: rule.kind, value: v });
    }
  }
  return out;
}

export function detectGrowthMarketing(input: GrowthInput): GrowthTechnology[] {
  const bags = extractGrowthChannels(input);
  const containers = input.gtmContainers ?? [];
  const out: GrowthTechnology[] = [];

  for (const sig of GROWTH_MARKETING_SIGNATURES) {
    const direct = matchDirect(sig, bags);
    const viaGtm = matchContainers(sig, containers);
    const hits = [...direct, ...viaGtm];
    if (hits.length === 0) continue;

    // Count each evidence TYPE once (strongest rule wins the type).
    const bestByType = new Map<GrowthEvidenceType, TypeHit>();
    for (const h of hits) {
      const prev = bestByType.get(h.type);
      if (!prev || h.weight > prev.weight) bestByType.set(h.type, h);
    }

    let p = 1;
    for (const h of bestByType.values()) p *= 1 - h.weight;
    p = 1 - p;

    const hasStrong = [...bestByType.keys()].some((t) => GROWTH_STRONG_TYPES.has(t));
    if (!hasStrong) p = Math.min(p, NO_STRONG_CAP);

    const allHeaderOnly = [...bestByType.values()].every((h) => h.headerOnly);
    if (allHeaderOnly) p = Math.min(p, HEADER_ONLY_CAP);

    const allLaunchOnly = [...bestByType.values()].every((h) => h.launchOnly);
    if (allLaunchOnly) p = Math.min(p, LAUNCH_ONLY_CAP);

    const directTypes = direct.length > 0;
    if (!directTypes) p = Math.min(p, GTM_ONLY_CAP);

    const score100 = Math.round(p * 100);
    if (score100 < REPORT_MIN_POINTS) continue;

    const evidence: GrowthEvidence[] = [...bestByType.values()].map((h) => ({
      type: h.type,
      detail: h.detail,
      ...(h.value ? { value: h.value } : {}),
      family: FAMILY_FOR_TYPE[h.type],
    }));
    // Keep per-container entries visible even though scoring counts the
    // type once: append the extra containers after the winning entry.
    const extraContainers = viaGtm.filter((h) => {
      const winner = bestByType.get('via-gtm');
      return winner && h.detail !== winner.detail;
    });
    for (const h of extraContainers) {
      evidence.push({
        type: 'via-gtm',
        detail: h.detail,
        ...(h.value ? { value: h.value } : {}),
        family: FAMILY_FOR_TYPE['via-gtm'],
      });
    }

    const extractedIds = extractIds(sig, bags, containers);

    // Salesforce: name the matched products.
    const products = [...new Set(hits.map((h) => h.product).filter((x): x is string => Boolean(x)))];
    let subNote: string | undefined;
    if (sig.id === 'salesforce' && products.length > 0) {
      subNote = `Matched product${products.length === 1 ? '' : 's'}: ${products.join(', ')}.`;
    }
    // GA legacy note: UA- without any G- is Universal Analytics (legacy).
    if (sig.id === 'google-analytics') {
      const hasG = extractedIds.some((e) => e.kind === 'GA4 measurement ID');
      const ua = extractedIds.filter((e) => e.kind === 'UA property (legacy)');
      if (!hasG && ua.length > 0) {
        subNote = `Universal Analytics (legacy) ${ua.map((e) => e.value).join(', ')}; GA4 (G-…) not seen.`;
      }
    }

    const band = bandForScore100(score100);
    out.push({
      id: sig.id,
      name: sig.name,
      website: sig.website,
      band,
      confidence: band === 'medium' ? 'medium' : band === 'low' ? 'low' : 'high',
      score: score100,
      score100,
      evidence,
      extractedIds,
      ...(subNote ? { subNote } : {}),
      ...(sig.variantNote ? { variantNote: sig.variantNote } : {}),
    });
  }

  return out.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
}

// ----------------------------------------------------------------
// Category grouping + server-side blind-spot warning
// ----------------------------------------------------------------

const CATEGORY_NAMES: Record<GrowthCategoryGroup['id'], string> = {
  analytics: 'Analytics',
  advertising: 'Advertising',
  marketing: 'Marketing',
  payments: 'Payments',
  chat: 'Chat & Support',
};

export function groupGrowthByCategory(techs: GrowthTechnology[]): GrowthCategoryGroup[] {
  const order: GrowthCategoryGroup['id'][] = ['analytics', 'advertising', 'marketing', 'payments', 'chat'];
  return order.map((id) => {
    const technologies = techs.filter((t) => {
      const sig = GROWTH_MARKETING_SIGNATURES.find((s) => s.id === t.id);
      return sig?.category === id;
    });
    return { id, name: CATEGORY_NAMES[id], count: technologies.length, technologies };
  });
}

/**
 * Server-side tagging / Zaraz blind spot: when the page shows a
 * server-side GTM endpoint or Cloudflare Zaraz, tools may load without
 * any client-visible vendor host.
 */
export function serverSideWarning(html: string, bundleJs: string[]): string | null {
  const hay = `${html.slice(0, 200_000)}\n${bundleJs.join('\n').slice(0, 200_000)}`.toLowerCase();
  if (hay.includes('/cdn-cgi/zaraz/') || hay.includes('zaraz.track') || hay.includes('sgtm.') || hay.includes('/g/collect?')) {
    return 'Tools may be loaded server-side or via Zaraz and cannot be fully detected.';
  }
  return null;
}
