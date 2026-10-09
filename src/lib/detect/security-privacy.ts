/**
 * Security & Privacy detector module (v1: 26 technologies).
 *
 * Pure functions, no network, Workers-runtime compatible.
 * Detection logic is fully data-driven: all vendor knowledge lives in
 * src/data/security-privacy-signatures.ts — this file never names a vendor.
 *
 * Channels inspected (attributes, code, headers, structure ONLY):
 * - resource URLs: script[src], link[href], iframe[src], img[src/srcset],
 *   source/video/audio/embed/track src, form[action], data-src
 * - inline <script> bodies (+ fetched first-party bundle JS bodies)
 * - meta tags, DOM ids/classes
 * - Set-Cookie names + CSP/response headers, storage keys
 * Visible page text and <a href> links are NEVER inspected.
 */

import {
  SECURITY_PRIVACY_SIGNATURES,
  STRONG_EVIDENCE_TYPES,
  type SecurityPrivacyEvidenceType,
  type SecurityPrivacySignature,
} from '../../data/security-privacy-signatures.ts';
import { sanitizeContainerJs } from './gtm-expansion.ts';

// ----------------------------------------------------------------
// Public types (mirror the API output schema)
// ----------------------------------------------------------------

export interface SecurityPrivacyEvidence {
  /** Evidence channel, e.g. "script-host". One entry per TYPE per tech. */
  type: SecurityPrivacyEvidenceType;
  /** Human-readable "why" line for the UI. */
  detail: string;
}

export type SecurityPrivacyConfidence = 'high' | 'medium' | 'low';

export interface SecurityPrivacyTechnology {
  id: string;
  name: string;
  website: string;
  confidence: SecurityPrivacyConfidence;
  /** 0.00–1.00 noisy-OR score. */
  score: number;
  /** 0–100 twin of `score` for the shared result-card UI. */
  score100: number;
  evidence: SecurityPrivacyEvidence[];
  variantNote?: string;
}

export interface SecurityPrivacyCategoryGroup {
  id: 'privacy' | 'security' | 'other';
  name: string;
  count: number;
  technologies: SecurityPrivacyTechnology[];
}

export interface SecurityPrivacyInput {
  html: string;
  headers?: Record<string, string>;
  cookies?: string[];
  /** Bodies of fetched first-party JS bundles (Pass 1b). */
  bundleJs?: string[];
  /** Fetched GTM container sources (container expansion — shared module). */
  gtmContainers?: Array<{ id: string; js: string }>;
  /** Rendered-pass extras (Pass 2 seam — empty in static mode). */
  globals?: string[];
  networkRequests?: string[];
  storageKeys?: string[];
}

// ----------------------------------------------------------------
// Thresholds (spec)
// ----------------------------------------------------------------

export const HIGH_MIN = 0.85;
export const MEDIUM_MIN = 0.6;
export const LOW_MIN = 0.35;
/** Below this: do NOT report. Never emit a weak guess. */
export const REPORT_MIN = 0.35;
/** No strong evidence → cap below High. */
export const NO_STRONG_CAP = 0.84;
/** Seen only in CSP header / comments → cap at Low. */
export const HEADER_ONLY_CAP = 0.59;

export function confidenceLabel(score: number): SecurityPrivacyConfidence {
  if (score >= HIGH_MIN) return 'high';
  if (score >= MEDIUM_MIN) return 'medium';
  return 'low';
}

// ----------------------------------------------------------------
// HTML channel extraction (regex-based, no DOM parser dependency)
// ----------------------------------------------------------------

export interface ParsedChannels {
  /** All loaded resource URLs (never <a href>, never prose). */
  resourceUrls: string[];
  /** iframe src values only (for iframe-type rules). */
  iframeSrcs: string[];
  inlineScripts: string[];
  meta: string[];
  idsAndClasses: string[];
  /** data-sitekey attribute values (for placeholder vetoes). */
  sitekeys: string[];
  comments: string[];
  csp: string;
}

const NON_USAGE_BLOCK_RX = /<(style|pre|code)[\s>][\s\S]*?<\/\1\s*>/gi;
const FENCED_CODE_RX = /```[\s\S]*?```/g;
const JSONLD_RX = /<script[^>]+type=["']application\/ld\+json["'][^>]*>[\s\S]*?<\/script\s*>/gi;
const COMMENT_RX = /<!--([\s\S]*?)-->/g;

function stripNonUsage(html: string): string {
  let out = html;
  out = out.replace(NON_USAGE_BLOCK_RX, '');
  out = out.replace(FENCED_CODE_RX, '');
  out = out.replace(JSONLD_RX, '');
  return out;
}

export function extractChannels(html: string, headers: Record<string, string> = {}): ParsedChannels {
  const resourceUrls: string[] = [];
  const iframeSrcs: string[] = [];
  const inlineScripts: string[] = [];
  const meta: string[] = [];
  const idsAndClasses: string[] = [];
  const comments: string[] = [];

  let m: RegExpExecArray | null;

  // Resource URLs — every loaded reference EXCEPT <a href>.
  const attrRx =
    /<(script|iframe|img|source|video|audio|embed|track|link|form)[^>]*?(?:src|href|action|data-src|data-href)=["']([^"']+)["']/gi;
  const srcsetRx = /<(img|source|video)[^>]*?srcset=["']([^"']+)["']/gi;
  while ((m = attrRx.exec(html)) !== null) {
    const tag = m[1].toLowerCase();
    const val = m[2];
    if (!val || val.startsWith('data:') || val.startsWith('blob:') || val.startsWith('javascript:')) continue;
    resourceUrls.push(val);
    if (tag === 'iframe') iframeSrcs.push(val);
  }
  while ((m = srcsetRx.exec(html)) !== null) {
    for (const part of m[2].split(',')) {
      const url = part.trim().split(/\s+/)[0];
      if (url && !url.startsWith('data:')) resourceUrls.push(url);
    }
  }

  // Inline scripts from usage HTML only (docs <pre>/<code>, <style>,
  // JSON-LD and fenced samples are stripped — quoting an SDK is not usage).
  const usage = stripNonUsage(html);
  const scriptRx = /<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script\s*>/gi;
  while ((m = scriptRx.exec(usage)) !== null) {
    if (m[1].trim()) inlineScripts.push(m[1]);
  }

  const metaRx = /<meta[^>]+(?:name|property|itemprop)=["']([^"']+)["'][^>]*content=["']([^"']+)["'][^>]*>/gi;
  while ((m = metaRx.exec(html)) !== null) {
    meta.push(`${m[1]}=${m[2]}`);
  }

  const idRx = /\bid\s*=\s*["']([^"']+)["']/gi;
  while ((m = idRx.exec(html)) !== null) idsAndClasses.push(m[1]);
  const classRx = /\bclass\s*=\s*["']([^"']+)["']/gi;
  while ((m = classRx.exec(html)) !== null) idsAndClasses.push(m[1]);

  const sitekeys: string[] = [];
  const sitekeyRx = /\bdata-sitekey\s*=\s*["']([^"']+)["']/gi;
  while ((m = sitekeyRx.exec(html)) !== null) sitekeys.push(m[1]);

  while ((m = COMMENT_RX.exec(html)) !== null) {
    comments.push(m[1]);
  }

  const csp = headers['content-security-policy'] ?? '';

  return { resourceUrls, iframeSrcs, inlineScripts, meta, idsAndClasses, sitekeys, comments, csp };
}

// ----------------------------------------------------------------
// Placeholder vetoes (a demo key is not an integration)
// ----------------------------------------------------------------

const PLACEHOLDER_RX =
  /(YOUR_SITE_KEY|YOUR_API_KEY|placeholder|example|test|x{3,}|12345|10000000-ffff-ffff-ffff-000000000001)/i;

/**
 * Veto when a widget's data-sitekey is a demo placeholder. Only short
 * values are checked — real sitekeys are long random strings, so a
 * 40-character production key can never trip this.
 */
function hasPlaceholderDom(ch: ParsedChannels): boolean {
  return ch.sitekeys.some((k) => k.length < 30 && PLACEHOLDER_RX.test(k));
}

// ----------------------------------------------------------------
// Core detection (noisy-OR over distinct evidence TYPES)
// ----------------------------------------------------------------

interface TypeHit {
  type: SecurityPrivacyEvidenceType;
  weight: number;
  detail: string;
  headerOnly: boolean;
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

export function detectSecurityPrivacy(input: SecurityPrivacyInput): SecurityPrivacyTechnology[] {
  const headers = input.headers ?? {};
  const cookies = input.cookies ?? [];
  const bundles = input.bundleJs ?? [];
  const ch = extractChannels(input.html, headers);

  const codeHay = [...ch.inlineScripts, ...bundles].join('\n');
  const resourceHay = [...ch.resourceUrls, ...(input.networkRequests ?? [])].join('\n');
  const domHay = ch.idsAndClasses.join(' ');
  const cookieHay = [...cookies, ...(input.storageKeys ?? [])].join(' ');
  const globalHay = [...(input.globals ?? []), codeHay].join('\n');
  const commentHay = ch.comments.join('\n');

  const out: SecurityPrivacyTechnology[] = [];

  for (const sig of SECURITY_PRIVACY_SIGNATURES) {
    const hits = [
      ...matchSignature(sig, {
        ch,
        codeHay,
        resourceHay,
        domHay,
        cookieHay,
        globalHay,
        commentHay,
        csp: ch.csp,
      }),
      ...matchGtmContainers(sig, input.gtmContainers ?? []),
    ];
    if (hits.length === 0) continue;

    // Count each evidence TYPE once (strongest rule wins the type).
    const bestByType = new Map<SecurityPrivacyEvidenceType, TypeHit>();
    for (const h of hits) {
      const prev = bestByType.get(h.type);
      if (!prev || h.weight > prev.weight) bestByType.set(h.type, h);
    }

    let confidence = 1;
    for (const h of bestByType.values()) confidence *= 1 - h.weight;
    confidence = 1 - confidence;

    const hasStrong = [...bestByType.keys()].some((t) => STRONG_EVIDENCE_TYPES.has(t));
    if (!hasStrong) confidence = Math.min(confidence, NO_STRONG_CAP);

    const allHeaderOnly = [...bestByType.values()].every((h) => h.headerOnly);
    if (allHeaderOnly) confidence = Math.min(confidence, HEADER_ONLY_CAP);

    if (confidence < REPORT_MIN) continue;

    // Placeholder sitekeys are demo code, not integrations.
    if (
      (sig.id === 'recaptcha' || sig.id === 'hcaptcha' || sig.id === 'cloudflare-turnstile') &&
      hasPlaceholderDom(ch)
    ) {
      continue;
    }

    const score = Math.round(confidence * 100) / 100;
    out.push({
      id: sig.id,
      name: sig.name,
      website: sig.website,
      confidence: confidenceLabel(score),
      score,
      score100: Math.round(score * 100),
      evidence: [...bestByType.values()].map((h) => ({ type: h.type, detail: h.detail })),
      ...(sig.variantNote ? { variantNote: sig.variantNote } : {}),
    });
  }

  return out.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
}

interface ChannelBags {
  ch: ParsedChannels;
  codeHay: string;
  resourceHay: string;
  domHay: string;
  cookieHay: string;
  globalHay: string;
  commentHay: string;
  csp: string;
}

function matchSignature(sig: SecurityPrivacySignature, bags: ChannelBags): TypeHit[] {
  const hits: TypeHit[] = [];

  for (const rule of sig.evidence) {
    const re = rx(rule.pattern);
    let matched = false;
    let headerOnly = false;

    switch (rule.type) {
      case 'script-host':
      case 'network-host': {
        if (re.test(bags.resourceHay)) {
          matched = true;
          // Vendor domain visible ONLY inside CSP / comments → weak.
          const withoutCspComments =
            bags.ch.resourceUrls.join('\n') + '\n' + bags.codeHay;
          if (!re.test(withoutCspComments) && (re.test(bags.csp) || re.test(bags.commentHay))) {
            headerOnly = true;
          }
        } else if (re.test(bags.csp) || re.test(bags.commentHay)) {
          matched = true;
          headerOnly = true;
        }
        break;
      }
      case 'iframe': {
        const iframeHay = bags.ch.iframeSrcs.join('\n');
        if (re.test(iframeHay)) {
          matched = true;
        } else if (re.test(bags.commentHay)) {
          matched = true;
          headerOnly = true;
        }
        // NOTE: <a href> watch/share links are never in iframeSrcs, so a
        // plain link to youtube.com can never satisfy an iframe rule.
        break;
      }
      case 'sdk-init':
      case 'runtime-global': {
        if (re.test(bags.globalHay)) matched = true;
        break;
      }
      case 'dom': {
        if (re.test(bags.domHay) || re.test(bags.codeHay)) matched = true;
        break;
      }
      case 'cookie-storage': {
        if (re.test(bags.cookieHay)) matched = true;
        break;
      }
    }

    if (matched) {
      hits.push({ type: rule.type, weight: rule.weight, detail: rule.description, headerOnly });
    }
  }

  return hits;
}

// ----------------------------------------------------------------
// GTM container expansion (shared gtm-expansion.ts fetches the files;
// this maps container-source matches to `via-gtm` evidence).
//
// Only host / SDK-init / global rules run against container sources —
// DOM ids, cookies, tag NAMES and comments can never match, so a
// technology is never reported just because its name appears in a tag
// name. Every container hit weighs 0.70 and `via-gtm` is NOT in
// STRONG_EVIDENCE_TYPES, so GTM-only evidence caps below High.
// ----------------------------------------------------------------

/** Rule types eligible for container-source matching. */
const GTM_ELIGIBLE: ReadonlySet<string> = new Set([
  'script-host',
  'network-host',
  'iframe',
  'sdk-init',
  'runtime-global',
]);

export const VIA_GTM_WEIGHT = 0.7;

function matchGtmContainers(
  sig: SecurityPrivacySignature,
  containers: Array<{ id: string; js: string }>,
): TypeHit[] {
  const hits: TypeHit[] = [];
  if (containers.length === 0) return hits;
  for (const c of containers) {
    // Tag names and comments are stripped first: a name match is not
    // integration evidence (hosts / init strings / ids only).
    const js = sanitizeContainerJs(c.js);
    for (const rule of sig.evidence) {
      if (!GTM_ELIGIBLE.has(rule.type)) continue;
      // Generic weak hints (e.g. IAB __tcfapi) stay weak: they can never
      // become container evidence on their own.
      if (rule.weight < 0.35) continue;
      if (rx(rule.pattern).test(js)) {
        hits.push({
          type: 'via-gtm',
          weight: VIA_GTM_WEIGHT,
          detail: `Found in GTM container ${c.id}: ${rule.description}`,
          headerOnly: false,
        });
        break; // one entry per container per technology
      }
    }
  }
  return hits;
}

// ----------------------------------------------------------------
// Category grouping for the API output schema
// ----------------------------------------------------------------

const CATEGORY_NAMES: Record<SecurityPrivacyCategory, string> = {
  privacy: 'Privacy / Consent',
  security: 'Security',
  other: 'Other technologies',
};

export function groupByCategory(techs: SecurityPrivacyTechnology[]): SecurityPrivacyCategoryGroup[] {
  const order: SecurityPrivacyCategory[] = ['privacy', 'security', 'other'];
  return order.map((id) => {
    const technologies = techs.filter((t) => {
      const sig = SECURITY_PRIVACY_SIGNATURES.find((s) => s.id === t.id);
      return sig?.category === id;
    });
    return { id, name: CATEGORY_NAMES[id], count: technologies.length, technologies };
  });
}
