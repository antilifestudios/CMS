/**
 * Signature types and engine.
 *
 * Data-driven: loads JSON from src/data/signatures/*.json.
 * Uses string search and pre-compiled regex — no DOM parser.
 * Workers-runtime compatible (no Node APIs).
 */

// ----------------------------------------------------------------
// Types
// ----------------------------------------------------------------

export type SignalType =
  | 'meta-generator'
  | 'html-path'
  | 'html-regex'
  | 'script-host'
  | 'stylesheet-url'
  | 'js-global'
  | 'inline-script'
  | 'meta-tag'
  | 'link-relation'
  | 'header'
  | 'cookie-name'
  | 'probe';

/**
 * Fingerprint strength — how much a single matching signal proves the tech.
 * - definitive: unambiguous vendor signals (cf-ray, server: cloudflare,
 *   x-vercel-id, an explicit generator tag naming the tech).
 * - strong: product-specific asset paths or markers (/_astro/,
 *   /_next/static/, data-astro-cid).
 * - weak: generic patterns other tech could also produce.
 * Optional in the JSON so older entries safely default to 'weak'.
 */
export type SignalStrength = 'definitive' | 'strong' | 'weak';

/**
 * Independent evidence families. Correlated manifestations of one
 * underlying fingerprint (e.g. three URLs on the same CDN host) share
 * a family; confidence rewards corroboration ACROSS families, never
 * duplicated lines within one.
 */
export type EvidenceFamily =
  | 'NETWORK'
  | 'HTML'
  | 'ASSET'
  | 'SCRIPT'
  | 'META'
  | 'COOKIE'
  | 'PLATFORM_IDENTIFIER';

/** Default family per signal channel (overridable per rule). */
export function familyForSignal(type: SignalType, explicit?: EvidenceFamily): EvidenceFamily {
  if (explicit) return explicit;
  switch (type) {
    case 'header':           return 'NETWORK';
    case 'cookie-name':      return 'COOKIE';
    case 'meta-generator':
    case 'meta-tag':         return 'META';
    case 'script-host':
    case 'js-global':        return 'SCRIPT';
    case 'stylesheet-url':
    case 'html-path':        return 'ASSET';
    case 'inline-script':
    case 'html-regex':
    case 'link-relation':    return 'HTML';
    case 'probe':            return 'PLATFORM_IDENTIFIER';
  }
}

/** Default specificity multiplier per strength (overridable per rule). */
export function specificityForStrength(strength: SignalStrength, explicit?: number): number {
  if (typeof explicit === 'number') return Math.min(1, Math.max(0, explicit));
  switch (strength) {
    case 'definitive': return 1.0;
    case 'strong':     return 0.7;
    case 'weak':       return 0.3;
  }
}

export interface Signal {
  type: SignalType;
  /** For header signals: which header name */
  name?: string;
  /** Regex pattern string */
  pattern: string;
  /** Confidence contribution (0–100): HOW PROVING this concrete
   *  signal is. Known official SDK ≈ 90+, unique init/endpoint ≈
   *  80–90, resource domain ≈ 55–70, generic keyword ≈ 10–30.
   *  The confidence model scales this by specificity, so one very
   *  strong signal can confirm a technology on its own. */
  weight: number;
  /** Fingerprint strength (defaults to 'weak' when omitted) */
  strength?: SignalStrength;
  /** Capture group index for version extraction */
  versionGroup?: number;
  /** Evidence family override (defaults from signal type) */
  family?: EvidenceFamily;
  /** Specificity multiplier 0–1 (defaults from strength) */
  specificity?: number;
  /** Human-readable evidence line, e.g. "Known Sentry browser SDK
   *  detected". Shown in "Why we think this". */
  description?: string;
  /** Stable signal id for cross-page dedupe (defaults to type:index). */
  signalId?: string;
}

export interface Probe {
  /** Relative path to probe, e.g. "/wp-json/" */
  path: string;
  /** String that must appear in the response body */
  successSignal: string;
  weight: number;
}

export interface TechSignature {
  id: string;
  name: string;
  category: string;
  signals: Signal[];
  probes?: Probe[];
  /** Tech IDs that, if detected, exclude this one */
  excludes?: string[];
  /** Slug for /cms/[slug] page */
  pageSlug?: string;
  /**
   * False-positive guards (all optional, backward compatible):
   * - negative: regexes that veto the tech when matched (e.g. a docs
   *   page merely discussing the technology).
   * - minFamilies: minimum distinct evidence families required.
   */
  negative?: string[];
  minFamilies?: number;
}

export interface Evidence {
  type: SignalType;
  artifact: string;
  weight: number;
  /**
   * Stable signal name for cross-page dedupe (header name, cookie
   * name, or the matched pattern for HTML signals). Always set by
   * the engine; pipeline augmentations must set it too.
   */
  name: string;
  /** Sample matched value for display (may differ per page). */
  value: string;
  /** Fingerprint strength of the rule that produced this evidence. */
  strength: SignalStrength;
  /** Independent evidence family this signal belongs to. */
  family: EvidenceFamily;
  /** Specificity multiplier 0–1 applied to this signal. */
  specificity: number;
  /** Human-readable evidence line, e.g. "Known Sentry browser SDK
   *  detected". Rendered in "Why we think this". */
  description: string;
  /** Stable rule-level id (signalId or type fallback) for dedupe. */
  signalId: string;
}

/** 0–100 deterministic confidence label (see confidence.ts). */
export type ScoreLabel = 'VERY HIGH' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT';

export interface DetectionResult {
  id: string;
  name: string;
  category: string;
  confidence: number;
  confidenceLabel: 'confirmed' | 'likely' | 'possible';
  version?: string;
  evidence: Evidence[];
  pageSlug?: string;
  /**
   * Evidence-model scoring (added by applyConfidenceModel, optional so
   * older consumers keep working): 0–100 score, human label, distinct
   * evidence families, and ids of conflicting candidates when the tech
   * lost a mutually-exclusive contest.
   */
  score?: number;
  scoreLabel?: ScoreLabel;
  families?: number;
  conflicting?: string[];
}

// ----------------------------------------------------------------
// Load all signatures
// ----------------------------------------------------------------
import cmsRaw       from '../../data/signatures/cms.json' with { type: 'json' };
import buildersRaw  from '../../data/signatures/builders.json' with { type: 'json' };
import ecommerceRaw from '../../data/signatures/ecommerce.json' with { type: 'json' };
import frameworksRaw from '../../data/signatures/frameworks.json' with { type: 'json' };
import hostingRaw   from '../../data/signatures/hosting.json' with { type: 'json' };
import marketingRaw from '../../data/signatures/marketing.json' with { type: 'json' };
import securityRaw  from '../../data/signatures/security.json' with { type: 'json' };

export const ALL_SIGNATURES: TechSignature[] = [
  ...cmsRaw,
  ...buildersRaw,
  ...ecommerceRaw,
  ...frameworksRaw,
  ...hostingRaw,
  ...marketingRaw,
  ...securityRaw,
] as TechSignature[];

// Pre-compile all regex patterns at module load
const COMPILED: Map<string, RegExp> = new Map();

function regex(pattern: string): RegExp {
  if (!COMPILED.has(pattern)) {
    COMPILED.set(pattern, new RegExp(pattern, 'i'));
  }
  return COMPILED.get(pattern)!;
}

// ----------------------------------------------------------------
// Confidence scoring
// ----------------------------------------------------------------

/**
 * Clamp total weight and compute confidence label.
 * We use saturating addition capped at 100 to avoid over-counting.
 */
function scoreToLabel(score: number): 'confirmed' | 'likely' | 'possible' {
  if (score >= 90) return 'confirmed';
  if (score >= 70) return 'likely';
  return 'possible';
}

// ----------------------------------------------------------------
// Input context
// ----------------------------------------------------------------

export interface MatchContext {
  html: string;
  headers: Record<string, string>;
  cookies: string[];
  probeResults?: Record<string, string>; // probe path → response body
  _cleanedHtml?: string;
  _resourceUrls?: string[];
}

interface ResourceRef {
  tag: string;
  attr: string;
  src: string;
}

/**
 * Pre-extract resource URLs once per context.
 */
function getResourceUrls(ctx: MatchContext): ResourceRef[] {
  if (ctx._resourceUrls) return ctx._resourceUrls as unknown as ResourceRef[];
  const refs: ResourceRef[] = [];
  const attrRx =
    /<(script|iframe|img|source|video|audio|embed|track|link|form)[^>]+?(?:src|href|action|data-src)=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = attrRx.exec(ctx.html)) !== null) {
    const tag = m[1].toLowerCase();
    const val = m[2];
    if (val && !val.startsWith('data:') && !val.startsWith('blob:') && !val.startsWith('javascript:')) {
      const attr = tag === 'link' ? 'href' : tag === 'form' ? 'action' : 'src';
      refs.push({ tag, attr, src: val });
    }
  }
  ctx._resourceUrls = refs as unknown as string[];
  return refs;
}

const NON_USAGE_BLOCK_RX = /<(style|pre|code)[\s>][\s\S]*?<\/\1\s*>/gi;
const FENCED_CODE_RX = /```[\s\S]*?```/g;
const JSONLD_RX = /<script[^>]+type=["']application\/ld\+json["'][^>]*>[\s\S]*?<\/script\s*>/gi;
const SAMPLE_CONTAINER_RX =
  /<(div|figure)[^>]*class=["'][^"']*(code-wrapper|codeblock|code-sample|gatsby-highlight|prettyprint|codehilite|highlighter-|(?<=["'\s])highlight(?=["'\s]))[^"']*["'][^>]*>[\s\S]*?<\/\1\s*>/gi;

function usageHtml(html: string): string {
  let out = html;
  if (NON_USAGE_BLOCK_RX.test(out)) {
    NON_USAGE_BLOCK_RX.lastIndex = 0;
    out = out.replace(NON_USAGE_BLOCK_RX, '');
  }
  if (FENCED_CODE_RX.test(out)) {
    FENCED_CODE_RX.lastIndex = 0;
    out = out.replace(FENCED_CODE_RX, '');
  }
  if (JSONLD_RX.test(out)) {
    JSONLD_RX.lastIndex = 0;
    out = out.replace(JSONLD_RX, '');
  }
  if (SAMPLE_CONTAINER_RX.test(out)) {
    SAMPLE_CONTAINER_RX.lastIndex = 0;
    out = out.replace(SAMPLE_CONTAINER_RX, '');
  }
  return out;
}

function getCleanedHtml(ctx: MatchContext): string {
  if (ctx._cleanedHtml !== undefined) return ctx._cleanedHtml;
  ctx._cleanedHtml = usageHtml(ctx.html);
  return ctx._cleanedHtml;
}

// ----------------------------------------------------------------
// Core matching
// ----------------------------------------------------------------

function matchSignal(
  signal: Signal,
  ctx: MatchContext
): { matched: boolean; artifact: string; version?: string; name: string; value: string } {
  const rx = regex(signal.pattern);
  const none = { matched: false, artifact: '', name: '', value: '' };

  switch (signal.type) {
    case 'meta-generator': {
      // Fast check: if "generator" is not in HTML at all, skip regex
      if (!ctx.html.toLowerCase().includes('generator')) return none;
      const genRx = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/gi;
      let m: RegExpExecArray | null;
      while ((m = genRx.exec(ctx.html)) !== null) {
        const content = m[1];
        const match = rx.exec(content);
        if (match) {
          const version = signal.versionGroup ? (match[signal.versionGroup] ?? '') : undefined;
          return { matched: true, artifact: `meta[generator]: "${content}"`, version, name: 'generator', value: content.slice(0, 120) };
        }
      }
      return none;
    }

    case 'html-path':
    case 'html-regex':
    case 'js-global':
    case 'inline-script': {
      const searched = getCleanedHtml(ctx);
      const match = rx.exec(searched);
      if (match) {
        const marker = match[0].slice(0, 80);
        const at = match.index ?? 0;
        const from = Math.max(0, at - 24);
        const context = searched
          .slice(from, at + 56)
          .replace(/\s+/g, ' ')
          .trim()
          .slice(0, 80);
        return {
          matched: true,
          artifact: `html: "${marker}"`,
          name: marker,
          value: context || marker,
        };
      }
      return none;
    }

    case 'script-host': {
      const refs = getResourceUrls(ctx);
      for (const { tag, attr, src } of refs) {
        if (rx.test(src)) {
          let host = signal.pattern;
          if (/^https?:\/\//i.test(src) || src.startsWith('//')) {
            try {
              host = new URL(src.startsWith('//') ? `https:${src}` : src).hostname;
            } catch {
              /* keep pattern */
            }
          }
          return {
            matched: true,
            artifact: `${tag}[${attr}]: "${src.slice(0, 120)}"`,
            name: host,
            value: src.slice(0, 120),
          };
        }
      }
      return none;
    }

    case 'link-relation': {
      // Match <link rel="..." href="..." /> where href matches
      const linkRx = /<link[^>]+rel=["']([^"']+)["'][^>]*href=["']([^"']+)["']/gi;
      let m: RegExpExecArray | null;
      while ((m = linkRx.exec(ctx.html)) !== null) {
        const href = m[2];
        if (rx.test(href)) {
          return {
            matched: true,
            artifact: `link[${m[1]}]: "${href.slice(0, 120)}"`,
            name: href.slice(0, 80),
            value: href.slice(0, 120),
          };
        }
      }
      // rel may come after href — try the reversed attribute order too
      const linkRx2 = /<link[^>]+href=["']([^"']+)["'][^>]*rel=["']([^"']+)["']/gi;
      while ((m = linkRx2.exec(ctx.html)) !== null) {
        const href = m[1];
        if (rx.test(href)) {
          return {
            matched: true,
            artifact: `link[${m[2]}]: "${href.slice(0, 120)}"`,
            name: href.slice(0, 80),
            value: href.slice(0, 120),
          };
        }
      }
      return none;
    }

    case 'stylesheet-url': {
      // Match <link ... href="..."> (stylesheet or any linked asset)
      const cssRx = /<link[^>]+href=["']([^"']+)["']/gi;
      let m: RegExpExecArray | null;
      while ((m = cssRx.exec(ctx.html)) !== null) {
        const href = m[1];
        if (rx.test(href)) {
          return { matched: true, artifact: `stylesheet: "${href.slice(0, 120)}"`, name: href.slice(0, 80), value: href.slice(0, 120) };
        }
      }
      return none;
    }

    case 'meta-tag': {
      // Match any <meta name|property|itemprop="..." content="...">
      const metaRx = /<meta[^>]+(?:name|property|itemprop)=["']([^"']+)["'][^>]+content=["']([^"']+)["']/gi;
      let m: RegExpExecArray | null;
      while ((m = metaRx.exec(ctx.html)) !== null) {
        const combined = `${m[1]}=${m[2]}`;
        if (rx.test(combined) || rx.test(m[2])) {
          return {
            matched: true,
            artifact: `meta[${m[1]}]: "${m[2].slice(0, 120)}"`,
            name: m[1],
            value: m[2].slice(0, 120),
          };
        }
      }
      return none;
    }

    case 'header': {
      const headerName = (signal.name ?? '').toLowerCase();
      const value = ctx.headers[headerName] ?? '';
      // A missing/empty header must never match — patterns like ".*"
      // would otherwise match the empty string and false-positive.
      if (!value.trim()) return none;
      const match = rx.exec(value);
      if (match) {
        const version = signal.versionGroup ? (match[signal.versionGroup] ?? '') : undefined;
        return {
          matched: true,
          artifact: `header[${headerName}]: "${value.slice(0, 120)}"`,
          version,
          name: headerName,
          value: value.slice(0, 120),
        };
      }
      return none;
    }

    case 'cookie-name': {
      for (const cookie of ctx.cookies) {
        if (rx.test(cookie)) {
          return { matched: true, artifact: `cookie: "${cookie}"`, name: cookie, value: cookie };
        }
      }
      return none;
    }

    case 'probe': {
      // Probe results are pre-loaded by the pipeline
      const probeKey = signal.name ?? '';
      const body = ctx.probeResults?.[probeKey] ?? '';
      if (body && rx.test(body)) {
        return { matched: true, artifact: `probe[${probeKey}]`, name: probeKey, value: signal.pattern.slice(0, 120) };
      }
      return none;
    }
  }
}

// ----------------------------------------------------------------
// Tech-level matching
// ----------------------------------------------------------------

/** Fallback evidence line when a rule carries no explicit
 *  description. Never exposes raw regex — describes the channel. */
function fallbackDescription(signal: Signal, techName: string): string {
  switch (signal.type) {
    case 'script-host':    return `${techName} resource URL detected`;
    case 'stylesheet-url': return `${techName} stylesheet detected`;
    case 'link-relation':  return `${techName} linked resource detected`;
    case 'header':         return `${techName} HTTP header detected${signal.name ? ` (${signal.name})` : ''}`;
    case 'cookie-name':    return `${techName} cookie detected`;
    case 'meta-generator': return `${techName} generator tag detected`;
    case 'meta-tag':       return `${techName} meta tag detected`;
    case 'js-global':      return `${techName} JavaScript global detected`;
    case 'inline-script':  return `${techName} initialization code detected`;
    case 'html-path':      return `${techName} asset path detected`;
    case 'html-regex':     return `${techName} code signature detected`;
    case 'probe':          return `${techName} endpoint responded`;
  }
}

function matchTech(
  sig: TechSignature,
  ctx: MatchContext
): DetectionResult | null {
  const evidenceList: Evidence[] = [];
  let totalWeight = 0;
  let version: string | undefined;

  // NOTE: matching is purely technical — MatchContext carries only
  // fetched HTML, response headers and cookie names. The target's own
  // hostname/URL is never an input, so a domain name alone can never
  // establish a detection.
  sig.signals.forEach((signal, index) => {
    const { matched, artifact, version: v, name, value } = matchSignal(signal, ctx);
    if (matched) {
      // Saturating add — each signal can contribute at most its weight,
      // but total won't exceed 100 via diminishing returns
      const contribution = Math.round(
        signal.weight * (1 - totalWeight / 100)
      );
      totalWeight = Math.min(100, totalWeight + contribution);
      const strength = signal.strength ?? 'weak';
      evidenceList.push({
        type: signal.type,
        artifact,
        weight: signal.weight,
        name,
        value,
        strength,
        family: familyForSignal(signal.type, signal.family),
        specificity: specificityForStrength(strength, signal.specificity),
        description: signal.description ?? fallbackDescription(signal, sig.name),
        signalId: signal.signalId ?? `${sig.id}#${signal.type}:${index}`,
      });
      if (v && !version) version = v;
    }
  });

  // Probe-based signals (already fetched by the pipeline)
  if (sig.probes && ctx.probeResults) {
    for (const probe of sig.probes) {
      const body = ctx.probeResults[probe.path] ?? '';
      if (body.includes(probe.successSignal)) {
        const contribution = Math.round(probe.weight * (1 - totalWeight / 100));
        totalWeight = Math.min(100, totalWeight + contribution);
        evidenceList.push({
          type: 'probe',
          artifact: `probe[${probe.path}]: found "${probe.successSignal}"`,
          weight: probe.weight,
          name: probe.path,
          value: probe.successSignal,
          // A probe hit (e.g. /wp-json/ answering, theme style.css)
          // is product-specific: strong, not definitive on its own.
          strength: 'strong',
          family: 'PLATFORM_IDENTIFIER',
          specificity: specificityForStrength('strong'),
          description: `${sig.name} endpoint responded`,
          signalId: `${sig.id}#probe:${probe.path}`,
        });
      }
    }
  }

  if (evidenceList.length === 0) return null;

  // Negative veto: an explicit "this is NOT usage" marker kills the
  // detection outright (e.g. documentation pages merely discussing
  // the technology). Checked against raw HTML only.
  if (sig.negative && sig.negative.length > 0) {
    for (const pattern of sig.negative) {
      try {
        if (new RegExp(pattern, 'i').test(ctx.html)) return null;
      } catch {
        /* ignore invalid patterns — fail open, never fail closed */
      }
    }
  }

  // Minimum independent families: correlated manifestations of one
  // fingerprint (same CDN host three times) do not count as proof.
  if (sig.minFamilies && sig.minFamilies > 1) {
    const families = new Set(evidenceList.map((e) => e.family));
    if (families.size < sig.minFamilies) return null;
  }

  return {
    id: sig.id,
    name: sig.name,
    category: sig.category,
    confidence: totalWeight,
    confidenceLabel: scoreToLabel(totalWeight),
    version,
    evidence: evidenceList,
    pageSlug: sig.pageSlug,
  };
}

// ----------------------------------------------------------------
// Public API
// ----------------------------------------------------------------

/**
 * Run all signatures against the context.
 * Returns sorted results (highest confidence first), per category.
 * Applies excludes rules.
 */
export function runSignatureEngine(ctx: MatchContext): DetectionResult[] {
  const results: DetectionResult[] = [];

  for (const sig of ALL_SIGNATURES) {
    const result = matchTech(sig, ctx);
    if (result) results.push(result);
  }

  // Apply excludes: if tech A excludes B, remove B when A is in results
  const detectedIds = new Set(results.map((r) => r.id));
  const excluded = new Set<string>();

  for (const sig of ALL_SIGNATURES) {
    if (sig.excludes && detectedIds.has(sig.id)) {
      for (const ex of sig.excludes) {
        excluded.add(ex);
      }
    }
  }

  return results
    .filter((r) => !excluded.has(r.id))
    .sort((a, b) => b.confidence - a.confidence);
}
