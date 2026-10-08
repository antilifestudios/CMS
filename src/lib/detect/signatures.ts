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
  | 'header'
  | 'cookie-name'
  | 'probe';

export interface Signal {
  type: SignalType;
  /** For header signals: which header name */
  name?: string;
  /** Regex pattern string */
  pattern: string;
  /** Confidence contribution (0–100) */
  weight: number;
  /** Capture group index for version extraction */
  versionGroup?: number;
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
}

export interface Evidence {
  type: SignalType;
  artifact: string;
  weight: number;
}

export interface DetectionResult {
  id: string;
  name: string;
  category: string;
  confidence: number;
  confidenceLabel: 'confirmed' | 'likely' | 'possible';
  version?: string;
  evidence: Evidence[];
  pageSlug?: string;
}

// ----------------------------------------------------------------
// Load all signatures
// ----------------------------------------------------------------
import cmsRaw       from '../../data/signatures/cms.json';
import buildersRaw  from '../../data/signatures/builders.json';
import ecommerceRaw from '../../data/signatures/ecommerce.json';
import frameworksRaw from '../../data/signatures/frameworks.json';
import hostingRaw   from '../../data/signatures/hosting.json';

export const ALL_SIGNATURES: TechSignature[] = [
  ...cmsRaw,
  ...buildersRaw,
  ...ecommerceRaw,
  ...frameworksRaw,
  ...hostingRaw,
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
}

// ----------------------------------------------------------------
// Core matching
// ----------------------------------------------------------------

function matchSignal(
  signal: Signal,
  ctx: MatchContext
): { matched: boolean; artifact: string; version?: string } {
  const rx = regex(signal.pattern);

  switch (signal.type) {
    case 'meta-generator': {
      // Match <meta name="generator" content="..." />
      const genRx = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/gi;
      let m: RegExpExecArray | null;
      while ((m = genRx.exec(ctx.html)) !== null) {
        const content = m[1];
        const match = rx.exec(content);
        if (match) {
          const version = signal.versionGroup ? (match[signal.versionGroup] ?? '') : undefined;
          return { matched: true, artifact: `meta[generator]: "${content}"`, version };
        }
      }
      return { matched: false, artifact: '' };
    }

    case 'html-path':
    case 'html-regex': {
      const match = rx.exec(ctx.html);
      if (match) {
        return {
          matched: true,
          artifact: `html: "${match[0].slice(0, 80)}"`,
        };
      }
      return { matched: false, artifact: '' };
    }

    case 'script-host': {
      // Find script src attributes
      const scriptRx = /<script[^>]+src=["']([^"']+)["']/gi;
      let m: RegExpExecArray | null;
      while ((m = scriptRx.exec(ctx.html)) !== null) {
        const src = m[1];
        if (rx.test(src)) {
          return { matched: true, artifact: `script[src]: "${src.slice(0, 120)}"` };
        }
      }
      return { matched: false, artifact: '' };
    }

    case 'header': {
      const headerName = (signal.name ?? '').toLowerCase();
      const value = ctx.headers[headerName] ?? '';
      // A missing/empty header must never match — patterns like ".*"
      // would otherwise match the empty string and false-positive.
      if (!value.trim()) return { matched: false, artifact: '' };
      const match = rx.exec(value);
      if (match) {
        const version = signal.versionGroup ? (match[signal.versionGroup] ?? '') : undefined;
        return {
          matched: true,
          artifact: `header[${headerName}]: "${value.slice(0, 120)}"`,
          version,
        };
      }
      return { matched: false, artifact: '' };
    }

    case 'cookie-name': {
      for (const cookie of ctx.cookies) {
        if (rx.test(cookie)) {
          return { matched: true, artifact: `cookie: "${cookie}"` };
        }
      }
      return { matched: false, artifact: '' };
    }

    case 'probe': {
      // Probe results are pre-loaded by the pipeline
      const probeKey = signal.name ?? '';
      const body = ctx.probeResults?.[probeKey] ?? '';
      if (body && rx.test(body)) {
        return { matched: true, artifact: `probe[${probeKey}]` };
      }
      return { matched: false, artifact: '' };
    }
  }
}

// ----------------------------------------------------------------
// Tech-level matching
// ----------------------------------------------------------------

function matchTech(
  sig: TechSignature,
  ctx: MatchContext
): DetectionResult | null {
  const evidenceList: Evidence[] = [];
  let totalWeight = 0;
  let version: string | undefined;

  for (const signal of sig.signals) {
    const { matched, artifact, version: v } = matchSignal(signal, ctx);
    if (matched) {
      // Saturating add — each signal can contribute at most its weight,
      // but total won't exceed 100 via diminishing returns
      const contribution = Math.round(
        signal.weight * (1 - totalWeight / 100)
      );
      totalWeight = Math.min(100, totalWeight + contribution);
      evidenceList.push({ type: signal.type, artifact, weight: signal.weight });
      if (v && !version) version = v;
    }
  }

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
        });
      }
    }
  }

  if (evidenceList.length === 0) return null;

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
