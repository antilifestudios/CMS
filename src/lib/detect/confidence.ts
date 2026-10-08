/**
 * Evidence-based confidence model — deterministic 0–100 scoring.
 *
 * The score answers: "How strongly does the available evidence support
 * this detection?" It is NOT a calibrated probability.
 *
 * Methodology:
 *  1. Every signal carries an author-assigned evidence weight (0–100):
 *     a known official SDK URL (~90–95) outweighs a generic keyword
 *     (~10–30). The weight is scaled by the signal's specificity
 *     multiplier (0–1): definitive 1.0 / strong 0.7 / weak 0.3.
 *     ONE very strong, highly specific signal can therefore score
 *     HIGH / VERY HIGH on its own.
 *  2. Correlated signals are grouped into evidence families; each
 *     family contributes only its SINGLE strongest adjusted signal.
 *     Three URLs on the same CDN host never outvote one good header.
 *  3. Independent families combine with noisy-OR: each new family
 *     corroborates, with diminishing returns — never a plain average.
 *  4. A SMALL corroboration bonus rewards 2+ / 3+ independent
 *     families. Family count is descriptive corroboration, NEVER the
 *     confidence itself: one definitive signal still outscores three
 *     weak hints.
 *  5. Quality ceilings: evidence with no strong-or-better signal caps
 *     at LOW (weak hints stay hints); evidence with no definitive
 *     signal caps below VERY HIGH (only a uniquely identifying
 *     signature confirms).
 *  6. A contradiction penalty demotes losers of a mutually-exclusive
 *     contest (e.g. WordPress vs Shopify as the primary platform).
 *  7. A coverage penalty applies when evidence spans only some of the
 *     scanned pages; minority presence caps at INSUFFICIENT.
 *  8. The result normalises to 0–100 with a human-readable label
 *     (VERY HIGH ≡ CONFIRMED, HIGH, MEDIUM, LOW, INSUFFICIENT).
 *
 * Pure functions, no network. Workers-runtime compatible.
 */

import {
  specificityForStrength,
  type DetectionResult,
  type Evidence,
  type ScoreLabel,
} from './signatures.ts';

// ----------------------------------------------------------------
// Thresholds & tuning constants (single place, documented)
// ----------------------------------------------------------------

/** Display floor: below this a detection is "Not confidently detected". */
export const MIN_DISPLAY_SCORE = 40;
/** Conservative floor for primary platform / theme detections. */
export const MIN_PRIMARY_SCORE = 60;

/** Base weight per fingerprint strength (fallback when a signal
 *  carries no explicit 0–100 weight). */
const STRENGTH_WEIGHT = {
  definitive: 1.0,
  strong: 0.65,
  weak: 0.3,
} as const;

/**
 * Quality ceilings — signal quality matters more than signal count.
 * - No signal stronger than "weak": weak hints stay hints (LOW max),
 *   however many families they span.
 * - No "definitive" signal: strong corroboration can reach HIGH, but
 *   only a uniquely identifying signature reaches VERY HIGH.
 */
const WEAK_ONLY_CEILING = 59;
const NO_DEFINITIVE_CEILING = 89;

/** Corroboration bonus by distinct family count. */
function corroborationBonus(families: number): number {
  if (families >= 4) return 12;
  if (families >= 3) return 8;
  if (families >= 2) return 4;
  return 0;
}

/** Categories that compete for "the primary platform" — mutually exclusive. */
const PRIMARY_PLATFORM_CATEGORIES = new Set(['cms', 'builder', 'ecommerce']);

/** Penalty scale applied to losers of a platform contest (× winner/100). */
const CONTRADICTION_PENALTY = 30;

/** Coverage below which a detection is a minority presence. */
const MINORITY_COVERAGE = 0.5;

// ----------------------------------------------------------------
// Labels
// ----------------------------------------------------------------

export function scoreToLabel5(score: number): ScoreLabel {
  if (score >= 90) return 'VERY HIGH';
  if (score >= 75) return 'HIGH';
  if (score >= 60) return 'MEDIUM';
  if (score >= 40) return 'LOW';
  return 'INSUFFICIENT';
}

// ----------------------------------------------------------------
// Core scoring
// ----------------------------------------------------------------

function adjustedSignal(e: Evidence): number {
  const spec =
    typeof e.specificity === 'number'
      ? Math.min(1, Math.max(0, e.specificity))
      : specificityForStrength(e.strength ?? 'weak');
  // Evidence-weighted: the rule author's 0–100 weight measures HOW
  // PROVING this concrete signal is (known SDK ≈ 90+, generic
  // keyword ≈ 10–30); specificity scales it. A single very strong,
  // highly specific signal therefore scores HIGH/VERY HIGH alone,
  // while weak signals stay weak however they are counted.
  const w =
    typeof e.weight === 'number'
      ? Math.min(100, Math.max(0, e.weight)) / 100
      : (STRENGTH_WEIGHT[e.strength ?? 'weak'] ?? 0.3);
  return w * spec;
}

/** Normalised dedupe key: the same underlying RESOURCE observed through
 *  two channels (e.g. one SDK URL in both the resource-attribute scan
 *  and a whole-HTML pattern) is ONE signal, not two. Resource identity
 *  is host + first path segment, so genuinely different integrations
 *  on one host (an embed iframe vs a player SDK) still corroborate.
 *  Non-URL values (init calls, cookie names) dedupe only on exact
 *  normalised equality within a family — different families stay
 *  independent, and same-family echoes are already capped by the
 *  best-per-family rule. */
function dedupeKey(e: Evidence): string {
  const raw = String(e.value ?? e.artifact ?? '').trim().toLowerCase();
  if (!raw) return `t::${e.family}::${e.name}`;
  const m = raw.match(/((?:[a-z0-9-]+\.)+[a-z]{2,})(:\d+)?(\/[a-z0-9_~.-]*)?/);
  if (m) {
    const host = m[1].replace(/^www\./, '');
    const seg = (m[3] ?? '').replace(/\/+$/, '');
    return `u::${host}${seg}`;
  }
  const norm = raw.replace(/^https?:\/\//, '').replace(/^\/\//, '').replace(/[/?#\s"'<>.,;:]+$/, '');
  return `t::${e.family}::${norm}`;
}

/**
 * Score one detection from its evidence list.
 * Returns the 0–100 score and the distinct family count.
 *
 * Families and confidence are separate concepts: the family count is
 * reported alongside the score as descriptive corroboration, but a
 * single family holding a definitive signature still scores VERY HIGH.
 */
export function scoreDetection(evidence: Evidence[]): { score: number; families: number } {
  if (evidence.length === 0) return { score: 0, families: 0 };

  // Deduplicate: the same underlying signal seen twice keeps only its
  // strongest observation.
  const deduped = new Map<string, Evidence>();
  for (const e of evidence) {
    const key = dedupeKey(e);
    const prev = deduped.get(key);
    if (!prev || adjustedSignal(e) > adjustedSignal(prev)) deduped.set(key, e);
  }

  // One contribution per family: the strongest adjusted signal only.
  const bestByFamily = new Map<string, number>();
  let hasDefinitive = false;
  let hasStrongOrBetter = false;
  for (const e of deduped.values()) {
    const family = e.family ?? 'HTML';
    const adj = adjustedSignal(e);
    if (adj > (bestByFamily.get(family) ?? -1)) bestByFamily.set(family, adj);
    if ((e.strength ?? 'weak') === 'definitive') hasDefinitive = true;
    if ((e.strength ?? 'weak') !== 'weak') hasStrongOrBetter = true;
  }

  const families = bestByFamily.size;

  // Noisy-OR combination: independent corroboration, diminishing returns.
  let combined = 0;
  for (const v of bestByFamily.values()) {
    combined = 1 - (1 - combined) * (1 - v);
  }

  let score = Math.round(combined * 100 + corroborationBonus(families));
  // Quality ceilings: many weak signals can never become HIGH, and
  // nothing without a uniquely identifying signature is CONFIRMED.
  if (!hasStrongOrBetter) score = Math.min(score, WEAK_ONLY_CEILING);
  if (!hasDefinitive) score = Math.min(score, NO_DEFINITIVE_CEILING);
  score = Math.min(100, Math.max(0, score));
  return { score, families };
}

/**
 * Coverage penalty for multi-page scans: evidence seen on only some
 * pages is worth less; minority presence caps at INSUFFICIENT (≤39).
 */
export function scoreForCoverage(score: number, detectedOn: number, checked: number): number {
  if (checked <= 0) return score;
  const coverage = detectedOn / checked;
  if (coverage >= 1) return score;
  if (coverage < MINORITY_COVERAGE) return Math.min(score, 39);
  return Math.round(score * (0.6 + 0.4 * coverage));
}

// ----------------------------------------------------------------
// Conflict handling
// ----------------------------------------------------------------

/**
 * Resolve mutually-exclusive primary-platform contests in place (on
 * copies): rank candidates, keep the strongest, penalise the rest so
 * weak contradictions fall to INSUFFICIENT instead of rendering as
 * equally-likely alternatives. Records the winner id on demoted
 * results via `conflicting`.
 */
export function resolveConflicts(results: DetectionResult[]): DetectionResult[] {
  const out = results.map((r) => ({ ...r }));
  const contenders = out
    .filter((r) => PRIMARY_PLATFORM_CATEGORIES.has(r.category) && typeof r.score === 'number')
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0));

  if (contenders.length < 2) return out;
  const winner = contenders[0];
  const winnerScore = winner.score ?? 0;
  // No confident winner → no contest to resolve; leave all as scored.
  if (winnerScore < MIN_PRIMARY_SCORE) return out;

  const penalty = Math.round((CONTRADICTION_PENALTY * winnerScore) / 100);
  for (const loser of contenders.slice(1)) {
    loser.score = Math.max(0, (loser.score ?? 0) - penalty);
    loser.scoreLabel = scoreToLabel5(loser.score ?? 0);
    loser.conflicting = [...(loser.conflicting ?? []), winner.id];
  }
  return out;
}

// ----------------------------------------------------------------
// Public entry point
// ----------------------------------------------------------------

export interface ConfidenceOptions {
  /** Per-tech page coverage for multi-page scans: id → { on, checked }. */
  coverage?: Map<string, { on: number; checked: number }>;
}

/**
 * Attach deterministic 0–100 scores to every detection, resolve
 * platform conflicts, and return results sorted by score (desc).
 * The legacy `confidence` / `confidenceLabel` fields are untouched.
 */
export function applyConfidenceModel(
  results: DetectionResult[],
  opts: ConfidenceOptions = {}
): DetectionResult[] {
  const scored = results.map((r) => {
    const { score: raw, families } = scoreDetection(r.evidence);
    let score = raw;
    const cov = opts.coverage?.get(r.id);
    if (cov) score = scoreForCoverage(score, cov.on, cov.checked);
    return {
      ...r,
      score,
      scoreLabel: scoreToLabel5(score),
      families,
    } as DetectionResult;
  });

  return resolveConflicts(scored).sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
}

/** Whether a scored detection may be displayed as a finding. */
export function passesThreshold(r: DetectionResult, isPrimary = false): boolean {
  if (typeof r.score !== 'number') return false;
  return r.score >= (isPrimary ? MIN_PRIMARY_SCORE : MIN_DISPLAY_SCORE);
}

// ----------------------------------------------------------------
// Debug explanation (dev-only, never rendered in production UI)
// ----------------------------------------------------------------

export interface DebugSignalBreakdown {
  artifact: string;
  family: string;
  strength: string;
  signalWeight: number;
  baseWeight: number;
  specificity: number;
  adjusted: number;
  familyWinner: boolean;
  duplicateOf?: string;
}

export interface DebugDetectionBreakdown {
  id: string;
  name: string;
  score: number;
  scoreLabel: ScoreLabel;
  families: number;
  corroborationBonus: number;
  signals: DebugSignalBreakdown[];
}

/**
 * Explain WHY a detection scored what it did, per evidence family.
 * Dev/debug only — call from console, tests, or /api/detect with
 * { debug: true }. Output shape mirrors the task spec:
 *   Technology: Sentry / Score: 97 / Signals: +40 known script ...
 */
export function explainDetection(evidence: Evidence[]): {
  score: number;
  families: number;
  bonus: number;
  signals: DebugSignalBreakdown[];
} {
  // Mirror scoreDetection: dedupe first, then best-per-family.
  const deduped = new Map<string, Evidence>();
  for (const e of evidence) {
    const key = dedupeKey(e);
    const prev = deduped.get(key);
    if (!prev || adjustedSignal(e) > adjustedSignal(prev)) deduped.set(key, e);
  }
  const bestByFamily = new Map<string, number>();
  for (const e of deduped.values()) {
    const adj = adjustedSignal(e);
    const fam = e.family ?? 'HTML';
    if (adj > (bestByFamily.get(fam) ?? -1)) bestByFamily.set(fam, adj);
  }
  const families = bestByFamily.size;
  const bonus = corroborationBonus(families);
  const signals: DebugSignalBreakdown[] = evidence.map((e) => {
    const signalWeight =
      typeof e.weight === 'number'
        ? Math.min(100, Math.max(0, e.weight))
        : Math.round((STRENGTH_WEIGHT[e.strength ?? 'weak'] ?? 0.3) * 100);
    const base = signalWeight / 100;
    const spec =
      typeof e.specificity === 'number'
        ? Math.min(1, Math.max(0, e.specificity))
        : specificityForStrength(e.strength ?? 'weak');
    const raw = base * spec;
    const fam = e.family ?? 'HTML';
    const winner = deduped.get(dedupeKey(e));
    return {
      artifact: e.artifact,
      family: fam,
      strength: e.strength ?? 'weak',
      signalWeight,
      baseWeight: +base.toFixed(3),
      specificity: +spec.toFixed(2),
      adjusted: +raw.toFixed(3),
      familyWinner: winner === e && raw >= (bestByFamily.get(fam) ?? Infinity),
      ...(winner && winner !== e ? { duplicateOf: winner.artifact } : {}),
    };
  });
  const { score } = scoreDetection(evidence);
  return { score, families, bonus, signals };
}

/** Explain every detection in a result list (debug payload). */
export function explainDetections(results: DetectionResult[]): DebugDetectionBreakdown[] {
  return results.map((r) => {
    const ex = explainDetection(r.evidence);
    return {
      id: r.id,
      name: r.name,
      score: r.score ?? ex.score,
      scoreLabel: r.scoreLabel ?? scoreToLabel5(ex.score),
      families: ex.families,
      corroborationBonus: ex.bonus,
      signals: ex.signals,
    };
  });
}
