/**
 * Evidence-based confidence model — deterministic 0–100 scoring.
 *
 * The score answers: "How strongly does the available evidence support
 * this detection?" It is NOT a calibrated probability.
 *
 * Methodology:
 *  1. Every fingerprint carries a base signal weight from its strength
 *     (definitive 1.0 / strong 0.65 / weak 0.30), adjusted by its
 *     specificity multiplier (0–1).
 *  2. Correlated signals are grouped into evidence families; each
 *     family contributes only its SINGLE strongest adjusted signal.
 *     Three URLs on the same CDN host never outvote one good header.
 *  3. Independent families combine with noisy-OR: each new family
 *     corroborates, with diminishing returns — never a plain average.
 *  4. A corroboration bonus rewards 2+ / 3+ independent families.
 *  5. A contradiction penalty demotes losers of a mutually-exclusive
 *     contest (e.g. WordPress vs Shopify as the primary platform).
 *  6. A coverage penalty applies when evidence spans only some of the
 *     scanned pages; minority presence caps at INSUFFICIENT.
 *  7. The result normalises to 0–100 with a human-readable label.
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

/** Base weight per fingerprint strength. */
const STRENGTH_WEIGHT = {
  definitive: 1.0,
  strong: 0.65,
  weak: 0.3,
} as const;

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
  const base = STRENGTH_WEIGHT[e.strength ?? 'weak'] ?? 0.3;
  const spec =
    typeof e.specificity === 'number'
      ? Math.min(1, Math.max(0, e.specificity))
      : specificityForStrength(e.strength ?? 'weak');
  return base * spec;
}

/**
 * Score one detection from its evidence list.
 * Returns the 0–100 score and the distinct family count.
 */
export function scoreDetection(evidence: Evidence[]): { score: number; families: number } {
  if (evidence.length === 0) return { score: 0, families: 0 };

  // One contribution per family: the strongest adjusted signal only.
  const bestByFamily = new Map<string, number>();
  for (const e of evidence) {
    const family = e.family ?? 'HTML';
    const adj = adjustedSignal(e);
    if (adj > (bestByFamily.get(family) ?? -1)) bestByFamily.set(family, adj);
  }

  const families = bestByFamily.size;

  // Noisy-OR combination: independent corroboration, diminishing returns.
  let combined = 0;
  for (const v of bestByFamily.values()) {
    combined = 1 - (1 - combined) * (1 - v);
  }

  let score = Math.round(combined * 100 + corroborationBonus(families));
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
