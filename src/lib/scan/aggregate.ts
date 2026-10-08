/**
 * Per-technology evidence aggregation — pure functions, no network.
 * Workers-runtime compatible (plain data in, plain data out).
 *
 * Invariants enforced here:
 * - Evidence is grouped by techId. A detection may only display
 *   evidence whose techId matches it — never a shared flat list.
 * - Confidence is computed per technology from SIGNAL STRENGTH
 *   (union across pages), never from raw evidence line counts and
 *   never from the weakest page. A tech seen strongly on all pages
 *   is not downgraded by one weaker page.
 * - Evidence is deduplicated by signal (type + name): one line per
 *   signal with a sample value and a page count, strongest first.
 */

import type {
  AggregatedEvidence,
  AggregatedTech,
  ConfidenceLevel,
  PageScanResult,
  TechEvidenceItem,
} from './types';
import type { DetectionResult, SignalStrength } from '../detect/signatures';

// ----------------------------------------------------------------
// Confidence rule (single definition).
// Confidence comes from the STRENGTH of the fingerprint rules that
// fired, not from how many raw lines matched:
//   - High: at least one definitive signal (cf-ray, server:
//     cloudflare, an explicit generator tag …), OR two or more
//     strong signals (/_astro/, data-astro-cid, …).
//   - Medium: exactly one strong signal, OR multiple weak ones.
//   - Low: a single weak signal, or signals seen on only a minority
//     of pages.
// Multi-page coverage: a tech on every sampled page keeps whatever
// the rules earn; a tech on only some pages is capped at Medium (and
// the summary line says so, e.g. 9/15); a minority presence is Low.
// ----------------------------------------------------------------

/** Page coverage below which a tech counts as a minority presence. */
const MINORITY_COVERAGE = 0.5;

const STRENGTH_RANK: Record<SignalStrength, number> = {
  definitive: 0,
  strong: 1,
  weak: 2,
};

/**
 * Display groups for evidence rows. Cookies travel over HTTP headers
 * and script URLs are asset paths, so they fold into those groups;
 * probes (rare in scans) keep their own group at the end.
 */
const GROUP_RANK: Record<string, number> = {
  header: 0,
  'cookie-name': 0,
  'html-regex': 1,
  'meta-generator': 1,
  'html-path': 2,
  'script-host': 2,
  probe: 3,
};

function groupRank(signalType: string): number {
  return GROUP_RANK[signalType] ?? 4;
}

export interface TechSignalInput {
  strength: SignalStrength;
}

export function confidenceForTech(opts: {
  /** Deduped signals observed for this tech (union across pages). */
  signals: TechSignalInput[];
  /** Overall page coverage: detectedOn / checkedPages (1 when unknown). */
  coverage: number;
}): ConfidenceLevel {
  const { signals, coverage } = opts;
  if (signals.length === 0) return 'Low';
  // A minority presence never earns more than Low, however strong.
  if (coverage < MINORITY_COVERAGE) return 'Low';

  const definitives = signals.filter((s) => s.strength === 'definitive').length;
  const strongs = signals.filter((s) => s.strength === 'strong').length;
  const weaks = signals.filter((s) => s.strength === 'weak').length;

  let level: ConfidenceLevel;
  if (definitives >= 1 || strongs >= 2) level = 'High';
  else if (strongs === 1 || weaks >= 2) level = 'Medium';
  else level = 'Low'; // a single weak signal

  // Partial presence (some, but not all, pages) caps at Medium and
  // the summary line reports the fraction, e.g. 9/15.
  if (coverage < 1 && level === 'High') level = 'Medium';
  return level;
}

/**
 * Tag every evidence line of one detection with the technology id
 * whose rule produced it. These items must only ever be grouped by
 * techId — never flattened into a shared list.
 */
export function toTechItems(result: DetectionResult, pageUrl: string): TechEvidenceItem[] {
  return result.evidence.map((e) => ({
    techId: result.id,
    signalType: e.type,
    name: e.name || e.type,
    value: e.value || e.artifact,
    pageUrl,
    strength: e.strength ?? 'weak',
  }));
}

/** Single-page confidence for one technology, using the shared rule. */
export function pageTechConfidence(result: DetectionResult): ConfidenceLevel {
  return confidenceForTech({
    signals: result.evidence.map((e) => ({ strength: e.strength ?? 'weak' })),
    coverage: 1,
  });
}

// ----------------------------------------------------------------
// Aggregation
// ----------------------------------------------------------------

function kindFor(page: PageScanResult, techId: string): AggregatedTech['kind'] {
  if (page.frameworkId === techId) return 'framework';
  if (page.providerId === techId) return 'hosting';
  return 'other';
}

function nameFor(page: PageScanResult, techId: string): string {
  if (page.frameworkId === techId) return page.framework;
  if (page.providerId === techId) return page.provider;
  return techId;
}

function slugFor(page: PageScanResult, techId: string): string | undefined {
  if (page.frameworkId === techId) return page.frameworkSlug ?? undefined;
  if (page.providerId === techId) return page.providerSlug ?? undefined;
  return undefined;
}

/**
 * Merge per-page tech evidence into one rollup per technology.
 * A tech is detected if it is detected on any successful page;
 * `detectedOn`/`checkedPages` record how widespread it is (e.g. 15/15).
 */
export function aggregateTechs(pages: PageScanResult[]): AggregatedTech[] {
  const ok = pages.filter((p) => !p.error && !p.skippedByRobots);
  const checkedPages = ok.length;

  // Group raw evidence by techId — the only merge key. Items never
  // move between technologies.
  const byTech = new Map<
    string,
    { name: string; kind: AggregatedTech['kind']; pageSlug?: string; items: TechEvidenceItem[] }
  >();
  const seenOn = new Map<string, Set<string>>(); // techId -> distinct page urls

  const ensureTech = (page: PageScanResult, id: string) => {
    if (!byTech.has(id)) {
      byTech.set(id, { name: nameFor(page, id), kind: kindFor(page, id), pageSlug: slugFor(page, id), items: [] });
    }
    const entry = byTech.get(id)!;
    if (entry.name === id) {
      const better = nameFor(page, id);
      if (better !== id) entry.name = better;
    }
    if (!entry.pageSlug) {
      const slug = slugFor(page, id);
      if (slug) entry.pageSlug = slug;
    }
    if (!seenOn.has(id)) seenOn.set(id, new Set());
  };

  for (const page of ok) {
    const items = page.techEvidence ?? [];
    // Fall back to legacy ids so a tech with no structured evidence
    // still appears (without evidence lines) rather than vanishing.
    const legacyIds = [page.frameworkId, page.providerId].filter(
      (id): id is string => typeof id === 'string' && id.length > 0
    );
    for (const id of legacyIds) {
      ensureTech(page, id);
      if (items.every((it) => it.techId !== id)) {
        // No structured evidence on this page, but the tech was
        // detected here — count the page.
        seenOn.get(id)!.add(page.url);
      }
    }
    for (const item of items) {
      if (!item.techId) continue;
      ensureTech(page, item.techId);
      byTech.get(item.techId)!.items.push(item);
      seenOn.get(item.techId)!.add(item.pageUrl || page.url);
    }
  }

  const out: AggregatedTech[] = [];
  for (const [techId, entry] of byTech) {
    // Dedupe by signal (type + name): one line per signal with a
    // sample value, the strongest observed strength, and the distinct
    // page count.
    const bySignal = new Map<
      string,
      { signalType: string; name: string; sampleValue: string; strength: SignalStrength; pages: Set<string> }
    >();
    for (const item of entry.items) {
      const key = `${item.signalType}\0${item.name}`;
      if (!bySignal.has(key)) {
        bySignal.set(key, {
          signalType: item.signalType,
          name: item.name,
          sampleValue: item.value,
          strength: item.strength,
          pages: new Set(),
        });
      }
      const sig = bySignal.get(key)!;
      if (STRENGTH_RANK[item.strength] < STRENGTH_RANK[sig.strength]) {
        sig.strength = item.strength;
        sig.sampleValue = item.value;
      }
      sig.pages.add(item.pageUrl);
    }

    const evidence: AggregatedEvidence[] = [...bySignal.values()]
      .map((s) => ({
        signalType: s.signalType,
        name: s.name,
        sampleValue: s.sampleValue,
        pagesSeen: s.pages.size,
        strength: s.strength,
      }))
      .sort((a, b) => {
        const sa = STRENGTH_RANK[a.strength] - STRENGTH_RANK[b.strength];
        if (sa !== 0) return sa;
        const ga = groupRank(a.signalType) - groupRank(b.signalType);
        if (ga !== 0) return ga;
        if (b.pagesSeen !== a.pagesSeen) return b.pagesSeen - a.pagesSeen;
        return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
      });

    const detectedOn = seenOn.get(techId)?.size ?? 0;
    const coverage = checkedPages > 0 ? detectedOn / checkedPages : 1;

    out.push({
      techId,
      name: entry.name,
      kind: entry.kind,
      confidence: confidenceForTech({
        signals: evidence.map((e) => ({ strength: e.strength })),
        coverage,
      }),
      detectedOn,
      checkedPages,
      evidence,
      ...(entry.pageSlug ? { pageSlug: entry.pageSlug } : {}),
    });
  }

  return out;
}
