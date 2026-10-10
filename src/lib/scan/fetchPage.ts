/**
 * Single-page fetch for multi-path scans.
 * Reuses SSRF guards + signature engine; records the redirect chain.
 */
import { validateUrl, validateRedirect } from '../detect/ssrf';
import { runSignatureEngine } from '../detect/signatures';
import { isChallengeResponse } from '../detect/protection';
import { SCAN_CONFIG } from './config';
import { pageTechConfidence, toTechItems } from './aggregate';
import type { ConfidenceLevel, PageScanResult, RedirectHop, TechEvidenceItem } from './types';

export interface Budget {
  used: number;
  ceiling: number;
}

export function confidenceFromScore(label: 'confirmed' | 'likely' | 'possible'): ConfidenceLevel {
  if (label === 'confirmed') return 'High';
  if (label === 'likely') return 'Medium';
  return 'Low';
}

function extractHeaders(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

function extractCookieNames(res: Response): string[] {
  const getter = (res.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  let raw: string[] = [];
  if (typeof getter === 'function') {
    try {
      raw = getter.call(res.headers);
    } catch {
      raw = [];
    }
  }
  if (raw.length === 0) {
    const h = res.headers.get('set-cookie') ?? '';
    if (!h) return [];
    raw = h.split(/,(?=[^;,=\s]+\s*=)/);
  }
  return raw
    .map((s) => s.split(';')[0].split('=')[0].trim())
    .filter(Boolean);
}

async function readCappedText(res: Response, maxBytes: number): Promise<string> {
  if (!res.body) {
    const buf = await res.arrayBuffer();
    const capped = buf.byteLength > maxBytes ? buf.slice(0, maxBytes) : buf;
    return new TextDecoder().decode(capped);
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        const remaining = maxBytes - total;
        if (remaining <= 0) break;
        const slice = value.length > remaining ? value.subarray(0, remaining) : value;
        chunks.push(slice);
        total += slice.length;
        if (total >= maxBytes) break;
      }
    }
  } finally {
    try {
      await reader.cancel();
    } catch {
      /* noop */
    }
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.length;
  }
  return new TextDecoder().decode(merged);
}

/** Minimal robots.txt check: honour `User-agent: *` Disallow rules (prefix match). */
export function isAllowedByRobots(robotsTxt: string, path: string): boolean {
  const lines = robotsTxt.split('\n').map((l) => l.trim());
  let inWildcard = false;
  const disallows: string[] = [];
  for (const line of lines) {
    const clean = line.split('#')[0].trim();
    if (/^user-agent\s*:/i.test(clean)) {
      inWildcard = /^\s*user-agent\s*:\s*\*\s*$/i.test(clean);
    } else if (inWildcard && /^disallow\s*:/i.test(clean)) {
      const rule = clean.split(':').slice(1).join(':').trim();
      if (rule) disallows.push(rule);
    }
  }
  for (const rule of disallows) {
    if (rule === '/') return false;
    if (path.startsWith(rule)) return false;
  }
  return true;
}

const FRAMEWORK_CATEGORIES = new Set(['cms', 'builder', 'ecommerce', 'framework']);

export async function fetchSinglePage(
  pageUrl: string,
  rootHost: string,
  robotsTxt: string,
  budget: Budget,
  timeoutMs = SCAN_CONFIG.PER_PAGE_TIMEOUT_MS
): Promise<PageScanResult> {
  const fail = (error: string): PageScanResult => ({
    url: pageUrl,
    finalUrl: pageUrl,
    redirectChain: [],
    crossDomainRedirect: false,
    framework: 'Unknown',
    frameworkId: null,
    provider: 'Unknown',
    providerId: null,
    confidence: 'Low',
    evidence: [error],
    techEvidence: [],
    frameworkConfidence: 'Low',
    providerConfidence: 'Low',
    error,
  });

  // Robots pre-check (no subrequest cost — robots.txt fetched once per scan)
  try {
    const path = new URL(pageUrl).pathname;
    if (robotsTxt && !isAllowedByRobots(robotsTxt, path)) {
      return {
        ...fail('Skipped: disallowed by robots.txt'),
        skippedByRobots: true,
      };
    }
  } catch {
    return fail('Invalid URL');
  }

  const validated = validateUrl(pageUrl);
  if (!validated.ok) return fail(`Rejected: ${validated.code}`);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let current = validated.url.toString();
  const chain: RedirectHop[] = [];
  let hops = 0;

  try {
    for (;;) {
      if (budget.used >= budget.ceiling) {
        return { ...fail('Skipped: subrequest budget reached'), redirectChain: chain };
      }
      budget.used += 1;

      let res: Response;
      try {
        res = await fetch(current, {
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': SCAN_CONFIG.USER_AGENT,
            Accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
          },
        });
      } catch (e) {
        if (String(e).includes('abort')) return { ...fail('Timeout'), redirectChain: chain };
        return { ...fail('Fetch failed'), redirectChain: chain };
      }

      if (res.status >= 301 && res.status <= 308) {
        const location = res.headers.get('location');
        if (!location) return { ...fail('Bad redirect'), redirectChain: chain };
        chain.push({ url: current, status: res.status });
        // Best effort: release the redirect body
        try {
          await res.arrayBuffer();
        } catch {
          /* noop */
        }
        const next = validateRedirect(location, current);
        if (!next.ok) return { ...fail(`Redirect rejected: ${next.code}`), redirectChain: chain };
        current = next.url.toString();
        hops += 1;
        if (hops > SCAN_CONFIG.MAX_REDIRECT_HOPS) {
          return { ...fail('Too many redirects'), redirectChain: chain };
        }
        continue;
      }

      // Final response — detect from headers + capped HTML
      const headers = extractHeaders(res);
      const cookies = extractCookieNames(res);
      const contentType = (headers['content-type'] ?? '').toLowerCase();
      const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml') || !contentType;

      let html = '';
      if (isHtml && res.status < 400) {
        try {
          html = await readCappedText(res, SCAN_CONFIG.PER_PAGE_HTML_CAP);
        } catch {
          html = '';
        }
      }
      // Always release
      try {
        if (!html && res.body) await res.arrayBuffer();
      } catch {
        /* noop */
      }

      // A challenge page served with status 200 must never be scanned
      // as normal HTML — headers/cookies only, flagged as limited.
      const challenged = isChallengeResponse(res.status, html);
      const results = runSignatureEngine({ html: challenged ? '' : html, headers, cookies }).filter((r) => r.category !== 'analytics');
      const fw = results.find((r) => FRAMEWORK_CATEGORIES.has(r.category));
      const prov = results.find((r) => r.category === 'hosting');

      // Legacy flat list kept for the per-page results matrix only.
      // Summary cards must use techEvidence (grouped by techId).
      const evidence: string[] = [];
      if (fw) for (const e of fw.evidence.slice(0, 2)) evidence.push(e.artifact);
      if (prov) for (const e of prov.evidence.slice(0, 2)) evidence.push(e.artifact);

      // All-category evidence: every detection tags its own lines with
      // its techId (toTechItems), so summary cards group correctly by
      // technology. The legacy flat list below stays framework/provider
      // only for the per-page results matrix.
      const techEvidence: TechEvidenceItem[] = results.flatMap((r) =>
        toTechItems(r, pageUrl)
      );
      const frameworkConfidence: ConfidenceLevel = fw ? pageTechConfidence(fw) : 'Low';
      const providerConfidence: ConfidenceLevel = prov ? pageTechConfidence(prov) : 'Low';

      const confLabel = fw?.confidenceLabel ?? prov?.confidenceLabel ?? 'possible';

      let finalHost = rootHost;
      let crossDomain = false;
      try {
        finalHost = new URL(current).hostname.toLowerCase();
        crossDomain = finalHost !== rootHost.toLowerCase();
      } catch {
        /* keep */
      }

      return {
        url: pageUrl,
        finalUrl: current,
        redirectChain: chain,
        crossDomainRedirect: crossDomain,
        framework: fw?.name ?? 'Unknown',
        frameworkId: fw?.id ?? null,
        frameworkSlug: fw?.pageSlug ?? null,
        provider: prov?.name ?? 'Unknown',
        providerId: prov?.id ?? null,
        providerSlug: prov?.pageSlug ?? null,
        confidence: confidenceFromScore(confLabel),
        evidence: evidence.length > 0 ? evidence : ['No distinctive fingerprint matched'],
        techEvidence,
        frameworkConfidence,
        providerConfidence,
        // Challenge pages keep their header-derived hints but are
        // excluded from the baseline like any other limited page.
        ...(challenged
          ? { error: 'Blocked: bot-protection challenge — headers and cookies only' }
          : {}),
      };
    }
  } finally {
    clearTimeout(timer);
  }
}
