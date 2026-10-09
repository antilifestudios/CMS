/**
 * Website Safety & Security Checking Engine.
 *
 * Evidence-based security, threat intelligence, encryption, and header analysis.
 * Cloudflare Workers runtime compatible (pure fetch, web crypto, standard APIs).
 * Zero mandatory external paid dependencies; respects Cloudflare Free limits.
 */

import { validateUrl } from './ssrf.ts';

// ----------------------------------------------------------------
// Public Types
// ----------------------------------------------------------------

export type SafetyVerdict =
  | 'no_known_threats'
  | 'potential_concerns'
  | 'known_threat'
  | 'incomplete';

export type CheckCategory =
  | 'threat_intel'
  | 'connection'
  | 'headers'
  | 'redirects'
  | 'url_anatomy'
  | 'dns';

export type FindingStatus = 'pass' | 'concern' | 'threat' | 'unavailable';
export type FindingSeverity = 'none' | 'low' | 'medium' | 'high' | 'critical';

export interface SafetyFinding {
  id: string;
  name: string;
  category: CheckCategory;
  status: FindingStatus;
  severity: FindingSeverity;
  title: string;
  evidence: string;
  whyItMatters: string;
  remediation?: string;
  source: string;
}

export interface ThreatIntelResult {
  source: string;
  checked: boolean;
  listed: boolean;
  statusText: string;
  threatType?: string;
  details?: string;
}

export interface ConnectionSecurityReport {
  isHttps: boolean;
  httpRedirectsToHttps: boolean | null;
  certificateValid: boolean;
  tlsError?: string;
  hsts: {
    enabled: boolean;
    maxAge?: number;
    includeSubDomains: boolean;
    preload: boolean;
    raw?: string;
  };
  mixedContent: {
    hasInsecureResources: boolean;
    count: number;
    samples: string[];
  };
}

export interface HeaderAnalysisItem {
  present: boolean;
  value?: string;
  summary: string;
  details?: string;
}

export interface SecurityHeadersReport {
  csp: HeaderAnalysisItem & { hasUnsafeInline?: boolean; hasUnsafeEval?: boolean };
  hsts: HeaderAnalysisItem;
  xContentTypeOptions: HeaderAnalysisItem & { isNosniff: boolean };
  xFrameOptions: HeaderAnalysisItem & { protected: boolean };
  referrerPolicy: HeaderAnalysisItem & { recommended: boolean };
  permissionsPolicy: HeaderAnalysisItem;
  serverExposure: HeaderAnalysisItem & { server?: string; poweredBy?: string; exposesVersion: boolean };
}

export interface RedirectHopItem {
  url: string;
  status?: number;
}

export interface RedirectAnalysisReport {
  hopsCount: number;
  chain: RedirectHopItem[];
  hasCrossDomain: boolean;
  hasDowngrade: boolean;
  hasLoop: boolean;
  isExcessive: boolean;
  finalDestination: string;
}

export interface UrlAnatomyReport {
  rawUrl: string;
  normalizedUrl: string;
  hostname: string;
  protocol: string;
  isIpAddress: boolean;
  isPunycode: boolean;
  hasSuspiciousKeywords: boolean;
  detectedKeywords: string[];
  subdomainCount: number;
  unusualPort: boolean;
}

export interface DnsInfrastructureReport {
  resolves: boolean;
  ipAddresses: string[];
  dnssec: {
    enabled: boolean;
    validated: boolean;
  };
  caaRecord: {
    present: boolean;
    records: string[];
  };
}

export interface SafetyReport {
  verdict: SafetyVerdict;
  verdictTitle: string;
  verdictSummary: string;
  safetyScore: number;
  ratingLabel: 'Low Risk' | 'Moderate Risk' | 'High Risk' | 'Inconclusive';
  scannedHost: string;
  scannedAt: string;
  stats: {
    passed: number;
    concerns: number;
    threats: number;
    unavailable: number;
    total: number;
  };
  threatIntelligence: {
    sources: ThreatIntelResult[];
    cleanCount: number;
    threatCount: number;
    unavailableCount: number;
  };
  connectionSecurity: ConnectionSecurityReport;
  securityHeaders: SecurityHeadersReport;
  redirectAnalysis: RedirectAnalysisReport;
  urlAnatomy: UrlAnatomyReport;
  dnsInfrastructure: DnsInfrastructureReport;
  findings: SafetyFinding[];
}

// ----------------------------------------------------------------
// Heuristics & Constants
// ----------------------------------------------------------------

const HIGH_RISK_KEYWORDS = [
  'login-update',
  'account-verify',
  'secure-banking',
  'wallet-connect',
  'auth-confirm',
  'password-reset',
  'security-alert',
  'paypal-verify',
  'appleid-verify',
  'chase-online',
  'wellsfargo-verify',
  'binance-security',
  'metamask-auth',
  'webscr',
];

const RECOMMENDED_REFERRER_POLICIES = [
  'strict-origin-when-cross-origin',
  'no-referrer',
  'strict-origin',
  'same-origin',
];

const ONE_YEAR_SECONDS = 31536000;
const DOH_TIMEOUT_MS = 2500;
const HTTP_CHECK_TIMEOUT_MS = 3000;

// ----------------------------------------------------------------
// 1. URL Anatomy Analysis
// ----------------------------------------------------------------

export function analyzeUrlAnatomy(rawUrl: string): UrlAnatomyReport {
  let trimmed = (rawUrl || '').trim();
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    trimmed = `https://${trimmed}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return {
      rawUrl,
      normalizedUrl: rawUrl,
      hostname: rawUrl,
      protocol: 'unknown',
      isIpAddress: false,
      isPunycode: false,
      hasSuspiciousKeywords: false,
      detectedKeywords: [],
      subdomainCount: 0,
      unusualPort: false,
    };
  }

  const host = parsed.hostname.toLowerCase();
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':');
  const isPunycode = host.startsWith('xn--') || host.includes('.xn--');

  const parts = host.split('.').filter(Boolean);
  // Example: a.b.c.example.com -> parts length 5 -> subdomains = 5 - 2 = 3
  const subdomainCount = Math.max(0, parts.length - 2);

  const matchedKeywords: string[] = [];
  for (const kw of HIGH_RISK_KEYWORDS) {
    if (host.includes(kw) || parsed.pathname.toLowerCase().includes(kw)) {
      matchedKeywords.push(kw);
    }
  }

  const unusualPort = parsed.port !== '' && parsed.port !== '80' && parsed.port !== '443';

  return {
    rawUrl,
    normalizedUrl: parsed.toString(),
    hostname: host,
    protocol: parsed.protocol.replace(':', ''),
    isIpAddress: isIp,
    isPunycode,
    hasSuspiciousKeywords: matchedKeywords.length > 0,
    detectedKeywords: matchedKeywords,
    subdomainCount,
    unusualPort,
  };
}

// ----------------------------------------------------------------
// 2. HTTP Security Headers Analysis
// ----------------------------------------------------------------

export function analyzeSecurityHeaders(headers: Record<string, string>): SecurityHeadersReport {
  const h: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers || {})) {
    h[k.toLowerCase()] = v;
  }

  // 1. CSP
  const rawCsp = h['content-security-policy'];
  const hasCsp = typeof rawCsp === 'string' && rawCsp.trim().length > 0;
  const hasUnsafeInline = hasCsp && rawCsp.includes("'unsafe-inline'");
  const hasUnsafeEval = hasCsp && rawCsp.includes("'unsafe-eval'");

  const csp: HeaderAnalysisItem & { hasUnsafeInline?: boolean; hasUnsafeEval?: boolean } = {
    present: hasCsp,
    value: rawCsp,
    summary: hasCsp
      ? hasUnsafeInline
        ? 'Present with unsafe-inline directive'
        : 'Configured and active'
      : 'Missing Content-Security-Policy',
    details: hasCsp
      ? 'Restricts resource loading domains, reducing Cross-Site Scripting (XSS) risk.'
      : 'Leaves the application reliant solely on browser defaults against XSS and data injections.',
    hasUnsafeInline,
    hasUnsafeEval,
  };

  // 2. HSTS
  const rawHsts = h['strict-transport-security'];
  const hasHsts = typeof rawHsts === 'string' && rawHsts.trim().length > 0;
  let hstsSummary = 'Missing HSTS';
  if (hasHsts) {
    const m = /max-age=(\d+)/i.exec(rawHsts);
    const maxAge = m ? parseInt(m[1], 10) : 0;
    if (maxAge >= ONE_YEAR_SECONDS) {
      hstsSummary = `Enforced (max-age: ${Math.round(maxAge / 86400)} days)`;
    } else {
      hstsSummary = `Short duration (max-age: ${Math.round(maxAge / 86400)} days)`;
    }
  }

  const hstsItem: HeaderAnalysisItem = {
    present: hasHsts,
    value: rawHsts,
    summary: hstsSummary,
    details: hasHsts
      ? 'Instructs browsers to always use HTTPS, preventing man-in-the-middle protocol downgrades.'
      : 'Initial connections over HTTP are not protected against SSL stripping attacks.',
  };

  // 3. X-Content-Type-Options
  const rawXcto = h['x-content-type-options'];
  const isNosniff = typeof rawXcto === 'string' && rawXcto.trim().toLowerCase() === 'nosniff';
  const xContentTypeOptions = {
    present: !!rawXcto,
    value: rawXcto,
    isNosniff,
    summary: isNosniff ? 'Properly set to nosniff' : 'Missing or invalid',
    details: isNosniff
      ? 'Stops browsers from MIME-sniffing responses away from the declared content-type.'
      : 'Browsers may interpret uploaded files (such as images) as executable scripts.',
  };

  // 4. X-Frame-Options (or CSP frame-ancestors)
  const rawXfo = h['x-frame-options'];
  const xfoVal = (rawXfo || '').trim().toUpperCase();
  const cspHasFrameAncestors = hasCsp && rawCsp.includes('frame-ancestors');
  const frameProtected =
    cspHasFrameAncestors || xfoVal === 'DENY' || xfoVal === 'SAMEORIGIN';

  const xFrameOptions = {
    present: !!rawXfo || cspHasFrameAncestors,
    value: rawXfo || (cspHasFrameAncestors ? 'CSP frame-ancestors' : undefined),
    protected: frameProtected,
    summary: frameProtected
      ? cspHasFrameAncestors
        ? 'Protected via CSP frame-ancestors'
        : `Protected via ${xfoVal}`
      : 'Missing clickjacking protection',
    details: frameProtected
      ? 'Prevents unauthorized framing of the website in hidden iframes (anti-clickjacking).'
      : 'Attackers could potentially frame this page to hijack user clicks or interactions.',
  };

  // 5. Referrer-Policy
  const rawRef = h['referrer-policy'];
  const refVal = (rawRef || '').trim().toLowerCase();
  const isRecommendedRef = RECOMMENDED_REFERRER_POLICIES.some((p) => refVal.includes(p));

  const referrerPolicy = {
    present: !!rawRef,
    value: rawRef,
    recommended: isRecommendedRef,
    summary: isRecommendedRef
      ? `Configured (${refVal})`
      : rawRef
        ? `Configured with permissive policy (${refVal})`
        : 'Missing Referrer-Policy',
    details: isRecommendedRef
      ? 'Prevents sensitive query strings or path data from leaking to third-party destinations.'
      : 'Referrer headers may expose sensitive internal path details or session tokens to external links.',
  };

  // 6. Permissions-Policy
  const rawPerm = h['permissions-policy'] || h['feature-policy'];
  const permissionsPolicy = {
    present: !!rawPerm,
    value: rawPerm,
    summary: rawPerm ? 'Configured' : 'Not configured',
    details: rawPerm
      ? 'Restricts browser device features (camera, microphone, geolocation) to authorized origins.'
      : 'Relies on browser permission prompts rather than explicit origin restriction policy.',
  };

  // 7. Server information disclosure
  const server = h['server'];
  const poweredBy = h['x-powered-by'];
  const exposesVersion =
    (/\d+\.\d+/.test(server || '') || /\d+\.\d+/.test(poweredBy || ''));

  const serverExposure = {
    present: !!server || !!poweredBy,
    server,
    poweredBy,
    exposesVersion,
    summary: exposesVersion
      ? 'Server banner exposes specific software version'
      : server || poweredBy
        ? 'Generic server header disclosed'
        : 'No server banner disclosed',
    details: exposesVersion
      ? `Exposes explicit version (${[server, poweredBy].filter(Boolean).join(', ')}), assisting vulnerability scanners.`
      : 'Standard server header without specific patch/version details.',
  };

  return {
    csp,
    hsts: hstsItem,
    xContentTypeOptions,
    xFrameOptions,
    referrerPolicy,
    permissionsPolicy,
    serverExposure,
  };
}

// ----------------------------------------------------------------
// 3. Mixed Content Detection (in HTML)
// ----------------------------------------------------------------

export function detectMixedContent(html: string, isHttpsPage: boolean): {
  hasInsecureResources: boolean;
  count: number;
  samples: string[];
} {
  if (!isHttpsPage || !html) {
    return { hasInsecureResources: false, count: 0, samples: [] };
  }

  // Look for active & passive resources loaded via http://
  const mixedResourceRx =
    /<(?:script|link|iframe|img|audio|video|source|embed)[^>]*?(?:src|href)=["'](http:\/\/[^"']+)["']/gi;

  const samples: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = mixedResourceRx.exec(html)) !== null) {
    const url = m[1];
    if (!samples.includes(url)) {
      samples.push(url);
      if (samples.length >= 10) break;
    }
  }

  return {
    hasInsecureResources: samples.length > 0,
    count: samples.length,
    samples,
  };
}

// ----------------------------------------------------------------
// 4. Redirect Chain Analysis
// ----------------------------------------------------------------

export function analyzeRedirectChain(
  initialUrl: string,
  finalUrl: string,
  redirectChain: string[],
): RedirectAnalysisReport {
  const chain: RedirectHopItem[] = (redirectChain && redirectChain.length > 0)
    ? redirectChain.map((u) => ({ url: u }))
    : [{ url: initialUrl }];

  // Ensure initial and final are represented
  if (chain[0].url !== initialUrl) {
    chain.unshift({ url: initialUrl });
  }
  if (chain[chain.length - 1].url !== finalUrl && finalUrl) {
    chain.push({ url: finalUrl });
  }

  let hasCrossDomain = false;
  let hasDowngrade = false;
  let initialHost = '';
  try {
    initialHost = new URL(initialUrl).hostname.toLowerCase();
  } catch {
    /* noop */
  }

  for (let i = 0; i < chain.length; i++) {
    const cur = chain[i].url;
    try {
      const parsed = new URL(cur);
      const curHost = parsed.hostname.toLowerCase();
      if (initialHost && curHost !== initialHost && !curHost.endsWith(`.${initialHost}`)) {
        hasCrossDomain = true;
      }
      if (i > 0) {
        const prev = chain[i - 1].url;
        const prevParsed = new URL(prev);
        if (prevParsed.protocol === 'https:' && parsed.protocol === 'http:') {
          hasDowngrade = true;
        }
      }
    } catch {
      /* ignore invalid */
    }
  }

  const hopsCount = Math.max(0, chain.length - 1);
  const isExcessive = hopsCount > 3;

  return {
    hopsCount,
    chain,
    hasCrossDomain,
    hasDowngrade,
    hasLoop: false,
    isExcessive,
    finalDestination: finalUrl || initialUrl,
  };
}

// ----------------------------------------------------------------
// 5. DNS & Infrastructure Signals (Cloudflare DoH)
// ----------------------------------------------------------------

export interface DohResponse {
  Status: number;
  AD?: boolean;
  Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
}

export async function checkDnsInfrastructure(
  hostname: string,
  fetchImpl: typeof fetch = fetch,
): Promise<DnsInfrastructureReport> {
  const report: DnsInfrastructureReport = {
    resolves: false,
    ipAddresses: [],
    dnssec: { enabled: false, validated: false },
    caaRecord: { present: false, records: [] },
  };

  if (!hostname || /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    return report;
  }

  try {
    // 1. Query A records with DNSSEC flag (do=true)
    const aController = new AbortController();
    const aTimer = setTimeout(() => aController.abort(), DOH_TIMEOUT_MS);
    const aRes = await fetchImpl(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A&do=true`,
      {
        headers: { Accept: 'application/dns-json' },
        signal: aController.signal,
      },
    );
    clearTimeout(aTimer);

    if (aRes.ok) {
      const json = (await aRes.json()) as DohResponse;
      if (json.Status === 0 && Array.isArray(json.Answer)) {
        report.resolves = true;
        report.dnssec.validated = Boolean(json.AD);
        for (const ans of json.Answer) {
          if (ans.type === 1 && ans.data) {
            report.ipAddresses.push(ans.data);
          }
          if (ans.type === 46) {
            // RRSIG DNSSEC record
            report.dnssec.enabled = true;
          }
        }
      }
    }
  } catch {
    /* fail soft */
  }

  try {
    // 2. Query CAA records (type 257)
    const caaController = new AbortController();
    const caaTimer = setTimeout(() => caaController.abort(), DOH_TIMEOUT_MS);
    const caaRes = await fetchImpl(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=CAA`,
      {
        headers: { Accept: 'application/dns-json' },
        signal: caaController.signal,
      },
    );
    clearTimeout(caaTimer);

    if (caaRes.ok) {
      const json = (await caaRes.json()) as DohResponse;
      if (json.Status === 0 && Array.isArray(json.Answer)) {
        for (const ans of json.Answer) {
          if (ans.type === 257 && ans.data) {
            report.caaRecord.present = true;
            report.caaRecord.records.push(ans.data);
          }
        }
      }
    }
  } catch {
    /* fail soft */
  }

  return report;
}

// ----------------------------------------------------------------
// 6. Threat Intelligence & Malicious Feeds
// ----------------------------------------------------------------

export async function queryCloudflareSecurityDns(
  hostname: string,
  fetchImpl: typeof fetch = fetch,
): Promise<ThreatIntelResult> {
  const result: ThreatIntelResult = {
    source: 'Cloudflare Security Threat Intelligence (1.1.1.2)',
    checked: false,
    listed: false,
    statusText: 'Check unavailable',
  };

  if (!hostname || /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    return result;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DOH_TIMEOUT_MS);
    const res = await fetchImpl(
      `https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
      {
        headers: { Accept: 'application/dns-json' },
        signal: controller.signal,
      },
    );
    clearTimeout(timer);

    if (res.ok) {
      const json = (await res.json()) as DohResponse;
      result.checked = true;
      // Cloudflare 1.1.1.2 blocks malicious domains by returning 0.0.0.0 or NXDOMAIN (Status 3)
      if (json.Status === 3) {
        result.listed = true;
        result.threatType = 'Blocked Domain / Malware / Phishing';
        result.statusText = 'Flagged as malicious by Cloudflare Security feed';
      } else if (json.Status === 0 && Array.isArray(json.Answer)) {
        const isSinkholed = json.Answer.some((a) => a.data === '0.0.0.0');
        if (isSinkholed) {
          result.listed = true;
          result.threatType = 'Malware Distribution / Sinkholed';
          result.statusText = 'Blocked by Cloudflare automated threat filter';
        } else {
          result.listed = false;
          result.statusText = 'Clean (no active threat listing detected)';
        }
      } else {
        result.listed = false;
        result.statusText = 'Clean (no active threat listing detected)';
      }
    }
  } catch {
    result.statusText = 'Threat feed check timed out (failed soft)';
  }

  return result;
}

export async function queryGoogleSafeBrowsing(
  urlToCheck: string,
  apiKey?: string,
  fetchImpl: typeof fetch = fetch,
): Promise<ThreatIntelResult> {
  const key = apiKey || (typeof process !== 'undefined' ? process.env?.GOOGLE_SAFE_BROWSING_API_KEY : undefined);

  if (!key) {
    return {
      source: 'Google Safe Browsing v4',
      checked: false,
      listed: false,
      statusText: 'Feed not active (optional API key not configured in environment)',
      details: 'To enable Google Safe Browsing lookups, set GOOGLE_SAFE_BROWSING_API_KEY.',
    };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const res = await fetchImpl(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'cmsdetectorai', clientVersion: '2.0.0' },
          threatInfo: {
            threatTypes: [
              'MALWARE',
              'SOCIAL_ENGINEERING',
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION',
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: urlToCheck }],
          },
        }),
        signal: controller.signal,
      },
    );
    clearTimeout(timer);

    if (res.ok) {
      const data = (await res.json()) as { matches?: Array<{ threatType: string }> };
      if (data.matches && data.matches.length > 0) {
        return {
          source: 'Google Safe Browsing v4',
          checked: true,
          listed: true,
          threatType: data.matches[0].threatType,
          statusText: `Flagged as ${data.matches[0].threatType}`,
        };
      }
      return {
        source: 'Google Safe Browsing v4',
        checked: true,
        listed: false,
        statusText: 'Clean (no active threat matches reported by Google)',
      };
    }
  } catch {
    /* fail soft */
  }

  return {
    source: 'Google Safe Browsing v4',
    checked: false,
    listed: false,
    statusText: 'Provider lookup timed out or unavailable',
  };
}

export async function queryUrlhaus(
  hostname: string,
  authKey?: string,
  fetchImpl: typeof fetch = fetch,
): Promise<ThreatIntelResult> {
  const key =
    authKey ||
    (typeof process !== 'undefined'
      ? process.env?.URLHAUS_AUTH_KEY || process.env?.ABUSE_CH_API_KEY
      : undefined);

  if (!key) {
    return {
      source: 'URLhaus Malware Intelligence (Abuse.ch)',
      checked: false,
      listed: false,
      statusText: 'Feed not active (optional Auth-Key not configured in environment)',
      details: 'To enable direct abuse.ch URLhaus host lookup, configure URLHAUS_AUTH_KEY.',
    };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const res = await fetchImpl('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Auth-Key': key,
      },
      body: `host=${encodeURIComponent(hostname)}`,
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (res.ok) {
      const data = (await res.json()) as {
        query_status: string;
        url_count?: number;
        threat?: string;
      };
      if (data.query_status === 'ok') {
        return {
          source: 'URLhaus Malware Intelligence (Abuse.ch)',
          checked: true,
          listed: true,
          threatType: data.threat || 'Malware Distribution',
          statusText: `Listed for active malware distribution (${data.url_count ?? 1} URLs recorded)`,
        };
      }
      return {
        source: 'URLhaus Malware Intelligence (Abuse.ch)',
        checked: true,
        listed: false,
        statusText: 'Clean (host not listed in URLhaus malware database)',
      };
    }
  } catch {
    /* fail soft */
  }

  return {
    source: 'URLhaus Malware Intelligence (Abuse.ch)',
    checked: false,
    listed: false,
    statusText: 'Provider lookup timed out or unavailable',
  };
}

// ----------------------------------------------------------------
// 7. HTTP to HTTPS Redirection Test
// ----------------------------------------------------------------

export async function testHttpToHttpsRedirect(
  hostname: string,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean | null> {
  if (!hostname || /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    return null;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), HTTP_CHECK_TIMEOUT_MS);
    const res = await fetchImpl(`http://${hostname}`, {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CMSDetector-AI/1.0 (+https://cmsdetectorai.com)',
        Accept: 'text/html,*/*',
      },
    });
    clearTimeout(timer);

    if (res.status >= 301 && res.status <= 308) {
      const loc = res.headers.get('location') || '';
      return /^https:\/\//i.test(loc.trim());
    }
    // Returned 200 on unencrypted HTTP without redirecting
    if (res.status === 200) {
      return false;
    }
  } catch {
    // Port 80 closed, dropped or timeout — common for HTTPS-only hosts
    return null;
  }
  return null;
}

// ----------------------------------------------------------------
// 8. Main Aggregator & Deterministic Scoring Engine
// ----------------------------------------------------------------

export interface SafetyAnalysisInput {
  rawUrl: string;
  finalUrl: string;
  redirectChain: string[];
  headers: Record<string, string>;
  html: string;
  fetchImpl?: typeof fetch;
  envKeys?: {
    googleSafeBrowsingKey?: string;
    urlhausAuthKey?: string;
  };
}

export async function analyzeWebsiteSafety(
  input: SafetyAnalysisInput,
): Promise<SafetyReport> {
  const fetchImpl = input.fetchImpl || fetch;
  const anatomy = analyzeUrlAnatomy(input.rawUrl);
  const secHeaders = analyzeSecurityHeaders(input.headers);
  const redirects = analyzeRedirectChain(input.rawUrl, input.finalUrl, input.redirectChain);

  const finalProtocol = (input.finalUrl ? new URL(input.finalUrl).protocol : anatomy.protocol + ':')
    .replace(':', '')
    .toLowerCase();
  const isHttps = finalProtocol === 'https';

  const mixedContent = detectMixedContent(input.html, isHttps);

  // Parallel asynchronous network checks:
  const [httpRedirectsToHttps, dnsReport, cfThreat, googleThreat, urlhausThreat] =
    await Promise.all([
      testHttpToHttpsRedirect(anatomy.hostname, fetchImpl),
      checkDnsInfrastructure(anatomy.hostname, fetchImpl),
      queryCloudflareSecurityDns(anatomy.hostname, fetchImpl),
      queryGoogleSafeBrowsing(input.rawUrl, input.envKeys?.googleSafeBrowsingKey, fetchImpl),
      queryUrlhaus(anatomy.hostname, input.envKeys?.urlhausAuthKey, fetchImpl),
    ]);

  const threatSources: ThreatIntelResult[] = [cfThreat, googleThreat, urlhausThreat];

  // Parse HSTS
  const rawHsts = input.headers['strict-transport-security'] || '';
  const hasHsts = Boolean(rawHsts);
  const maxAgeMatch = /max-age=(\d+)/i.exec(rawHsts);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : undefined;
  const includeSubDomains = /includesubdomains/i.test(rawHsts);
  const preload = /preload/i.test(rawHsts);

  const connectionSecurity: ConnectionSecurityReport = {
    isHttps,
    httpRedirectsToHttps,
    certificateValid: isHttps,
    hsts: {
      enabled: hasHsts,
      maxAge,
      includeSubDomains,
      preload,
      raw: rawHsts || undefined,
    },
    mixedContent,
  };

  // Compile Findings list
  const findings: SafetyFinding[] = [];

  // A. Threat Intelligence Findings
  for (const src of threatSources) {
    if (src.checked && src.listed) {
      findings.push({
        id: `threat-${src.source.replace(/\s+/g, '-').toLowerCase()}`,
        name: src.source,
        category: 'threat_intel',
        status: 'threat',
        severity: 'critical',
        title: `Listed in Threat Feed: ${src.threatType || 'Malicious'}`,
        evidence: src.statusText,
        whyItMatters:
          'The domain or URL has been flagged for malicious activity (malware distribution, phishing, or botnet activity) by established security feeds.',
        remediation:
          'Do not proceed or submit sensitive credentials. If you own this site, inspect your server for malware and request a review.',
        source: src.source,
      });
    } else if (src.checked && !src.listed) {
      findings.push({
        id: `clean-${src.source.replace(/\s+/g, '-').toLowerCase()}`,
        name: src.source,
        category: 'threat_intel',
        status: 'pass',
        severity: 'none',
        title: 'No Known Threat Listing Detected',
        evidence: src.statusText,
        whyItMatters:
          'No active malware, phishing, or scam reports were found for this domain in this feed.',
        source: src.source,
      });
    } else {
      findings.push({
        id: `avail-${src.source.replace(/\s+/g, '-').toLowerCase()}`,
        name: src.source,
        category: 'threat_intel',
        status: 'unavailable',
        severity: 'none',
        title: 'Threat Intelligence Provider Feed Status',
        evidence: src.statusText,
        whyItMatters:
          'This threat database was not queried during this scan (either due to environment configuration or upstream timeout).',
        source: src.source,
      });
    }
  }

  // B. Connection Security Findings
  if (isHttps) {
    findings.push({
      id: 'conn-https-valid',
      name: 'HTTPS Transport Encryption',
      category: 'connection',
      status: 'pass',
      severity: 'none',
      title: 'HTTPS Active and Enforced',
      evidence: `Connection established over ${input.finalUrl}`,
      whyItMatters:
        'Encrypts traffic between your browser and the website, guarding login credentials and data against network eavesdropping.',
      source: 'TLS Handshake',
    });
  } else {
    findings.push({
      id: 'conn-https-missing',
      name: 'HTTPS Transport Encryption',
      category: 'connection',
      status: 'threat',
      severity: 'high',
      title: 'Unencrypted Plain HTTP Connection',
      evidence: `Connected over plaintext HTTP (${input.finalUrl})`,
      whyItMatters:
        'All data, passwords, and form submissions are transmitted in plaintext and can be intercepted or modified by network eavesdroppers.',
      remediation: 'Install an SSL/TLS certificate and configure 301 redirects to HTTPS.',
      source: 'Protocol Scheme',
    });
  }

  if (httpRedirectsToHttps === true) {
    findings.push({
      id: 'conn-http-redirect',
      name: 'HTTP to HTTPS Redirection',
      category: 'connection',
      status: 'pass',
      severity: 'none',
      title: 'Automatic HTTPS Redirection Enforced',
      evidence: 'Plain HTTP requests automatically redirect to secure HTTPS.',
      whyItMatters:
        'Prevents visitors who type a bare domain from remaining on an unencrypted HTTP connection.',
      source: 'HTTP Front-Door Probe',
    });
  } else if (httpRedirectsToHttps === false) {
    findings.push({
      id: 'conn-http-no-redirect',
      name: 'HTTP to HTTPS Redirection',
      category: 'connection',
      status: 'concern',
      severity: 'medium',
      title: 'Plain HTTP Does Not Redirect to HTTPS',
      evidence: 'Server served HTTP content on port 80 without redirecting to HTTPS.',
      whyItMatters:
        'Visitors who do not explicitly type https:// may browse the site over an unencrypted connection.',
      remediation: 'Configure server-level 301 redirect from HTTP to HTTPS for all routes.',
      source: 'HTTP Front-Door Probe',
    });
  }

  if (hasHsts) {
    const isStrong = (maxAge || 0) >= ONE_YEAR_SECONDS;
    findings.push({
      id: 'conn-hsts',
      name: 'HTTP Strict Transport Security (HSTS)',
      category: 'connection',
      status: isStrong ? 'pass' : 'concern',
      severity: isStrong ? 'none' : 'low',
      title: isStrong ? 'Strong HSTS Policy Enforced' : 'Short-Duration HSTS Policy',
      evidence: rawHsts,
      whyItMatters:
        'Instructs modern web browsers to refuse unencrypted connections, guarding against SSL stripping attacks.',
      remediation: isStrong
        ? undefined
        : 'Increase max-age to at least 31536000 (1 year) and consider includeSubDomains.',
      source: 'Strict-Transport-Security Header',
    });
  } else {
    findings.push({
      id: 'conn-hsts-missing',
      name: 'HTTP Strict Transport Security (HSTS)',
      category: 'connection',
      status: 'concern',
      severity: 'medium',
      title: 'Missing HSTS Header',
      evidence: 'Header Strict-Transport-Security was not found.',
      whyItMatters:
        'First-time visitors could be vulnerable to downgrade attacks if an attacker intercepts their initial connection.',
      remediation:
        'Add Strict-Transport-Security: max-age=31536000; includeSubDomains to server headers.',
      source: 'Strict-Transport-Security Header',
    });
  }

  if (mixedContent.hasInsecureResources) {
    findings.push({
      id: 'conn-mixed-content',
      name: 'Mixed Content Resources',
      category: 'connection',
      status: 'threat',
      severity: 'high',
      title: `Insecure Mixed Content Detected (${mixedContent.count} resource${mixedContent.count === 1 ? '' : 's'})`,
      evidence: mixedContent.samples.slice(0, 3).join(', '),
      whyItMatters:
        'An HTTPS webpage loading scripts or resources over plain HTTP compromises encryption and allows attackers to inject malicious code.',
      remediation: 'Update all embedded resource URLs in HTML and scripts to use https://.',
      source: 'HTML Resource Inspection',
    });
  } else if (isHttps) {
    findings.push({
      id: 'conn-mixed-clean',
      name: 'Mixed Content Resources',
      category: 'connection',
      status: 'pass',
      severity: 'none',
      title: 'No Insecure Mixed Content Found',
      evidence: 'All embedded scripts, styles, and media use secure HTTPS URLs.',
      whyItMatters: 'Guarantees the integrity of the secure encrypted session.',
      source: 'HTML Resource Inspection',
    });
  }

  // C. Browser Security Headers Findings
  if (secHeaders.csp.present) {
    findings.push({
      id: 'hdr-csp',
      name: 'Content-Security-Policy (CSP)',
      category: 'headers',
      status: secHeaders.csp.hasUnsafeInline ? 'concern' : 'pass',
      severity: secHeaders.csp.hasUnsafeInline ? 'low' : 'none',
      title: secHeaders.csp.hasUnsafeInline
        ? 'CSP Active with unsafe-inline'
        : 'Content-Security-Policy Enforced',
      evidence: (secHeaders.csp.value || '').slice(0, 120),
      whyItMatters:
        'Restricts domains that can execute scripts, preventing malicious code injection and XSS.',
      source: 'Content-Security-Policy Header',
    });
  } else {
    findings.push({
      id: 'hdr-csp-missing',
      name: 'Content-Security-Policy (CSP)',
      category: 'headers',
      status: 'concern',
      severity: 'medium',
      title: 'Missing Content-Security-Policy',
      evidence: 'No Content-Security-Policy header returned.',
      whyItMatters:
        'Without CSP, the browser has no origin whitelist to prevent rogue scripts from executing if an XSS vulnerability exists.',
      remediation: 'Implement a Content-Security-Policy header restricting script-src and object-src.',
      source: 'HTTP Response Headers',
    });
  }

  if (secHeaders.xContentTypeOptions.isNosniff) {
    findings.push({
      id: 'hdr-xcto',
      name: 'X-Content-Type-Options',
      category: 'headers',
      status: 'pass',
      severity: 'none',
      title: 'MIME-Sniffing Prevention (nosniff)',
      evidence: 'X-Content-Type-Options: nosniff',
      whyItMatters: 'Blocks browsers from executing non-executable MIME types as scripts.',
      source: 'X-Content-Type-Options Header',
    });
  } else {
    findings.push({
      id: 'hdr-xcto-missing',
      name: 'X-Content-Type-Options',
      category: 'headers',
      status: 'concern',
      severity: 'low',
      title: 'Missing X-Content-Type-Options',
      evidence: 'Header missing or not set to nosniff.',
      whyItMatters:
        'Browsers might misinterpret user-uploaded files as executable JavaScript.',
      remediation: 'Set X-Content-Type-Options: nosniff.',
      source: 'HTTP Response Headers',
    });
  }

  if (secHeaders.xFrameOptions.protected) {
    findings.push({
      id: 'hdr-xfo',
      name: 'Clickjacking Protection (X-Frame-Options)',
      category: 'headers',
      status: 'pass',
      severity: 'none',
      title: secHeaders.xFrameOptions.summary,
      evidence: secHeaders.xFrameOptions.value || 'DENY/SAMEORIGIN',
      whyItMatters: 'Prevents the website from being loaded inside malicious hidden iframes.',
      source: 'X-Frame-Options / CSP Header',
    });
  } else {
    findings.push({
      id: 'hdr-xfo-missing',
      name: 'Clickjacking Protection (X-Frame-Options)',
      category: 'headers',
      status: 'concern',
      severity: 'medium',
      title: 'Missing Clickjacking Protection',
      evidence: 'Neither X-Frame-Options nor CSP frame-ancestors is configured.',
      whyItMatters:
        'An attacker could display this website inside an invisible iframe to trick users into unauthorized clicks.',
      remediation: 'Set X-Frame-Options: SAMEORIGIN or CSP frame-ancestors.',
      source: 'HTTP Response Headers',
    });
  }

  if (secHeaders.referrerPolicy.recommended) {
    findings.push({
      id: 'hdr-referrer',
      name: 'Referrer-Policy',
      category: 'headers',
      status: 'pass',
      severity: 'none',
      title: 'Secure Referrer Policy Configured',
      evidence: `Referrer-Policy: ${secHeaders.referrerPolicy.value}`,
      whyItMatters: 'Protects confidential URLs and query tokens from leaking to external websites.',
      source: 'Referrer-Policy Header',
    });
  } else {
    findings.push({
      id: 'hdr-referrer-concern',
      name: 'Referrer-Policy',
      category: 'headers',
      status: 'concern',
      severity: 'low',
      title: secHeaders.referrerPolicy.present ? 'Permissive Referrer-Policy' : 'Missing Referrer-Policy',
      evidence: secHeaders.referrerPolicy.value || 'None specified (defaults to browser default)',
      whyItMatters: 'Sensitive query parameters or internal URLs might leak to third-party referrers.',
      remediation: 'Set Referrer-Policy: strict-origin-when-cross-origin.',
      source: 'Referrer-Policy Header',
    });
  }

  if (secHeaders.serverExposure.exposesVersion) {
    findings.push({
      id: 'hdr-server-version',
      name: 'Server Version Disclosure',
      category: 'headers',
      status: 'concern',
      severity: 'low',
      title: 'Server Banner Discloses Specific Version',
      evidence: [secHeaders.serverExposure.server, secHeaders.serverExposure.poweredBy]
        .filter(Boolean)
        .join(', '),
      whyItMatters:
        'Advertising exact server software versions helps attackers pinpoint known CVEs and exploits.',
      remediation: 'Disable server banners or remove version numbers in server configurations.',
      source: 'Server / X-Powered-By Header',
    });
  }

  // D. Redirect Findings
  if (redirects.hasDowngrade) {
    findings.push({
      id: 'redir-downgrade',
      name: 'Protocol Downgrade Redirect',
      category: 'redirects',
      status: 'threat',
      severity: 'critical',
      title: 'Dangerous Insecure Downgrade (HTTPS to HTTP)',
      evidence: 'Redirect chain transitioned from an HTTPS URL to an insecure HTTP URL.',
      whyItMatters:
        'Redirecting visitors from encrypted to unencrypted connections strips security protection and exposes session data.',
      remediation: 'Ensure all redirect hops maintain or upgrade to HTTPS.',
      source: 'Redirect Chain Inspector',
    });
  }

  if (redirects.hasCrossDomain) {
    findings.push({
      id: 'redir-cross-domain',
      name: 'Cross-Domain Redirection',
      category: 'redirects',
      status: 'concern',
      severity: 'medium',
      title: 'Redirects Across Different Domains',
      evidence: `Redirected to destination: ${redirects.finalDestination}`,
      whyItMatters:
        'Redirecting to an unexpected third-party domain can be a sign of domain hijacking, affiliate spoofing, or open-redirect abuse.',
      source: 'Redirect Chain Inspector',
    });
  }

  if (redirects.isExcessive) {
    findings.push({
      id: 'redir-excessive',
      name: 'Excessive Redirect Hops',
      category: 'redirects',
      status: 'concern',
      severity: 'low',
      title: `Excessive Redirect Chain (${redirects.hopsCount} hops)`,
      evidence: redirects.chain.map((c) => c.url).join(' → '),
      whyItMatters:
        'Multiple successive redirects slow down site load time and increase exposure to intermediate interception.',
      source: 'Redirect Chain Inspector',
    });
  }

  // E. URL Anatomy Findings
  if (anatomy.isPunycode) {
    findings.push({
      id: 'url-punycode',
      name: 'Internationalized Domain / Punycode',
      category: 'url_anatomy',
      status: 'concern',
      severity: 'medium',
      title: 'Punycode Internationalized Domain Detected',
      evidence: `Hostname contains punycode: ${anatomy.hostname}`,
      whyItMatters:
        'Punycode domains can be used for homograph attacks where lookalike Cyrillic or Greek characters spoof legitimate brand domains.',
      source: 'URL Parser',
    });
  }

  if (anatomy.isIpAddress) {
    findings.push({
      id: 'url-ip-host',
      name: 'Direct IP Address Host',
      category: 'url_anatomy',
      status: 'concern',
      severity: 'medium',
      title: 'Direct IP Address URL Format',
      evidence: `Hostname is an IP literal: ${anatomy.hostname}`,
      whyItMatters:
        'Legitimate consumer services use registered domain names. IP address links are frequently used in phishing campaigns.',
      source: 'URL Parser',
    });
  }

  if (anatomy.hasSuspiciousKeywords) {
    findings.push({
      id: 'url-suspicious-keywords',
      name: 'Deceptive URL Pattern Indicators',
      category: 'url_anatomy',
      status: 'concern',
      severity: 'medium',
      title: `Sensitive Keywords in Hostname (${anatomy.detectedKeywords.join(', ')})`,
      evidence: `Matched indicators: ${anatomy.detectedKeywords.join(', ')}`,
      whyItMatters:
        'Combining financial or account-verification keywords with complex subdomains is a common phishing heuristic.',
      source: 'URL Pattern Matcher',
    });
  }

  // F. DNS Infrastructure Findings
  if (dnsReport.resolves) {
    findings.push({
      id: 'dns-resolves',
      name: 'DNS Resolution & IP Routing',
      category: 'dns',
      status: 'pass',
      severity: 'none',
      title: 'Domain Resolves to Public IP Infrastructure',
      evidence: `Resolved IP: ${dnsReport.ipAddresses.slice(0, 3).join(', ')}`,
      whyItMatters: 'Confirms valid DNS records and accessible public hosting infrastructure.',
      source: 'Cloudflare DoH Query',
    });
  }

  if (dnsReport.dnssec.validated) {
    findings.push({
      id: 'dns-dnssec',
      name: 'DNSSEC Cryptographic Validation',
      category: 'dns',
      status: 'pass',
      severity: 'none',
      title: 'DNSSEC Cryptographically Validated',
      evidence: 'Cloudflare DoH returned Authenticated Data (AD) flag with RRSIG records.',
      whyItMatters:
        'DNSSEC protects DNS responses against cache poisoning and spoofing attacks.',
      source: 'Cloudflare DNSSEC Resolver',
    });
  }

  if (dnsReport.caaRecord.present) {
    findings.push({
      id: 'dns-caa',
      name: 'Certification Authority Authorization (CAA)',
      category: 'dns',
      status: 'pass',
      severity: 'none',
      title: 'CAA Records Configured',
      evidence: dnsReport.caaRecord.records.join('; '),
      whyItMatters:
        'CAA records restrict which certificate authorities are allowed to issue SSL certificates for this domain, preventing rogue issuance.',
      source: 'Cloudflare CAA Query',
    });
  }

  // ----------------------------------------------------------------
  // Deterministic Scoring & Verdict Calculation
  // ----------------------------------------------------------------

  let score = 100;
  let hasThreat = false;
  let hasConcern = false;

  for (const f of findings) {
    if (f.status === 'threat') {
      hasThreat = true;
      if (f.severity === 'critical') score -= 50;
      else if (f.severity === 'high') score -= 25;
      else score -= 15;
    } else if (f.status === 'concern') {
      hasConcern = true;
      if (f.severity === 'medium') score -= 8;
      else if (f.severity === 'low') score -= 4;
      else score -= 2;
    }
  }

  // Minimum and maximum bounds
  score = Math.max(10, Math.min(100, Math.round(score)));

  let verdict: SafetyVerdict;
  let verdictTitle = '';
  let verdictSummary = '';

  if (hasThreat) {
    verdict = 'known_threat';
    verdictTitle = 'Security Threat Detected';
    verdictSummary =
      'High-risk security findings or active threat feed listings were detected. Visiting this site or entering sensitive personal information is strongly discouraged.';
  } else if (hasConcern || score < 80 || !isHttps) {
    verdict = 'potential_concerns';
    verdictTitle = 'Potential Concerns Detected';
    verdictSummary =
      'No confirmed malware was reported in active threat feeds, but configuration weaknesses or suspicious structural indicators were found. Exercise caution.';
  } else {
    verdict = 'no_known_threats';
    verdictTitle = 'No Known Threats Detected';
    verdictSummary =
      'No active malware, phishing listings, or dangerous security misconfigurations were detected in the queried databases and technical checks. As always, practice normal online caution.';
  }

  // Count stats
  const stats = {
    passed: findings.filter((f) => f.status === 'pass').length,
    concerns: findings.filter((f) => f.status === 'concern').length,
    threats: findings.filter((f) => f.status === 'threat').length,
    unavailable: findings.filter((f) => f.status === 'unavailable').length,
    total: findings.length,
  };

  const ratingLabel: 'Low Risk' | 'Moderate Risk' | 'High Risk' | 'Inconclusive' =
    verdict === 'known_threat'
      ? 'High Risk'
      : verdict === 'potential_concerns'
        ? 'Moderate Risk'
        : 'Low Risk';

  return {
    verdict,
    verdictTitle,
    verdictSummary,
    safetyScore: score,
    ratingLabel,
    scannedHost: anatomy.hostname,
    scannedAt: new Date().toISOString(),
    stats,
    threatIntelligence: {
      sources: threatSources,
      cleanCount: threatSources.filter((s) => s.checked && !s.listed).length,
      threatCount: threatSources.filter((s) => s.checked && s.listed).length,
      unavailableCount: threatSources.filter((s) => !s.checked).length,
    },
    connectionSecurity,
    securityHeaders: secHeaders,
    redirectAnalysis: redirects,
    urlAnatomy: anatomy,
    dnsInfrastructure: dnsReport,
    findings,
  };
}
