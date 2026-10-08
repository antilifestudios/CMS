/**
 * Bot-protection identification — pure functions, no network.
 * Workers-runtime compatible.
 *
 * When the pipeline hits a bot-protection / challenge response it must
 * NOT run normal technology detection against the challenge HTML as if
 * it were the site's real page. This module:
 *  1. decides whether a response IS a challenge (isChallengeResponse),
 *  2. identifies the protection provider from strong evidence only
 *     (identifyProtection — headers/cookies/challenge scripts first,
 *     body markers as corroboration, never a single generic word),
 *  3. builds the bot_protected result payload (buildBotProtection),
 *  4. guards multi-page scans against 200-status challenge pages
 *     (selectScanHtml).
 */

export interface ProtectionProvider {
  name: string;
  /** 0–100, capped at 98 — evidence supports, never proves absolutely. */
  confidence: number;
  evidence: string[];
}

export interface BotProtectionInfo {
  status: 'bot_protected';
  httpStatus: number;
  provider: ProtectionProvider | null;
  /** Curated subset of response headers (server, protection markers). */
  responseHeaders: Record<string, string>;
  limitations: string[];
}

// ----------------------------------------------------------------
// Challenge detection (moved here from pipeline.ts so every scanner
// shares one definition — same semantics as before).
// ----------------------------------------------------------------

const CHALLENGE_MARKERS =
  /challenge|captcha|security check|ddos protection|just a moment|verify you are human|access denied|request blocked|perimeterx|datadome|kasada|shape\.sh|incapsula/i;

/**
 * A response is a bot-protection/challenge response when its body carries
 * challenge markers (WAFs sometimes answer 200) or its status is an
 * access-control status without readable content.
 */
export function isChallengeResponse(status: number, html: string): boolean {
  const sample = html.slice(0, 8000);
  // Challenge copy on any status (some WAFs answer 200) means a block.
  if (CHALLENGE_MARKERS.test(sample)) return true;
  // 429 is always rate-limiting; 403/503 without readable content are blocks.
  if (status === 429) return true;
  if (status === 403 || status === 503 || status === 401 || status === 407) return true;
  return false;
}

/**
 * Multi-page scanner guard: a challenge page served with status 200 must
 * not be scanned as normal HTML. Returns '' for challenge responses so
 * only headers/cookies feed detection.
 */
export function selectScanHtml(status: number, html: string): string {
  return isChallengeResponse(status, html) ? '' : html;
}

// ----------------------------------------------------------------
// Provider signatures
// ----------------------------------------------------------------

type Ctx = { status: number; headers: Record<string, string>; cookies: string[]; html: string };

interface Rule {
  /** 'strong': provider-specific header/cookie/script — can identify alone. */
  kind: 'strong' | 'supporting';
  /** Human-readable evidence label (no raw values, no PII). */
  label: string;
  test: (ctx: Ctx) => boolean;
}

interface ProviderSpec {
  id: string;
  name: string;
  rules: Rule[];
}

const header = (name: string) => (ctx: Ctx) => ctx.headers[name] ?? '';
const hasHeader = (name: string, rx: RegExp): Rule['test'] => (ctx) => rx.test(header(name)(ctx));
const hasCookie = (rx: RegExp): Rule['test'] => (ctx) => ctx.cookies.some((c) => rx.test(c));
const hasBody = (rx: RegExp): Rule['test'] => (ctx) => rx.test(ctx.html.slice(0, 20000));

const PROVIDERS: ProviderSpec[] = [
  {
    id: 'cloudflare',
    name: 'Cloudflare',
    rules: [
      { kind: 'strong', label: 'Server: cloudflare', test: hasHeader('server', /^cloudflare$/i) },
      { kind: 'strong', label: 'CF-Ray response header', test: (c) => !!header('cf-ray')(c) },
      { kind: 'strong', label: 'cf-mitigated: challenge header', test: (c) => !!header('cf-mitigated')(c) },
      { kind: 'strong', label: '__cf_bm bot-manager cookie', test: hasCookie(/^__cf_bm$/i) },
      { kind: 'strong', label: 'cf_clearance clearance cookie', test: hasCookie(/^cf_clearance$/i) },
      { kind: 'strong', label: 'Cloudflare challenge script', test: hasBody(/challenges\.cloudflare\.com|cdn-cgi\/challenge-platform|cf-challenge/) },
      { kind: 'supporting', label: 'Cloudflare challenge markers', test: hasBody(/just a moment|attention required.*cloudflare|verifying you are human.*cloudflare|cf-please-wait/i) },
      { kind: 'supporting', label: 'Turnstile widget on challenge page', test: hasBody(/cf-turnstile|challenges\.cloudflare\.com\/turnstile/) },
    ],
  },
  {
    id: 'cloudflare-turnstile',
    name: 'Cloudflare Turnstile',
    rules: [
      { kind: 'strong', label: 'Turnstile API script on challenge page', test: hasBody(/challenges\.cloudflare\.com\/turnstile\/v0\/api\.js/) },
      { kind: 'strong', label: 'Turnstile widget with sitekey', test: hasBody(/class\s*=\s*["'][^"']*cf-turnstile[^"']*["'][^>]*data-sitekey/) },
    ],
  },
  {
    id: 'akamai',
    name: 'Akamai',
    rules: [
      { kind: 'strong', label: 'Server: AkamaiGHost', test: hasHeader('server', /akamai/i) },
      { kind: 'strong', label: 'ak_bmsc Bot Manager cookie', test: hasCookie(/^ak_bmsc$/i) },
      { kind: 'strong', label: '_abck sensor cookie', test: hasCookie(/^_abck$/i) },
      { kind: 'strong', label: 'bm_sv challenge cookie', test: hasCookie(/^bm_sv$/i) },
      { kind: 'supporting', label: 'Akamai reference error page', test: hasBody(/akamai.*reference|reference.*akamai|edge[sS]uite|AkamaiGHost/i) },
    ],
  },
  {
    id: 'imperva',
    name: 'Imperva',
    rules: [
      { kind: 'strong', label: 'incap_ses_ session cookie', test: hasCookie(/^incap_ses_/i) },
      { kind: 'strong', label: 'visid_incap visitor cookie', test: hasCookie(/^visid_incap$/i) },
      { kind: 'strong', label: 'X-Iinfo header', test: (c) => !!header('x-iinfo')(c) },
      { kind: 'strong', label: 'X-CDN: Imperva header', test: hasHeader('x-cdn', /imperva/i) },
      { kind: 'supporting', label: 'Incapsula challenge markers', test: hasBody(/incapsula|imperva.*(block|challenge)|request unsuccessful/i) },
    ],
  },
  {
    id: 'datadome',
    name: 'DataDome',
    rules: [
      { kind: 'strong', label: 'datadome device cookie', test: hasCookie(/^datadome$/i) },
      { kind: 'strong', label: 'X-dd-b challenge header', test: (c) => !!header('x-dd-b')(c) },
      { kind: 'strong', label: 'DataDome challenge script', test: hasBody(/captcha\.datadome\.co|geo\.datadome\.co|js\.datadome\.co/) },
      { kind: 'supporting', label: 'DataDome challenge markers', test: hasBody(/datadome|geo-edge.*captcha/i) },
    ],
  },
  {
    id: 'perimeterx',
    name: 'PerimeterX / HUMAN',
    rules: [
      { kind: 'strong', label: 'px3 Bot Defender cookie', test: hasCookie(/^px3$/i) },
      { kind: 'strong', label: '_px3 fingerprint cookie', test: hasCookie(/^_px3$/i) },
      { kind: 'strong', label: '_pxvid visitor cookie', test: hasCookie(/^_pxvid$/i) },
      { kind: 'strong', label: 'PerimeterX challenge script', test: hasBody(/px-captcha|perimeterx.*captcha|collector\.px-cdn\.net/) },
      { kind: 'supporting', label: 'PerimeterX challenge markers', test: hasBody(/perimeterx|human.*verify you are human.*press.*hold/i) },
    ],
  },
  {
    id: 'aws-waf',
    name: 'AWS WAF',
    rules: [
      { kind: 'strong', label: 'aws-waf-token cookie', test: hasCookie(/^aws-waf-token$/i) },
      { kind: 'strong', label: 'AWS WAF challenge script', test: hasBody(/aws-waf-token|awswaf\.js/) },
      { kind: 'supporting', label: 'AWS request ID with block page', test: (c) => !!header('x-amzn-requestid')(c) && /request blocked|access denied|forbidden/i.test(c.html.slice(0, 8000)) },
    ],
  },
  {
    id: 'fastly',
    name: 'Fastly',
    rules: [
      { kind: 'strong', label: 'Server: Fastly', test: hasHeader('server', /^fastly$/i) },
      { kind: 'strong', label: 'X-Served-By cache header', test: (c) => /^cache-/.test(header('x-served-by')(c)) },
      { kind: 'supporting', label: 'Fastly error reference', test: hasBody(/fastly.*error|generated by varnish.*fastly/i) },
    ],
  },
  {
    id: 'recaptcha',
    name: 'Google reCAPTCHA',
    rules: [
      { kind: 'strong', label: 'reCAPTCHA challenge script', test: hasBody(/google\.com\/recaptcha\/(api|enterprise)\.js|recaptcha\.net\/recaptcha\/(api|enterprise)\.js/) },
      { kind: 'supporting', label: 'reCAPTCHA widget on block page', test: hasBody(/g-recaptcha\s+data-sitekey|grecaptcha\.execute/) },
    ],
  },
  {
    id: 'hcaptcha',
    name: 'hCaptcha',
    rules: [
      { kind: 'strong', label: 'hCaptcha challenge script', test: hasBody(/js\.hcaptcha\.com\/1\.js/) },
      { kind: 'supporting', label: 'hCaptcha widget on block page', test: hasBody(/h-captcha\s+data-sitekey|hcaptcha\.execute/) },
    ],
  },
];

/** Minimum score (0–100) to name a provider. */
const IDENTIFY_THRESHOLD = 40;

function scoreSpec(spec: ProviderSpec, ctx: Ctx): { score: number; strong: number; evidence: string[] } {
  let total = 0;
  let strong = 0;
  const evidence: string[] = [];
  for (const rule of spec.rules) {
    let hit = false;
    try {
      hit = rule.test(ctx);
    } catch {
      hit = false;
    }
    if (!hit) continue;
    // Saturating add with diminishing returns — duplicated markers
    // from one fingerprint never inflate the score.
    const w = rule.kind === 'strong' ? 55 : 25;
    total = Math.min(100, total + Math.round(w * (1 - total / 100)));
    if (rule.kind === 'strong') strong += 1;
    evidence.push(rule.label);
  }
  return { score: total, strong, evidence };
}

/**
 * Identify the protection provider from response signals.
 * Returns null when evidence is insufficient — a single generic word
 * (e.g. "challenge" in body text) never identifies a provider; at
 * least one provider-specific (strong) signal is required.
 */
export function identifyProtection(
  status: number,
  headers: Record<string, string>,
  cookies: string[],
  html: string
): ProtectionProvider | null {
  const normalized: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) normalized[k.toLowerCase()] = v;
  const ctx: Ctx = { status, headers: normalized, cookies, html };

  let best: { spec: ProviderSpec; score: number; evidence: string[] } | null = null;
  for (const spec of PROVIDERS) {
    const { score, strong, evidence } = scoreSpec(spec, ctx);
    if (score < IDENTIFY_THRESHOLD || strong < 1) continue;
    if (!best || score > best.score) best = { spec, score, evidence };
  }
  if (!best) return null;
  return {
    name: best.spec.name,
    // Evidence supports, never proves absolutely.
    confidence: Math.min(98, best.score) / 100,
    evidence: best.evidence,
  };
}

// ----------------------------------------------------------------
// Result payload
// ----------------------------------------------------------------

const RELEVANT_HEADER_RX =
  /^(server|cf-ray|cf-mitigated|cf-cache-status|retry-after|x-iinfo|x-cdn|x-served-by|x-amzn-requestid|x-dd-b|x-px-.*|x-akamai-.*|content-type)$/i;

/** Curated subset of response headers — protection markers, no cookies. */
export function pickRelevantHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (RELEVANT_HEADER_RX.test(k)) out[k.toLowerCase()] = v.slice(0, 200);
  }
  return out;
}

/**
 * Build the bot_protected payload. The challenge HTML is used ONLY for
 * provider identification — never for technology detection.
 */
export function buildBotProtection(
  httpStatus: number,
  headers: Record<string, string>,
  cookies: string[],
  challengeHtml: string
): BotProtectionInfo {
  const provider = identifyProtection(httpStatus, headers, cookies, challengeHtml);
  return {
    status: 'bot_protected',
    httpStatus,
    provider,
    responseHeaders: pickRelevantHeaders(headers),
    limitations: [
      "The target website's normal HTML could not be retrieved.",
      'Technology results below come from response headers and cookies only — no page scripts, embeds, or consent tools could be inspected.',
    ],
  };
}
