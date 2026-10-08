/**
 * Security & Privacy signatures — the SINGLE source of truth for the
 * /security-privacy-detector (v1: exactly 26 technologies).
 *
 * Adding a technology NEVER means touching detection logic:
 *   1. Append one entry below (id, name, category, website, evidence[]).
 *   2. Add fixtures in tests/security-privacy-detector.test.ts.
 *   3. Done — the detector, API, and UI pick it up automatically.
 *
 * Evidence types and weights (spec):
 * - script-host / network-host (vendor domain actually loaded): 0.90
 * - runtime-global (rendered pass only, window globals):        0.85
 * - sdk-init (init call or DSN/key in inline or bundled JS):    0.80
 * - dom (characteristic element id/class):                      0.65
 * - cookie-storage (vendor cookie or storage key):               0.60
 * - iframe (YouTube, Vimeo, Google Maps embeds):                 0.90
 * - Generic string mentions in visible text or <a href>: IGNORED
 *   (weight 0 — never add such a pattern here).
 *
 * Confidence (noisy-OR over distinct evidence TYPES, not matches):
 *   confidence = 1 - Π(1 - weight_i)
 *   High >= 0.85 · Medium 0.60–0.84 · Low 0.35–0.59 · < 0.35 not reported.
 *
 * Workers-runtime compatible: plain data, no Node APIs.
 */

export type SecurityPrivacyCategory = 'privacy' | 'security' | 'other';

export type SecurityPrivacyEvidenceType =
  | 'script-host'
  | 'network-host'
  | 'runtime-global'
  | 'sdk-init'
  | 'dom'
  | 'cookie-storage'
  | 'iframe';

export interface SecurityPrivacyEvidenceRule {
  type: SecurityPrivacyEvidenceType;
  /** Regex source (case-insensitive). Matched against the channel for `type` — never against visible page text. */
  pattern: string;
  /** 0–1 contribution weight (see header). */
  weight: number;
  /** Human-readable "why" line shown in the UI. */
  description: string;
  /**
   * Where this rule may match. Defaults per type:
   * script-host/network-host/iframe → resource URLs + bundled JS + headers;
   * sdk-init/runtime-global → inline + bundled JS (+ globals when rendered);
   * dom → ids/classes; cookie-storage → cookies/storage keys.
   * `header-only` marks rules that are weak when seen ONLY in CSP/comments.
   */
  weakWhenHeaderOnly?: boolean;
}

export interface SecurityPrivacySignature {
  id: string;
  name: string;
  category: SecurityPrivacyCategory;
  website: string;
  evidence: SecurityPrivacyEvidenceRule[];
  /** Optional variant hint, e.g. how to tell reCAPTCHA v2 vs v3 vs Enterprise. */
  variantNote?: string;
}

/** Strong evidence types: at least one is required for High confidence. */
export const STRONG_EVIDENCE_TYPES: ReadonlySet<SecurityPrivacyEvidenceType> = new Set([
  'script-host',
  'network-host',
  'runtime-global',
  'sdk-init',
  'iframe',
]);

export const SECURITY_PRIVACY_SIGNATURES: SecurityPrivacySignature[] = [
  // ----------------------------------------------------------------
  // 01 Privacy / Consent (11)
  // ----------------------------------------------------------------
  {
    id: 'onetrust',
    name: 'OneTrust',
    category: 'privacy',
    website: 'https://www.onetrust.com',
    evidence: [
      { type: 'script-host', pattern: 'cdn\\.cookielaw\\.org', weight: 0.9, description: 'OneTrust SDK host loaded (cdn.cookielaw.org)' },
      { type: 'script-host', pattern: 'otSDKStub\\.js', weight: 0.9, description: 'OneTrust stub SDK (otSDKStub.js) loaded' },
      { type: 'sdk-init', pattern: 'OptanonWrapper|Optanon\\.Wrapper|OnetrustActiveGroups|OTBanner', weight: 0.8, description: 'OneTrust init call detected' },
      { type: 'runtime-global', pattern: '\\bOneTrust\\b|\\bOptanon\\b', weight: 0.85, description: 'OneTrust JS API present (OneTrust / Optanon)' },
      { type: 'cookie-storage', pattern: '\\bOptanonConsent\\b|\\bOptanonAlertBoxClosed\\b|\\bOTConsent\\b', weight: 0.6, description: 'OneTrust consent cookie' },
      { type: 'dom', pattern: 'onetrust-banner-sdk|onetrust-consent-sdk', weight: 0.65, description: 'OneTrust banner DOM element' },
    ],
  },
  {
    id: 'cookiebot',
    name: 'Cookiebot',
    category: 'privacy',
    website: 'https://cookiebot.com',
    evidence: [
      { type: 'script-host', pattern: 'consent\\.cookiebot\\.com|consentcdn\\.cookiebot\\.com', weight: 0.9, description: 'Cookiebot SDK host loaded' },
      { type: 'sdk-init', pattern: 'Cookiebot\\.(consent|show|renew)|data-cbid\\s*=|cbid\\s*=|CookieDeclaration', weight: 0.8, description: 'Cookiebot init / config detected' },
      { type: 'runtime-global', pattern: '\\bCookiebot\\b', weight: 0.85, description: 'Cookiebot JS API present' },
      { type: 'cookie-storage', pattern: '\\bCookieConsent\\b|\\bCookieInformationConsent\\b', weight: 0.6, description: 'Cookiebot consent cookie' },
      { type: 'dom', pattern: 'CybotCookiebotDialog|CookieDeclaration', weight: 0.65, description: 'Cookiebot dialog DOM element' },
    ],
  },
  {
    id: 'usercentrics',
    name: 'Usercentrics',
    category: 'privacy',
    website: 'https://usercentrics.com',
    evidence: [
      { type: 'script-host', pattern: 'app\\.usercentrics\\.eu|web\\.cmp\\.usercentrics\\.eu|usercentrics\\.eu/bundle', weight: 0.9, description: 'Usercentrics SDK host loaded' },
      { type: 'sdk-init', pattern: 'UC_UI\\.(showSecondLayer|showFirstLayer)|__ucCmp|data-settings-id[^>]*(usercentrics|UC_UI)', weight: 0.8, description: 'Usercentrics init detected' },
      { type: 'runtime-global', pattern: '\\bUC_UI\\b|\\busercentrics\\b', weight: 0.85, description: 'Usercentrics JS API present' },
      { type: 'cookie-storage', pattern: '\\buc_settings\\b|\\buc_consent\\b|\\busercentrics_consent\\b', weight: 0.6, description: 'Usercentrics storage key' },
      { type: 'dom', pattern: 'usercentrics-root', weight: 0.65, description: 'Usercentrics root DOM element' },
    ],
  },
  {
    id: 'trustarc',
    name: 'TrustArc',
    category: 'privacy',
    website: 'https://trustarc.com',
    evidence: [
      { type: 'script-host', pattern: 'consent\\.trustarc\\.com|truste\\.com', weight: 0.9, description: 'TrustArc SDK host loaded' },
      { type: 'sdk-init', pattern: 'TrustArc\\.cm\\.api|truste\\.js|jsDo\\.jsp|privacy\\.trustarc\\.com', weight: 0.8, description: 'TrustArc init detected' },
      { type: 'runtime-global', pattern: '\\btruste\\b', weight: 0.85, description: 'TrustArc JS API present' },
      { type: 'cookie-storage', pattern: '\\bnotice_preferences\\b|\\bnotice_gdpr_prefs\\b|\\bTAconsentID\\b|\\bnotice_behavior\\b', weight: 0.6, description: 'TrustArc consent cookie' },
      { type: 'dom', pattern: 'truste-consent-track', weight: 0.65, description: 'TrustArc consent DOM element' },
    ],
  },
  {
    id: 'iubenda',
    name: 'iubenda',
    category: 'privacy',
    website: 'https://www.iubenda.com',
    evidence: [
      { type: 'script-host', pattern: 'cdn\\.iubenda\\.com/cs/iubenda_cs\\.js|cdn\\.iubenda\\.com', weight: 0.9, description: 'iubenda SDK host loaded' },
      { type: 'sdk-init', pattern: '_iub\\.cs\\.consent|_iub\\.csConfiguration|iubenda\\.init|iubenda_cs\\.version', weight: 0.8, description: 'iubenda init detected' },
      { type: 'runtime-global', pattern: '\\b_iub\\b', weight: 0.85, description: 'iubenda JS API present (_iub)' },
      { type: 'cookie-storage', pattern: '_iub_cs-\\d+', weight: 0.6, description: 'iubenda consent cookie' },
      { type: 'dom', pattern: 'iubenda-cs-container', weight: 0.65, description: 'iubenda banner DOM element' },
    ],
  },
  {
    id: 'complianz',
    name: 'Complianz',
    category: 'privacy',
    website: 'https://complianz.io',
    evidence: [
      { type: 'script-host', pattern: '/wp-content/plugins/complianz-gdpr/', weight: 0.9, description: 'Complianz plugin path loaded' },
      { type: 'sdk-init', pattern: 'cmplz_set_cookie|cmplz_get_cookie|COMPLIANZ\\s*=|complianz\\.min\\.js', weight: 0.8, description: 'Complianz init detected' },
      { type: 'runtime-global', pattern: '\\bcomplianz\\b|\\bcmplz_', weight: 0.85, description: 'Complianz JS API present' },
      { type: 'cookie-storage', pattern: '\\bcmplz_[a-z_]+', weight: 0.6, description: 'Complianz consent cookie' },
      { type: 'dom', pattern: 'cmplz-cookiebanner-container', weight: 0.65, description: 'Complianz banner DOM element' },
    ],
  },
  {
    id: 'didomi',
    name: 'Didomi',
    category: 'privacy',
    website: 'https://www.didomi.io',
    evidence: [
      { type: 'script-host', pattern: 'sdk\\.privacy-center\\.org|sdk\\.didomi\\.io|cdn\\.privacy-center\\.org', weight: 0.9, description: 'Didomi SDK host loaded' },
      { type: 'sdk-init', pattern: 'Didomi\\.(notice|getUserConsentStatus)|didomiConfig|didomiOnReady|api\\.didomi\\.io/consent', weight: 0.8, description: 'Didomi init detected' },
      { type: 'runtime-global', pattern: '\\bDidomi\\b|\\bdidomiOnReady\\b', weight: 0.85, description: 'Didomi JS API present' },
      { type: 'cookie-storage', pattern: '\\bdidomi_token\\b|\\beuconsent-v2\\b', weight: 0.6, description: 'Didomi consent cookie' },
      { type: 'dom', pattern: 'didomi-host', weight: 0.65, description: 'Didomi host DOM element' },
    ],
  },
  {
    id: 'osano',
    name: 'Osano',
    category: 'privacy',
    website: 'https://www.osano.com',
    evidence: [
      { type: 'script-host', pattern: 'cmp\\.osano\\.com', weight: 0.9, description: 'Osano SDK host loaded' },
      { type: 'sdk-init', pattern: 'Osano\\.cm\\.(showDrawer|showDialog)|window\\.__osano|osano\\.init', weight: 0.8, description: 'Osano init detected' },
      { type: 'runtime-global', pattern: '\\bOsano\\b', weight: 0.85, description: 'Osano JS API present' },
      { type: 'cookie-storage', pattern: '\\bosano_consentmanager\\b', weight: 0.6, description: 'Osano consent cookie' },
      { type: 'dom', pattern: 'osano-cm-window', weight: 0.65, description: 'Osano banner DOM element' },
    ],
  },
  {
    id: 'cookieyes',
    name: 'CookieYes',
    category: 'privacy',
    website: 'https://www.cookieyes.com',
    evidence: [
      { type: 'script-host', pattern: 'cdn-cookieyes\\.com/client_data', weight: 0.9, description: 'CookieYes SDK host loaded' },
      { type: 'sdk-init', pattern: 'cky-consent|ckyBanner|cookieyes\\.init|app\\.cookieyes\\.com/cdn/cli\\.js', weight: 0.8, description: 'CookieYes init detected' },
      { type: 'runtime-global', pattern: '\\bgetCkyConsent\\b', weight: 0.85, description: 'CookieYes JS API present' },
      { type: 'cookie-storage', pattern: '\\bcookieyes-consent\\b|\\bcky-consent\\b|\\bcky-active-check\\b', weight: 0.6, description: 'CookieYes consent cookie' },
      { type: 'dom', pattern: 'cky-consent-container', weight: 0.65, description: 'CookieYes banner DOM element' },
    ],
  },
  {
    id: 'termly',
    name: 'Termly',
    category: 'privacy',
    website: 'https://termly.io',
    evidence: [
      { type: 'script-host', pattern: 'app\\.termly\\.io|cdn\\.termly\\.io|display\\.termly\\.io', weight: 0.9, description: 'Termly SDK host loaded (incl. resource-blocker)' },
      { type: 'sdk-init', pattern: 'termly\\.getConsentState|termly-embed|data-termly|display\\.termly\\.io/policy', weight: 0.8, description: 'Termly init detected' },
      { type: 'runtime-global', pattern: '\\bTermly\\b', weight: 0.85, description: 'Termly JS API present' },
      { type: 'dom', pattern: 'termly-code-snippet-support', weight: 0.65, description: 'Termly snippet DOM element' },
    ],
  },
  {
    id: 'quantcast-choice',
    name: 'Quantcast Choice',
    category: 'privacy',
    website: 'https://www.quantcast.com/choice',
    evidence: [
      { type: 'script-host', pattern: 'quantcast\\.mgr\\.consensu\\.org|cmp\\.quantcast\\.com|quantcast\\.com/choice', weight: 0.9, description: 'Quantcast Choice SDK host loaded' },
      { type: 'sdk-init', pattern: 'cmp\\.quantcast\\.com/choice/[\\w-]+/__tcf\\.js|quantcast\\.mgr\\.consent\\.js', weight: 0.8, description: 'Quantcast Choice init detected' },
      { type: 'dom', pattern: 'qc-cmp2-container|qc-cmp2-ui', weight: 0.65, description: 'Quantcast Choice dialog DOM element' },
      // NOTE: __tcfapi / euconsent-v2 are generic IAB TCF signals shared by
      // many CMPs — weak supporting evidence only, never enough alone.
      { type: 'sdk-init', pattern: '__tcfapi\\s*\\(', weight: 0.2, description: 'Generic TCF API call (weak — shared by many CMPs)' },
    ],
  },

  // ----------------------------------------------------------------
  // 02 Security & Monitoring (9)
  // ----------------------------------------------------------------
  {
    id: 'recaptcha',
    name: 'reCAPTCHA',
    category: 'security',
    website: 'https://www.google.com/recaptcha',
    variantNote: 'v2: checkbox widget (.g-recaptcha) · v3: api.js?render=<sitekey> + grecaptcha.execute · Enterprise: enterprise.js',
    evidence: [
      { type: 'script-host', pattern: 'google\\.com/recaptcha/(api|enterprise)\\.js|recaptcha\\.net/recaptcha/(api|enterprise)\\.js|gstatic\\.com/recaptcha', weight: 0.9, description: 'reCAPTCHA SDK host loaded' },
      { type: 'sdk-init', pattern: 'grecaptcha\\.(execute|render|ready)|google\\.com/recaptcha/(api|enterprise)\\.js\\?render=[\\w-]+|___grecaptcha_cfg', weight: 0.8, description: 'reCAPTCHA init call detected' },
      { type: 'runtime-global', pattern: '\\bgrecaptcha\\b', weight: 0.85, description: 'reCAPTCHA JS API present (grecaptcha)' },
      { type: 'dom', pattern: 'g-recaptcha|g-recaptcha-response', weight: 0.65, description: 'reCAPTCHA widget DOM element' },
    ],
  },
  {
    id: 'hcaptcha',
    name: 'hCaptcha',
    category: 'security',
    website: 'https://www.hcaptcha.com',
    evidence: [
      { type: 'script-host', pattern: 'js\\.hcaptcha\\.com|hcaptcha\\.com/1/api\\.js', weight: 0.9, description: 'hCaptcha SDK host loaded' },
      { type: 'sdk-init', pattern: 'hcaptcha\\.(execute|render|getResponse)', weight: 0.8, description: 'hCaptcha init call detected' },
      { type: 'runtime-global', pattern: '\\bhcaptcha\\b', weight: 0.85, description: 'hCaptcha JS API present' },
      { type: 'dom', pattern: 'h-captcha|h-captcha-response', weight: 0.65, description: 'hCaptcha widget DOM element' },
    ],
  },
  {
    id: 'sentry',
    name: 'Sentry',
    category: 'security',
    website: 'https://sentry.io',
    evidence: [
      { type: 'script-host', pattern: 'browser\\.sentry-cdn\\.com|js\\.sentry-cdn\\.com', weight: 0.9, description: 'Sentry browser SDK host loaded' },
      { type: 'network-host', pattern: '[\\w-]+\\.ingest\\.sentry\\.io|\\.sentry\\.io/api/\\d+/envelope', weight: 0.9, description: 'Sentry ingest endpoint referenced' },
      { type: 'sdk-init', pattern: 'Sentry\\.init\\(|dsn\\s*:', weight: 0.8, description: 'Sentry DSN / init detected' },
      { type: 'runtime-global', pattern: '\\bSentry\\b|__SENTRY__', weight: 0.85, description: 'Sentry JS API present' },
    ],
  },
  {
    id: 'cloudflare-turnstile',
    name: 'Cloudflare Turnstile',
    category: 'security',
    website: 'https://www.cloudflare.com/products/turnstile',
    evidence: [
      // Do NOT confuse with general Cloudflare CDN / bot-challenge pages.
      { type: 'script-host', pattern: 'challenges\\.cloudflare\\.com/turnstile/v0/api\\.js', weight: 0.9, description: 'Turnstile SDK host loaded' },
      { type: 'sdk-init', pattern: 'turnstile\\.(render|execute|reset)', weight: 0.8, description: 'Turnstile init call detected' },
      { type: 'runtime-global', pattern: '\\bturnstile\\b', weight: 0.85, description: 'Turnstile JS API present' },
      { type: 'dom', pattern: 'cf-turnstile|cf-turnstile-response', weight: 0.65, description: 'Turnstile widget DOM element' },
    ],
  },
  {
    id: 'fingerprint',
    name: 'Fingerprint',
    category: 'security',
    website: 'https://fingerprint.com',
    variantNote: 'Open-source vs Pro distinguished by host (openfpcdn.io = OSS, fpjs.io / fpcdn.io = Pro) when visible.',
    evidence: [
      { type: 'script-host', pattern: 'fpjs\\.io|fpcdn\\.io|openfpcdn\\.io|@fingerprintjs', weight: 0.9, description: 'Fingerprint SDK host loaded' },
      { type: 'sdk-init', pattern: 'FingerprintJS\\.load\\(|@fingerprintjs/fingerprintjs', weight: 0.8, description: 'FingerprintJS init detected' },
      { type: 'runtime-global', pattern: '\\bFingerprintJS\\b|\\bFingerprint\\b', weight: 0.85, description: 'Fingerprint JS API present' },
    ],
  },
  {
    id: 'datadog',
    name: 'Datadog',
    category: 'security',
    website: 'https://www.datadoghq.com',
    evidence: [
      { type: 'script-host', pattern: 'datadoghq-browser-agent\\.com|browser-intake-datadoghq\\.com', weight: 0.9, description: 'Datadog browser SDK host loaded' },
      { type: 'sdk-init', pattern: 'DD_RUM\\.init\\(|DD_LOGS\\.init\\(|@datadog/browser-(rum|logs)', weight: 0.8, description: 'Datadog RUM/Logs init detected' },
      { type: 'runtime-global', pattern: '\\bDD_RUM\\b|\\bDD_LOGS\\b', weight: 0.85, description: 'Datadog JS API present' },
      { type: 'cookie-storage', pattern: '\\b_dd_s\\b', weight: 0.6, description: 'Datadog session cookie' },
    ],
  },
  {
    id: 'new-relic',
    name: 'New Relic',
    category: 'security',
    website: 'https://newrelic.com',
    evidence: [
      { type: 'script-host', pattern: 'js-agent\\.newrelic\\.com|bam\\.nr-data\\.net', weight: 0.9, description: 'New Relic agent host loaded' },
      { type: 'sdk-init', pattern: 'NREUM\\.(init|info|loader_config)|newrelic\\.(addPageAction|setCustomAttribute)', weight: 0.8, description: 'New Relic init detected' },
      { type: 'runtime-global', pattern: '\\bnewrelic\\b|\\bNREUM\\b', weight: 0.85, description: 'New Relic JS API present' },
    ],
  },
  {
    id: 'bugsnag',
    name: 'Bugsnag',
    category: 'security',
    website: 'https://www.bugsnag.com',
    evidence: [
      { type: 'script-host', pattern: 'js\\.bugsnag\\.com|notify\\.bugsnag\\.com|sessions\\.bugsnag\\.com|d2wy8f7a9ursnm\\.cloudfront\\.net', weight: 0.9, description: 'Bugsnag SDK/endpoint host loaded' },
      { type: 'sdk-init', pattern: 'Bugsnag\\.(start|notify|load)', weight: 0.8, description: 'Bugsnag init detected' },
      { type: 'runtime-global', pattern: '\\bBugsnag\\b', weight: 0.85, description: 'Bugsnag JS API present' },
    ],
  },
  {
    id: 'rollbar',
    name: 'Rollbar',
    category: 'security',
    website: 'https://rollbar.com',
    evidence: [
      { type: 'script-host', pattern: 'cdn\\.rollbar\\.com|api\\.rollbar\\.com', weight: 0.9, description: 'Rollbar SDK/API host loaded' },
      { type: 'sdk-init', pattern: 'Rollbar\\.(configure|error|init)|_rollbarConfig\\s*=', weight: 0.8, description: 'Rollbar init detected' },
      { type: 'runtime-global', pattern: '\\bRollbar\\b|\\b_rollbarConfig\\b', weight: 0.85, description: 'Rollbar JS API present' },
    ],
  },

  // ----------------------------------------------------------------
  // 03 Other (6) — controlled fallback: ONLY with identifiable
  // integration evidence, never a weak guess.
  // ----------------------------------------------------------------
  {
    id: 'cloudinary',
    name: 'Cloudinary',
    category: 'other',
    website: 'https://cloudinary.com',
    evidence: [
      { type: 'script-host', pattern: 'res\\.cloudinary\\.com|upload\\.cloudinary\\.com|widget\\.cloudinary\\.com', weight: 0.9, description: 'Cloudinary host in image/video/srcset/source' },
      { type: 'sdk-init', pattern: 'cloudinary\\.(createUploadWidget|videoPlayer|Cloudinary)|cloudinary-core|cloudinary-video-player', weight: 0.8, description: 'Cloudinary SDK init detected' },
    ],
  },
  {
    id: 'algolia',
    name: 'Algolia',
    category: 'other',
    website: 'https://www.algolia.com',
    evidence: [
      { type: 'script-host', pattern: 'cdn\\.algolia\\.com|cdn\\.algolianet\\.com|cdn\\.jsdelivr\\.net/npm/(algoliasearch|instantsearch)|unpkg\\.com/(algoliasearch|instantsearch)', weight: 0.9, description: 'Algolia SDK host loaded' },
      { type: 'network-host', pattern: '[\\w-]+\\.algolia\\.net|[\\w-]+\\.algolianet\\.com|[\\w-]+-dsn\\.algolia\\.net|algolianet\\.com', weight: 0.9, description: 'Algolia API endpoint referenced' },
      { type: 'sdk-init', pattern: 'algoliasearch\\s*\\(|docsearch\\s*\\(\\s*\\{[^}]*apiKey|instantsearch\\s*\\(\\s*\\{', weight: 0.8, description: 'Algolia search init detected' },
      { type: 'dom', pattern: 'ais-[\\w-]+', weight: 0.65, description: 'InstantSearch DOM class detected' },
    ],
  },
  {
    id: 'google-maps',
    name: 'Google Maps',
    category: 'other',
    website: 'https://maps.google.com',
    evidence: [
      { type: 'script-host', pattern: 'maps\\.googleapis\\.com/maps/api/js|maps\\.google\\.com/maps/api/js', weight: 0.9, description: 'Google Maps JS API loaded' },
      { type: 'iframe', pattern: 'google\\.com/maps/embed', weight: 0.9, description: 'Google Maps embed iframe' },
      { type: 'sdk-init', pattern: 'new\\s+google\\.maps\\.(Map|Marker|InfoWindow|places\\.Autocomplete)|google\\.maps\\.MapTypeId', weight: 0.8, description: 'Google Maps init detected' },
      { type: 'runtime-global', pattern: 'google\\.maps', weight: 0.85, description: 'google.maps API present' },
    ],
  },
  {
    id: 'youtube',
    name: 'YouTube',
    category: 'other',
    website: 'https://www.youtube.com',
    evidence: [
      // Plain links to youtube.com/watch are NOT integration evidence.
      { type: 'iframe', pattern: '(www\\.)?youtube\\.com/embed/[\\w-]{6,}|youtube-nocookie\\.com/embed/[\\w-]{6,}', weight: 0.9, description: 'YouTube embed iframe' },
      { type: 'script-host', pattern: 'youtube\\.com/iframe_api|www\\.youtube\\.com/s/player/', weight: 0.9, description: 'YouTube player SDK loaded' },
      { type: 'sdk-init', pattern: 'onYouTubeIframeAPIReady|YT\\.Player\\(', weight: 0.8, description: 'YouTube player API call detected' },
      { type: 'runtime-global', pattern: '\\bYT\\b', weight: 0.85, description: 'YouTube JS API present (YT)' },
    ],
  },
  {
    id: 'vimeo',
    name: 'Vimeo',
    category: 'other',
    website: 'https://vimeo.com',
    evidence: [
      { type: 'iframe', pattern: 'player\\.vimeo\\.com/video/\\d+', weight: 0.9, description: 'Vimeo embed iframe' },
      { type: 'script-host', pattern: 'player\\.vimeo\\.com/api/player\\.js|vimeocdn\\.com', weight: 0.9, description: 'Vimeo player SDK/assets loaded' },
      { type: 'sdk-init', pattern: 'new\\s+Vimeo\\.Player\\(|Vimeo\\.Player\\(', weight: 0.8, description: 'Vimeo player API call detected' },
    ],
  },
  {
    id: 'font-awesome',
    name: 'Font Awesome',
    category: 'other',
    website: 'https://fontawesome.com',
    evidence: [
      { type: 'script-host', pattern: 'kit\\.fontawesome\\.com|use\\.fontawesome\\.com|cdnjs.*font-awesome|@fortawesome', weight: 0.9, description: 'Font Awesome kit/CDN/bundle loaded' },
      // A lone generic "fa" class is NOT enough — require style-qualified classes.
      { type: 'dom', pattern: 'fa-(solid|regular|brands|sharp)\\s+fa-[\\w-]+', weight: 0.65, description: 'Font Awesome icon markup detected' },
    ],
  },
];

export const SECURITY_PRIVACY_IDS = SECURITY_PRIVACY_SIGNATURES.map((s) => s.id);

export function getSecurityPrivacySignature(id: string): SecurityPrivacySignature | undefined {
  return SECURITY_PRIVACY_SIGNATURES.find((s) => s.id === id);
}
