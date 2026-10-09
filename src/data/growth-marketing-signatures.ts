/**
 * Growth & Marketing signatures — the SINGLE source of truth for the
 * /growth-marketing-detector (v1: exactly 38 technologies).
 *
 * Adding a technology NEVER means touching detection logic:
 *   1. Append one entry below (id, name, category, website, evidence[]).
 *   2. Add fixtures in tests/growth-marketing.test.ts.
 *   3. Done — the detector, API, and UI pick it up automatically.
 *
 * Evidence types and weights (noisy-OR over distinct TYPES, not matches;
 * score computed in 0-1, then score100 = round(p*100), bands from the
 * shared confidence.ts scale: VERY HIGH >= 90, HIGH >= 75, MEDIUM >= 60,
 * LOW >= 40, below 40 not reported):
 * - script-host (vendor script/pixel host referenced):              0.90
 * - sdk-init (init call with an ID/key pattern):                    0.85
 * - via GTM container expansion (detector-added, never in this file): 0.70
 * - dom (characteristic id/class, vendor form action, data attr):   0.60
 *   (generic hooks like #card-container use 0.30 — supporting only)
 * - cookie-storage (vendor cookie in a Set-Cookie header):           0.55
 *   (JS-set cookies are invisible to a static scan)
 * - Plain <a href> links, visible text mentions, lone generic globals
 *   (dataLayer, analytics, ApplePaySession, paypal.me …): weight 0 —
 *   never add such a pattern here; the detector never scans those
 *   channels at all.
 *
 * GTM containers are scanned with script-host + sdk-init rules ONLY
 * (hosts, init strings, ids — never tag names or comments), and any
 * container hit becomes `via-gtm` evidence at 0.70.
 *
 * Workers-runtime compatible: plain data, no Node APIs.
 */

export type GrowthCategory = 'analytics' | 'advertising' | 'marketing' | 'payments' | 'chat';

export type GrowthEvidenceType =
  | 'script-host'
  | 'sdk-init'
  | 'dom'
  | 'cookie-storage'
  | 'via-gtm';

export interface GrowthEvidenceRule {
  type: Exclude<GrowthEvidenceType, 'via-gtm'>;
  /** Regex source (case-insensitive). Matched against the channel for `type` — never against visible page text or <a href>. */
  pattern: string;
  /** 0–1 contribution weight (see header). */
  weight: number;
  /** Human-readable "why" line shown in the UI. */
  description: string;
  /**
   * For multi-product vendors (Salesforce): which product this rule
   * proves. Matched products are listed in the result `subNote`.
   */
  product?: string;
  /**
   * When true the rule is weak by nature (e.g. Adobe Launch is a tag
   * manager, not proof of Adobe Analytics). If ONLY launchOnly rules
   * match, the score caps at Low.
   */
  launchOnly?: boolean;
}

export interface GrowthIdRule {
  /** Label shown next to the value, e.g. "GA4 measurement ID". */
  kind: string;
  /** Regex source with ONE capture group around the identifier. */
  pattern: string;
}

export interface GrowthSignature {
  id: string;
  name: string;
  category: GrowthCategory;
  website: string;
  evidence: GrowthEvidenceRule[];
  /** Public identifiers extracted verbatim (the exact evidence). */
  ids?: GrowthIdRule[];
  variantNote?: string;
}

/** Strong evidence types: at least one is required for High or better. */
export const GROWTH_STRONG_TYPES: ReadonlySet<GrowthEvidenceType> = new Set([
  'script-host',
  'sdk-init',
]);

export const GROWTH_MARKETING_SIGNATURES: GrowthSignature[] = [
  // ----------------------------------------------------------------
  // 01 Analytics (10)
  // ----------------------------------------------------------------
  {
    id: 'google-analytics',
    name: 'Google Analytics',
    category: 'analytics',
    website: 'https://marketingplatform.google.com/about/analytics/',
    evidence: [
      // gtag.js is shared with Google Ads — the id prefix decides, so the
      // host rule requires G- (AW- belongs to google-ads).
      { type: 'script-host', pattern: 'googletagmanager\\.com/gtag/js\\?id=G-', weight: 0.9, description: 'gtag.js loader for a GA4 property (G-…)' },
      { type: 'script-host', pattern: 'google-analytics\\.com/(analytics\\.js|ga\\.js|g/collect)', weight: 0.9, description: 'Google Analytics library loaded' },
      { type: 'sdk-init', pattern: 'gtag\\(\\s*[\'"]config[\'"]\\s*,\\s*[\'"]G-|ga\\(\\s*[\'"]create[\'"]|_gaq\\.push\\(', weight: 0.85, description: 'Google Analytics init call with tracking ID' },
      { type: 'cookie-storage', pattern: '_ga(_[A-Z0-9]+)?\\b|_gid\\b', weight: 0.55, description: 'Google Analytics cookie (_ga / _gid)' },
    ],
    ids: [
      { kind: 'GA4 measurement ID', pattern: '\\b(G-[A-Z0-9]{4,})\\b' },
      { kind: 'UA property (legacy)', pattern: '\\b(UA-\\d+-\\d+)\\b' },
    ],
    variantNote: 'G- = GA4 · AW- = Google Ads (see Google Ads) · UA- = Universal Analytics (legacy).',
  },
  {
    id: 'google-tag-manager',
    name: 'Google Tag Manager',
    category: 'analytics',
    website: 'https://marketingplatform.google.com/about/tag-manager/',
    evidence: [
      { type: 'script-host', pattern: 'googletagmanager\\.com/(gtm\\.js\\?id=GTM-|ns\\.html\\?id=GTM-)', weight: 0.9, description: 'GTM container loader referenced (gtm.js / ns.html)' },
      { type: 'sdk-init', pattern: 'google_tag_manager\\b', weight: 0.85, description: 'GTM runtime global (google_tag_manager)' },
    ],
    ids: [{ kind: 'GTM container ID', pattern: '\\b(GTM-[A-Z0-9]+)\\b' }],
    variantNote: 'A lone `dataLayer` without gtm.js / ns.html / google_tag_manager is NOT enough.',
  },
  {
    id: 'microsoft-clarity',
    name: 'Microsoft Clarity',
    category: 'analytics',
    website: 'https://clarity.microsoft.com',
    evidence: [
      { type: 'script-host', pattern: 'clarity\\.ms/tag/', weight: 0.9, description: 'Clarity tag script loaded (clarity.ms/tag/)' },
      { type: 'sdk-init', pattern: 'clarity\\(\\s*[\'"](set|identify|consent|event|upgrade)', weight: 0.85, description: 'Clarity API call with project id' },
      { type: 'cookie-storage', pattern: '_clck\\b|_clsk\\b', weight: 0.55, description: 'Clarity cookie (_clck / _clsk)' },
    ],
    ids: [{ kind: 'Clarity project ID', pattern: 'clarity\\.ms/tag/([a-z0-9]+)' }],
  },
  {
    id: 'hotjar',
    name: 'Hotjar',
    category: 'analytics',
    website: 'https://www.hotjar.com',
    evidence: [
      { type: 'script-host', pattern: 'static\\.hotjar\\.com/c/hotjar-|script\\.hotjar\\.com', weight: 0.9, description: 'Hotjar script loaded' },
      { type: 'sdk-init', pattern: 'hj\\(\\s*[\'"](trigger|identify|event|stateChange)|_hjSettings\\s*=', weight: 0.85, description: 'Hotjar init call (hj / _hjSettings)' },
      { type: 'cookie-storage', pattern: '_hjSessionUser_|_hjSession_', weight: 0.55, description: 'Hotjar session cookie' },
    ],
    ids: [{ kind: 'Hotjar site ID', pattern: 'hotjar-(\\d+)\\.js' }],
  },
  {
    id: 'matomo',
    name: 'Matomo',
    category: 'analytics',
    website: 'https://matomo.org',
    evidence: [
      // Self-hosted installs have no vendor domain — file names and _paq carry it.
      { type: 'script-host', pattern: 'matomo\\.js|piwik\\.js|matomo\\.php|[\\w.-]*matomo\\.cloud', weight: 0.9, description: 'Matomo tracker file / cloud host referenced' },
      { type: 'sdk-init', pattern: '_paq\\.push\\(', weight: 0.85, description: 'Matomo queue init (_paq.push)' },
      { type: 'cookie-storage', pattern: '_pk_id\\.|_pk_ses\\.', weight: 0.55, description: 'Matomo cookie (_pk_id / _pk_ses)' },
    ],
  },
  {
    id: 'plausible',
    name: 'Plausible',
    category: 'analytics',
    website: 'https://plausible.io',
    evidence: [
      { type: 'script-host', pattern: 'plausible\\.io/js/[\\w./-]*\\.js', weight: 0.9, description: 'Plausible script loaded (plausible.io/js/)' },
      { type: 'sdk-init', pattern: 'plausible\\(\\s*[\'"]', weight: 0.85, description: 'Plausible event call' },
      // Self-hosted/proxied installs: data-domain plus a script.js path.
      // data-domain alone is a hint (Low), the pair reaches Medium.
      { type: 'dom', pattern: 'data-domain\\s*=', weight: 0.55, description: 'Plausible data-domain attribute' },
      { type: 'script-host', pattern: '/script\\.js(\\?[^"\'\\s]*)?(["\'\\s]|$)', weight: 0.3, description: 'Proxied script.js path (supporting evidence only)' },
    ],
  },
  {
    id: 'mixpanel',
    name: 'Mixpanel',
    category: 'analytics',
    website: 'https://mixpanel.com',
    evidence: [
      { type: 'script-host', pattern: 'cdn\\.mxpnl\\.com|api(-js)?\\.mixpanel\\.com', weight: 0.9, description: 'Mixpanel CDN/API host referenced' },
      { type: 'sdk-init', pattern: 'mixpanel\\.init\\(', weight: 0.85, description: 'Mixpanel init with project token' },
      { type: 'cookie-storage', pattern: 'mp_[a-f0-9]+_mixpanel', weight: 0.55, description: 'Mixpanel cookie (mp_<token>_mixpanel)' },
    ],
    ids: [{ kind: 'Mixpanel project token', pattern: 'mixpanel\\.init\\(\\s*[\'"]([a-f0-9]{16,})[\'"]' }],
  },
  {
    id: 'posthog',
    name: 'PostHog',
    category: 'analytics',
    website: 'https://posthog.com',
    evidence: [
      { type: 'script-host', pattern: '[\\w.-]*i\\.posthog\\.com|app\\.posthog\\.com', weight: 0.9, description: 'PostHog host referenced' },
      { type: 'sdk-init', pattern: 'posthog\\.(init|capture)\\(', weight: 0.85, description: 'PostHog init/capture call' },
      { type: 'cookie-storage', pattern: 'ph_[a-z0-9]+_posthog', weight: 0.55, description: 'PostHog cookie (ph_<key>_posthog)' },
    ],
  },
  {
    id: 'segment',
    name: 'Segment',
    category: 'analytics',
    website: 'https://segment.com',
    evidence: [
      // A lone global named `analytics` is generic — require the CDN host
      // or the snippet version marker.
      { type: 'script-host', pattern: 'cdn\\.segment\\.com/analytics\\.js|api\\.segment\\.io', weight: 0.9, description: 'Segment CDN/API host referenced' },
      { type: 'sdk-init', pattern: 'analytics\\.SNIPPET_VERSION|analytics\\.load\\(', weight: 0.85, description: 'Segment snippet init marker' },
      { type: 'cookie-storage', pattern: 'ajs_anonymous_id|ajs_user_id', weight: 0.55, description: 'Segment cookie (ajs_anonymous_id / ajs_user_id)' },
    ],
    ids: [{ kind: 'Segment write key', pattern: 'cdn\\.segment\\.com/analytics\\.js/v1/([A-Za-z0-9]+)/analytics\\.min\\.js' }],
  },
  {
    id: 'adobe-analytics',
    name: 'Adobe Analytics',
    category: 'analytics',
    website: 'https://business.adobe.com/products/analytics/adobe-analytics.html',
    evidence: [
      { type: 'script-host', pattern: '[\\w.-]*\\.omtrdc\\.net|[\\w.-]*\\.2o7\\.net|AppMeasurement\\.js|s_code\\.js', weight: 0.9, description: 'Adobe Analytics endpoint/library referenced' },
      { type: 'sdk-init', pattern: 's_gi\\(|s_account\\s*=|AppMeasurement\\.getInstance', weight: 0.85, description: 'Adobe Analytics init (s_gi / s_account)' },
      { type: 'cookie-storage', pattern: 's_cc\\b|s_sq\\b|AMCV_[A-Za-z0-9_-]+', weight: 0.55, description: 'Adobe Analytics cookie (s_cc / s_sq / AMCV_)' },
      // assets.adobedtm.com / _satellite = Adobe Launch (a tag manager),
      // NOT proof of Analytics — weak, capped at Low on its own.
      { type: 'script-host', pattern: 'assets\\.adobedtm\\.com', weight: 0.4, description: 'Adobe Launch loader (tag manager — not proof of Analytics)', launchOnly: true },
      { type: 'sdk-init', pattern: '_satellite\\.|satelliteLib-', weight: 0.4, description: 'Adobe Launch API (tag manager — not proof of Analytics)', launchOnly: true },
      // demdex.net = Audience Manager/ECID — supporting evidence only.
      { type: 'script-host', pattern: 'demdex\\.net', weight: 0.3, description: 'Adobe Audience Manager/ECID host (supporting evidence only)' },
    ],
  },

  // ----------------------------------------------------------------
  // 02 Advertising (8)
  // ----------------------------------------------------------------
  {
    id: 'google-ads',
    name: 'Google Ads',
    category: 'advertising',
    website: 'https://ads.google.com',
    evidence: [
      { type: 'script-host', pattern: 'googleadservices\\.com/pagead/conversion|googletagmanager\\.com/gtag/js\\?id=AW-|googleads\\.g\\.doubleclick\\.net/pagead/viewthroughconversion', weight: 0.9, description: 'Google Ads conversion tag referenced' },
      { type: 'sdk-init', pattern: 'gtag\\(\\s*[\'"]config[\'"]\\s*,\\s*[\'"]AW-|google_conversion_id|goog_report_conversion', weight: 0.85, description: 'Google Ads conversion init (AW-…)' },
      { type: 'cookie-storage', pattern: '_gcl_au\\b|_gcl_aw\\b', weight: 0.55, description: 'Google Ads click cookie (_gcl_au / _gcl_aw)' },
    ],
    ids: [{ kind: 'Google Ads conversion ID', pattern: '\\b(AW-[0-9]{4,}(?:/[A-Za-z0-9_-]+)?)\\b' }],
  },
  {
    id: 'google-adsense',
    name: 'Google AdSense',
    category: 'advertising',
    website: 'https://www.google.com/adsense/',
    evidence: [
      { type: 'script-host', pattern: 'pagead2\\.googlesyndication\\.com/pagead/js/adsbygoogle\\.js', weight: 0.9, description: 'AdSense library loaded (adsbygoogle.js)' },
      { type: 'sdk-init', pattern: 'adsbygoogle\\.push\\(|adsbygoogle\\s*=\\s*window\\.adsbygoogle', weight: 0.85, description: 'AdSense ad-unit init (adsbygoogle.push)' },
      { type: 'dom', pattern: 'adsbygoogle', weight: 0.6, description: 'AdSense ad-unit markup (ins.adsbygoogle)' },
    ],
    ids: [{ kind: 'AdSense publisher ID', pattern: '\\b(ca-pub-\\d+)\\b' }],
  },
  {
    id: 'meta-pixel',
    name: 'Meta Pixel',
    category: 'advertising',
    website: 'https://www.facebook.com/business/tools/meta-pixel',
    evidence: [
      { type: 'script-host', pattern: 'connect\\.facebook\\.net/[\\w./-]+/fbevents\\.js|facebook\\.com/tr\\?id=', weight: 0.9, description: 'Meta Pixel library / noscript pixel referenced' },
      { type: 'sdk-init', pattern: 'fbq\\(\\s*[\'"]init[\'"]|_fbq\\.push\\(', weight: 0.85, description: "Meta Pixel init (fbq('init', …))" },
      { type: 'cookie-storage', pattern: '_fbp\\b|_fbc\\b', weight: 0.55, description: 'Meta Pixel cookie (_fbp / _fbc)' },
    ],
    ids: [
      { kind: 'Meta Pixel ID', pattern: 'fbq\\(\\s*[\'"]init[\'"]\\s*,\\s*[\'"]?(\\d{6,})' },
      { kind: 'Meta Pixel ID', pattern: 'facebook\\.com/tr\\?id=(\\d+)' },
    ],
  },
  {
    id: 'tiktok-pixel',
    name: 'TikTok Pixel',
    category: 'advertising',
    website: 'https://ads.tiktok.com',
    evidence: [
      { type: 'script-host', pattern: 'analytics\\.tiktok\\.com/i18n/pixel/events\\.js', weight: 0.9, description: 'TikTok Pixel library loaded' },
      { type: 'sdk-init', pattern: 'ttq\\.(load|track|page|identify)\\(', weight: 0.85, description: 'TikTok Pixel call (ttq…)' },
      { type: 'cookie-storage', pattern: '_ttp\\b', weight: 0.55, description: 'TikTok cookie (_ttp)' },
    ],
    ids: [{ kind: 'TikTok Pixel ID', pattern: 'ttq\\.load\\(\\s*[\'"]([A-Z0-9]+)[\'"]' }],
  },
  {
    id: 'linkedin-insight',
    name: 'LinkedIn Insight Tag',
    category: 'advertising',
    website: 'https://www.linkedin.com/help/linkedin/answer/a427660',
    evidence: [
      { type: 'script-host', pattern: 'snap\\.licdn\\.com/li\\.lms-analytics/insight\\.min\\.js|px\\.ads\\.linkedin\\.com', weight: 0.9, description: 'LinkedIn Insight Tag library loaded' },
      { type: 'sdk-init', pattern: '_linkedin_partner_id|_linkedin_data_partner_ids|lintrk\\(', weight: 0.85, description: 'LinkedIn partner-id init' },
    ],
    ids: [{ kind: 'LinkedIn partner ID', pattern: '_linkedin_partner_id\\s*=\\s*["\']?(\\d+)' }],
  },
  {
    id: 'pinterest-tag',
    name: 'Pinterest Tag',
    category: 'advertising',
    website: 'https://help.pinterest.com/en/business/article/install-the-pinterest-tag',
    evidence: [
      { type: 'script-host', pattern: 's\\.pinimg\\.com/ct/core\\.js|ct\\.pinterest\\.com', weight: 0.9, description: 'Pinterest Tag library loaded' },
      { type: 'sdk-init', pattern: 'pintrk\\(\\s*[\'"]load[\'"]|pintrk\\.page\\(', weight: 0.85, description: "Pinterest Tag init (pintrk('load', …))" },
      { type: 'cookie-storage', pattern: '_pin_unauth\\b|_pinterest_ct_rt\\b', weight: 0.55, description: 'Pinterest cookie (_pin_unauth)' },
    ],
    ids: [{ kind: 'Pinterest Tag ID', pattern: 'pintrk\\(\\s*[\'"]load[\'"]\\s*,\\s*[\'"]?(\\d+)' }],
  },
  {
    id: 'reddit-pixel',
    name: 'Reddit Pixel',
    category: 'advertising',
    website: 'https://ads.reddit.com',
    evidence: [
      { type: 'script-host', pattern: 'redditstatic\\.com/ads/pixel\\.js|alb\\.reddit\\.com', weight: 0.9, description: 'Reddit Pixel library loaded' },
      { type: 'sdk-init', pattern: 'rdt\\(\\s*[\'"]init[\'"]', weight: 0.85, description: "Reddit Pixel init (rdt('init', …))" },
      { type: 'cookie-storage', pattern: '_rdt_uuid\\b', weight: 0.55, description: 'Reddit cookie (_rdt_uuid)' },
    ],
    ids: [{ kind: 'Reddit Pixel ID', pattern: 'rdt\\(\\s*[\'"]init[\'"]\\s*,\\s*[\'"]([\\w-]+)[\'"]' }],
  },
  {
    id: 'snapchat-pixel',
    name: 'Snapchat Pixel',
    category: 'advertising',
    website: 'https://ads.snapchat.com',
    evidence: [
      { type: 'script-host', pattern: 'sc-static\\.net/scevent\\.min\\.js|tr\\.snapchat\\.com', weight: 0.9, description: 'Snap Pixel library loaded' },
      { type: 'sdk-init', pattern: 'snaptr\\(\\s*[\'"]init[\'"]', weight: 0.85, description: "Snap Pixel init (snaptr('init', …))" },
      { type: 'cookie-storage', pattern: '_scid\\b', weight: 0.55, description: 'Snap cookie (_scid)' },
    ],
    ids: [{ kind: 'Snap Pixel ID', pattern: 'snaptr\\(\\s*[\'"]init[\'"]\\s*,\\s*[\'"]([a-f0-9-]+)[\'"]' }],
  },

  // ----------------------------------------------------------------
  // 03 Marketing (6)
  // ----------------------------------------------------------------
  {
    id: 'hubspot',
    name: 'HubSpot',
    category: 'marketing',
    website: 'https://www.hubspot.com',
    evidence: [
      { type: 'script-host', pattern: 'js\\.hs-scripts\\.com/\\d+\\.js|js\\.hs-analytics\\.net|js\\.hsforms\\.net|track\\.hubspot\\.com', weight: 0.9, description: 'HubSpot tracking/forms script loaded' },
      { type: 'sdk-init', pattern: '_hsq\\.push\\(|hbspt\\.forms\\.create\\(', weight: 0.85, description: 'HubSpot queue/form init (_hsq / hbspt)' },
      { type: 'cookie-storage', pattern: 'hubspotutk\\b|__hstc\\b|__hssc\\b', weight: 0.55, description: 'HubSpot cookie (hubspotutk)' },
    ],
    ids: [{ kind: 'HubSpot portal ID', pattern: 'js\\.hs-scripts\\.com/(\\d+)\\.js' }],
    variantNote: 'The generic HubSpot script alone is "HubSpot" — chat needs js.usemessages.com (see HubSpot Chat).',
  },
  {
    id: 'klaviyo',
    name: 'Klaviyo',
    category: 'marketing',
    website: 'https://www.klaviyo.com',
    evidence: [
      { type: 'script-host', pattern: 'static\\.klaviyo\\.com/onsite/js/klaviyo\\.js|a\\.klaviyo\\.com', weight: 0.9, description: 'Klaviyo onsite script loaded' },
      { type: 'sdk-init', pattern: 'klaviyo\\.(identify|track|push)|_learnq\\.push\\(', weight: 0.85, description: 'Klaviyo identify/track call' },
      { type: 'cookie-storage', pattern: '__kla_id\\b', weight: 0.55, description: 'Klaviyo cookie (__kla_id)' },
    ],
    ids: [{ kind: 'Klaviyo company ID', pattern: 'klaviyo\\.js\\?company_id=([A-Za-z0-9]+)' }],
  },
  {
    id: 'mailchimp',
    name: 'Mailchimp',
    category: 'marketing',
    website: 'https://mailchimp.com',
    evidence: [
      { type: 'script-host', pattern: 'chimpstatic\\.com/mcjs-connected|[\\w-]+\\.list-manage\\.com', weight: 0.9, description: 'Mailchimp connected-site script / list-manage endpoint' },
      { type: 'dom', pattern: 'mc_embed_signup|mc-embedded-subscribe-form|list-manage\\.com/subscribe', weight: 0.6, description: 'Mailchimp embed form markup / subscribe action' },
    ],
  },
  {
    id: 'activecampaign',
    name: 'ActiveCampaign',
    category: 'marketing',
    website: 'https://www.activecampaign.com',
    evidence: [
      { type: 'script-host', pattern: 'trackcmp\\.net|diffuser-cdn\\.app-us1\\.com|[\\w-]+\\.activehosted\\.com', weight: 0.9, description: 'ActiveCampaign tracking/forms host referenced' },
      { type: 'sdk-init', pattern: 'vgo\\(\\s*[\'"]setAccount[\'"]', weight: 0.85, description: 'ActiveCampaign site-tracking init (vgo)' },
    ],
  },
  {
    id: 'marketo',
    name: 'Marketo',
    category: 'marketing',
    website: 'https://www.marketo.com',
    evidence: [
      { type: 'script-host', pattern: 'munchkin\\.marketo\\.net/munchkin\\.js|[\\w-]+\\.marketo\\.com/js/forms2', weight: 0.9, description: 'Marketo Munchkin/forms script loaded' },
      { type: 'sdk-init', pattern: 'Munchkin\\.init\\(|MktoForms2\\.loadForm\\(', weight: 0.85, description: 'Marketo Munchkin/forms init' },
      { type: 'cookie-storage', pattern: '_mkto_trk\\b', weight: 0.55, description: 'Marketo cookie (_mkto_trk)' },
    ],
    ids: [
      { kind: 'Marketo Munchkin ID', pattern: 'Munchkin\\.init\\(\\s*[\'"]([A-Za-z0-9-]+)[\'"]' },
      { kind: 'Marketo host', pattern: 'MktoForms2\\.loadForm\\(\\s*[\'"]?(//[\\w.-]+\\.marketo\\.com)' },
    ],
  },
  {
    id: 'salesforce',
    name: 'Salesforce',
    category: 'marketing',
    website: 'https://www.salesforce.com',
    evidence: [
      { type: 'script-host', pattern: 'pi\\.pardot\\.com/pd\\.js|go\\.pardot\\.com', weight: 0.9, description: 'Pardot tracking script loaded', product: 'Pardot' },
      { type: 'script-host', pattern: 'webto\\.salesforce\\.com/servlet/servlet\\.WebToLead', weight: 0.9, description: 'Salesforce Web-to-Lead form action', product: 'Web-to-Lead' },
      { type: 'script-host', pattern: 'service\\.force\\.com/embeddedservice|salesforceliveagent\\.com', weight: 0.9, description: 'Salesforce Embedded Service / Live Agent', product: 'Embedded Service chat' },
      { type: 'script-host', pattern: 'cdn\\.evgnet\\.com', weight: 0.9, description: 'Salesforce Marketing Cloud (Evergage) CDN', product: 'Marketing Cloud' },
      { type: 'script-host', pattern: '[\\w-]+\\.force\\.com|[\\w-]+\\.my\\.site\\.com', weight: 0.9, description: 'Salesforce Experience Cloud domain', product: 'Experience Cloud' },
      { type: 'sdk-init', pattern: 'piAId\\s*=|piCId\\s*=|embedded_svc\\.settings', weight: 0.85, description: 'Salesforce Pardot/Embedded init' },
    ],
    variantNote: 'Reported as "Salesforce" with the matched product named in a sub-note.',
  },

  // ----------------------------------------------------------------
  // 04 Payments (7)
  // ----------------------------------------------------------------
  {
    id: 'stripe',
    name: 'Stripe',
    category: 'payments',
    website: 'https://stripe.com',
    evidence: [
      { type: 'script-host', pattern: 'js\\.stripe\\.com/v[23]|checkout\\.stripe\\.com|m\\.stripe\\.network', weight: 0.9, description: 'Stripe SDK loaded (js.stripe.com)' },
      { type: 'sdk-init', pattern: 'Stripe\\(\\s*[\'"]pk_(live|test)_|new\\s+Stripe\\(', weight: 0.85, description: 'Stripe initialised with publishable key' },
      { type: 'dom', pattern: 'stripe-buy-button|stripe-pricing-table|__privateStripeFrame', weight: 0.6, description: 'Stripe checkout element / iframe' },
      { type: 'cookie-storage', pattern: '__stripe_mid\\b|__stripe_sid\\b', weight: 0.55, description: 'Stripe cookie (__stripe_mid / __stripe_sid)' },
    ],
    variantNote: 'A plain link to buy.stripe.com without the SDK is Low at most (links are never scanned).',
  },
  {
    id: 'paypal',
    name: 'PayPal',
    category: 'payments',
    website: 'https://www.paypal.com',
    evidence: [
      { type: 'script-host', pattern: 'paypal\\.com/sdk/js\\?client-id=|paypalobjects\\.com/api/checkout\\.js|paypal\\.com/cgi-bin/webscr', weight: 0.9, description: 'PayPal SDK / legacy button endpoint referenced' },
      { type: 'sdk-init', pattern: 'paypal\\.Buttons\\.(render|\\()|paypal\\.Buttons\\(', weight: 0.85, description: 'PayPal Buttons render call' },
    ],
    ids: [{ kind: 'PayPal client ID', pattern: 'paypal\\.com/sdk/js\\?client-id=([A-Za-z0-9_-]+)' }],
    variantNote: 'A plain paypal.me link is IGNORED (links are never scanned).',
  },
  {
    id: 'razorpay',
    name: 'Razorpay',
    category: 'payments',
    website: 'https://razorpay.com',
    evidence: [
      { type: 'script-host', pattern: 'checkout\\.razorpay\\.com/v1/checkout\\.js|checkout-static\\.razorpay\\.com', weight: 0.9, description: 'Razorpay checkout script loaded' },
      { type: 'sdk-init', pattern: 'new\\s+Razorpay\\(', weight: 0.85, description: 'Razorpay checkout initialised' },
      { type: 'dom', pattern: 'data-payment_button_id', weight: 0.6, description: 'Razorpay payment-button attribute' },
    ],
  },
  {
    id: 'square',
    name: 'Square',
    category: 'payments',
    website: 'https://squareup.com',
    evidence: [
      { type: 'script-host', pattern: 'web\\.squarecdn\\.com/v1/square\\.js|js\\.squareup\\.com/v2/paymentform', weight: 0.9, description: 'Square payments SDK loaded' },
      { type: 'sdk-init', pattern: 'Square\\.payments\\(|SqPaymentForm\\(', weight: 0.85, description: 'Square payments init' },
      // #card-container is generic on its own — supporting evidence only.
      { type: 'dom', pattern: 'sq-payment-form|square-payment|card-container', weight: 0.3, description: 'Square payment-form hook (supporting evidence only)' },
    ],
  },
  {
    id: 'adyen',
    name: 'Adyen',
    category: 'payments',
    website: 'https://www.adyen.com',
    evidence: [
      { type: 'script-host', pattern: 'checkoutshopper[^"\'\\s]*\\.adyen\\.com', weight: 0.9, description: 'Adyen checkout SDK loaded' },
      { type: 'sdk-init', pattern: 'AdyenCheckout\\s*\\(', weight: 0.85, description: 'AdyenCheckout initialised' },
      { type: 'dom', pattern: 'adyen-checkout__', weight: 0.6, description: 'Adyen checkout markup' },
    ],
  },
  {
    id: 'apple-pay',
    name: 'Apple Pay',
    category: 'payments',
    website: 'https://developer.apple.com/apple-pay/',
    evidence: [
      // WARNING: window.ApplePaySession exists in Safari on EVERY site —
      // a bare global is NEVER evidence. Require an actual integration.
      { type: 'script-host', pattern: 'applepay\\.cdn-apple\\.com/jsapi/.*/apple-pay-sdk\\.js', weight: 0.9, description: 'Apple Pay JS SDK loaded' },
      { type: 'sdk-init', pattern: 'new\\s+ApplePaySession\\(\\s*\\d+', weight: 0.85, description: 'ApplePaySession constructed with version' },
      { type: 'dom', pattern: 'apple-pay-button|-apple-pay-button-style', weight: 0.6, description: 'Apple Pay button element / style' },
    ],
  },
  {
    id: 'google-pay',
    name: 'Google Pay',
    category: 'payments',
    website: 'https://pay.google.com',
    evidence: [
      { type: 'script-host', pattern: 'pay\\.google\\.com/gp/p/js/pay\\.js', weight: 0.9, description: 'Google Pay library loaded' },
      { type: 'sdk-init', pattern: 'google\\.payments\\.api\\.PaymentsClient', weight: 0.85, description: 'Google Pay PaymentsClient constructed' },
      { type: 'dom', pattern: 'gpay-button|gpay-card-info-container', weight: 0.6, description: 'Google Pay button markup' },
    ],
  },

  // ----------------------------------------------------------------
  // 05 Chat & Support (7)
  // ----------------------------------------------------------------
  {
    id: 'intercom',
    name: 'Intercom',
    category: 'chat',
    website: 'https://www.intercom.com',
    evidence: [
      { type: 'script-host', pattern: 'widget\\.intercom\\.io/widget/|js\\.intercomcdn\\.com', weight: 0.9, description: 'Intercom widget script loaded' },
      { type: 'sdk-init', pattern: 'Intercom\\(\\s*[\'"]boot[\'"]|intercomSettings\\s*=', weight: 0.85, description: 'Intercom boot call / settings' },
      { type: 'dom', pattern: 'intercom-container', weight: 0.6, description: 'Intercom container element' },
      { type: 'cookie-storage', pattern: 'intercom-id-|intercom-session-', weight: 0.55, description: 'Intercom cookie' },
    ],
    ids: [{ kind: 'Intercom app ID', pattern: 'widget\\.intercom\\.io/widget/([a-z0-9]+)' }],
  },
  {
    id: 'zendesk',
    name: 'Zendesk',
    category: 'chat',
    website: 'https://www.zendesk.com',
    evidence: [
      { type: 'script-host', pattern: 'static\\.zdassets\\.com/ekr/snippet\\.js|v2\\.zopim\\.com', weight: 0.9, description: 'Zendesk widget snippet loaded' },
      { type: 'sdk-init', pattern: 'zE\\(\\s*[\'"]|zESettings\\s*=|\\$zopim', weight: 0.85, description: 'Zendesk widget API call (zE / $zopim)' },
      { type: 'cookie-storage', pattern: '__zlcmid\\b', weight: 0.55, description: 'Zendesk chat cookie (__zlcmid)' },
    ],
    ids: [{ kind: 'Zendesk snippet key', pattern: 'snippet\\.js\\?key=([a-f0-9-]+)' }],
    variantNote: 'A link to a *.zendesk.com help center without the widget is Low at most (links are never scanned).',
  },
  {
    id: 'crisp',
    name: 'Crisp',
    category: 'chat',
    website: 'https://crisp.chat',
    evidence: [
      { type: 'script-host', pattern: 'client\\.crisp\\.chat/l\\.js', weight: 0.9, description: 'Crisp chat script loaded' },
      { type: 'sdk-init', pattern: '\\$crisp\\.push\\(|CRISP_WEBSITE_ID\\s*=', weight: 0.85, description: 'Crisp init (CRISP_WEBSITE_ID)' },
      { type: 'dom', pattern: 'crisp-client', weight: 0.6, description: 'Crisp client element' },
    ],
    ids: [{ kind: 'Crisp website ID', pattern: 'CRISP_WEBSITE_ID\\s*=\\s*[\'"]([a-f0-9-]+)[\'"]' }],
  },
  {
    id: 'tawkto',
    name: 'Tawk.to',
    category: 'chat',
    website: 'https://www.tawk.to',
    evidence: [
      { type: 'script-host', pattern: 'embed\\.tawk\\.to/', weight: 0.9, description: 'Tawk.to embed script loaded' },
      { type: 'sdk-init', pattern: 'Tawk_API|Tawk_LoadStart', weight: 0.85, description: 'Tawk.to API present' },
      { type: 'cookie-storage', pattern: 'twk_uuid_|TawkConnectionTime\\b', weight: 0.55, description: 'Tawk.to cookie' },
    ],
    ids: [{ kind: 'Tawk.to property/widget', pattern: 'embed\\.tawk\\.to/([a-f0-9]+/[a-z0-9]+)' }],
  },
  {
    id: 'drift',
    name: 'Drift',
    category: 'chat',
    website: 'https://www.drift.com',
    evidence: [
      { type: 'script-host', pattern: 'js\\.driftt\\.com/include/|js\\.drift\\.com', weight: 0.9, description: 'Drift chat script loaded' },
      { type: 'sdk-init', pattern: 'drift(t)?\\.load\\(|drift\\.identify\\(', weight: 0.85, description: 'Drift snippet init' },
      { type: 'dom', pattern: 'drift-widget|drift-frame-controller', weight: 0.6, description: 'Drift widget element' },
      { type: 'cookie-storage', pattern: 'drift_aid\\b|driftt_aid\\b', weight: 0.55, description: 'Drift cookie' },
    ],
    ids: [{ kind: 'Drift snippet ID', pattern: 'js\\.driftt\\.com/include/([a-z0-9]+)/' }],
  },
  {
    id: 'livechat',
    name: 'LiveChat',
    category: 'chat',
    website: 'https://www.livechat.com',
    evidence: [
      { type: 'script-host', pattern: 'cdn\\.livechatinc\\.com/tracking\\.js|secure\\.livechatinc\\.com', weight: 0.9, description: 'LiveChat tracking script loaded' },
      { type: 'sdk-init', pattern: 'LiveChatWidget\\.(call|on|init)|__lc\\.license\\s*=', weight: 0.85, description: 'LiveChat widget init' },
      { type: 'cookie-storage', pattern: '__lc_cid\\b|__lc2_cid\\b', weight: 0.55, description: 'LiveChat cookie' },
    ],
  },
  {
    id: 'hubspot-chat',
    name: 'HubSpot Chat',
    category: 'chat',
    website: 'https://www.hubspot.com/products/crm/live-chat',
    evidence: [
      // Chat-specific evidence ONLY — the generic HubSpot script alone is
      // "HubSpot", never "HubSpot Chat".
      { type: 'script-host', pattern: 'js\\.usemessages\\.com/conversations-embed\\.js', weight: 0.9, description: 'HubSpot conversations embed loaded' },
      { type: 'sdk-init', pattern: 'HubSpotConversations', weight: 0.85, description: 'HubSpot Conversations API present' },
      { type: 'dom', pattern: 'hubspot-messages-iframe-container', weight: 0.6, description: 'HubSpot chat iframe container' },
    ],
  },
];

export const GROWTH_MARKETING_IDS = GROWTH_MARKETING_SIGNATURES.map((s) => s.id);

export function getGrowthMarketingSignature(id: string): GrowthSignature | undefined {
  return GROWTH_MARKETING_SIGNATURES.find((s) => s.id === id);
}
