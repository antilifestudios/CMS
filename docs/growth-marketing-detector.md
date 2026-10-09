# Growth & Marketing Detector — maintainer notes

Page: `/growth-marketing-detector` · API: `POST /api/growth-detect`

Detects 38 technologies in 5 categories (Analytics 10 · Advertising 8 ·
Marketing 6 · Payments 7 · Chat & Support 7). Static scan only
(`mode: "static"`), reusing the shared engine from the security-privacy
detector: channel extraction, signature-data-file pattern, noisy-OR
evidence combination (computed in 0–1, then `score100 = round(p*100)`),
bands from the shared `confidence.ts` scale
(VERY HIGH ≥ 90 · HIGH ≥ 75 · MEDIUM ≥ 60 · LOW ≥ 40 · below 40 never
reported), the "Static scan" notice, and the info icon.

## How to add a new technology (no logic changes needed)

1. Open `src/data/growth-marketing-signatures.ts` and append **one entry**
   (id, name, category, website, evidence[], optional ids[]).
2. Pick evidence `type` + `weight` from the fixed scale at the top of that
   file (host 0.90 · init 0.85 · via-gtm 0.70 (detector-added) · DOM 0.60 ·
   cookie 0.55). **Never add visible-text or `<a href>` patterns** — the
   detector never scans those channels.
3. Add fixtures in `tests/growth-marketing.test.ts`
   (positive · negative · near-miss) and run `npm test`.

## Detection passes (all static)

1. Fetch HTML (same SSRF guard, redirects, caps as the security
   detector). Parse script/link/iframe/img/noscript/form/a attributes,
   inline scripts, meta tags, DOM ids/classes, `data-*` attributes,
   custom-element tags, `<style>` hooks, and Set-Cookie headers.
2. Scan the largest first-party JS bundles (5 × 250 KB) for vendor
   hosts, SDK init calls, and IDs.
3. **GTM container expansion** (`src/lib/detect/gtm-expansion.ts`,
   shared with the security detector): extract every `GTM-XXXXXXX` id
   from HTML + bundles, fetch up to 3 public container files
   (pinned to `www.googletagmanager.com`, 5 s timeout, 400 KB cap,
   short-TTL cache, fail-soft with a warning) and scan them with the
   same signatures. Container hits become `via-gtm` evidence at 0.70 —
   never the top band on its own. `gtag.js` ids (`G-`/`AW-`/`GT-`) are
   extracted for disambiguation and `extractedIds` but not fetched
   (`gtag.js` is a generic loader with no per-id content).
4. Public identifiers (`G-…`, `GTM-…`, `AW-…`, `ca-pub-…`, pixel IDs,
   portal IDs, …) are returned as `extractedIds` and shown in the
   evidence view.

## Disambiguation rules (enforced by signatures + tests)

- `gtag.js` id prefix decides the product: `G-` = Analytics,
  `AW-` = Ads, `GT-` = generic tag, `UA-` = legacy (reported with a
  "Universal Analytics (legacy)" sub-note when no `G-` is present).
- Lone `dataLayer` / `analytics` global / `ApplePaySession` /
  `paypal.me` link / plain HubSpot script / `assets.adobedtm.com`
  alone never detect (Adobe Launch caps at Low).
- Salesforce reports as "Salesforce" with the matched product
  (Pardot, Web-to-Lead, Embedded Service chat, Marketing Cloud,
  Experience Cloud) in `subNote`.

## Honest limitations (shown in the UI)

- Consent-gated tags (common in the EU) may not fire without consent.
- Server-side tagging, first-party proxies, Zaraz (`/cdn-cgi/zaraz/`)
  and platform-native integrations can hide vendor hosts — surfaced as
  a warning, never as revenue/business language.
- "Not detected" never means "not used".

## Cloudflare Workers Free-tier fit

Shared `src/lib/detect/static-collect.ts` enforces: 1 MB HTML cap,
5 × 250 KB bundles, 3 × 400 KB GTM containers, ≤ 40 subrequests per
invocation (redirects + HEAD + bundles + containers share one budget),
streams cancelled at the cap, cheap `includes()` prefilter with regexes
only near hits, per-IP rate limit (20/min) + 10-min result cache.
Truncation surfaces a "Partial scan" warning. Post-deploy: watch Workers
Logs for CPU time and report sites exceeding ~8 ms.

## Manual QA checklist (verify live — don't assume)

- Analytics: GA4 `G-…` site · GTM `GTM-…` site · Clarity · Hotjar ·
  Matomo cloud + a self-hosted Matomo (no vendor domain) · Plausible ·
  Mixpanel · PostHog · Segment · Adobe (AppMeasurement vs Launch-only)
- Advertising: Ads `AW-…` · AdSense `ca-pub-…` · Meta Pixel (+ noscript
  `facebook.com/tr`) · TikTok · LinkedIn · Pinterest · Reddit · Snapchat
- Marketing: HubSpot (+ portal id) · Klaviyo · Mailchimp embed form ·
  ActiveCampaign · Marketo · Salesforce Pardot
- Payments: Stripe · PayPal SDK (vs `paypal.me` link) · Razorpay ·
  Square · Adyen · Apple Pay (vs Safari bare global) · Google Pay
- Chat: Intercom · Zendesk · Crisp · Tawk.to · Drift · LiveChat ·
  HubSpot Chat (vs plain HubSpot script)
- GTM-only: page loading just `gtm.js` whose container injects a pixel
- Negative: `example.com` → empty state with the static-scan note
