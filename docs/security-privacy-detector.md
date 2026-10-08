# Security & Privacy Detector — maintainer notes

Page: `/security-privacy-detector` · API: `POST /api/security-privacy-detect`

## How to add a new technology (no logic changes needed)

1. Open `src/data/security-privacy-signatures.ts` and append **one entry**:
   ```ts
   {
     id: 'my-tech',            // unique, kebab-case
     name: 'My Tech',           // display name
     category: 'privacy' | 'security' | 'other',
     website: 'https://…',      // vendor homepage
     evidence: [
       { type: 'script-host', pattern: 'vendor\\.com/sdk', weight: 0.9,
         description: 'My Tech SDK host loaded' },
       // …more evidence rules
     ],
   },
   ```
2. Pick evidence `type` + `weight` from the fixed scale at the top of that
   file (host 0.90 · global 0.85 · init 0.80 · DOM 0.65 · cookie 0.60 ·
   iframe 0.90). **Never add visible-text or `<a href>` patterns** — they
   are weight 0 by design and the detector never scans those channels.
3. Add three fixtures in `tests/security-privacy-detector.test.ts`
   (positive · negative · near-miss) and run `npm test`.

The detector (`src/lib/detect/security-privacy.ts`), the API route, and the
page UI pick the new technology up automatically, including category counts.

## Confidence recap

Noisy-OR over distinct evidence **types** (not matches):
`1 − Π(1 − weight)`. High ≥ 0.85 (needs a strong type: host, global, init,
or iframe) · Medium 0.60–0.84 · Low 0.35–0.59 · below 0.35 not reported.
DOM/cookie-only caps below High; CSP/comment-only caps at Low.

## Rendered pass (Pass 2) seam

The endpoint currently runs static-only (`mode: "static"`) plus
first-party bundle scanning. `detectSecurityPrivacy()` already accepts
`globals`, `networkRequests`, and `storageKeys` — wire a headless-browser
pass (Cloudflare Browser Rendering or Playwright) to fill those in and flip
`mode` to `"rendered"`; no signature or scoring changes required.

## Manual QA checklist (verify live — don't assume)

Load each site in the detector and confirm the expected hit, then view
source to confirm the evidence line matches reality.

### Privacy / Consent
- [ ] OneTrust — `onetrust.com` (cdn.cookielaw.org, OptanonConsent)
- [ ] Cookiebot — `cookiebot.com` (consent.cookiebot.com, CookieConsent)
- [ ] Usercentrics — `usercentrics.com` (app.usercentrics.eu)
- [ ] TrustArc — `trustarc.com` (consent.trustarc.com)
- [ ] iubenda — `iubenda.com` (cdn.iubenda.com, _iub_cs-)
- [ ] Complianz — any WordPress site running Complianz (`/wp-content/plugins/complianz-gdpr/`)
- [ ] Didomi — `didomi.io` (sdk.privacy-center.org, didomi_token)
- [ ] Osano — `osano.com` (cmp.osano.com)
- [ ] CookieYes — `cookieyes.com` (cdn-cookieyes.com/client_data)
- [ ] Termly — `termly.io` (app.termly.io/resource-blocker)
- [ ] Quantcast Choice — a site on the Quantcast CMP list (cmp.quantcast.com)

### Security & Monitoring
- [ ] reCAPTCHA v2 — `google.com/recaptcha` (.g-recaptcha widget)
- [ ] reCAPTCHA v3 — any `api.js?render=<key>` + `grecaptcha.execute` site
- [ ] reCAPTCHA Enterprise — `enterprise.js` loader site
- [ ] hCaptcha — `hcaptcha.com` (.h-captcha widget)
- [ ] Sentry — `sentry.io` (browser.sentry-cdn.com + DSN)
- [ ] Cloudflare Turnstile — `cloudflare.com/products/turnstile` demo
- [ ] Fingerprint — `fingerprint.com` (fpjs.io Pro vs openfpcdn.io OSS)
- [ ] Datadog — `datadoghq.com` (DD_RUM, _dd_s)
- [ ] New Relic — `newrelic.com` (js-agent.newrelic.com, NREUM)
- [ ] Bugsnag — `bugsnag.com` (d2wy8f7a9ursnm.cloudfront.net)
- [ ] Rollbar — `rollbar.com` (cdn.rollbar.com, _rollbarConfig)

### Other (controlled fallback)
- [ ] Cloudinary — `cloudinary.com` (res.cloudinary.com images)
- [ ] Algolia — `algolia.com` (algoliasearch / InstantSearch)
- [ ] Google Maps — `maps.google.com` (maps.googleapis.com + embed iframe)
- [ ] YouTube — any `youtube.com/embed/…` page (and confirm a
      `youtube.com/watch` link page does NOT detect)
- [ ] Vimeo — any `player.vimeo.com/video/…` page
- [ ] Font Awesome — `fontawesome.com` (kit + fa-solid classes; confirm a
      lone `fa` class page does NOT detect)

### Negative controls
- [ ] `example.com` → "No supported technologies detected" (honest empty)
- [ ] Generic Cloudflare-fronted site (no Turnstile widget) → no Turnstile
- [ ] Any IAB-TCF site without Quantcast → no Quantcast Choice
