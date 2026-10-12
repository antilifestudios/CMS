# CMS Detector AI

Tech-stack detection running on Astro + Cloudflare Workers (free tier).

## Detectors

| Page | API | Signatures | Notes |
| ---- | --- | ---------- | ----- |
| `/security-privacy-detector` | `POST /api/security-privacy-detect` | `src/data/security-privacy-signatures.ts` (26 techs) | Static scan + first-party bundles + GTM container expansion |
| `/growth-marketing-detector` | `POST /api/growth-detect` | `src/data/growth-marketing-signatures.ts` (38 techs) | Static scan + bundles + GTM expansion, `extractedIds` per finding |

Shared engine (imported, never duplicated): `src/lib/detect/static-collect.ts`
(fetch, SSRF guard, subrequest budget, byte caps), `src/lib/detect/gtm-expansion.ts`
(container fetch + id extraction), channel extraction + noisy-OR scoring in
`src/lib/detect/security-privacy.ts`, bands from `src/lib/detect/confidence.ts`.

Maintainer docs: `docs/security-privacy-detector.md`, `docs/growth-marketing-detector.md`.
Tests: `npm test` (fixture-based, no network).
## Commands

| Command                   | Action                                           |
| :------------------------ | :----------------------------------------------- |
| `npm install`             | Installs dependencies                            |
| `npm run dev`             | Starts local dev server at `localhost:4321`      |
| `npm run build`           | Build your production site to `./dist/`          |
| `npm run preview`         | Preview your build locally, before deploying     |
| `npm test`                | Run test suite                                   |
| `npm run smoke`           | Run live smoke test verification                 |
