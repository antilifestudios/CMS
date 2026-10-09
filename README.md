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

## Astro Starter Kit: Minimal

```sh
npm create astro@latest -- --template minimal
```

> 🧑‍🚀 **Seasoned astronaut?** Delete this file. Have fun!

## 🚀 Project Structure

Inside of your Astro project, you'll see the following folders and files:

```text
/
├── public/
├── src/
│   └── pages/
│       └── index.astro
└── package.json
```

Astro looks for `.astro` or `.md` files in the `src/pages/` directory. Each page is exposed as a route based on its file name.

There's nothing special about `src/components/`, but that's where we like to put any Astro/React/Vue/Svelte/Preact components.

Any static assets, like images, can be placed in the `public/` directory.

## 🧞 Commands

All commands are run from the root of the project, from a terminal:

| Command                   | Action                                           |
| :------------------------ | :----------------------------------------------- |
| `npm install`             | Installs dependencies                            |
| `npm run dev`             | Starts local dev server at `localhost:4321`      |
| `npm run build`           | Build your production site to `./dist/`          |
| `npm run preview`         | Preview your build locally, before deploying     |
| `npm run astro ...`       | Run CLI commands like `astro add`, `astro check` |
| `npm run astro -- --help` | Get help using the Astro CLI                     |

## 👀 Want to learn more?

Feel free to check [our documentation](https://docs.astro.build) or jump into our [Discord server](https://astro.build/chat).
