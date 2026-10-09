---
title: "How to Find What CMS a Website Uses: Step-by-Step Guide"
description: "Learn how to manually inspect any website's CMS using browser DevTools, view-source indicators, HTTP response headers, and direct endpoint probes."
publishDate: 2026-10-07
updatedDate: 2026-10-09
tags: ["Guides", "DevTools", "Inspection", "WordPress", "Shopify"]
readingTime: "4 min read"
---

Identifying the content management system (CMS) or framework powering a website can be accomplished in under a minute without installing third-party extensions. By inspecting public source code and network requests, you can uncover clear technical footprints.

Here are the three fastest manual inspection techniques used by web engineers and security researchers.

## Method 1: Page Source Inspection (30 Seconds)

Every browser allows you to view the raw HTML payload transmitted by the web server.

1. Navigate to the website and open the source view:
   - Windows/Linux: Press `Ctrl + U`
   - macOS: Press `Cmd + Option + U`
2. Open the page search dialog (`Ctrl + F` or `Cmd + F`) and look for the following patterns:
   - `generator` — Many platforms include a meta tag identifying the engine (e.g. `<meta name="generator" content="WordPress">` or `Ghost 5.82`).
   - `wp-content` — Conclusive evidence of WordPress media or theme assets.
   - `cdn.shopify.com` — Confirms Shopify hosting and theme assets.
   - `__NEXT_DATA__` — Indicates a Next.js server-rendered application.
   - `website-files.com` — Standard asset hosting domain for Webflow sites.
   - `static.parastorage.com` or `wixstatic.com` — Identifies Wix site builders.

## Method 2: Inspecting Response Headers (30 Seconds)

Web servers and edge CDNs often append revealing response headers to document requests.

1. Press `F12` to open Browser Developer Tools and select the **Network** tab.
2. Refresh the page (`Ctrl + R` or `Cmd + R`).
3. Click the first row (the root document request) and navigate to the **Headers** sub-panel.
4. Review the **Response Headers** section for specific markers:
   - `x-powered-by`: Often lists PHP, ASP.NET, Next.js, or Express.
   - `x-vercel-id`: Confirms Vercel edge deployment.
   - `x-nf-request-id`: Confirms Netlify edge hosting.
   - `x-shopify-stage`: Confirms Shopify cloud infrastructure.
   - `server`: May declare Cloudflare, openresty, or Apache.

## Method 3: Direct Endpoint Probes (20 Seconds)

Most major content platforms expose standardized administrative or API routes. Appending these to a domain name can confirm the platform:

- Append `/wp-json/` — Returns the WordPress REST API JSON index containing registered namespaces.
- Append `/ghost/` — Triggers a redirect to the Ghost Admin authentication interface.
- Append `/products.json` — Returns product catalog JSON on standard Shopify storefronts.
- Append `/config` — Often redirects to the Squarespace login portal on hosted Squarespace domains.

## When Manual Methods Fail

Modern enterprise websites frequently decouple their front-end presentations from their backend CMSs (known as headless architecture) or strip server headers for security hardening. 

In such cases, an automated tool like [CMS Detector AI](/) crawls multiple pages, examines script bundles, analyzes DNS records, and identifies subtle framework signals that manual checks might overlook.
