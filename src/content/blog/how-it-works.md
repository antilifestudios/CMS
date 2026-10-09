---
title: "How It Works: Deterministic CMS Detection at the Edge"
description: "An inside look into our multi-signal pipeline: HTTP header parsing, DOM artifact matching, selective probing, and confidence scoring without guessing."
publishDate: 2026-10-09
updatedDate: 2026-10-09
tags: ["Architecture", "Detection", "Edge Computing", "Heuristics"]
readingTime: "5 min read"
---

CMS Detector AI was engineered to replace opaque, database-dependent site profiling tools with a fast, deterministic edge engine. Rather than relying on historical crawl records or speculative AI hallucination, our system runs live HTTP queries against public endpoints and verifies explicit platform markers.

Every result returned by our scanner includes verifiable evidence — the exact header, HTML snippet, or API response that triggered the detection — along with a calculated confidence rating.

## The Multi-Pass Detection Pipeline

When a user submits a URL, the edge engine executes a structured, multi-pass inspection sequence designed to minimize latency while maintaining strict security boundaries.

### 1. Normalization and SSRF Guarding

Before dispatching network requests, the input URL is normalized and validated against strict Server-Side Request Forgery (SSRF) filters:

- Enforces standard HTTP/HTTPS protocols on ports 80 and 443.
- Rejects localhost, private IPv4/IPv6 ranges (e.g. 10.0.0.0/8, 192.168.0.0/16, 127.0.0.1, ::1), and reserved top-level domains.
- Prevents cloud metadata endpoint traversal (such as 169.254.169.254).
- Validates each redirection step independently to prevent open redirect bypasses.

### 2. Streamed Edge Fetching

The target document is fetched using an honest crawler user agent within a Cloudflare Worker runtime. To ensure speed and resource conservation:

- HTML payload size is capped at 500 KB using a streaming reader.
- Subrequest deadlines are bounded to prevent hang states.
- HTTP response headers and cookie names (excluding sensitive cookie values) are extracted.

### 3. Static Signature Matching

The retrieved HTML, headers, and script sources are analyzed against an optimized catalog of regex and substring signatures:

- **Meta Generator Tags:** Standardized meta tags (e.g. `<meta name="generator" content="WordPress 6.6">`) provide unambiguous primary signals.
- **Asset Paths:** Directory conventions like `/wp-content/themes/`, `/cdn.shopify.com/s/files/`, or `/_next/static/` indicate core framework infrastructure.
- **Script Hosts and Bundles:** Third-party vendor domains, analytics tags, and compiled bundle structures are evaluated.
- **Response Headers:** Headers like `x-powered-by`, `x-vercel-id`, `cf-ray`, or `x-shopify-stage` reveal hosting and infrastructure providers.

### 4. Selective Corroboration Probes

When static signals indicate a candidate platform but require further confirmation, the engine may dispatch up to 4 lightweight verification probes:

- Probing standard public API endpoints, such as `/wp-json/` for WordPress or `/products.json` for Shopify storefronts.
- Verifying theme stylesheet headers (`style.css`) to extract theme author and version data.
- Probes are strictly used to corroborate or extract metadata; they never invent a positive detection on their own.

## The Confidence Scoring Model

Because modern websites frequently employ reverse proxies, micro-frontends, and multi-CDN architectures, a single signal is rarely sufficient to declare a confirmed platform. We employ a weighted scoring model:

- **Confirmed (90–100%):** A unique, unambiguous fingerprint — such as an active generator tag, proprietary framework header, or authenticated REST namespace.
- **Likely (70–89%):** Multiple independent high-weight signals, such as distinctive asset paths combined with specific cookie identifiers.
- **Possible (below 70%):** Weak or generic heuristics (such as common server banners). These are reported transparently as possibilities, never as conclusive headline answers.

When a site exposes no identifiable platform fingerprints, we state clearly that the site appears custom-built or headless, rather than guessing.
