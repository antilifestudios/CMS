---
title: "Shopify Signatures: How to Detect Shopify Stores and Themes"
description: "A deep dive into Shopify platform detection: global CDN endpoints, window.Shopify browser objects, theme identifiers, and headless Hydrogen storefronts."
publishDate: 2026-09-28
updatedDate: 2026-10-09
tags: ["Shopify", "Signatures", "E-commerce", "Themes"]
readingTime: "4 min read"
---

Shopify is the dominant cloud commerce platform for independent merchants, mid-market retailers, and global enterprise brands. Because Shopify hosts storefront infrastructure on its proprietary cloud environment, detecting a Shopify deployment involves checking both cloud network markers and client-side DOM objects.

Here is a breakdown of the primary technical signals that confirm a Shopify storefront and identify its active theme.

## Core Shopify Infrastructure Footprints

Shopify handles all core storefront routing, checkout sessions, and static asset delivery. These operations introduce distinct technical markers.

### 1. Global CDN and Script Hosts

Every standard Shopify store serves theme assets and media from Shopify's dedicated content delivery network:

- `cdn.shopify.com/s/files/...`: Primary static media and uploaded image host.
- `cdn.shopify.com/shopifycloud/...`: Houses platform runtime scripts, checkout frameworks, and internationalization files.
- `monorail-edge.shopifysvc.com`: Shopify's internal client telemetry and event tracking endpoint.

### 2. Browser Window Objects and DOM Metadata

When a Shopify page renders in the browser, the theme Liquid template populates global JavaScript configurations:

```javascript
window.Shopify = window.Shopify || {};
window.Shopify.shop = "store-handle.myshopify.com";
window.Shopify.currency = { active: "USD", rate: "1.0" };
window.Shopify.theme = {
  name: "Dawn",
  id: 135402094768,
  theme_store_id: 887,
  role: "main"
};
```

Inspecting the `window.Shopify.theme` object exposes the human-readable theme title, the unique theme installation ID, and the Theme Store catalog identifier (such as 887 for Shopify's default Dawn theme).

### 3. Response Headers and Cookies

HTTP responses from Shopify storefront servers include custom cloud headers:

- `x-shopify-stage`: Indicates production edge environment.
- `x-shopid`: Contains the merchant's numeric shop identifier.
- `cf-ray`: Shopify operates its edge on Cloudflare enterprise routing.
- Cookies such as `_shopify_s`, `_shopify_y`, and `cart_sig` manage tracking and cart state.

## Theme Architecture and Storefront Probes

Shopify themes are built with Liquid templates, schema JSON, and CSS/JS assets bundled into the storefront.

Public endpoints provide immediate verification of commerce functionality:

- **Product Catalog Probe:** Appending `/products.json` or `/products/<handle>.json` returns product lists, variants, pricing, and image URLs formatted in standard JSON.
- **Cart API Probe:** Appending `/cart.js` returns the shopper's active cart payload and line item attributes.

Our dedicated [Shopify Theme Detector](/shopify-theme-detector) evaluates these storefront objects to identify official Shopify Theme Store themes, commercial third-party themes, or bespoke agency builds.

## Detecting Headless Shopify Deployments

Modern enterprise retailers frequently operate headless storefronts using Shopify Hydrogen (built on Remix) or Next.js, connecting to the Shopify Storefront API via GraphQL.

In these decoupled architectures, standard Liquid tags and `window.Shopify` globals are absent. However, detection remains possible by analyzing:

- GraphQL requests directed to `https://<store>.myshopify.com/api/<version>/graphql.json`.
- Checkout redirect URLs routing to `checkout.shopify.com` or custom domains configured on Shopify's edge.
- Client-side checkout SDK bundles and Storefront API query schemas.
