/**
 * Per-technology editorial content for /cms/[slug] pages.
 * Hand-written copy — no auto-generated filler.
 * Technology names are proper nouns and never translated.
 */

export interface TechFaq {
  q: string;
  a: string;
}

export interface TechContent {
  slug: string;
  name: string;
  category: 'cms' | 'builder' | 'ecommerce' | 'framework' | 'hosting';
  tagline: string;
  metaTitle: string;
  metaDescription: string;
  /** What the technology is + who uses it (2 short paragraphs). */
  about: string[];
  /** Kinds of artifacts we match (shown as "How we detect it"). */
  detects: string[];
  /** Manual verification steps a reader can do in under a minute. */
  verify: string[];
  alternatives: Array<{ name: string; slug: string }>;
  faqs: TechFaq[];
  related: Array<{ name: string; slug: string }>;
}

const WP_ALTS = [
  { name: 'Drupal', slug: 'drupal' },
  { name: 'Ghost', slug: 'ghost' },
  { name: 'Webflow', slug: 'webflow' },
];

export const TECHNOLOGIES: TechContent[] = [
  // ---------------------------------------------------------- CMS ----
  {
    slug: 'wordpress',
    name: 'WordPress',
    category: 'cms',
    tagline: 'The open-source CMS powering over 40% of the web.',
    metaTitle: 'How to Tell If a Site Uses WordPress (5 Checks)',
    metaDescription:
      'Check if any site runs WordPress: generator tags, wp-content paths, REST API. Free detector with evidence, plus manual checks.',
    about: [
      'WordPress is the most widely used content management system in the world, powering blogs, business sites, news outlets, and a large share of online stores (via WooCommerce). It is open-source, written in PHP, and extended through thousands of themes and plugins.',
      'Typical users range from solo bloggers to large publishers and agencies. Because it is so common, identifying WordPress is usually straightforward — it leaves several distinctive fingerprints in page HTML and HTTP headers.',
    ],
    detects: [
      'Generator meta tag (<meta name="generator" content="WordPress …">)',
      'Asset paths containing /wp-content/ or /wp-includes/',
      'Link header pointing at the WP REST API (api.w.org)',
      'WordPress session cookies (wordpress_, wp-settings-)',
      'REST API probe (/wp-json/) and theme stylesheet (style.css)',
    ],
    verify: [
      'View page source (Ctrl+U) and search for "wp-content" — a match means WordPress assets are loading.',
      'Open example.com/wp-json/ in your browser. A JSON response listing "namespaces" confirms WordPress.',
      'Right-click the page, inspect the <head>, and look for a generator meta tag naming WordPress and its version.',
    ],
    alternatives: WP_ALTS,
    faqs: [
      {
        q: 'Can a WordPress site hide that it uses WordPress?',
        a: 'Partially. Security plugins can remove the generator tag and rename paths, but the REST API, feed URLs, and plugin asset paths usually remain. A hidden setup may reduce our confidence, but rarely eliminates every signal.',
      },
      {
        q: 'Does detecting WordPress also detect the theme?',
        a: 'Yes, when the theme stylesheet is reachable. We read the Theme Name, Author, and Version directly from the active theme’s style.css file.',
      },
      {
        q: 'Is WordPress.com the same as WordPress?',
        a: 'No. WordPress.com is a hosted service built on WordPress software. Self-hosted WordPress.org sites are far more common and fully detectable with the checks above.',
      },
    ],
    related: [
      { name: 'WooCommerce', slug: 'woocommerce' },
      { name: 'WP Engine', slug: 'wp-engine' },
      { name: 'Drupal', slug: 'drupal' },
    ],
  },
  {
    slug: 'drupal',
    name: 'Drupal',
    category: 'cms',
    tagline: 'Enterprise-grade open-source CMS for complex, high-security sites.',
    metaTitle: 'How to Tell If a Site Uses Drupal (4 Checks)',
    metaDescription:
      'Spot Drupal via generator tags, X-Drupal-Cache headers, and Drupal.settings. Free evidence-based detector plus manual checks.',
    about: [
      'Drupal is an open-source CMS favoured by governments, universities, and large enterprises that need granular permissions, multilingual content, and strong security practices. It is written in PHP on top of Symfony components.',
      'Drupal sites often serve authenticated, personalised content, so some fingerprints (like cache headers) only appear on anonymous page views.',
    ],
    detects: [
      'Generator meta tag naming Drupal and its version',
      'X-Drupal-Cache and X-Generator response headers',
      'Drupal.settings JavaScript object in page HTML',
      'Drupal session cookie names',
    ],
    verify: [
      'View source and search for "Drupal.settings" or "drupal.js".',
      'Open DevTools → Network, reload, and look for x-drupal-cache or x-generator response headers.',
      'Try example.com/node — Drupal’s classic content path often resolves or redirects meaningfully.',
    ],
    alternatives: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'TYPO3', slug: 'typo3' },
      { name: 'Craft CMS', slug: 'craft-cms' },
    ],
    faqs: [
      {
        q: 'Why do some Drupal sites show no generator tag?',
        a: 'Hardened Drupal installations routinely remove the generator metatag. Headers and JavaScript settings objects are harder to strip, so we check those too.',
      },
      {
        q: 'Can you detect the Drupal version?',
        a: 'Sometimes. The generator tag and change-log files can expose it, but security-conscious sites hide version details. We report a version only when we see direct evidence.',
      },
      {
        q: 'Is Drupal still widely used?',
        a: 'Yes — especially in government, higher education, and enterprise. Its market share is smaller than WordPress but stable in those sectors.',
      },
    ],
    related: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'TYPO3', slug: 'typo3' },
      { name: 'Acquia / Cloudflare hosting', slug: 'cloudflare' },
    ],
  },
  {
    slug: 'joomla',
    name: 'Joomla',
    category: 'cms',
    tagline: 'Flexible open-source CMS popular with community and membership sites.',
    metaTitle: 'How to Tell If a Site Uses Joomla (4 Checks)',
    metaDescription:
      'Identify Joomla via its generator tag, /media/jui/ paths, and session cookies. Free detector with evidence and manual checks.',
    about: [
      'Joomla is an open-source CMS that sits between WordPress and Drupal in complexity, with strong multilingual support and access-control lists built in. It powers community portals, directories, and small-business sites.',
      'Joomla’s generator tag is its clearest fingerprint; hardened sites may remove it, leaving media paths and scripts as secondary evidence.',
    ],
    detects: [
      'Generator meta tag ("Joomla! - Open Source Content Management")',
      'Asset paths under /media/jui/, /media/system/, /components/com_',
      'Joomla JavaScript files and 32-character session cookie names',
    ],
    verify: [
      'View source and search for "joomla" — media and component paths are distinctive.',
      'Check the <head> for a generator meta tag naming Joomla.',
      'Look at cookies in DevTools → Application: a 32-hex-character session cookie is a Joomla hallmark.',
    ],
    alternatives: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Drupal', slug: 'drupal' },
      { name: 'TYPO3', slug: 'typo3' },
    ],
    faqs: [
      {
        q: 'What is the fastest Joomla check?',
        a: 'View source and search for "/media/jui/". That path prefix is specific to Joomla’s bundled interface assets.',
      },
      {
        q: 'Can the Joomla version be detected?',
        a: 'The generator tag sometimes includes it, but most maintained sites hide it. We only report a version with direct evidence.',
      },
      {
        q: 'Is Joomla still actively developed?',
        a: 'Yes. Joomla 4 and 5 modernised the codebase significantly, and it remains a solid choice for membership and directory sites.',
      },
    ],
    related: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Drupal', slug: 'drupal' },
      { name: 'Cloudflare', slug: 'cloudflare' },
    ],
  },
  {
    slug: 'ghost',
    name: 'Ghost',
    category: 'cms',
    tagline: 'Minimal publishing platform for blogs, newsletters, and memberships.',
    metaTitle: 'How to Tell If a Site Uses Ghost (3 Checks)',
    metaDescription:
      'Detect Ghost via its generator tag, /ghost/ admin paths, and image URLs. Free evidence-based check plus manual steps.',
    about: [
      'Ghost is a Node.js publishing platform built for professional bloggers, newsletters, and paid-membership publications. It pairs a clean editor with built-in subscriptions and email delivery.',
      'Ghost sites are fast and minimal, which means fewer fingerprints — but the generator tag and admin path are highly distinctive when present.',
    ],
    detects: [
      'Generator meta tag naming Ghost and its version',
      'Admin and asset paths under /ghost/ and /content/images/',
      'X-Ghost-Cache-Status response header',
    ],
    verify: [
      'View source and search for "ghost" — the generator tag usually names the exact version.',
      'Append /ghost/ to the domain: Ghost’s admin screen confirms the platform instantly.',
      'Inspect image URLs: /content/images/ paths are Ghost’s default upload location.',
    ],
    alternatives: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Webflow', slug: 'webflow' },
      { name: 'Framer', slug: 'framer' },
    ],
    faqs: [
      {
        q: 'Does /ghost/ always exist on Ghost sites?',
        a: 'On standard installs, yes — it serves the admin interface. Some hosts remap it, but the generator tag usually remains.',
      },
      {
        q: 'Is Ghost good for SEO?',
        a: 'Yes. Ghost outputs clean semantic HTML, fast pages, and automatic structured data, which is a solid technical SEO baseline.',
      },
      {
        q: 'Can Ghost power a whole business site, not just a blog?',
        a: 'Absolutely — with themes, memberships, and integrations it runs full publications and documentation sites.',
      },
    ],
    related: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Cloudflare', slug: 'cloudflare' },
      { name: 'Fastly', slug: 'fastly' },
    ],
  },
  {
    slug: 'typo3',
    name: 'TYPO3',
    category: 'cms',
    tagline: 'Enterprise CMS of choice for European corporations and agencies.',
    metaTitle: 'How to Tell If a Site Uses TYPO3 (3 Checks)',
    metaDescription:
      'Spot TYPO3 via /typo3conf/ paths, its generator tag, and backend fingerprints. Free detector with evidence.',
    about: [
      'TYPO3 is an open-source enterprise CMS with deep roots in Europe, used for corporate sites, intranets, and multi-site installations that need strict editorial workflows.',
      'Its /typo3conf/ and /typo3temp/ asset paths are unusual enough to be near-conclusive on their own.',
    ],
    detects: [
      'Asset paths under /typo3/, /typo3conf/, /typo3temp/',
      'Generator meta tag naming TYPO3',
      'TYPO3 backend JavaScript markers',
    ],
    verify: [
      'View source and search for "typo3conf" — this directory only exists on TYPO3 sites.',
      'Look for the generator meta tag in the page <head>.',
      'Try example.com/typo3/ — the backend login screen confirms the platform.',
    ],
    alternatives: [
      { name: 'Drupal', slug: 'drupal' },
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Umbraco', slug: 'umbraco' },
    ],
    faqs: [
      {
        q: 'Where is TYPO3 most popular?',
        a: 'Germany, the Netherlands, and Scandinavia, especially for corporate and public-sector sites built by specialised agencies.',
      },
      {
        q: 'Can TYPO3 versions be detected remotely?',
        a: 'Sometimes via the generator tag, but maintained enterprise sites hide it. We report versions only with direct evidence.',
      },
      {
        q: 'TYPO3 vs Drupal — how to choose?',
        a: 'Both serve enterprise needs; TYPO3 dominates in German-speaking markets with strong agency ecosystems, while Drupal leads in English-speaking government and higher education.',
      },
    ],
    related: [
      { name: 'Drupal', slug: 'drupal' },
      { name: 'Umbraco', slug: 'umbraco' },
      { name: 'WordPress', slug: 'wordpress' },
    ],
  },
  {
    slug: 'craft-cms',
    name: 'Craft CMS',
    category: 'cms',
    tagline: 'Developer-loved CMS for bespoke, content-rich websites.',
    metaTitle: 'How to Tell If a Site Uses Craft CMS (3 Checks)',
    metaDescription:
      'Detect Craft CMS via its powered-by header, CraftSessionId cookies, and control-panel paths. Free evidence-based check.',
    about: [
      'Craft CMS is a commercial CMS (built on Yii/PHP) prized by agencies for fully custom front-ends — no forced theming layer. It powers portfolio sites, hospitality brands, and editorial properties.',
      'Craft deliberately exposes few front-end fingerprints, so its response headers and cookies carry most of the signal.',
    ],
    detects: [
      'X-Powered-By header naming Craft CMS',
      'CraftSessionId and CRAFT_CSRF_TOKEN cookies',
      'Control-panel paths (/admin, /cpresources/) when exposed',
    ],
    verify: [
      'Open DevTools → Network, reload, and inspect response headers for x-powered-by: Craft CMS.',
      'Check DevTools → Application → Cookies for CraftSessionId.',
      'View source for "cpresources" — Craft’s control-panel resource path.',
    ],
    alternatives: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Webflow', slug: 'webflow' },
      { name: 'Drupal', slug: 'drupal' },
    ],
    faqs: [
      {
        q: 'Why is Craft CMS hard to detect from HTML alone?',
        a: 'Craft renders fully custom templates with no mandatory markup, so front-end fingerprints are minimal by design. Headers and cookies are the reliable channel.',
      },
      {
        q: 'Is Craft CMS free?',
        a: 'Craft offers a free Solo plan; Pro and Enterprise tiers add multi-site, workflows, and support.',
      },
      {
        q: 'Who typically builds with Craft?',
        a: 'Design-led agencies and in-house teams that want complete template control without fighting a theme system.',
      },
    ],
    related: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Webflow', slug: 'webflow' },
      { name: 'Cloudflare', slug: 'cloudflare' },
    ],
  },
  {
    slug: 'umbraco',
    name: 'Umbraco',
    category: 'cms',
    tagline: 'Friendly .NET CMS for organisations standardised on Microsoft.',
    metaTitle: 'How to Tell If a Site Uses Umbraco (3 Checks)',
    metaDescription:
      'Identify Umbraco via its version header, /umbraco/ paths, and context cookies. Free detector with evidence.',
    about: [
      'Umbraco is an open-source CMS built on .NET, popular with organisations that run Microsoft infrastructure. It balances editor-friendliness with developer control.',
      'Its dedicated version header makes confident detection easy when the site hasn’t stripped headers at the proxy layer.',
    ],
    detects: [
      'X-Umbraco-Version response header',
      'Backend paths under /umbraco/',
      'UMB_UCONTEXT and UMB-XSRF-TOKEN cookies',
    ],
    verify: [
      'Inspect response headers in DevTools → Network for x-umbraco-version.',
      'View source and search for "/umbraco/".',
      'Check cookies for UMB_UCONTEXT.',
    ],
    alternatives: [
      { name: 'Sitecore', slug: 'sitecore' },
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Drupal', slug: 'drupal' },
    ],
    faqs: [
      {
        q: 'Is Umbraco only for Windows hosting?',
        a: 'No — modern Umbraco runs on cross-platform .NET and can be hosted on Linux containers as well as Azure App Service.',
      },
      {
        q: 'Umbraco vs Sitecore?',
        a: 'Umbraco is open-source and lighter-weight; Sitecore is an enterprise digital-experience platform with marketing tooling. Budget and personalisation needs usually decide.',
      },
      {
        q: 'Can the Umbraco version be hidden?',
        a: 'Yes — stripping the version header at the CDN or proxy is common hardening. Cookie and path signals then carry the detection.',
      },
    ],
    related: [
      { name: 'Sitecore', slug: 'sitecore' },
      { name: 'Cloudflare', slug: 'cloudflare' },
      { name: 'AWS CloudFront', slug: 'aws-cloudfront' },
    ],
  },
  {
    slug: 'hubspot-cms',
    name: 'HubSpot CMS',
    category: 'cms',
    tagline: 'CRM-powered CMS (Content Hub) for inbound marketing teams.',
    metaTitle: 'How to Tell If a Site Uses HubSpot CMS (3 Checks)',
    metaDescription:
      'Spot HubSpot CMS via hs-scripts, HubSpot headers, and tracking code. Free evidence-based detector.',
    about: [
      'HubSpot’s CMS (now Content Hub) bundles hosting, CRM data, and marketing automation, targeting B2B teams that want personalisation without managing infrastructure.',
      'Its analytics and forms scripts load on nearly every HubSpot page, making script-host evidence the strongest channel.',
    ],
    detects: [
      'Scripts from js.hs-scripts.com, js.hsforms.net, hs-analytics.net',
      'X-HS-CF-Cache-Status and HubSpot cache headers',
      'HubSpot embed markers (hbspt.) in page HTML',
    ],
    verify: [
      'View source and search for "hs-scripts" — HubSpot’s tracking script is near-universal on its CMS.',
      'Inspect response headers for x-hs-cf-cache-status.',
      'Look for HubSpot forms embeds (hbspt.forms.create) in the page source.',
    ],
    alternatives: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Webflow', slug: 'webflow' },
      { name: 'Squarespace', slug: 'squarespace' },
    ],
    faqs: [
      {
        q: 'Does HubSpot tracking code alone prove HubSpot CMS?',
        a: 'Not by itself — WordPress sites often add HubSpot tracking too. We weigh CMS-specific headers and hosting markers before calling it.',
      },
      {
        q: 'Is HubSpot CMS good for SEO?',
        a: 'It handles technical basics (SSL, CDN, sitemaps) automatically. Content quality and site structure still determine rankings.',
      },
      {
        q: 'Can you leave HubSpot CMS with your content?',
        a: 'Export options exist but migrations take planning, especially for smart content and CRM-driven personalisation.',
      },
    ],
    related: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Webflow', slug: 'webflow' },
      { name: 'Cloudflare', slug: 'cloudflare' },
    ],
  },
  {
    slug: 'sitecore',
    name: 'Sitecore',
    category: 'cms',
    tagline: 'Enterprise digital-experience platform for personalisation at scale.',
    metaTitle: 'How to Tell If a Site Uses Sitecore (3 Checks)',
    metaDescription:
      'Detect Sitecore via its cookies, shell paths, and page-mode headers. Free evidence-based check.',
    about: [
      'Sitecore is an enterprise DXP combining CMS, commerce, and marketing personalisation. It serves large brands with complex, multi-market content operations.',
      'Front-end output is fully custom, so detection leans on cookies and platform headers rather than markup.',
    ],
    detects: [
      'SC_ANALYTICS_GLOBAL_COOKIE and sitecore_ cookies',
      'Sitecore shell and handler paths in HTML',
      'X-Sitecore-Page-Mode response header',
    ],
    verify: [
      'Check DevTools → Application → Cookies for SC_ANALYTICS_GLOBAL_COOKIE.',
      'View source and search for "sitecore".',
      'Inspect response headers for x-sitecore-page-mode.',
    ],
    alternatives: [
      { name: 'Umbraco', slug: 'umbraco' },
      { name: 'Drupal', slug: 'drupal' },
      { name: 'Contentful-backed site', slug: 'contentful' },
    ],
    faqs: [
      {
        q: 'Sitecore XM vs XP — does detection differ?',
        a: 'Both share cookie and header fingerprints. Headless XM Cloud setups expose fewer markers, which we report transparently.',
      },
      {
        q: 'Why do Sitecore sites rarely show a generator tag?',
        a: 'Enterprise Sitecore builds use fully custom rendering hosts, so generator tags are absent by default rather than stripped.',
      },
      {
        q: 'Is Sitecore headless now?',
        a: 'Increasingly — XM Cloud and headless SXA separate content delivery from the CMS, which reduces detectable surface.',
      },
    ],
    related: [
      { name: 'Umbraco', slug: 'umbraco' },
      { name: 'Contentful-backed site', slug: 'contentful' },
      { name: 'Akamai', slug: 'akamai' },
    ],
  },
  {
    slug: 'contentful',
    name: 'Contentful-backed site',
    category: 'cms',
    tagline: 'Headless content infrastructure behind custom front-ends.',
    metaTitle: 'How to Tell If a Site Uses Contentful (3 Checks)',
    metaDescription:
      'Spot Contentful-backed sites via ctfassets image URLs and delivery API hosts. Free evidence-based check.',
    about: [
      'Contentful is a headless CMS: editors manage content in its app while developers render it through any framework. What visitors see is fully custom, so detection focuses on asset and API hosts.',
      'Image URLs on images.ctfassets.net are the clearest public fingerprint.',
    ],
    detects: [
      'Image and asset URLs on images.ctfassets.net / assets.ctfassets.net',
      'Delivery API host cdn.contentful.com in scripts or data',
      'Contentful SDK references in JavaScript bundles',
    ],
    verify: [
      'View source and search for "ctfassets" — image URLs are the giveaway.',
      'Open DevTools → Network → Img and look for ctfassets.net hosts.',
      'Search bundled JS for "cdn.contentful.com".',
    ],
    alternatives: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Ghost', slug: 'ghost' },
      { name: 'Next.js', slug: 'nextjs' },
    ],
    faqs: [
      {
        q: 'Can you detect Contentful when images use a custom CDN?',
        a: 'Sometimes not — a custom image proxy removes the clearest signal. API hosts in JavaScript may still reveal it.',
      },
      {
        q: 'Does Contentful detection include the front-end framework?',
        a: 'Separately, yes. We report the framework (e.g. Next.js) alongside the Contentful evidence when both are visible.',
      },
      {
        q: 'Contentful vs traditional CMS?',
        a: 'Contentful suits multi-channel publishing (web, apps, IoT) with developer teams; traditional CMSs are faster for template-driven marketing sites.',
      },
    ],
    related: [
      { name: 'Next.js', slug: 'nextjs' },
      { name: 'Gatsby', slug: 'gatsby' },
      { name: 'Vercel', slug: 'vercel' },
    ],
  },

  // ------------------------------------------------------ Builders ----
  {
    slug: 'wix',
    name: 'Wix',
    category: 'builder',
    tagline: 'Drag-and-drop website builder for small businesses.',
    metaTitle: 'How to Tell If a Site Uses Wix (3 Checks)',
    metaDescription:
      'Identify Wix via its generator tag, wixstatic assets, and request headers. Free evidence-based detector.',
    about: [
      'Wix is a hosted website builder aimed at small businesses, restaurants, and portfolios — no code or hosting management required.',
      'Wix pages load distinctive runtime scripts and static assets, making detection reliable even without the generator tag.',
    ],
    detects: [
      'Generator meta tag ("Wix.com Website Builder")',
      'Assets from static.wixstatic.com / parastorage',
      'X-Wix-Request-Id response header',
    ],
    verify: [
      'View source and search for "wixstatic" or "parastorage".',
      'Check the generator meta tag in the page <head>.',
      'Inspect response headers for x-wix-request-id.',
    ],
    alternatives: [
      { name: 'Squarespace', slug: 'squarespace' },
      { name: 'Webflow', slug: 'webflow' },
      { name: 'WordPress', slug: 'wordpress' },
    ],
    faqs: [
      {
        q: 'Can Wix sites hide the builder fingerprints?',
        a: 'Effectively no — the runtime and asset hosts are required for the page to function, so they remain visible.',
      },
      {
        q: 'Is Wix good for SEO?',
        a: 'Wix covers technical basics well. Competitive niches still depend on content, links, and site structure.',
      },
      {
        q: 'Can you tell which Wix template a site uses?',
        a: 'Not reliably — templates converge once customised, so we report the platform rather than guessing the template.',
      },
    ],
    related: [
      { name: 'Squarespace', slug: 'squarespace' },
      { name: 'Webflow', slug: 'webflow' },
      { name: 'GoDaddy Website Builder', slug: 'godaddy-builder' },
    ],
  },
  {
    slug: 'squarespace',
    name: 'Squarespace',
    category: 'builder',
    tagline: 'Design-led builder favoured by creatives and portfolios.',
    metaTitle: 'How to Tell If a Site Uses Squarespace (3 Checks)',
    metaDescription:
      'Spot Squarespace via its CDN hosts, generator tag, and cookies. Free evidence-based detector with manual checks.',
    about: [
      'Squarespace targets photographers, designers, restaurants, and boutiques with polished templates and built-in commerce.',
      'Its static asset CDN and template framework markers are consistent across versions 7.0 and 7.1.',
    ],
    detects: [
      'Assets from static1.squarespace.com / squarespace-cdn.com',
      'Generator meta tag naming Squarespace',
      'Squarespace session cookies',
    ],
    verify: [
      'View source and search for "squarespace-cdn" or "static1.squarespace".',
      'Check the generator meta tag in the <head>.',
      'Append /config to the URL — Squarespace’s login redirect confirms the platform.',
    ],
    alternatives: [
      { name: 'Wix', slug: 'wix' },
      { name: 'Webflow', slug: 'webflow' },
      { name: 'Framer', slug: 'framer' },
    ],
    faqs: [
      {
        q: 'Squarespace 7.0 vs 7.1 — can you tell?',
        a: 'Often, from template and asset markers, but both report as Squarespace with the version detail in evidence when visible.',
      },
      {
        q: 'Does /config always work?',
        a: 'On standard Squarespace sites it redirects to login. Custom enterprise setups may disable it.',
      },
      {
        q: 'Is Squarespace good for blogging?',
        a: 'Yes for simple blogs. Heavy editorial workflows usually outgrow it toward WordPress or Ghost.',
      },
    ],
    related: [
      { name: 'Wix', slug: 'wix' },
      { name: 'Webflow', slug: 'webflow' },
      { name: 'Framer', slug: 'framer' },
    ],
  },
  {
    slug: 'webflow',
    name: 'Webflow',
    category: 'builder',
    tagline: 'Visual development platform for designer-built marketing sites.',
    metaTitle: 'How to Tell If a Site Uses Webflow (3 Checks)',
    metaDescription:
      'Detect Webflow via website-files assets, webflow.js, and its generator tag. Free detector with evidence.',
    about: [
      'Webflow lets designers build production sites visually while exporting clean HTML, CSS, and JS. It is popular for SaaS marketing sites and agency work.',
      'Its asset CDN and engine script are consistent fingerprints across hosted and exported sites.',
    ],
    detects: [
      'Assets from assets.website-files.com',
      'webflow.js engine script and Webflow generator tag',
      'uploads-ssl.webflow.com image hosts',
    ],
    verify: [
      'View source and search for "website-files" or "webflow.js".',
      'Check the generator meta tag — Webflow stamps it by default.',
      'Inspect image URLs for uploads-ssl.webflow.com.',
    ],
    alternatives: [
      { name: 'Framer', slug: 'framer' },
      { name: 'Squarespace', slug: 'squarespace' },
      { name: 'WordPress', slug: 'wordpress' },
    ],
    faqs: [
      {
        q: 'Can exported Webflow sites still be detected?',
        a: 'Usually yes — webflow.js and asset references typically survive export unless deliberately cleaned.',
      },
      {
        q: 'Is Webflow good for SEO?',
        a: 'Yes. Clean code output, fast hosting, and full meta control give a strong technical baseline.',
      },
      {
        q: 'Webflow vs Framer?',
        a: 'Webflow offers deeper CMS and logic features; Framer is faster for turning Figma-like designs into live pages.',
      },
    ],
    related: [
      { name: 'Framer', slug: 'framer' },
      { name: 'Squarespace', slug: 'squarespace' },
      { name: 'Fastly', slug: 'fastly' },
    ],
  },
  {
    slug: 'framer',
    name: 'Framer',
    category: 'builder',
    tagline: 'Design-to-site builder turning mockups into live pages.',
    metaTitle: 'How to Tell If a Site Uses Framer (3 Checks)',
    metaDescription:
      'Spot Framer via framerusercontent assets and its generator tag. Free evidence-based detector.',
    about: [
      'Framer converts designs into live React-powered sites with hosting included, popular for startup landing pages and portfolios.',
      'Its asset pipeline leaves consistent framerusercontent.com references.',
    ],
    detects: [
      'Assets from framerusercontent.com',
      'Framer generator meta tag',
      'Framer runtime scripts in page HTML',
    ],
    verify: [
      'View source and search for "framerusercontent".',
      'Check the generator meta tag in the <head>.',
      'Inspect scripts for Framer’s runtime chunks.',
    ],
    alternatives: [
      { name: 'Webflow', slug: 'webflow' },
      { name: 'Carrd', slug: 'carrd' },
      { name: 'Squarespace', slug: 'squarespace' },
    ],
    faqs: [
      {
        q: 'Framer vs Webflow — which is easier to detect?',
        a: 'Both are easy; Framer’s asset host is slightly more distinctive because fewer third parties use it.',
      },
      {
        q: 'Are Framer sites good for SEO?',
        a: 'Framer handles basics (meta, sitemap, SSL) well for landing pages. Large content sites usually need a CMS instead.',
      },
      {
        q: 'Can Framer sites use custom domains?',
        a: 'Yes — detection still works because asset hosts don’t change with the domain.',
      },
    ],
    related: [
      { name: 'Webflow', slug: 'webflow' },
      { name: 'Carrd', slug: 'carrd' },
      { name: 'Vercel', slug: 'vercel' },
    ],
  },
  {
    slug: 'weebly',
    name: 'Weebly',
    category: 'builder',
    tagline: 'Simple builder (by Square) for small stores and sites.',
    metaTitle: 'How to Tell If a Site Uses Weebly (3 Checks)',
    metaDescription:
      'Identify Weebly via its generator tag and editmysite assets. Free evidence-based detector.',
    about: [
      'Weebly, owned by Square, serves very small businesses that want a site and simple store with minimal setup.',
      'Its editmysite.com asset hosts are the most durable fingerprint.',
    ],
    detects: [
      'Generator meta tag naming Weebly',
      'Assets from editmysite.com / Weebly CDN hosts',
      'Weebly editor markers in HTML',
    ],
    verify: [
      'View source and search for "editmysite" or "weebly".',
      'Check the generator meta tag.',
      'Inspect script hosts for Weebly CDN domains.',
    ],
    alternatives: [
      { name: 'Wix', slug: 'wix' },
      { name: 'GoDaddy Website Builder', slug: 'godaddy-builder' },
      { name: 'SITE123', slug: 'site123' },
    ],
    faqs: [
      {
        q: 'Is Weebly the same as Square Online?',
        a: 'Square Online grew out of Weebly technology. Classic Weebly sites keep the editmysite fingerprints.',
      },
      {
        q: 'Should new sites still choose Weebly?',
        a: 'Only for the simplest needs — Wix, Squarespace, and Carrd now cover the same ground with more active development.',
      },
      {
        q: 'Can Weebly be self-hosted?',
        a: 'No — it is a hosted builder, which is exactly why its asset hosts are such reliable signals.',
      },
    ],
    related: [
      { name: 'Wix', slug: 'wix' },
      { name: 'SITE123', slug: 'site123' },
      { name: 'Jimdo', slug: 'jimdo' },
    ],
  },
  {
    slug: 'godaddy-builder',
    name: 'GoDaddy Website Builder',
    category: 'builder',
    tagline: 'GoDaddy’s hosted builder for quick small-business sites.',
    metaTitle: 'How to Tell If a Site Uses GoDaddy Builder (3 Checks)',
    metaDescription:
      'Detect GoDaddy Website Builder via SITEPAD headers and builder markers. Free evidence-based check.',
    about: [
      'GoDaddy’s Website Builder (formerly GoCentral) offers template-driven sites bundled with domain and hosting for businesses that want everything in one account.',
      'Server headers and builder runtime markers provide the clearest signals.',
    ],
    detects: [
      'Server header identifying SITEPAD infrastructure',
      'GoDaddy builder runtime markers in HTML',
      'Generator tag naming the builder',
    ],
    verify: [
      'Inspect response headers for the server signature.',
      'View source and search for "godaddy" builder paths.',
      'Check the generator meta tag.',
    ],
    alternatives: [
      { name: 'Wix', slug: 'wix' },
      { name: 'Weebly', slug: 'weebly' },
      { name: 'SITE123', slug: 'site123' },
    ],
    faqs: [
      {
        q: 'Builder vs WordPress hosting from GoDaddy — how to tell?',
        a: 'GoDaddy also sells WordPress hosting, which detects as WordPress. The SITEPAD markers specifically indicate the Website Builder product.',
      },
      {
        q: 'Can you migrate off GoDaddy Builder easily?',
        a: 'With effort — builder content doesn’t export cleanly, so plan a manual rebuild on the new platform.',
      },
      {
        q: 'Is it good for SEO?',
        a: 'Adequate for local brochure sites. Competitive content strategies usually move to WordPress or Webflow.',
      },
    ],
    related: [
      { name: 'Wix', slug: 'wix' },
      { name: 'Weebly', slug: 'weebly' },
      { name: 'SITE123', slug: 'site123' },
    ],
  },
  {
    slug: 'jimdo',
    name: 'Jimdo',
    category: 'builder',
    tagline: 'European builder for small businesses and Dolphin AI sites.',
    metaTitle: 'How to Tell If a Site Uses Jimdo (2 Checks)',
    metaDescription:
      'Spot Jimdo via jimdocdn assets and its generator tag. Free evidence-based detector.',
    about: [
      'Jimdo is a German website builder popular with European small businesses, offering both a classic editor and an AI-assisted Dolphin builder.',
      'Its CDN hostnames are consistent across both product lines.',
    ],
    detects: [
      'Assets from jimdocdn.com / static.jimdo.com',
      'Generator meta tag naming Jimdo',
    ],
    verify: [
      'View source and search for "jimdo".',
      'Inspect image and script hosts for jimdocdn.com.',
    ],
    alternatives: [
      { name: 'Wix', slug: 'wix' },
      { name: 'Weebly', slug: 'weebly' },
      { name: 'SITE123', slug: 'site123' },
    ],
    faqs: [
      {
        q: 'Jimdo Creator vs Dolphin — detectable difference?',
        a: 'Both report as Jimdo; asset patterns may hint at the variant, which we include in evidence when visible.',
      },
      {
        q: 'Is Jimdo popular outside Europe?',
        a: 'Less so — its strength is German-speaking markets with localised support and legal templates.',
      },
      {
        q: 'Can Jimdo sites use custom domains?',
        a: 'Yes, and detection still works because the CDN hosts stay the same.',
      },
    ],
    related: [
      { name: 'Wix', slug: 'wix' },
      { name: 'SITE123', slug: 'site123' },
      { name: 'Strikingly', slug: 'strikingly' },
    ],
  },
  {
    slug: 'strikingly',
    name: 'Strikingly',
    category: 'builder',
    tagline: 'One-page builder for quick landing pages.',
    metaTitle: 'How to Tell If a Site Uses Strikingly (2 Checks)',
    metaDescription:
      'Detect Strikingly via its CDN hosts and generator tag. Free evidence-based check.',
    about: [
      'Strikingly specialises in single-page sites — event pages, resumes, and MVPs — with a very fast path from signup to published page.',
      'Its CDN hostnames are the primary fingerprint.',
    ],
    detects: [
      'Assets from strikinglycdn.com / s.strikingly.com',
      'Generator meta tag naming Strikingly',
    ],
    verify: [
      'View source and search for "strikingly".',
      'Inspect asset hosts for the Strikingly CDN.',
    ],
    alternatives: [
      { name: 'Carrd', slug: 'carrd' },
      { name: 'Google Sites', slug: 'google-sites' },
      { name: 'Jimdo', slug: 'jimdo' },
    ],
    faqs: [
      {
        q: 'Is Strikingly only for one-page sites?',
        a: 'Mostly — multi-section single pages are its sweet spot; it also supports simple stores and blogs.',
      },
      {
        q: 'Strikingly vs Carrd?',
        a: 'Carrd is cheaper and more minimal; Strikingly offers more built-in sections and commerce for simple needs.',
      },
      {
        q: 'Are Strikingly sites fast?',
        a: 'Generally yes — single-page output with CDN assets keeps load times low.',
      },
    ],
    related: [
      { name: 'Carrd', slug: 'carrd' },
      { name: 'Google Sites', slug: 'google-sites' },
      { name: 'Jimdo', slug: 'jimdo' },
    ],
  },
  {
    slug: 'google-sites',
    name: 'Google Sites',
    category: 'builder',
    tagline: 'Google’s free builder for simple team and project pages.',
    metaTitle: 'How to Tell If a Site Uses Google Sites (2 Checks)',
    metaDescription:
      'Identify Google Sites via sites.google hosts and page structure. Free evidence-based detector.',
    about: [
      'Google Sites is a free, no-frills builder inside Google Workspace, used for intranets, classroom pages, and quick project sites.',
      'Hosting on Google infrastructure with classic sites.google URL patterns makes it recognisable.',
    ],
    detects: [
      'Hosts under sites.google.com and gstatic sites paths',
      'Google Sites viewer scripts in page HTML',
    ],
    verify: [
      'Check the URL — sites.google.com/view/ addresses are definitive.',
      'View source and search for "sites.google".',
      'For custom domains, inspect scripts for Google Sites viewer code.',
    ],
    alternatives: [
      { name: 'Strikingly', slug: 'strikingly' },
      { name: 'Carrd', slug: 'carrd' },
      { name: 'WordPress', slug: 'wordpress' },
    ],
    faqs: [
      {
        q: 'Can Google Sites use a custom domain?',
        a: 'Yes via Workspace mapping — the underlying Google hosts still reveal the platform.',
      },
      {
        q: 'Is Google Sites good for SEO?',
        a: 'It gets indexed fine, but limited meta control and structure make it a poor choice for competitive SEO.',
      },
      {
        q: 'Classic vs new Google Sites — does it matter?',
        a: 'Both detect as Google Sites; new Sites pages use the viewer runtime we match on.',
      },
    ],
    related: [
      { name: 'Strikingly', slug: 'strikingly' },
      { name: 'Carrd', slug: 'carrd' },
      { name: 'Wix', slug: 'wix' },
    ],
  },
  {
    slug: 'carrd',
    name: 'Carrd',
    category: 'builder',
    tagline: 'Ultra-simple one-page sites, from free to nearly free.',
    metaTitle: 'How to Tell If a Site Uses Carrd (2 Checks)',
    metaDescription:
      'Spot Carrd via its generator tag and carrd.co assets. Free evidence-based detector.',
    about: [
      'Carrd builds single-page sites — link-in-bio pages, waitlists, and portfolios — with famously low pricing and minimal overhead.',
      'Its generator tag and asset hosts are explicit by default.',
    ],
    detects: [
      'Generator meta tag naming Carrd',
      'Assets from assets.carrd.co',
    ],
    verify: [
      'View source and search for "carrd" — the generator tag is usually present.',
      'Check script and asset hosts for carrd.co domains.',
    ],
    alternatives: [
      { name: 'Strikingly', slug: 'strikingly' },
      { name: 'Framer', slug: 'framer' },
      { name: 'Google Sites', slug: 'google-sites' },
    ],
    faqs: [
      {
        q: 'Can the Carrd badge be removed?',
        a: 'On paid plans, yes — but the generator tag and asset hosts typically remain detectable.',
      },
      {
        q: 'Is Carrd good for SEO?',
        a: 'For single-page presence and link-in-bio use, yes. It is not a blogging or content platform.',
      },
      {
        q: 'Carrd vs Linktree?',
        a: 'Carrd offers full page design control; Linktree is a templated link list. Both suit social bios.',
      },
    ],
    related: [
      { name: 'Strikingly', slug: 'strikingly' },
      { name: 'Framer', slug: 'framer' },
      { name: 'Google Sites', slug: 'google-sites' },
    ],
  },
  {
    slug: 'site123',
    name: 'SITE123',
    category: 'builder',
    tagline: 'Guided builder promising a live site in three steps.',
    metaTitle: 'How to Tell If a Site Uses SITE123 (2 Checks)',
    metaDescription:
      'Detect SITE123 via its generator tag and static CDN. Free evidence-based check.',
    about: [
      'SITE123 targets beginners with a step-by-step setup flow covering sites, stores, and bookings in many languages.',
      'Its generator tag and static CDN hosts are consistent markers.',
    ],
    detects: [
      'Generator meta tag naming SITE123',
      'Assets from site123static.com / s123 CDN hosts',
    ],
    verify: ['View source and search for "site123".', 'Inspect asset hosts for the SITE123 static CDN.'],
    alternatives: [
      { name: 'Wix', slug: 'wix' },
      { name: 'Weebly', slug: 'weebly' },
      { name: 'Jimdo', slug: 'jimdo' },
    ],
    faqs: [
      {
        q: 'Is SITE123 free?',
        a: 'It offers a free plan with SITE123 branding; paid plans add domains and remove ads.',
      },
      {
        q: 'Who is SITE123 best for?',
        a: 'Beginners wanting a multilingual small site online fast, without design decisions.',
      },
      {
        q: 'Can SITE123 run a real store?',
        a: 'Simple stores, yes. Serious commerce usually migrates to Shopify or WooCommerce.',
      },
    ],
    related: [
      { name: 'Wix', slug: 'wix' },
      { name: 'Weebly', slug: 'weebly' },
      { name: 'Jimdo', slug: 'jimdo' },
    ],
  },

  // ---------------------------------------------------- E-commerce ----
  {
    slug: 'shopify',
    name: 'Shopify',
    category: 'ecommerce',
    tagline: 'The hosted commerce platform behind millions of stores.',
    metaTitle: 'How to Tell If a Store Uses Shopify (4 Checks)',
    metaDescription:
      'Detect Shopify via cdn.shopify.com, Shopify.theme data, and store headers. Includes theme detection.',
    about: [
      'Shopify is the leading hosted e-commerce platform, handling storefronts, checkout, and payments for brands from startups to enterprises (Shopify Plus).',
      'Because checkout and storefront infrastructure is standardised, Shopify leaves strong, consistent fingerprints.',
    ],
    detects: [
      'Storefront assets from cdn.shopify.com',
      'Shopify.theme object embedded in page HTML (theme name + ID)',
      'myshopify.com references and Shopify cookies (_shopify_, cart)',
    ],
    verify: [
      'View source and search for "cdn.shopify.com" or "myshopify".',
      'Search the source for "Shopify.theme" — it reveals the active theme name.',
      'Append /products.json to a collection URL: Shopify’s JSON API confirms the platform.',
    ],
    alternatives: [
      { name: 'WooCommerce', slug: 'woocommerce' },
      { name: 'BigCommerce', slug: 'bigcommerce' },
      { name: 'Magento / Adobe Commerce', slug: 'magento' },
    ],
    faqs: [
      {
        q: 'Can you detect the exact Shopify theme?',
        a: 'Usually yes — the Shopify.theme object names the theme, and we report the theme ID when present.',
      },
      {
        q: 'Does a Shopify buy button on WordPress count?',
        a: 'No. We distinguish full Shopify storefronts from WordPress sites that merely embed Shopify checkout buttons, and say which is which.',
      },
      {
        q: 'Shopify vs WooCommerce — how to choose?',
        a: 'Shopify trades control for convenience (hosted, fast setup); WooCommerce offers full ownership on WordPress with more maintenance.',
      },
    ],
    related: [
      { name: 'WooCommerce', slug: 'woocommerce' },
      { name: 'BigCommerce', slug: 'bigcommerce' },
      { name: 'Cloudflare', slug: 'cloudflare' },
    ],
  },
  {
    slug: 'woocommerce',
    name: 'WooCommerce',
    category: 'ecommerce',
    tagline: 'Open-source commerce plugin turning WordPress into a store.',
    metaTitle: 'How to Tell If a Site Uses WooCommerce (3 Checks)',
    metaDescription:
      'Spot WooCommerce via /plugins/woocommerce/ paths, cart scripts, and shop cookies. Free detector with evidence.',
    about: [
      'WooCommerce is the open-source e-commerce plugin for WordPress, powering a huge share of online stores that want full ownership of code and data.',
      'Every WooCommerce store is also a WordPress site — we report both, with the plugin evidence listed separately.',
    ],
    detects: [
      'Asset paths under /wp-content/plugins/woocommerce/',
      'Cart and checkout scripts (wc-add-to-cart, woocommerce.min.js)',
      'WooCommerce session cookies',
    ],
    verify: [
      'View source and search for "woocommerce" — plugin paths are conclusive.',
      'Look for cart fragments and wc-ajax endpoints in network requests.',
      'Append /shop/ or /cart/ — WooCommerce’s default pages often exist.',
    ],
    alternatives: [
      { name: 'Shopify', slug: 'shopify' },
      { name: 'BigCommerce', slug: 'bigcommerce' },
      { name: 'PrestaShop', slug: 'prestashop' },
    ],
    faqs: [
      {
        q: 'Is WooCommerce always on WordPress?',
        a: 'Yes — it is a WordPress plugin. A WooCommerce detection implies WordPress, and we report both.',
      },
      {
        q: 'WooCommerce vs Shopify costs?',
        a: 'WooCommerce software is free but you pay hosting, extensions, and maintenance time; Shopify bundles everything into a subscription.',
      },
      {
        q: 'Can headless WooCommerce be detected?',
        a: 'Harder — decoupled front-ends hide plugin paths. Store API endpoints and cookies may still reveal it.',
      },
    ],
    related: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Shopify', slug: 'shopify' },
      { name: 'WP Engine', slug: 'wp-engine' },
    ],
  },
  {
    slug: 'magento',
    name: 'Magento / Adobe Commerce',
    category: 'ecommerce',
    tagline: 'Enterprise commerce for complex catalogues (Adobe Commerce).',
    metaTitle: 'How to Tell If a Site Uses Magento (4 Checks)',
    metaDescription:
      'Detect Magento via /pub/static/ paths, Mage objects, and its generator tag. Free evidence-based check.',
    about: [
      'Magento (Adobe Commerce) serves mid-market and enterprise retailers with complex catalogues, multi-store setups, and deep customisation needs.',
      'Its static-asset pipeline and JavaScript framework leave distinctive path fingerprints.',
    ],
    detects: [
      'Asset paths under /static/, /pub/static/, /skin/frontend/, /js/mage/',
      'Mage.Cookies and Magento_ JavaScript markers',
      'Generator meta tag naming Magento',
    ],
    verify: [
      'View source and search for "/static/" versioned asset paths or "Mage.".',
      'Check the generator meta tag in the <head>.',
      'Look for requirejs-config and Magento UI component markers in scripts.',
    ],
    alternatives: [
      { name: 'Shopify', slug: 'shopify' },
      { name: 'BigCommerce', slug: 'bigcommerce' },
      { name: 'WooCommerce', slug: 'woocommerce' },
    ],
    faqs: [
      {
        q: 'Magento Open Source vs Adobe Commerce?',
        a: 'Same core fingerprints. Commerce adds cloud hosting markers and B2B modules that may appear as extra evidence.',
      },
      {
        q: 'Why do Magento detections mention versions rarely?',
        a: 'Version exposure is a known hardening step on Magento; paths and JS markers carry the detection instead.',
      },
      {
        q: 'Is Magento overkill for small stores?',
        a: 'Usually — its hosting and development costs suit established retailers with complex needs.',
      },
    ],
    related: [
      { name: 'Shopify', slug: 'shopify' },
      { name: 'BigCommerce', slug: 'bigcommerce' },
      { name: 'Fastly', slug: 'fastly' },
    ],
  },
  {
    slug: 'bigcommerce',
    name: 'BigCommerce',
    category: 'ecommerce',
    tagline: 'Hosted commerce with strong B2B and multi-storefront features.',
    metaTitle: 'How to Tell If a Site Uses BigCommerce (3 Checks)',
    metaDescription:
      'Spot BigCommerce via its CDN, stencil markers, and request headers. Free detector with evidence.',
    about: [
      'BigCommerce is a hosted e-commerce platform competing with Shopify Plus, with strengths in B2B selling and headless storefronts.',
      'Its CDN hostnames and Stencil theme markers are reliable fingerprints.',
    ],
    detects: [
      'Assets from cdn BigCommerce hosts (cdn*.bigcommerce.com)',
      'Stencil theme and template markers',
      'X-BC-SID and BigCommerce response headers',
    ],
    verify: [
      'View source and search for "bigcommerce".',
      'Inspect script and image hosts for the BigCommerce CDN.',
      'Check response headers for BigCommerce identifiers.',
    ],
    alternatives: [
      { name: 'Shopify', slug: 'shopify' },
      { name: 'Magento / Adobe Commerce', slug: 'magento' },
      { name: 'WooCommerce', slug: 'woocommerce' },
    ],
    faqs: [
      {
        q: 'BigCommerce vs Shopify?',
        a: 'Both are strong hosted options; BigCommerce differentiates on built-in B2B features and flexible APIs, Shopify on app ecosystem and ease.',
      },
      {
        q: 'Can headless BigCommerce be detected?',
        a: 'Often via API hosts and checkout domains, though confidence is lower than for Stencil storefronts.',
      },
      {
        q: 'Does BigCommerce charge transaction fees?',
        a: 'No platform transaction fees on any plan — payment processor fees still apply.',
      },
    ],
    related: [
      { name: 'Shopify', slug: 'shopify' },
      { name: 'Magento / Adobe Commerce', slug: 'magento' },
      { name: 'Akamai', slug: 'akamai' },
    ],
  },
  {
    slug: 'prestashop',
    name: 'PrestaShop',
    category: 'ecommerce',
    tagline: 'Open-source commerce strong in European markets.',
    metaTitle: 'How to Tell If a Site Uses PrestaShop (3 Checks)',
    metaDescription:
      'Identify PrestaShop via its generator tag, module paths, and cookies. Free evidence-based detector.',
    about: [
      'PrestaShop is an open-source e-commerce platform especially popular in France, Spain, and Italy for independent retailers.',
      'Its module system and theme paths provide clear fingerprints.',
    ],
    detects: [
      'Generator meta tag naming PrestaShop',
      'Module and theme asset paths',
      'PrestaShop session cookies',
    ],
    verify: [
      'View source and search for "prestashop".',
      'Check the generator meta tag.',
      'Inspect cookies for PrestaShop session names.',
    ],
    alternatives: [
      { name: 'WooCommerce', slug: 'woocommerce' },
      { name: 'OpenCart', slug: 'opencart' },
      { name: 'Shopify', slug: 'shopify' },
    ],
    faqs: [
      {
        q: 'Where is PrestaShop most used?',
        a: 'France and southern Europe, where its localisation and agency ecosystem are strongest.',
      },
      {
        q: 'PrestaShop vs WooCommerce?',
        a: 'PrestaShop is commerce-first with its own admin; WooCommerce inherits WordPress content strengths. Catalogue-first stores often prefer PrestaShop.',
      },
      {
        q: 'Is PrestaShop free?',
        a: 'The software is free; budget for hosting, modules, and maintenance.',
      },
    ],
    related: [
      { name: 'OpenCart', slug: 'opencart' },
      { name: 'WooCommerce', slug: 'woocommerce' },
      { name: 'Cloudflare', slug: 'cloudflare' },
    ],
  },
  {
    slug: 'opencart',
    name: 'OpenCart',
    category: 'ecommerce',
    tagline: 'Lightweight open-source shop software for lean catalogues.',
    metaTitle: 'How to Tell If a Site Uses OpenCart (3 Checks)',
    metaDescription:
      'Spot OpenCart via catalog/theme paths and route parameters. Free detector with evidence.',
    about: [
      'OpenCart is a long-running open-source cart favoured for small catalogues and low hosting requirements.',
      'Its catalog/view/theme paths and route= URL parameters are classic markers.',
    ],
    detects: [
      'Theme paths under /catalog/view/theme/ and /image/catalog/',
      'route=common/home URL parameters and opencart markers',
      'OCSESSID session cookie',
    ],
    verify: [
      'View page URLs for route= parameters — OpenCart’s signature pattern.',
      'View source and search for "opencart" or "/catalog/view/".',
      'Check cookies for OCSESSID.',
    ],
    alternatives: [
      { name: 'PrestaShop', slug: 'prestashop' },
      { name: 'WooCommerce', slug: 'woocommerce' },
      { name: 'Shopify', slug: 'shopify' },
    ],
    faqs: [
      {
        q: 'Is OpenCart still maintained?',
        a: 'Yes, with periodic major releases. Its extension marketplace is smaller than WooCommerce’s but covers essentials.',
      },
      {
        q: 'OpenCart vs PrestaShop?',
        a: 'OpenCart is lighter and simpler; PrestaShop offers richer built-in commerce features for growing stores.',
      },
      {
        q: 'Can OpenCart scale?',
        a: 'For modest catalogues with caching, yes. Large or complex operations usually outgrow it.',
      },
    ],
    related: [
      { name: 'PrestaShop', slug: 'prestashop' },
      { name: 'WooCommerce', slug: 'woocommerce' },
      { name: 'Cloudflare', slug: 'cloudflare' },
    ],
  },

  // ---------------------------------------------------- Frameworks ----
  {
    slug: 'nextjs',
    name: 'Next.js',
    category: 'framework',
    tagline: 'React framework for production apps and marketing sites.',
    metaTitle: 'How to Tell If a Site Uses Next.js (3 Checks)',
    metaDescription:
      'Detect Next.js via __NEXT_DATA__, /_next/static/ chunks, and headers. Free evidence-based check.',
    about: [
      'Next.js (by Vercel) is the dominant React framework, used for everything from SaaS apps to headless storefronts and content sites.',
      'Its build output paths are standardised, making detection reliable — though a framework finding never replaces CMS detection on content sites.',
    ],
    detects: [
      '__NEXT_DATA__ payload embedded in HTML',
      'Chunk paths under /_next/static/',
      'X-Powered-By: Next.js header when exposed',
    ],
    verify: [
      'View source and search for "__NEXT_DATA__" or "/_next/static/".',
      'Open DevTools → Network and look for _next chunk requests.',
      'Check response headers for Next.js identifiers.',
    ],
    alternatives: [
      { name: 'Nuxt', slug: 'nuxt' },
      { name: 'Gatsby', slug: 'gatsby' },
      { name: 'Astro', slug: 'astro' },
    ],
    faqs: [
      {
        q: 'Does Next.js mean the site has no CMS?',
        a: 'No — Next.js often renders content from a headless CMS (Contentful, Sanity, WordPress). We report both layers when visible.',
      },
      {
        q: 'Next.js vs plain React?',
        a: 'Plain React SPAs show an empty shell; Next.js typically server-renders content into the HTML, which is exactly what we analyse.',
      },
      {
        q: 'Are Next.js sites good for SEO?',
        a: 'Server-rendered Next.js pages are crawler-friendly. Client-only routes still need care with rendering and metadata.',
      },
    ],
    related: [
      { name: 'Vercel', slug: 'vercel' },
      { name: 'Nuxt', slug: 'nuxt' },
      { name: 'Contentful-backed site', slug: 'contentful' },
    ],
  },
  {
    slug: 'nuxt',
    name: 'Nuxt',
    category: 'framework',
    tagline: 'Vue framework for universal, server-rendered apps.',
    metaTitle: 'How to Tell If a Site Uses Nuxt (3 Checks)',
    metaDescription:
      'Spot Nuxt via __NUXT__ payloads, /_nuxt/ builds, and version headers. Free evidence-based check.',
    about: [
      'Nuxt is the standard Vue.js meta-framework for server-rendered sites and apps, popular with agencies and SaaS teams in the Vue ecosystem.',
      'Its build directory and state payloads are consistent fingerprints.',
    ],
    detects: [
      '__NUXT__ / __NUXT_DATA__ state payloads',
      'Build paths under /_nuxt/',
      'X-Nuxt-Version header when exposed',
    ],
    verify: [
      'View source and search for "__NUXT" or "/_nuxt/".',
      'Inspect scripts for Nuxt build chunks.',
      'Check response headers for Nuxt identifiers.',
    ],
    alternatives: [
      { name: 'Next.js', slug: 'nextjs' },
      { name: 'Gatsby', slug: 'gatsby' },
      { name: 'Astro', slug: 'astro' },
    ],
    faqs: [
      {
        q: 'Nuxt 2 vs Nuxt 3 — detectable?',
        a: 'Sometimes, from payload shapes and build paths. Both report as Nuxt with details in evidence when visible.',
      },
      {
        q: 'Is Nuxt good for content sites?',
        a: 'Yes with Nuxt Content or a headless CMS — server rendering keeps pages crawler-friendly.',
      },
      {
        q: 'Nuxt vs Next.js?',
        a: 'Largely a Vue-vs-React ecosystem choice; capabilities overlap heavily.',
      },
    ],
    related: [
      { name: 'Next.js', slug: 'nextjs' },
      { name: 'Vue admin? See Laravel', slug: 'laravel' },
      { name: 'Vercel', slug: 'vercel' },
    ],
  },
  {
    slug: 'gatsby',
    name: 'Gatsby',
    category: 'framework',
    tagline: 'React static-site generator for fast content sites.',
    metaTitle: 'How to Tell If a Site Uses Gatsby (3 Checks)',
    metaDescription:
      'Detect Gatsby via ___gatsby markers, page-data.json, and chunk names. Free evidence-based check.',
    about: [
      'Gatsby generates static React sites from CMS, markdown, or API data, historically popular for blogs and docs with excellent performance defaults.',
      'Its data-layer markers survive in production HTML.',
    ],
    detects: [
      '___gatsby global and page-data.json references',
      'Gatsby chunk and loader scripts',
      'Gatsby cache-busted static paths',
    ],
    verify: [
      'View source and search for "gatsby" — loader and chunk references appear throughout.',
      'Append page-data.json thinking: Gatsby serves per-page JSON (e.g. /about/page-data.json).',
      'Inspect scripts for gatsby-chunk-mapping.',
    ],
    alternatives: [
      { name: 'Next.js', slug: 'nextjs' },
      { name: 'Astro', slug: 'astro' },
      { name: 'Nuxt', slug: 'nuxt' },
    ],
    faqs: [
      {
        q: 'Is Gatsby still a good choice?',
        a: 'For static content sites, yes — though many teams now pick Next.js or Astro for flexible rendering.',
      },
      {
        q: 'Gatsby vs Astro?',
        a: 'Both ship fast static pages; Astro sends less JavaScript by default, while Gatsby offers a mature React plugin ecosystem.',
      },
      {
        q: 'Can Gatsby sites use a CMS?',
        a: 'Yes — sourcing from WordPress, Contentful, or markdown at build time is the classic Gatsby architecture.',
      },
    ],
    related: [
      { name: 'Next.js', slug: 'nextjs' },
      { name: 'Astro', slug: 'astro' },
      { name: 'Netlify', slug: 'netlify' },
    ],
  },
  {
    slug: 'astro',
    name: 'Astro',
    category: 'framework',
    tagline: 'Islands-architecture framework shipping minimal JavaScript.',
    metaTitle: 'How to Tell If a Site Uses Astro (2 Checks)',
    metaDescription:
      'Spot Astro via astro-island tags and data-astro-cid attributes. Free evidence-based check.',
    about: [
      'Astro builds content sites with "islands" of interactivity, shipping near-zero JavaScript by default. This very site is built with Astro.',
      'Its compiler markers appear in production HTML unless explicitly stripped.',
    ],
    detects: ['astro-island custom elements', 'data-astro-cid scoped-style attributes'],
    verify: [
      'View source and search for "astro-island" or "data-astro-cid".',
      'Inspect components for Astro’s scoped styling attributes.',
    ],
    alternatives: [
      { name: 'Gatsby', slug: 'gatsby' },
      { name: 'Next.js', slug: 'nextjs' },
      { name: 'Nuxt', slug: 'nuxt' },
    ],
    faqs: [
      {
        q: 'Does Astro work with a CMS?',
        a: 'Yes — Astro commonly pulls content from WordPress, Contentful, or content collections at build time.',
      },
      {
        q: 'Astro vs Next.js for blogs?',
        a: 'Astro typically ships less JavaScript and faster pages for content; Next.js suits app-like interactivity.',
      },
      {
        q: 'Can Astro islands be detected when empty?',
        a: 'Fully static Astro pages may show only cid attributes; interactive islands add the astro-island marker.',
      },
    ],
    related: [
      { name: 'Gatsby', slug: 'gatsby' },
      { name: 'Next.js', slug: 'nextjs' },
      { name: 'Netlify', slug: 'netlify' },
    ],
  },
  {
    slug: 'laravel',
    name: 'Laravel',
    category: 'framework',
    tagline: 'PHP framework behind custom apps and Blade-rendered sites.',
    metaTitle: 'How to Tell If a Site Uses Laravel (3 Checks)',
    metaDescription:
      'Detect Laravel via session cookies, Livewire paths, and CSRF markers. Free evidence-based check.',
    about: [
      'Laravel is the most popular PHP framework, powering SaaS products, dashboards, and custom sites — often with server-rendered Blade templates we can analyse.',
      'API-only Laravel backends leave little public trace, which we report honestly.',
    ],
    detects: [
      'laravel_session and XSRF-TOKEN cookies',
      'Livewire and vendor asset paths',
      'Laravel CSRF and Blade markers',
    ],
    verify: [
      'Check DevTools → Application → Cookies for laravel_session.',
      'View source and search for "livewire" or "/vendor/".',
      'Inspect forms for _token fields with Laravel’s structure.',
    ],
    alternatives: [
      { name: 'Django', slug: 'django' },
      { name: 'Ruby on Rails', slug: 'rails' },
      { name: 'Next.js', slug: 'nextjs' },
    ],
    faqs: [
      {
        q: 'Can API-only Laravel apps be detected?',
        a: 'Rarely from the front-end — without Blade output or cookies there may be no public evidence, and we say so.',
      },
      {
        q: 'Laravel vs WordPress?',
        a: 'Laravel is a framework for custom builds; WordPress is a CMS for content sites. Different jobs, sometimes combined headlessly.',
      },
      {
        q: 'Is Laravel good for SEO?',
        a: 'Server-rendered Laravel pages are fully crawler-readable; SPA front-ends on Laravel APIs need rendering care.',
      },
    ],
    related: [
      { name: 'Django', slug: 'django' },
      { name: 'Ruby on Rails', slug: 'rails' },
      { name: 'Cloudflare', slug: 'cloudflare' },
    ],
  },
  {
    slug: 'django',
    name: 'Django',
    category: 'framework',
    tagline: 'Python framework for secure, data-driven applications.',
    metaTitle: 'How to Tell If a Site Uses Django (3 Checks)',
    metaDescription:
      'Spot Django via csrftoken cookies, admin paths, and CSRF markers. Free evidence-based check.',
    about: [
      'Django is Python’s batteries-included web framework, behind data-heavy products, newsrooms, and the famous auto-generated admin.',
      'Its CSRF machinery and admin paths are the most visible public markers.',
    ],
    detects: [
      'csrftoken and sessionid cookies',
      'csrfmiddlewaretoken fields and admin URL patterns',
      'Django contrib static paths',
    ],
    verify: [
      'Check cookies for csrftoken.',
      'Try example.com/admin/ — Django’s unmistakable login screen confirms it.',
      'View source and search for "csrfmiddlewaretoken".',
    ],
    alternatives: [
      { name: 'Laravel', slug: 'laravel' },
      { name: 'Ruby on Rails', slug: 'rails' },
      { name: 'Next.js', slug: 'nextjs' },
    ],
    faqs: [
      {
        q: 'Does /admin/ always exist on Django sites?',
        a: 'On standard deployments, yes — though security-conscious teams relocate or restrict it.',
      },
      {
        q: 'Django vs Laravel?',
        a: 'Comparable scope in different languages; team expertise and ecosystem usually decide.',
      },
      {
        q: 'Can Django serve SEO-friendly pages?',
        a: 'Yes — Django templates server-render fully-readable HTML, an excellent SEO baseline.',
      },
    ],
    related: [
      { name: 'Laravel', slug: 'laravel' },
      { name: 'Ruby on Rails', slug: 'rails' },
      { name: 'Cloudflare', slug: 'cloudflare' },
    ],
  },
  {
    slug: 'rails',
    name: 'Ruby on Rails',
    category: 'framework',
    tagline: 'Productivity-first Ruby framework behind many startups.',
    metaTitle: 'How to Tell If a Site Uses Ruby on Rails (3 Checks)',
    metaDescription:
      'Detect Rails via session cookies, CSRF meta tags, and Turbo markers. Free evidence-based check.',
    about: [
      'Ruby on Rails powers startups and scale-ups (Shopify, GitHub, and Basecamp famously among them) with convention-driven development.',
      'Its CSRF meta tags and Turbo/Stimulus markers show in server-rendered HTML.',
    ],
    detects: [
      'Rails session cookie patterns',
      'csrf-token meta tags with Rails param structure',
      'Turbo / Turbolinks data attributes',
    ],
    verify: [
      'View source and search for "csrf-token" alongside "authenticity_token".',
      'Look for data-turbo or data-turbolinks attributes.',
      'Check cookies for Rails session names.',
    ],
    alternatives: [
      { name: 'Django', slug: 'django' },
      { name: 'Laravel', slug: 'laravel' },
      { name: 'Next.js', slug: 'nextjs' },
    ],
    faqs: [
      {
        q: 'Is Rails still relevant?',
        a: 'Yes — Rails 7+ with Hotwire renewed its full-stack story, and hiring remains steady.',
      },
      {
        q: 'Rails vs Django?',
        a: 'Similar productivity philosophies; language preference and library needs decide.',
      },
      {
        q: 'Are Rails sites slow?',
        a: 'Well-built Rails apps with caching are fast; framework choice rarely determines real-world speed.',
      },
    ],
    related: [
      { name: 'Django', slug: 'django' },
      { name: 'Laravel', slug: 'laravel' },
      { name: 'Cloudflare', slug: 'cloudflare' },
    ],
  },

  // ------------------------------------------------------ Hosting ----
  {
    slug: 'cloudflare',
    name: 'Cloudflare',
    category: 'hosting',
    tagline: 'CDN, DNS, and edge security in front of millions of sites.',
    metaTitle: 'How to Tell If a Site Uses Cloudflare (3 Checks)',
    metaDescription:
      'Detect Cloudflare via cf-ray, server headers, and cache status. Free evidence-based hosting check.',
    about: [
      'Cloudflare sits in front of sites as a reverse proxy providing CDN caching, DDoS protection, and DNS — regardless of the underlying CMS or host.',
      'Detecting Cloudflare identifies the edge layer, not the origin server; both facts matter when asking "who hosts this website".',
    ],
    detects: [
      'cf-ray response header (unique per request)',
      'server: cloudflare header',
      'cf-cache-status header showing edge cache state',
    ],
    verify: [
      'Open DevTools → Network, reload, click the document request, and look for cf-ray in response headers.',
      'Check the server header for "cloudflare".',
      'Note cf-cache-status: HIT/MISS/DYNAMIC tells you whether the edge served the page.',
    ],
    alternatives: [
      { name: 'Fastly', slug: 'fastly' },
      { name: 'Akamai', slug: 'akamai' },
      { name: 'AWS CloudFront', slug: 'aws-cloudfront' },
    ],
    faqs: [
      {
        q: 'Does Cloudflare mean Cloudflare hosts the site?',
        a: 'Not exactly — Cloudflare is usually the CDN/security layer; the origin may be AWS, a VPS, or shared hosting behind it.',
      },
      {
        q: 'Can sites hide Cloudflare?',
        a: 'Rarely worth it — cf-ray is injected by the edge itself. Grey-clouded (DNS-only) setups are the exception.',
      },
      {
        q: 'Is Cloudflare free?',
        a: 'It has a generous free tier covering CDN, DNS, and basic security — this very site runs on it.',
      },
    ],
    related: [
      { name: 'Fastly', slug: 'fastly' },
      { name: 'AWS CloudFront', slug: 'aws-cloudfront' },
      { name: 'WordPress', slug: 'wordpress' },
    ],
  },
  {
    slug: 'vercel',
    name: 'Vercel',
    category: 'hosting',
    tagline: 'Frontend cloud built for Next.js and modern frameworks.',
    metaTitle: 'How to Tell If a Site Uses Vercel (3 Checks)',
    metaDescription:
      'Spot Vercel via x-vercel-id, cache headers, and edge markers. Free evidence-based hosting check.',
    about: [
      'Vercel hosts Next.js apps, static sites, and AI workloads on its edge network, popular with startups and framework-led teams.',
      'Its request headers are injected at the edge and highly distinctive.',
    ],
    detects: [
      'x-vercel-id response header',
      'x-vercel-cache edge cache header',
      'server: Vercel header',
    ],
    verify: [
      'Inspect response headers for x-vercel-id.',
      'Check x-vercel-cache for HIT/MISS edge state.',
      'Look at the server header.',
    ],
    alternatives: [
      { name: 'Netlify', slug: 'netlify' },
      { name: 'Cloudflare', slug: 'cloudflare' },
      { name: 'GitHub Pages', slug: 'github-pages' },
    ],
    faqs: [
      {
        q: 'Does Vercel hosting imply Next.js?',
        a: 'Often but not always — Vercel hosts any static or framework output. We report the framework separately when visible.',
      },
      {
        q: 'Vercel vs Netlify?',
        a: 'Both excel at frontend hosting; Vercel leads for Next.js, Netlify for static/JAMstack workflows with built-in forms and identity.',
      },
      {
        q: 'Can Vercel headers be removed?',
        a: 'Not the core request IDs — they are part of the platform’s edge routing.',
      },
    ],
    related: [
      { name: 'Next.js', slug: 'nextjs' },
      { name: 'Netlify', slug: 'netlify' },
      { name: 'Cloudflare', slug: 'cloudflare' },
    ],
  },
  {
    slug: 'netlify',
    name: 'Netlify',
    category: 'hosting',
    tagline: 'JAMstack pioneer for static sites and serverless functions.',
    metaTitle: 'How to Tell If a Site Uses Netlify (3 Checks)',
    metaDescription:
      'Identify Netlify via x-nf-request-id and server headers. Free evidence-based hosting check.',
    about: [
      'Netlify hosts static sites, Astro/Gatsby/Next.js output, and serverless functions with git-based deploys.',
      'Its request-ID header is unique per response and definitive.',
    ],
    detects: ['x-nf-request-id response header', 'server: Netlify header'],
    verify: [
      'Inspect response headers for x-nf-request-id.',
      'Check the server header for Netlify.',
      'Look for Netlify form or identity endpoints in page HTML.',
    ],
    alternatives: [
      { name: 'Vercel', slug: 'vercel' },
      { name: 'GitHub Pages', slug: 'github-pages' },
      { name: 'Cloudflare', slug: 'cloudflare' },
    ],
    faqs: [
      {
        q: 'Netlify vs Vercel for Astro sites?',
        a: 'Both are excellent; either deploys Astro output with edge caching. Tooling preferences usually decide.',
      },
      {
        q: 'Is Netlify only for static sites?',
        a: 'No — serverless and edge functions add dynamic behaviour while keeping the static-first model.',
      },
      {
        q: 'Can Netlify host WordPress?',
        a: 'Only headless WordPress front-ends — classic PHP WordPress needs traditional hosting.',
      },
    ],
    related: [
      { name: 'Vercel', slug: 'vercel' },
      { name: 'Astro', slug: 'astro' },
      { name: 'Gatsby', slug: 'gatsby' },
    ],
  },
  {
    slug: 'aws-cloudfront',
    name: 'AWS CloudFront',
    category: 'hosting',
    tagline: 'Amazon’s global CDN fronting S3, ALBs, and custom origins.',
    metaTitle: 'How to Tell If a Site Uses AWS CloudFront (3 Checks)',
    metaDescription:
      'Detect CloudFront via x-amz-cf-id, PoP headers, and Via markers. Free evidence-based hosting check.',
    about: [
      'CloudFront is AWS’s CDN, commonly placed in front of S3 static sites, load balancers, or API Gateway endpoints.',
      'Its x-amz-cf-id header is present on every edge response and unique per request.',
    ],
    detects: [
      'x-amz-cf-id response header',
      'x-amz-cf-pop edge location header',
      'Via header naming CloudFront',
    ],
    verify: [
      'Inspect response headers for x-amz-cf-id.',
      'Check x-amz-cf-pop — the three-letter code names the serving edge location.',
      'Look at the Via header for CloudFront.',
    ],
    alternatives: [
      { name: 'Cloudflare', slug: 'cloudflare' },
      { name: 'Fastly', slug: 'fastly' },
      { name: 'Akamai', slug: 'akamai' },
    ],
    faqs: [
      {
        q: 'CloudFront vs S3 — which hosts the site?',
        a: 'Often both: S3 stores the files, CloudFront delivers them. Headers identify the CDN layer.',
      },
      {
        q: 'Can CloudFront hide the origin?',
        a: 'Origins stay private behind CloudFront by default, though headers sometimes leak origin software versions.',
      },
      {
        q: 'Is CloudFront expensive?',
        a: 'Pay-as-you-go with a free tier; costs scale with traffic and invalidations.',
      },
    ],
    related: [
      { name: 'Cloudflare', slug: 'cloudflare' },
      { name: 'Fastly', slug: 'fastly' },
      { name: 'Next.js', slug: 'nextjs' },
    ],
  },
  {
    slug: 'fastly',
    name: 'Fastly',
    category: 'hosting',
    tagline: 'Programmable edge CDN for instant purging and compute.',
    metaTitle: 'How to Tell If a Site Uses Fastly (3 Checks)',
    metaDescription:
      'Spot Fastly via x-served-by cache nodes and request IDs. Free evidence-based hosting check.',
    about: [
      'Fastly is a high-performance edge CDN used by publishers and platforms that need instant cache purges and edge logic.',
      'Its cache-node headers name the serving PoP on every response.',
    ],
    detects: [
      'x-served-by header naming a Fastly cache node',
      'x-fastly-request-id header',
      'fastly-restarts header',
    ],
    verify: [
      'Inspect response headers for x-served-by containing "fastly".',
      'Check x-fastly-request-id.',
      'The node name in x-served-by reveals the serving PoP.',
    ],
    alternatives: [
      { name: 'Cloudflare', slug: 'cloudflare' },
      { name: 'Akamai', slug: 'akamai' },
      { name: 'AWS CloudFront', slug: 'aws-cloudfront' },
    ],
    faqs: [
      {
        q: 'Fastly vs Cloudflare?',
        a: 'Fastly offers finer edge programmability (VCL/Compute); Cloudflare bundles broader security and DNS. High-traffic publishers often pick Fastly.',
      },
      {
        q: 'What does x-served-by tell me?',
        a: 'Which cache node served the response — useful for debugging cache HIT/MISS behaviour.',
      },
      {
        q: 'Is Fastly only for enterprises?',
        a: 'It skews toward serious traffic, but pay-as-you-go plans exist for smaller sites.',
      },
    ],
    related: [
      { name: 'Cloudflare', slug: 'cloudflare' },
      { name: 'Akamai', slug: 'akamai' },
      { name: 'Ghost', slug: 'ghost' },
    ],
  },
  {
    slug: 'akamai',
    name: 'Akamai',
    category: 'hosting',
    tagline: 'Enterprise CDN and edge security at massive scale.',
    metaTitle: 'How to Tell If a Site Uses Akamai (3 Checks)',
    metaDescription:
      'Detect Akamai via Ghost servers, request IDs, and cache headers. Free evidence-based hosting check.',
    about: [
      'Akamai operates one of the world’s largest edge networks, serving enterprises, media streaming, and commerce with CDN plus bot management.',
      'Its server and request-ID headers identify the edge layer.',
    ],
    detects: [
      'server: AkamaiGHost / AkamaiNetStorage headers',
      'x-akamai-request-id header',
      'Akamai cacheability headers',
    ],
    verify: [
      'Inspect the server response header for AkamaiGHost.',
      'Look for x-akamai-request-id.',
      'Check for Akamai bot-manager cookies on protected sites.',
    ],
    alternatives: [
      { name: 'Cloudflare', slug: 'cloudflare' },
      { name: 'Fastly', slug: 'fastly' },
      { name: 'AWS CloudFront', slug: 'aws-cloudfront' },
    ],
    faqs: [
      {
        q: 'Does Akamai mean the site is enterprise?',
        a: 'Usually — Akamai contracts skew enterprise, though small-site exposure exists via partner bundles.',
      },
      {
        q: 'Can Akamai block detection?',
        a: 'Bot Manager can challenge automated fetches. We report BLOCKED honestly and show header evidence.',
      },
      {
        q: 'Akamai vs Cloudflare?',
        a: 'Akamai leads in large-scale media delivery and enterprise security; Cloudflare in accessible, bundled edge services.',
      },
    ],
    related: [
      { name: 'Cloudflare', slug: 'cloudflare' },
      { name: 'Fastly', slug: 'fastly' },
      { name: 'Sitecore', slug: 'sitecore' },
    ],
  },
  {
    slug: 'wp-engine',
    name: 'WP Engine',
    category: 'hosting',
    tagline: 'Managed WordPress hosting for agencies and businesses.',
    metaTitle: 'How to Tell If a Site Uses WP Engine (3 Checks)',
    metaDescription:
      'Identify WP Engine via its powered-by header and platform markers. Free evidence-based hosting check.',
    about: [
      'WP Engine is a managed WordPress host offering staging, automated updates, and performance tooling for agencies and mid-market sites.',
      'Its platform headers distinguish it from generic WordPress hosting.',
    ],
    detects: [
      'X-Powered-By: WP Engine header',
      'WP Engine backend and cookie markers',
    ],
    verify: [
      'Inspect response headers for x-powered-by naming WP Engine.',
      'Check cookies for WP Engine session markers.',
      'Confirm WordPress separately via wp-content paths.',
    ],
    alternatives: [
      { name: 'Kinsta', slug: 'kinsta' },
      { name: 'Cloudflare', slug: 'cloudflare' },
      { name: 'WordPress', slug: 'wordpress' },
    ],
    faqs: [
      {
        q: 'WP Engine vs Kinsta?',
        a: 'Both are premium managed WordPress hosts; compare staging workflows, support, and pricing for your traffic level.',
      },
      {
        q: 'Does WP Engine hosting prove WordPress?',
        a: 'Practically yes — WP Engine only hosts WordPress, so expect both detections together.',
      },
      {
        q: 'Can hosts hide these headers?',
        a: 'Some strip them at the proxy; WordPress core signals then carry the CMS detection regardless.',
      },
    ],
    related: [
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'Kinsta', slug: 'kinsta' },
      { name: 'WooCommerce', slug: 'woocommerce' },
    ],
  },
  {
    slug: 'kinsta',
    name: 'Kinsta',
    category: 'hosting',
    tagline: 'Google-Cloud-powered managed WordPress hosting.',
    metaTitle: 'How to Tell If a Site Uses Kinsta (2 Checks)',
    metaDescription:
      'Spot Kinsta via x-kinsta-cache and edge headers. Free evidence-based hosting check.',
    about: [
      'Kinsta is a managed WordPress host running on Google Cloud with a focus on speed dashboards and developer tooling.',
      'Its cache header is the definitive marker.',
    ],
    detects: ['x-kinsta-cache response header', 'Kinsta edge-location markers'],
    verify: [
      'Inspect response headers for x-kinsta-cache.',
      'Confirm WordPress core signals separately.',
    ],
    alternatives: [
      { name: 'WP Engine', slug: 'wp-engine' },
      { name: 'Cloudflare', slug: 'cloudflare' },
      { name: 'WordPress', slug: 'wordpress' },
    ],
    faqs: [
      {
        q: 'Kinsta vs WP Engine?',
        a: 'Feature-parity is close; Kinsta emphasises Cloud infrastructure and analytics UI, WP Engine agency tooling.',
      },
      {
        q: 'Does Kinsta host non-WordPress sites?',
        a: 'Its flagship is WordPress; application and database hosting are separate products with different markers.',
      },
      {
        q: 'Is Kinsta good for WooCommerce?',
        a: 'Yes — its caching and PHP workers suit stores, though high-traffic checkouts need plan headroom.',
      },
    ],
    related: [
      { name: 'WP Engine', slug: 'wp-engine' },
      { name: 'WordPress', slug: 'wordpress' },
      { name: 'WooCommerce', slug: 'woocommerce' },
    ],
  },
  {
    slug: 'github-pages',
    name: 'GitHub Pages',
    category: 'hosting',
    tagline: 'Free static hosting straight from a GitHub repo.',
    metaTitle: 'How to Tell If a Site Uses GitHub Pages (2 Checks)',
    metaDescription:
      'Detect GitHub Pages via its server header and request IDs. Free evidence-based hosting check.',
    about: [
      'GitHub Pages publishes static sites directly from repositories — docs, portfolios, and project pages — free with github.io subdomains or custom domains.',
      'Its server header is explicit and consistent.',
    ],
    detects: ['server: GitHub.com header', 'x-github-request-id header'],
    verify: [
      'Inspect response headers for the GitHub server signature.',
      'Check for x-github-request-id.',
      'github.io subdomains are definitive by themselves.',
    ],
    alternatives: [
      { name: 'Netlify', slug: 'netlify' },
      { name: 'Vercel', slug: 'vercel' },
      { name: 'Cloudflare', slug: 'cloudflare' },
    ],
    faqs: [
      {
        q: 'GitHub Pages vs Netlify?',
        a: 'Pages is simplest for repo-published docs; Netlify adds forms, functions, and deploy previews.',
      },
      {
        q: 'Can GitHub Pages run WordPress?',
        a: 'No — static output only. Static export plugins can publish WordPress content to it.',
      },
      {
        q: 'Are GitHub Pages sites fast?',
        a: 'Yes — global CDN delivery of static files with no server rendering.',
      },
    ],
    related: [
      { name: 'Netlify', slug: 'netlify' },
      { name: 'Vercel', slug: 'vercel' },
      { name: 'Gatsby', slug: 'gatsby' },
    ],
  },
];

export const TECH_MAP = new Map(TECHNOLOGIES.map((t) => [t.slug, t]));

export const CATEGORY_LABELS: Record<TechContent['category'], string> = {
  cms: 'Content Management Systems',
  builder: 'Site Builders',
  ecommerce: 'E-commerce Platforms',
  framework: 'Frameworks',
  hosting: 'Hosting & CDN',
};
