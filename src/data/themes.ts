/**
 * Known-theme catalogs for annotation ONLY.
 *
 * These lists never *detect* a theme. Theme identity always comes from
 * technical evidence (the WordPress theme slug in /wp-content/themes/<slug>/
 * plus style.css headers, or the Shopify.theme name/ID object). The catalog
 * merely labels an already-extracted theme as "known" vs "custom/unknown"
 * so the UI can say "custom theme" instead of guessing.
 */

// WordPress theme slugs (lowercase) reliably fingerprintable via
// /wp-content/themes/<slug>/ + style.css Theme Name headers.
const KNOWN_WP_THEMES = new Set([
  'astra',
  'divi',
  'avada',
  'generatepress',
  'kadence',
  'oceanwp',
  'blocksy',
  'neve',
  'hello-elementor',
  'twentytwentyfour',
  'twentytwentythree',
  'twentytwentytwo',
  'flatsome',
  'woodmart',
  'porto',
  'enfold',
  'betheme',
  'the7',
  'newspaper',
  'jannah',
  'soledad',
  'salient',
  'uncode',
  'bridge',
  'jupiter',
  'storefront',
  'sydney',
  'customizr',
  'colormag',
  'hueman',
  'zakra',
  'phlox',
]);

// Official / widely-used Shopify theme names (lowercase) as reported
// by the Shopify.theme object embedded in storefront HTML.
const KNOWN_SHOPIFY_THEMES = new Set([
  'dawn',
  'impulse',
  'prestige',
  'refresh',
  'sense',
  'craft',
  'ride',
  'taste',
  'debut',
  'debutify',
  'brooklyn',
  'minimal',
  'supply',
  'boundless',
  'narrative',
  'venue',
  'empire',
  'warehouse',
  'motion',
  'broadcast',
  'palo alto',
  'ella',
  'testament',
  'parallax',
  'retina',
  'flex',
  'turbo',
  'symmetry',
  'cascade',
  'editions',
  'studio',
  'crave',
  'colorblock',
  'sense',
]);

/** True when a WordPress theme slug is a recognised public theme. */
export function isKnownWpTheme(slug: string | undefined): boolean {
  if (!slug) return false;
  return KNOWN_WP_THEMES.has(slug.toLowerCase().replace(/-child$/, ''));
}

/** True when a Shopify theme name is a recognised public theme. */
export function isKnownShopifyTheme(name: string | undefined): boolean {
  if (!name) return false;
  const norm = name.toLowerCase().trim();
  if (KNOWN_SHOPIFY_THEMES.has(norm)) return true;
  // "Dawn 2.0", "Prestige (v7)" style suffixes still count as known.
  const base = norm.replace(/[\s\-_v]*\d+(\.\d+)*\s*$/, '').trim();
  return KNOWN_SHOPIFY_THEMES.has(base);
}
