/**
 * Known-theme catalogs for annotation and fallback identity.
 *
 * Theme identity always comes from technical evidence (the WordPress
 * theme slug in /wp-content/themes/<slug>/ plus style.css headers, or
 * the Shopify.theme name/ID/theme_store_id object). The catalog provides
 * canonical naming, authors, documentation links, and Theme Store mappings.
 */

export interface WpThemeMeta {
  name: string;
  author?: string;
  url?: string;
}

export const KNOWN_WP_THEME_NAMES: Record<string, WpThemeMeta> = {
  astra: { name: 'Astra', author: 'Brainstorm Force', url: 'https://wordpress.org/themes/astra/' },
  divi: { name: 'Divi', author: 'Elegant Themes', url: 'https://www.elegantthemes.com/gallery/divi/' },
  avada: { name: 'Avada', author: 'ThemeFusion', url: 'https://avada.com/' },
  generatepress: { name: 'GeneratePress', author: 'Tom Usborne', url: 'https://generatepress.com/' },
  kadence: { name: 'Kadence', author: 'Kadence WP', url: 'https://wordpress.org/themes/kadence/' },
  oceanwp: { name: 'OceanWP', author: 'OceanWP', url: 'https://wordpress.org/themes/oceanwp/' },
  blocksy: { name: 'Blocksy', author: 'CreativeThemes', url: 'https://creativethemes.com/blocksy/' },
  neve: { name: 'Neve', author: 'ThemeIsle', url: 'https://themeisle.com/themes/neve/' },
  'hello-elementor': { name: 'Hello Elementor', author: 'Elementor Team', url: 'https://wordpress.org/themes/hello-elementor/' },
  twentytwentyfour: { name: 'Twenty Twenty-Four', author: 'WordPress.org', url: 'https://wordpress.org/themes/twentytwentyfour/' },
  twentytwentythree: { name: 'Twenty Twenty-Three', author: 'WordPress.org', url: 'https://wordpress.org/themes/twentytwentythree/' },
  twentytwentytwo: { name: 'Twenty Twenty-Two', author: 'WordPress.org', url: 'https://wordpress.org/themes/twentytwentytwo/' },
  twentytwentyone: { name: 'Twenty Twenty-One', author: 'WordPress.org', url: 'https://wordpress.org/themes/twentytwentyone/' },
  twentytwenty: { name: 'Twenty Twenty', author: 'WordPress.org', url: 'https://wordpress.org/themes/twentytwenty/' },
  flatsome: { name: 'Flatsome', author: 'UX-themes', url: 'https://flatsome.uxthemes.com/' },
  woodmart: { name: 'WoodMart', author: 'XTemos', url: 'https://xtemos.com/woodmart/' },
  porto: { name: 'Porto', author: 'Porto Themes', url: 'https://portotheme.com/' },
  enfold: { name: 'Enfold', author: 'Kriesi', url: 'https://kriesi.at/themes/enfold/' },
  betheme: { name: 'Betheme', author: 'Muffin Group', url: 'https://muffingroup.com/betheme/' },
  the7: { name: 'The7', author: 'Dream-Theme', url: 'https://the7.io/' },
  newspaper: { name: 'Newspaper', author: 'tagDiv', url: 'https://tagdiv.com/' },
  jannah: { name: 'Jannah', author: 'TieLabs', url: 'https://tielabs.com/' },
  soledad: { name: 'Soledad', author: 'PenciDesign', url: 'https://pencidesign.com/' },
  salient: { name: 'Salient', author: 'ThemeNectar', url: 'https://themenectar.com/' },
  uncode: { name: 'Uncode', author: 'Undsgn', url: 'https://undsgn.com/' },
  bridge: { name: 'Bridge', author: 'Qode Interactive', url: 'https://qodeinteractive.com/' },
  jupiter: { name: 'Jupiter', author: 'Artbees', url: 'https://artbees.net/' },
  storefront: { name: 'Storefront', author: 'Automattic', url: 'https://wordpress.org/themes/storefront/' },
  sydney: { name: 'Sydney', author: 'aThemes', url: 'https://athemes.com/theme/sydney/' },
  customizr: { name: 'Customizr', author: 'PressCustomizr', url: 'https://wordpress.org/themes/customizr/' },
  colormag: { name: 'ColorMag', author: 'ThemeGrill', url: 'https://wordpress.org/themes/colormag/' },
  hueman: { name: 'Hueman', author: 'PressCustomizr', url: 'https://wordpress.org/themes/hueman/' },
  zakra: { name: 'Zakra', author: 'ThemeGrill', url: 'https://wordpress.org/themes/zakra/' },
  phlox: { name: 'Phlox', author: 'averta', url: 'https://wordpress.org/themes/phlox/' },
};

const KNOWN_WP_THEMES = new Set(Object.keys(KNOWN_WP_THEME_NAMES));

// Official Shopify Theme Store theme mappings by Store ID
export const SHOPIFY_THEME_STORE_IDS: Record<number, string> = {
  887: 'Dawn',
  888: 'Craft',
  889: 'Sense',
  890: 'Crave',
  891: 'Refresh',
  892: 'Ride',
  893: 'Studio',
  894: 'Taste',
  895: 'Colorblock',
  896: 'Origin',
  897: 'Spotlight',
  849: 'Prestige',
  857: 'Impulse',
  829: 'Motion',
  834: 'Broadcast',
  865: 'Symmetry',
  871: 'Pipeline',
  876: 'Focal',
  821: 'Venue',
  775: 'Empire',
  796: 'Warehouse',
  836: 'Palo Alto',
  730: 'Debut',
  721: 'Brooklyn',
  710: 'Minimal',
  737: 'Narrative',
  606: 'Supply',
  677: 'Jumpstart',
  743: 'Express',
};

// Official / widely-used Shopify theme names (lowercase)
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
  'origin',
  'spotlight',
  'focal',
  'pipeline',
]);

/** True when a WordPress theme slug is a recognised public theme. */
export function isKnownWpTheme(slug: string | undefined): boolean {
  if (!slug) return false;
  return KNOWN_WP_THEMES.has(slug.toLowerCase().replace(/-child$/, ''));
}

/** Get metadata for a known WordPress theme slug */
export function getKnownWpThemeMeta(slug: string | undefined): WpThemeMeta | undefined {
  if (!slug) return undefined;
  const base = slug.toLowerCase().replace(/-child$/, '');
  return KNOWN_WP_THEME_NAMES[base];
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

/** Lookup canonical theme name from a Shopify Theme Store ID */
export function getShopifyThemeStoreName(storeId: number | undefined): string | undefined {
  if (!storeId) return undefined;
  return SHOPIFY_THEME_STORE_IDS[storeId];
}

/** Get official Shopify Theme Store URL if known */
export function getShopifyThemeStoreUrl(themeName: string | undefined): string | undefined {
  if (!themeName) return undefined;
  const clean = themeName.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  if (KNOWN_SHOPIFY_THEMES.has(clean.replace(/-\d+.*$/, ''))) {
    return `https://themes.shopify.com/themes/${clean.replace(/-\d+.*$/, '')}`;
  }
  return undefined;
}
