/**
 * i18n configuration.
 * Add a locale to LOCALES and set published: true only when the full
 * content set (tool page, /cms/*, guides, trust pages) is ready.
 */

export interface LocaleConfig {
  /** BCP-47 language tag */
  code: string;
  /** Human-readable name in that language */
  label: string;
  /** URL segment used for this locale (empty string for default) */
  slug: string;
  /** Whether this locale appears in hreflang, sitemap, and the switcher */
  published: boolean;
  /** Text direction */
  dir: 'ltr' | 'rtl';
}

export const LOCALES: LocaleConfig[] = [
  {
    code: 'en',
    label: 'English',
    slug: '',
    published: true,
    dir: 'ltr',
  },
  // Future locales — add content before setting published: true
  // { code: 'es', label: 'Español', slug: 'es', published: false, dir: 'ltr' },
  // { code: 'pt', label: 'Português', slug: 'pt', published: false, dir: 'ltr' },
  // { code: 'de', label: 'Deutsch', slug: 'de', published: false, dir: 'ltr' },
];

export const DEFAULT_LOCALE = 'en';

/** Only locales that are published (linked in hreflang / sitemap / switcher) */
export const PUBLISHED_LOCALES = LOCALES.filter((l) => l.published);

/** Map from locale code to LocaleConfig */
export const LOCALE_MAP = new Map(LOCALES.map((l) => [l.code, l]));

/**
 * Per-locale URL slug overrides for known pages.
 * Key format: `${localeCode}:${pageKey}`.
 * Falls back to the English slug if no override exists.
 */
export const SLUG_OVERRIDES: Record<string, string> = {
  // Future: 'es:cms-detector' => 'detector-de-cms'
};
