import { LOCALES, DEFAULT_LOCALE, PUBLISHED_LOCALES, LOCALE_MAP, type LocaleConfig } from './config';
import type en from './en.json';

// Type alias for the translation dictionary shape
export type TranslationDict = typeof en;

// Dynamically import locale dictionaries
const dictionaries: Record<string, () => Promise<TranslationDict>> = {
  en: () => import('./en.json') as Promise<{ default: TranslationDict }> as Promise<TranslationDict>,
};

/**
 * Load the translation dictionary for a given locale code.
 * Falls back to English for any missing locale.
 */
export async function getTranslations(locale: string): Promise<TranslationDict> {
  const loader = dictionaries[locale] ?? dictionaries[DEFAULT_LOCALE];
  const mod = await loader();
  // Handle both ESM default export and plain JSON import
  return ('default' in (mod as Record<string, unknown>)
    ? (mod as { default: TranslationDict }).default
    : mod) as TranslationDict;
}

/**
 * Get a deeply-nested translation value by dot-path key.
 * Falls back to the key itself if not found.
 */
export function t(dict: TranslationDict, key: string, vars?: Record<string, string>): string {
  const parts = key.split('.');
  let value: unknown = dict;
  for (const part of parts) {
    if (typeof value !== 'object' || value === null) return key;
    value = (value as Record<string, unknown>)[part];
  }
  if (typeof value !== 'string') return key;
  if (!vars) return value;
  return value.replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? `{${k}}`);
}

/**
 * Resolve a page's canonical URL for a given locale.
 * Returns the base URL for the default locale (no prefix) or the locale-prefixed URL.
 */
export function localizeUrl(path: string, locale: string, siteUrl: string): string {
  const cfg = LOCALE_MAP.get(locale);
  if (!cfg || !cfg.published) return `${siteUrl}${path}`;
  if (locale === DEFAULT_LOCALE) return `${siteUrl}${path}`;
  return `${siteUrl}/${cfg.slug}${path}`;
}

/**
 * Build the hreflang link tags for a given page path.
 * Only includes published locales.
 */
export function buildHreflangLinks(
  pagePath: string,
  siteUrl: string
): Array<{ hreflang: string; href: string }> {
  const links: Array<{ hreflang: string; href: string }> = [];

  for (const loc of PUBLISHED_LOCALES) {
    links.push({
      hreflang: loc.code,
      href: localizeUrl(pagePath, loc.code, siteUrl),
    });
  }

  // x-default points to English (default locale)
  links.push({
    hreflang: 'x-default',
    href: localizeUrl(pagePath, DEFAULT_LOCALE, siteUrl),
  });

  return links;
}

/**
 * Get the locale config for a locale code, with fallback to default.
 */
export function getLocaleConfig(locale: string): LocaleConfig {
  return LOCALE_MAP.get(locale) ?? LOCALE_MAP.get(DEFAULT_LOCALE)!;
}

export { LOCALES, PUBLISHED_LOCALES, DEFAULT_LOCALE };
