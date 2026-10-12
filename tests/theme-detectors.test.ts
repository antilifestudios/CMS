import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  fetchWpThemeMeta,
  extractShopifyTheme,
  extractWpPlugins,
} from '../src/lib/detect/pipeline.ts';
import {
  isKnownWpTheme,
  getKnownWpThemeMeta,
  isKnownShopifyTheme,
  getShopifyThemeStoreName,
  getShopifyThemeStoreUrl,
} from '../src/data/themes.ts';

describe('WordPress Theme Detection', () => {
  it('extracts known theme identity even when style.css cannot be fetched', async () => {
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <link rel="stylesheet" href="/wp-content/themes/astra/assets/css/minified/style.min.css" />
        <script src="/wp-content/themes/astra/assets/js/minified/frontend.min.js"></script>
      </head>
      <body></body>
      </html>
    `;
    const meta = await fetchWpThemeMeta('https://example.com', html);
    assert.equal(meta.themeName, 'Astra');
    assert.equal(meta.themeAuthor, 'Brainstorm Force');
    assert.equal(meta.slug, 'astra');
    assert.equal(meta.isChild, false);
    assert.equal(isKnownWpTheme(meta.slug), true);
  });

  it('detects child themes and resolves parent metadata', async () => {
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <link rel="stylesheet" href="/wp-content/themes/generatepress-child/style.css" />
        <link rel="stylesheet" href="/wp-content/themes/generatepress/style.min.css" />
      </head>
      <body></body>
      </html>
    `;
    const meta = await fetchWpThemeMeta('https://example.com', html);
    assert.equal(meta.themeName, 'GeneratePress Child');
    assert.equal(meta.slug, 'generatepress-child');
    assert.equal(meta.isChild, true);
    assert.equal(meta.parentTheme, 'GeneratePress');
  });

  it('formats custom uncataloged theme slug into human title case', async () => {
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <link rel="stylesheet" href="/wp-content/themes/acme-modern-corp/dist/main.css" />
      </head>
      <body></body>
      </html>
    `;
    const meta = await fetchWpThemeMeta('https://example.com', html);
    assert.equal(meta.themeName, 'Acme Modern Corp');
    assert.equal(meta.slug, 'acme-modern-corp');
    assert.equal(meta.isChild, false);
    assert.equal(isKnownWpTheme(meta.slug), false);
  });

  it('extracts unique WordPress plugins from asset paths', () => {
    const html = `
      <link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css" />
      <script src="/wp-content/plugins/woocommerce/assets/js/frontend/cart.js"></script>
      <script src="/wp-content/plugins/contact-form-7/includes/js/index.js"></script>
      <link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css" />
      <script src="/wp-content/plugins/cache/wprocket.js"></script>
    `;
    const plugins = extractWpPlugins(html);
    assert.deepEqual(plugins, ['woocommerce', 'contact-form-7', 'elementor']);
  });
});

describe('Shopify Theme Detection', () => {
  it('extracts theme object from Shopify.theme JSON', () => {
    const html = `
      <script>
        Shopify.theme = {"name":"Dawn","id":134123456789,"theme_store_id":887,"role":"main"};
      </script>
    `;
    const theme = extractShopifyTheme(html);
    assert.equal(theme.name, 'Dawn');
    assert.equal(theme.id, '134123456789');
    assert.equal(theme.themeStoreId, 887);
    assert.equal(theme.themeStoreName, 'Dawn');
    assert.equal(theme.themeStoreUrl, 'https://themes.shopify.com/themes/dawn');
    assert.equal(theme.role, 'main');
    assert.equal(theme.known, true);
  });

  it('resolves underlying official theme when merchant renames theme', () => {
    const html = `
      <script>
        Shopify.theme = {"name":"Custom Holiday 2026 [Live]","id":99887766,"theme_store_id":849,"role":"main"};
      </script>
    `;
    const theme = extractShopifyTheme(html);
    assert.equal(theme.name, 'Custom Holiday 2026 [Live]');
    assert.equal(theme.themeStoreId, 849);
    assert.equal(theme.themeStoreName, 'Prestige');
    assert.equal(theme.themeStoreUrl, 'https://themes.shopify.com/themes/prestige');
    assert.equal(theme.known, true);
  });

  it('extracts theme name, version and ID from BOOMR analytics', () => {
    const html = `
      <script>
        window.BOOMR = window.BOOMR || {};
        BOOMR.themeName = "Impulse";
        BOOMR.themeVersion = "7.3.2";
        BOOMR.themeId = 857;
      </script>
    `;
    const theme = extractShopifyTheme(html);
    assert.equal(theme.name, 'Impulse');
    assert.equal(theme.version, '7.3.2');
    assert.equal(theme.id, '857');
    assert.equal(theme.known, true);
  });

  it('extracts direct Shopify.theme.name assignment', () => {
    const html = `
      <script>
        window.Shopify = window.Shopify || {};
        Shopify.theme = Shopify.theme || {};
        Shopify.theme.name = "Craft";
      </script>
      <meta name="theme-id" data-theme-id="987654321">
    `;
    const theme = extractShopifyTheme(html);
    assert.equal(theme.name, 'Craft');
    assert.equal(theme.id, '987654321');
    assert.equal(theme.known, true);
  });

  it('recognizes versioned Shopify theme names in catalog', () => {
    assert.equal(isKnownShopifyTheme('Dawn'), true);
    assert.equal(isKnownShopifyTheme('Dawn 2.0'), true);
    assert.equal(isKnownShopifyTheme('Prestige (v7.1)'), false); // parenthesis version
    assert.equal(isKnownShopifyTheme('Prestige 7.1'), true);
    assert.equal(isKnownShopifyTheme('Totally Custom Agency Theme'), false);
    assert.equal(getShopifyThemeStoreName(887), 'Dawn');
    assert.equal(getShopifyThemeStoreName(857), 'Impulse');
    assert.equal(getShopifyThemeStoreUrl('Dawn'), 'https://themes.shopify.com/themes/dawn');
  });
});
