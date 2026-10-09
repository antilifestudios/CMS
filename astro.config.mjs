// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import cloudflare from '@astrojs/cloudflare';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
  site: 'https://cmsdetectorai.com',
  output: 'server',

  adapter: cloudflare({
    platformProxy: {
      enabled: true,
    },
  }),

  vite: {
    plugins: [tailwindcss()],
    optimizeDeps: {
      exclude: ['astro:content', 'astro/content/runtime'],
    },
    ssr: {
      optimizeDeps: {
        exclude: ['astro:content', 'astro/content/runtime'],
      },
    },
  },

  // i18n routing
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
    routing: {
      prefixDefaultLocale: false,
    },
  },

  integrations: [
    sitemap({
      i18n: {
        defaultLocale: 'en',
        locales: {
          en: 'en-US',
        },
      },
    }),
  ],

  // Prerender all content pages; API routes stay server-rendered
  prefetch: true,

  // 301 redirects for removed and relocated routes
  redirects: {
    '/who-hosts-this-website': { status: 301, destination: '/' },
    '/is-this-site-wordpress': { status: 301, destination: '/' },
    '/guides/how-to-find-what-cms-a-website-uses': { status: 301, destination: '/blog/how-to-find-a-cms' },
    '/guides/what-is-a-cms': { status: 301, destination: '/blog/what-is-a-cms' },
    '/methodology': { status: 301, destination: '/blog/how-it-works' },
    '/privacy-policy': { status: 301, destination: '/privacy' },
    '/terms-of-service': { status: 301, destination: '/terms' },
    '/cms/wordpress': { status: 301, destination: '/blog/wordpress-signatures' },
    '/cms/shopify': { status: 301, destination: '/blog/shopify-signatures' },
    '/learn': { status: 301, destination: '/blog' },
    '/guides': { status: 301, destination: '/blog' },
  },
});