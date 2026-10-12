/// <reference types="astro/client" />
import type { APIRoute } from 'astro';

export const prerender = true;

const SITE = 'https://cmsdetectorai.com';

export const GET: APIRoute = () => {
  // Note: /?url= share views are handled via canonical + noindex.
  const body = [
    'User-agent: *',
    'Allow: /',
    'Disallow: /api/',
    'Disallow: /*?*extra=',
    `Sitemap: ${SITE}/sitemap-index.xml`,
    '',
  ].join('\n');
  return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
};
