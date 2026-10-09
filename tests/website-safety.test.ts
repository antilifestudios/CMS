/**
 * Website Safety Engine Tests.
 *
 * Unit tests covering:
 * - URL anatomy analysis (Punycode, IP literals, deceptive keywords, subdomains)
 * - Security headers analysis (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, server banners)
 * - Mixed content detection
 * - Redirect chain analysis (downgrade, cross-domain, excessive hops)
 * - Deterministic scoring & verdict calculation
 * - Fail-soft threat intelligence and DoH resolvers
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeUrlAnatomy,
  analyzeSecurityHeaders,
  detectMixedContent,
  analyzeRedirectChain,
  analyzeWebsiteSafety,
} from '../src/lib/detect/website-safety.ts';

describe('analyzeUrlAnatomy', () => {
  it('identifies standard clean domain', () => {
    const res = analyzeUrlAnatomy('https://example.com/blog');
    assert.equal(res.hostname, 'example.com');
    assert.equal(res.isIpAddress, false);
    assert.equal(res.isPunycode, false);
    assert.equal(res.hasSuspiciousKeywords, false);
    assert.equal(res.subdomainCount, 0);
  });

  it('detects punycode internationalized domains', () => {
    const res = analyzeUrlAnatomy('https://xn--e1afmkfd.xn--p1ai');
    assert.equal(res.isPunycode, true);
  });

  it('detects IP address based hostnames', () => {
    const res = analyzeUrlAnatomy('http://192.168.1.1/admin');
    assert.equal(res.isIpAddress, true);
  });

  it('detects suspicious phishing keywords in host or path', () => {
    const res = analyzeUrlAnatomy('https://secure-banking-login-update.example.net');
    assert.equal(res.hasSuspiciousKeywords, true);
    assert.ok(res.detectedKeywords.includes('login-update') || res.detectedKeywords.includes('secure-banking'));
  });

  it('counts excessive subdomains', () => {
    const res = analyzeUrlAnatomy('https://a.b.c.d.example.com');
    assert.ok(res.subdomainCount >= 3);
  });
});

describe('analyzeSecurityHeaders', () => {
  it('correctly audits secure headers', () => {
    const headers = {
      'content-security-policy': "default-src 'self'; script-src 'self' https://trusted.com",
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    };
    const res = analyzeSecurityHeaders(headers);
    assert.equal(res.csp.present, true);
    assert.equal(res.csp.hasUnsafeInline, false);
    assert.equal(res.xContentTypeOptions.isNosniff, true);
    assert.equal(res.xFrameOptions.protected, true);
    assert.equal(res.referrerPolicy.recommended, true);
    assert.equal(res.serverExposure.exposesVersion, false);
  });

  it('detects missing headers and weak configurations', () => {
    const headers = {
      'content-security-policy': "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      server: 'Apache/2.4.51 (Debian)',
      'x-powered-by': 'PHP/7.4.30',
    };
    const res = analyzeSecurityHeaders(headers);
    assert.equal(res.csp.hasUnsafeInline, true);
    assert.equal(res.csp.hasUnsafeEval, true);
    assert.equal(res.xContentTypeOptions.isNosniff, false);
    assert.equal(res.xFrameOptions.protected, false);
    assert.equal(res.serverExposure.exposesVersion, true);
  });
});

describe('detectMixedContent', () => {
  it('finds insecure HTTP resources on an HTTPS page', () => {
    const html = `
      <html>
        <head>
          <script src="http://cdn.insecure.com/script.js"></script>
          <link rel="stylesheet" href="https://secure.com/style.css">
        </head>
        <body>
          <img src="http://example.com/logo.png" />
          <iframe src="http://tracker.com/embed"></iframe>
        </body>
      </html>
    `;
    const res = detectMixedContent(html, true);
    assert.equal(res.hasInsecureResources, true);
    assert.equal(res.count, 3);
  });

  it('reports zero mixed content on clean HTTPS page', () => {
    const html = `<html><head><script src="https://cdn.secure.com/app.js"></script></head></html>`;
    const res = detectMixedContent(html, true);
    assert.equal(res.hasInsecureResources, false);
    assert.equal(res.count, 0);
  });

  it('does not flag mixed content on plain HTTP page', () => {
    const html = `<img src="http://example.com/image.png" />`;
    const res = detectMixedContent(html, false);
    assert.equal(res.hasInsecureResources, false);
  });
});

describe('analyzeRedirectChain', () => {
  it('detects HTTPS to HTTP downgrade redirection as critical risk', () => {
    const res = analyzeRedirectChain('https://example.com', 'http://unencrypted.com', [
      'https://example.com',
      'http://unencrypted.com',
    ]);
    assert.equal(res.hasDowngrade, true);
  });

  it('detects cross-domain redirection', () => {
    const res = analyzeRedirectChain('https://brand.com', 'https://completely-different-domain.org', [
      'https://brand.com',
      'https://completely-different-domain.org',
    ]);
    assert.equal(res.hasCrossDomain, true);
  });

  it('flags excessive hops', () => {
    const res = analyzeRedirectChain('https://example.com', 'https://example.com/final', [
      'https://example.com',
      'https://example.com/hop1',
      'https://example.com/hop2',
      'https://example.com/hop3',
      'https://example.com/hop4',
      'https://example.com/final',
    ]);
    assert.equal(res.isExcessive, true);
    assert.ok(res.hopsCount >= 4);
  });
});

describe('analyzeWebsiteSafety full pipeline', () => {
  it('returns clean verdict and high safety score for modern secure site', async () => {
    // Mock fetch for DoH / HTTP probes
    const mockFetch: typeof fetch = async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.includes('cloudflare-dns.com') && urlStr.includes('type=A')) {
        return new Response(
          JSON.stringify({
            Status: 0,
            AD: true,
            Answer: [{ name: 'example.com', type: 1, TTL: 300, data: '93.184.216.34' }],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (urlStr.includes('security.cloudflare-dns.com')) {
        return new Response(
          JSON.stringify({
            Status: 0,
            Answer: [{ name: 'example.com', type: 1, TTL: 300, data: '93.184.216.34' }],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (urlStr.includes('cloudflare-dns.com') && urlStr.includes('type=CAA')) {
        return new Response(
          JSON.stringify({
            Status: 0,
            Answer: [{ name: 'example.com', type: 257, TTL: 3600, data: '0 issue "digicert.com"' }],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (urlStr.startsWith('http://')) {
        return new Response(null, {
          status: 301,
          headers: { location: 'https://example.com/' },
        });
      }
      return new Response('Not found', { status: 404 });
    };

    const result = await analyzeWebsiteSafety({
      rawUrl: 'https://example.com',
      finalUrl: 'https://example.com',
      redirectChain: ['https://example.com'],
      headers: {
        'content-security-policy': "default-src 'self'",
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'SAMEORIGIN',
        'referrer-policy': 'strict-origin-when-cross-origin',
      },
      html: '<html><head><title>Secure Site</title></head><body><h1>Hello</h1></body></html>',
      fetchImpl: mockFetch,
    });

    assert.equal(result.verdict, 'no_known_threats');
    assert.ok(result.safetyScore >= 80, `Expected score >= 80, got ${result.safetyScore}`);
    assert.equal(result.connectionSecurity.isHttps, true);
    assert.equal(result.connectionSecurity.httpRedirectsToHttps, true);
    assert.equal(result.connectionSecurity.mixedContent.hasInsecureResources, false);
    assert.equal(result.stats.threats, 0);
    assert.ok(result.findings.length > 5);
  });

  it('assigns known_threat verdict when protocol downgrade is detected', async () => {
    const mockFetch: typeof fetch = async () => new Response(JSON.stringify({ Status: 0 }), { status: 200 });

    const result = await analyzeWebsiteSafety({
      rawUrl: 'https://example.com',
      finalUrl: 'http://insecure.com',
      redirectChain: ['https://example.com', 'http://insecure.com'],
      headers: {},
      html: '<html><body>Down graded</body></html>',
      fetchImpl: mockFetch,
    });

    assert.equal(result.verdict, 'known_threat');
    assert.equal(result.ratingLabel, 'High Risk');
    assert.ok(result.stats.threats > 0);
  });
});
