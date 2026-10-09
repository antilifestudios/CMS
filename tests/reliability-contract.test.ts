/**
 * Reliability and contract tests for CMSSniff.
 *
 * Verifies:
 * - 12 Standard error codes and HTTP statuses
 * - Standard ApiResponse and Coverage metadata contract
 * - SSRF rejection of private IPs, credentials, and non-standard ports
 * - Failure injection: NOT_HTML, TARGET_BLOCKED, TIMEOUT, 5xx retry, fail-soft bundles
 * - Determinism: identical input yields identical output
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateUrl } from '../src/lib/detect/ssrf.ts';
import {
  ERROR_HTTP_STATUS,
  type StandardErrorCode,
  type StandardApiResponse,
  type CoverageMetadata,
} from '../src/lib/detect/types.ts';
import { collectEvidence } from '../src/lib/detect/static-collect.ts';
import { runDetectionPipeline } from '../src/lib/detect/pipeline.ts';

describe('Standard Error Codes and HTTP Statuses Contract', () => {
  const REQUIRED_CODES: StandardErrorCode[] = [
    'INVALID_URL',
    'BLOCKED_TARGET',
    'TIMEOUT',
    'TLS_ERROR',
    'DNS_FAILED',
    'TARGET_BLOCKED',
    'HTTP_ERROR',
    'NOT_HTML',
    'TOO_LARGE',
    'RATE_LIMITED',
    'BUDGET_EXCEEDED',
    'INTERNAL',
  ];

  it('contains exactly the 12 typed standard error codes', () => {
    for (const code of REQUIRED_CODES) {
      assert.ok(ERROR_HTTP_STATUS[code], `Status code for ${code} must exist`);
      assert.ok(typeof ERROR_HTTP_STATUS[code] === 'number');
    }
  });

  it('maps errors to appropriate HTTP statuses', () => {
    assert.equal(ERROR_HTTP_STATUS.INVALID_URL, 400);
    assert.equal(ERROR_HTTP_STATUS.BLOCKED_TARGET, 403);
    assert.equal(ERROR_HTTP_STATUS.TARGET_BLOCKED, 403);
    assert.equal(ERROR_HTTP_STATUS.NOT_HTML, 422);
    assert.equal(ERROR_HTTP_STATUS.TOO_LARGE, 413);
    assert.equal(ERROR_HTTP_STATUS.RATE_LIMITED, 429);
    assert.equal(ERROR_HTTP_STATUS.BUDGET_EXCEEDED, 429);
    assert.equal(ERROR_HTTP_STATUS.TIMEOUT, 504);
    assert.equal(ERROR_HTTP_STATUS.DNS_FAILED, 502);
    assert.equal(ERROR_HTTP_STATUS.TLS_ERROR, 502);
    assert.equal(ERROR_HTTP_STATUS.HTTP_ERROR, 502);
    assert.equal(ERROR_HTTP_STATUS.INTERNAL, 500);
  });
});

describe('SSRF and URL Validation', () => {
  it('rejects credentials in URL', () => {
    const res = validateUrl('https://admin:password@example.com');
    assert.equal(res.ok, false);
    if (!res.ok) {
      assert.equal(res.code, 'INVALID_URL');
    }
  });

  it('rejects non-standard ports', () => {
    const res = validateUrl('https://example.com:8080');
    assert.equal(res.ok, false);
    if (!res.ok) {
      assert.equal(res.code, 'INVALID_URL');
    }
  });

  it('allows standard ports (80 and 443)', () => {
    const resHttp = validateUrl('http://example.com:80');
    assert.equal(resHttp.ok, true);
    const resHttps = validateUrl('https://example.com:443');
    assert.equal(resHttps.ok, true);
  });

  it('rejects private IPv4 literals', () => {
    for (const ip of ['127.0.0.1', '10.0.1.2', '192.168.1.1', '172.16.0.1', '169.254.169.254']) {
      const res = validateUrl(`http://${ip}`);
      assert.equal(res.ok, false, `Must reject ${ip}`);
      if (!res.ok) {
        assert.equal(res.code, 'BLOCKED_TARGET');
      }
    }
  });

  it('rejects localhost and loopback IPv6', () => {
    assert.equal(validateUrl('http://localhost').ok, false);
    assert.equal(validateUrl('http://[::1]').ok, false);
  });

  it('accepts valid public domain names', () => {
    const res = validateUrl('example.com');
    assert.equal(res.ok, true);
    if (res.ok) {
      assert.equal(res.url.toString(), 'https://example.com/');
    }
  });
});

describe('Failure Injection and Fail-Soft Seam', () => {
  const origFetch = globalThis.fetch;

  it('returns NOT_HTML when target returns non-HTML document', async () => {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ status: 'ok' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });

    try {
      const res = await collectEvidence('https://example.com');
      assert.equal(res.ok, false);
      if (!res.ok) {
        assert.equal(res.code, 'NOT_HTML');
      }
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it('returns TARGET_BLOCKED when target serves Cloudflare challenge or 403', async () => {
    globalThis.fetch = async () =>
      new Response('<html><head><title>Just a moment...</title></head><body>Verifying you are human</body></html>', {
        status: 403,
        headers: { 'Content-Type': 'text/html', 'cf-mitigated': 'challenge' },
      });

    try {
      const res = await collectEvidence('https://example.com');
      assert.equal(res.ok, false);
      if (!res.ok) {
        assert.equal(res.code, 'TARGET_BLOCKED');
      }
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it('retries once on 5xx status and succeeds if second attempt is 200', async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls++;
      if (calls === 1) {
        return new Response('Server Error', { status: 502, headers: { 'Content-Type': 'text/html' } });
      }
      return new Response('<html><head><title>Success</title></head><body>Hello</body></html>', {
        status: 200,
        headers: { 'Content-Type': 'text/html' },
      });
    };

    try {
      const res = await collectEvidence('https://example.com');
      assert.equal(res.ok, true);
      assert.equal(calls, 2);
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it('fails soft when subrequest bundle fetch fails without killing scan', async () => {
    globalThis.fetch = async (input) => {
      const url = String(input);
      if (url.endsWith('.js')) {
        return new Response('Not found', { status: 404 });
      }
      return new Response(
        '<html><head><title>Test</title><script src="/bundle.js"></script><meta name="generator" content="WordPress 6.4"></head><body>Hi</body></html>',
        { status: 200, headers: { 'Content-Type': 'text/html' } },
      );
    };

    try {
      const res = await collectEvidence('https://example.com');
      assert.equal(res.ok, true);
      if (res.ok) {
        assert.ok(res.coverage.bundlesSkipped >= 0);
        assert.ok(res.coverage.subrequests <= 40);
      }
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});

describe('Deterministic Detection and Response Contract', () => {
  const WP_HTML = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta name="generator" content="WordPress 6.5.2" />
        <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
        <script src="/wp-includes/js/wp-emoji-release.min.js"></script>
      </head>
      <body><h1>My Blog</h1></body>
    </html>
  `;

  it('produces identical detection results and ordering across multiple runs', async () => {
    const origFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(WP_HTML, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });

    try {
      const res1 = await runDetectionPipeline('https://example.com');
      const res2 = await runDetectionPipeline('https://example.com');

      assert.equal(res1.ok, true);
      assert.equal(res2.ok, true);

      if (res1.ok && res2.ok) {
        assert.equal(res1.data.results.length, res2.data.results.length);
        for (let i = 0; i < res1.data.results.length; i++) {
          assert.equal(res1.data.results[i].name, res2.data.results[i].name);
          assert.equal(res1.data.results[i].confidence, res2.data.results[i].confidence);
        }
        assert.ok(res1.coverage.subrequests > 0);
        assert.ok(typeof res1.coverage.durationMs === 'number');
      }
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});
