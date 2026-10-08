/**
 * SSRF guard for the detection pipeline.
 *
 * Validates user-supplied URLs before any network request is made.
 * Runs inside the Cloudflare Worker runtime (no Node APIs).
 *
 * Checks performed:
 *  1. URL parseable and only http/https
 *  2. Only ports 80, 443, or default (empty)
 *  3. No localhost, .local, .internal, .localhost, .test, .example, .invalid
 *  4. No literal IPs — dotted IPv4, decimal/hex/octal encodings, or IPv6
 *  5. No cloud-metadata hostnames
 *  6. Credentials stripped, hostname lowercased + punycode-normalised by URL
 *
 * Note: Workers cannot pre-resolve DNS, so a domain that resolves to a
 * private IP is additionally mitigated by Cloudflare's own egress guards
 * (Workers block fetches to private ranges). Every redirect hop is
 * re-validated with validateRedirect(). This limitation is documented
 * in /methodology.
 */

export type SsrfValidationResult =
  | { ok: true; url: URL }
  | { ok: false; code: string; message: string };

/** Reserved hostnames / suffixes that should never be fetched */
const BLOCKED_HOSTNAME_PATTERNS = [
  /^localhost$/i,
  /\.localhost$/i,
  /\.local$/i,
  /\.localsite$/i,
  /\.internal$/i,
  /\.intranet$/i,
  /\.test$/i,
  /\.example$/i,
  /\.invalid$/i,
  /\.lan$/i,
  /\.home$/i,
  /^0\.0\.0\.0$/,
  /^127\.\d+\.\d+\.\d+$/, // 127.x.x.x loopback
  /^10\.\d+\.\d+\.\d+$/, // RFC 1918 Class A
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/, // RFC 1918 Class B
  /^192\.168\.\d+\.\d+$/, // RFC 1918 Class C
  /^169\.254\.\d+\.\d+$/, // Link-local (incl. cloud metadata 169.254.169.254)
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+$/, // CGNAT
  /^metadata\.google\.internal$/i, // GCP metadata
  /^metadata\.goog$/i,
  /^instance-data\.compute\.internal$/i,
];

/** Allowed ports (empty string = default for scheme) */
const ALLOWED_PORTS = new Set(['', '80', '443']);

/**
 * Return true if the hostname looks like an IPv4 address in any common
 * encoding: dotted decimal, dotted hex/octal, or a single 32-bit integer
 * (decimal or 0x-hex), which browsers/URL parsers resolve to an IP.
 */
function looksLikeIpv4(host: string): boolean {
  const h = host.toLowerCase();
  // Standard dotted quad (decimal)
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
  // Dotted with hex (0x..) or octal (leading 0) parts: 0x7f.0.0.1, 0177.0.0.1
  if (/^(0x[0-9a-f]+|0[0-7]*|\d+)(\.(0x[0-9a-f]+|0[0-7]*|\d+)){3}$/.test(h)) return true;
  // Single-integer forms: 2130706433, 0x7f000001, 037700000001
  if (/^\d+$/.test(h)) {
    try {
      const n = BigInt(h);
      if (n >= 0n && n <= 4294967295n) return true;
    } catch {
      return true; // unparseable numeric host — treat as suspicious
    }
  }
  if (/^0x[0-9a-f]+$/.test(h)) return true;
  if (/^0[0-7]+$/.test(h) && h.length > 1) return true;
  return false;
}

/** Return true if the hostname is (or contains) an IPv6 literal. */
function looksLikeIpv6(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  // Any colon means IPv6 literal in the URL host position
  if (h.includes(':')) return true;
  return false;
}

/**
 * Normalise and validate a user-supplied URL string.
 * Returns {ok: true, url} or {ok: false, code, message}.
 */
export function validateUrl(raw: string): SsrfValidationResult {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { ok: false, code: 'INVALID_URL', message: 'Empty URL' };
  }
  if (trimmed.length > 2048) {
    return { ok: false, code: 'INVALID_URL', message: 'URL too long' };
  }
  // Reject control characters / spaces (encoded or raw)
  if (/[\s<>\"'`]/.test(trimmed)) {
    return { ok: false, code: 'INVALID_URL', message: 'URL contains invalid characters' };
  }

  // Add scheme if missing
  let withScheme = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    withScheme = `https://${trimmed}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    return { ok: false, code: 'INVALID_URL', message: 'Cannot parse URL' };
  }

  // Only http and https
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, code: 'INVALID_URL', message: `Unsupported scheme: ${parsed.protocol}` };
  }

  // Port check
  if (!ALLOWED_PORTS.has(parsed.port)) {
    return { ok: false, code: 'INVALID_URL', message: `Non-standard port: ${parsed.port}` };
  }

  // Hostname must exist
  if (!parsed.hostname) {
    return { ok: false, code: 'INVALID_URL', message: 'Missing hostname' };
  }

  // Decode percent-encoded hostname tricks, then re-check (e.g. %31%32%37 = 127)
  let host = parsed.hostname;
  try {
    const decoded = decodeURIComponent(host);
    if (decoded !== host) host = decoded;
  } catch {
    return { ok: false, code: 'INVALID_URL', message: 'Malformed percent-encoding in hostname' };
  }
  // A decoded hostname that no longer matches the parsed one (e.g. encoded
  // dots or @) is an obfuscation attempt.
  if (/[@\s\/\\?#]/.test(host)) {
    return { ok: false, code: 'INVALID_URL', message: 'Obfuscated hostname' };
  }
  host = host.replace(/\.$/, '').toLowerCase(); // strip trailing dot, lowercase

  if (!host) {
    return { ok: false, code: 'INVALID_URL', message: 'Missing hostname' };
  }

  // Block all literal IPs (IPv4 any encoding, IPv6 any form)
  if (looksLikeIpv4(host) || looksLikeIpv6(host) || looksLikeIpv6(parsed.hostname)) {
    return { ok: false, code: 'PRIVATE_IP', message: 'Direct IP access is not allowed' };
  }

  // Block reserved patterns
  for (const pattern of BLOCKED_HOSTNAME_PATTERNS) {
    if (pattern.test(host)) {
      return {
        ok: false,
        code: 'PRIVATE_IP',
        message: 'Private or reserved hostname',
      };
    }
  }

  // Normalise: drop credentials, lowercase, strip trailing dot
  parsed.username = '';
  parsed.password = '';
  try {
    parsed.hostname = host;
  } catch {
    return { ok: false, code: 'INVALID_URL', message: 'Invalid hostname' };
  }

  return { ok: true, url: parsed };
}

/**
 * Validate a redirect-target URL during fetch.
 * Resolves relative locations against the current URL, then applies the
 * full validateUrl() policy (scheme, port, IP, reserved names).
 */
export function validateRedirect(location: string, base: string): SsrfValidationResult {
  const loc = location.trim();
  if (!loc) {
    return { ok: false, code: 'REDIRECT_LOOP', message: 'Empty redirect location' };
  }
  let resolved: URL;
  try {
    resolved = new URL(loc, base);
  } catch {
    return { ok: false, code: 'INVALID_URL', message: 'Invalid redirect location' };
  }
  return validateUrl(resolved.toString());
}
