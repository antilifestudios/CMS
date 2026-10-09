/**
 * Standard typed error codes and HTTP status mappings for CMSSniff / CMS Detector AI.
 */

export type StandardErrorCode =
  | 'INVALID_URL'
  | 'BLOCKED_TARGET'
  | 'TIMEOUT'
  | 'TLS_ERROR'
  | 'DNS_FAILED'
  | 'TARGET_BLOCKED'
  | 'HTTP_ERROR'
  | 'NOT_HTML'
  | 'TOO_LARGE'
  | 'RATE_LIMITED'
  | 'BUDGET_EXCEEDED'
  | 'INTERNAL';

export interface CoverageMetadata {
  htmlBytes: number;
  bundlesScanned: number;
  bundlesSkipped: number;
  gtmContainersFetched: number;
  truncated: boolean;
  subrequests: number;
  durationMs: number;
}

export type ScanStatus = 'complete' | 'partial' | 'failed';

export interface StandardApiError {
  code: StandardErrorCode;
  message: string;
  retryable: boolean;
  httpStatus?: number;
  partialResults?: unknown[];
  botProtection?: unknown;
}

export interface StandardApiResponse<T> {
  ok: boolean;
  status: ScanStatus;
  coverage: CoverageMetadata;
  data?: T;
  error?: StandardApiError;
}

export const ERROR_HTTP_STATUS: Record<StandardErrorCode, number> = {
  INVALID_URL: 400,
  BLOCKED_TARGET: 403,
  TARGET_BLOCKED: 403,
  NOT_HTML: 422,
  RATE_LIMITED: 429,
  TIMEOUT: 504,
  DNS_FAILED: 502,
  TLS_ERROR: 502,
  HTTP_ERROR: 502,
  TOO_LARGE: 413,
  BUDGET_EXCEEDED: 429,
  INTERNAL: 500,
};

export const RETRYABLE_ERRORS = new Set<StandardErrorCode>([
  'TIMEOUT',
  'HTTP_ERROR',
  'RATE_LIMITED',
  'DNS_FAILED',
]);

export function isRetryable(code: StandardErrorCode): boolean {
  return RETRYABLE_ERRORS.has(code);
}
