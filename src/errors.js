'use strict';

/**
 * Error raised for anything that goes wrong while talking to Fluxer:
 * OAuth2 error responses, regular API errors, network failures, bad discovery documents.
 */
class FluxerError extends Error {
  /**
   * @param {string} message
   * @param {{ status?: number, code?: string, data?: unknown, cause?: unknown }} [details]
   */
  constructor(message, details = {}) {
    super(message, details.cause !== undefined ? { cause: details.cause } : undefined);
    this.name = 'FluxerError';
    /** HTTP status, when the error came from an HTTP response. */
    this.status = details.status;
    /** OAuth2 `error` value (e.g. `invalid_grant`) or API error `code` (e.g. `MISSING_OAUTH_SCOPE`). */
    this.code = details.code;
    /** Parsed response body, when available. */
    this.data = details.data;
  }
}

/**
 * Builds a FluxerError from a non-2xx response body.
 * Handles both the OAuth2 shape ({ error, error_description }) and the regular API shape ({ code, message }).
 */
function errorFromResponse(status, data) {
  const obj = data && typeof data === 'object' ? data : {};
  const code = obj.error || obj.code;
  const message =
    obj.error_description || obj.message || (typeof data === 'string' && data) || `Fluxer request failed with status ${status}`;
  return new FluxerError(String(message), { status, code: code ? String(code) : undefined, data });
}

module.exports = { FluxerError, errorFromResponse };
