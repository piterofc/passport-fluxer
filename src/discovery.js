'use strict';

const { FluxerError, errorFromResponse } = require('./errors');

/**
 * Reads `/.well-known/fluxer` from an instance origin and returns its public API base URL.
 * The Fluxer docs say never to hard-code API domains, so this is the default path.
 *
 * @param {string} origin    e.g. https://example.com
 * @param {{ fetch: typeof fetch, timeout: number }} opts
 * @returns {Promise<{ apiPublic: string, endpoints: Record<string, string> }>}
 */
async function discoverEndpoints(origin, { fetch: fetchImpl, timeout }) {
  const base = origin.replace(/\/+$/, '');
  // The reference docs put the document at the origin root; some deployments serve it under /v1.
  const candidates = [`${base}/.well-known/fluxer`, `${base}/v1/.well-known/fluxer`];
  let lastError;

  for (const url of candidates) {
    try {
      const res = await fetchImpl(url, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(timeout),
      });
      if (!res.ok) {
        lastError = errorFromResponse(res.status, await res.text().catch(() => undefined));
        continue;
      }
      const doc = await res.json();
      const apiPublic = doc && doc.endpoints && doc.endpoints.api_public;
      if (typeof apiPublic !== 'string' || !apiPublic) {
        lastError = new FluxerError(`Discovery document at ${url} has no endpoints.api_public`);
        continue;
      }
      return { apiPublic: apiPublic.replace(/\/+$/, ''), endpoints: doc.endpoints };
    } catch (err) {
      lastError = err;
    }
  }

  throw new FluxerError(`Could not discover Fluxer endpoints from ${origin}`, { cause: lastError });
}

module.exports = { discoverEndpoints };
