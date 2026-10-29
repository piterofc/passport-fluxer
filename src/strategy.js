'use strict';

const crypto = require('node:crypto');
const { Strategy: CustomStrategy } = require('passport-custom');
const { FluxerError, errorFromResponse } = require('./errors');
const { discoverEndpoints } = require('./discovery');

const DEFAULT_INSTANCE_URL = 'https://api.fluxer.app';
const DEFAULT_SCOPE = ['identify'];
const DEFAULT_TIMEOUT = 10_000;

/**
 * Passport strategy for "Sign in with Fluxer" (OAuth2 authorization code grant, with PKCE).
 *
 * It is built on top of `passport-custom`: the strategy decides whether the request is the
 * start of the flow (redirect to Fluxer) or the callback (`?code=...`), and in the callback case
 * hands off to passport-custom's `verify` plumbing, which runs the token exchange, loads the
 * profile and calls your `verify` function.
 */
class Strategy extends CustomStrategy {
  /**
   * @param {import('./index').StrategyOptions} options
   * @param {Function} verify  (accessToken, refreshToken, profile, done) — see README for variants
   */
  constructor(options, verify) {
    if (typeof options === 'function') {
      verify = options;
      options = undefined;
    }
    if (!options || typeof options !== 'object') throw new TypeError('passport-fluxer: options are required');
    if (typeof verify !== 'function') throw new TypeError('passport-fluxer: a verify callback is required');
    for (const key of ['clientID', 'clientSecret', 'callbackURL']) {
      if (typeof options[key] !== 'string' || !options[key]) {
        throw new TypeError(`passport-fluxer: option "${key}" is required`);
      }
    }

    let callbackURL;
    try {
      callbackURL = new URL(options.callbackURL);
    } catch {
      throw new TypeError('passport-fluxer: "callbackURL" must be an absolute URL');
    }
    if (callbackURL.protocol !== 'https:' && callbackURL.protocol !== 'http:') {
      throw new TypeError('passport-fluxer: "callbackURL" must use http or https');
    }

    const fetchImpl = options.fetch || globalThis.fetch;
    if (typeof fetchImpl !== 'function') {
      throw new Error('passport-fluxer: no fetch implementation found (Node 18+ is required, or pass options.fetch)');
    }

    // passport-custom hands the per-request strategy instance back as `this`; see _handleCallback.
    super({ passOptionsToCallback: true }, function (req, authOptions, done) {
      this._handleCallback(req, authOptions, done);
    });

    this.name = options.name || 'fluxer';
    this._verifyUser = verify;
    this._cfg = {
      clientID: options.clientID,
      clientSecret: options.clientSecret,
      // The token endpoint wants the redirect URI normalized (https://a.com -> https://a.com/).
      callbackURL: callbackURL.href,
      scope: normalizeScope(options.scope) || DEFAULT_SCOPE,
      instanceURL: options.instanceURL || DEFAULT_INSTANCE_URL,
      apiURL: options.apiURL ? options.apiURL.replace(/\/+$/, '') : undefined,
      state: options.state !== false,
      pkce: options.pkce !== false,
      passReqToCallback: options.passReqToCallback === true,
      timeout: options.timeout || DEFAULT_TIMEOUT,
      fetch: fetchImpl,
      sessionKey: options.sessionKey || `passport-fluxer:${this.name}`,
    };
    // Shared mutable box: passport clones the strategy per request, so caching must live in an object
    // that every clone references rather than on `this`.
    this._cache = { endpoints: null };
  }

  // ---------------------------------------------------------------------------------------------
  // passport entry point
  // ---------------------------------------------------------------------------------------------

  /**
   * @param {import('./index').Request} req
   * @param {import('./index').AuthenticateOptions} [options]
   */
  authenticate(req, options) {
    options = options || {};
    const query = getQuery(req);

    if (query.error) {
      this._clearSession(req);
      if (query.error === 'access_denied') {
        return this.fail({ message: query.error_description || 'The user denied access.' });
      }
      return this.error(new FluxerError(query.error_description || `Authorization failed: ${query.error}`, { code: String(query.error) }));
    }

    if (query.code) {
      // Callback phase: passport-custom calls this._verify(req, options, verified) -> _handleCallback.
      return super.authenticate(req, options);
    }

    this._startAuthorization(req, options).catch((err) => this.error(err));
  }

  // ---------------------------------------------------------------------------------------------
  // Phase 1: redirect to Fluxer
  // ---------------------------------------------------------------------------------------------

  async _startAuthorization(req, options) {
    const cfg = this._cfg;
    const { apiPublic } = await this._endpoints();

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: cfg.clientID,
      redirect_uri: cfg.callbackURL,
      scope: (normalizeScope(options.scope) || cfg.scope).join(' '),
    });

    if (cfg.state || cfg.pkce) {
      if (!req.session) {
        throw new Error(
          'passport-fluxer needs a session (e.g. express-session) to store the OAuth2 state / PKCE verifier. ' +
            'Add session middleware, or disable "state" and "pkce" (not recommended).',
        );
      }
      const saved = {};
      if (cfg.state) {
        saved.state = randomToken(24);
        params.set('state', saved.state);
      }
      if (cfg.pkce) {
        saved.verifier = randomToken(32);
        params.set('code_challenge', crypto.createHash('sha256').update(saved.verifier).digest('base64url'));
        params.set('code_challenge_method', 'S256');
      }
      req.session[cfg.sessionKey] = saved;
    }

    if (options.prompt) params.set('prompt', options.prompt);
    for (const [key, value] of Object.entries(options.authorizationParams || {})) {
      if (value !== undefined && value !== null) params.set(key, String(value));
    }

    this.redirect(`${apiPublic}/v1/oauth2/authorize?${params}`);
  }

  // ---------------------------------------------------------------------------------------------
  // Phase 2: callback (runs through passport-custom's verify slot)
  // ---------------------------------------------------------------------------------------------

  async _handleCallback(req, authOptions, done) {
    try {
      const cfg = this._cfg;
      const query = getQuery(req);
      let verifier;

      if (cfg.state || cfg.pkce) {
        const saved = req.session && req.session[cfg.sessionKey];
        if (req.session) delete req.session[cfg.sessionKey]; // single use
        if (!saved) {
          return done(null, false, { message: 'Unable to verify the authorization request: no pending login found in the session.' });
        }
        if (cfg.state && !safeEqual(saved.state, query.state)) {
          return done(null, false, { message: 'Invalid authorization request state.' });
        }
        verifier = saved.verifier;
      }

      const tokens = await this._requestToken({
        grant_type: 'authorization_code',
        code: String(query.code),
        redirect_uri: cfg.callbackURL,
        ...(verifier ? { code_verifier: verifier } : {}),
      });
      const profile = await this.userProfile(tokens.access_token);

      const verify = this._verifyUser;
      const withParams = verify.length === (cfg.passReqToCallback ? 6 : 5);
      const args = [];
      if (cfg.passReqToCallback) args.push(req);
      args.push(tokens.access_token, tokens.refresh_token);
      if (withParams) args.push(tokens);
      args.push(profile, done);

      const result = verify(...args);
      if (result && typeof result.then === 'function') result.then(undefined, done);
    } catch (err) {
      done(err);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Public helpers
  // ---------------------------------------------------------------------------------------------

  /**
   * Fetches the user from `/v1/oauth2/userinfo` and maps it to a Passport-style profile.
   * @param {string} accessToken
   */
  async userProfile(accessToken) {
    const { apiPublic } = await this._endpoints();
    const res = await this._cfg.fetch(`${apiPublic}/v1/oauth2/userinfo`, {
      headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' },
      signal: AbortSignal.timeout(this._cfg.timeout),
    });
    const data = await parseBody(res);
    if (!res.ok) throw errorFromResponse(res.status, data);
    if (!data || typeof data !== 'object' || !data.id) {
      throw new FluxerError('Fluxer returned an unexpected user information response', { status: res.status, data });
    }
    return buildProfile(data);
  }

  /**
   * Exchanges a refresh token for a new token pair. Refresh tokens are single use:
   * persist the returned `refresh_token` straight away, or the user has to log in again.
   * @param {string} refreshToken
   */
  refreshToken(refreshToken) {
    return this._requestToken({ grant_type: 'refresh_token', refresh_token: refreshToken });
  }

  /**
   * Revokes every token the token's user has for this application.
   * @param {string} token
   * @param {'access_token' | 'refresh_token'} [hint]  Pass `refresh_token` for refresh tokens, or Fluxer won't find them.
   */
  async revokeToken(token, hint) {
    const { apiPublic } = await this._endpoints();
    const body = new URLSearchParams({ token, client_id: this._cfg.clientID, client_secret: this._cfg.clientSecret });
    if (hint) body.set('token_type_hint', hint);
    const res = await this._cfg.fetch(`${apiPublic}/v1/oauth2/token/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body,
      signal: AbortSignal.timeout(this._cfg.timeout),
    });
    if (!res.ok) throw errorFromResponse(res.status, await parseBody(res));
  }

  // ---------------------------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------------------------

  async _endpoints() {
    const cfg = this._cfg;
    if (cfg.apiURL) return { apiPublic: cfg.apiURL, endpoints: {} };
    if (!this._cache.endpoints) {
      const pending = discoverEndpoints(cfg.instanceURL, { fetch: cfg.fetch, timeout: cfg.timeout });
      this._cache.endpoints = pending;
      pending.catch(() => {
        if (this._cache.endpoints === pending) this._cache.endpoints = null; // retry next time
      });
    }
    return this._cache.endpoints;
  }

  async _requestToken(params) {
    const cfg = this._cfg;
    const { apiPublic } = await this._endpoints();
    const body = new URLSearchParams({ ...params, client_id: cfg.clientID, client_secret: cfg.clientSecret });
    const res = await cfg.fetch(`${apiPublic}/v1/oauth2/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body,
      signal: AbortSignal.timeout(cfg.timeout),
    });
    const data = await parseBody(res);
    if (!res.ok) throw errorFromResponse(res.status, data);
    if (!data || typeof data !== 'object' || !data.access_token) {
      throw new FluxerError('Fluxer token response did not include an access_token', { status: res.status, data });
    }
    return data;
  }

  _clearSession(req) {
    if (req.session) delete req.session[this._cfg.sessionKey];
  }
}

// -----------------------------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------------------------

function buildProfile(raw) {
  const username = raw.username;
  const profile = {
    provider: 'fluxer',
    id: String(raw.id),
    username,
    discriminator: raw.discriminator,
    displayName: raw.global_name || username,
    globalName: raw.global_name ?? null,
    avatar: raw.avatar ?? null,
    avatarColor: raw.avatar_color ?? null,
    flags: raw.flags,
    bot: raw.bot === true,
    system: raw.system === true,
    _raw: JSON.stringify(raw),
    _json: raw,
  };
  // Only present with the `email` scope (which itself needs `identify`).
  if ('email' in raw) {
    profile.email = raw.email ?? null;
    profile.emailVerified = raw.verified === true;
    profile.emails = raw.email ? [{ value: raw.email, verified: raw.verified === true }] : [];
  }
  return profile;
}

function normalizeScope(scope) {
  if (scope === undefined || scope === null) return undefined;
  const list = Array.isArray(scope) ? scope : String(scope).split(/[\s,]+/);
  const clean = list.map((s) => String(s).trim()).filter(Boolean);
  return clean.length ? clean : undefined;
}

function randomToken(bytes) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function getQuery(req) {
  if (req.query && typeof req.query === 'object') return req.query;
  try {
    return Object.fromEntries(new URL(req.url, 'http://localhost').searchParams);
  } catch {
    return {};
  }
}

async function parseBody(res) {
  const text = await res.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

module.exports = { Strategy };
