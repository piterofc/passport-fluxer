'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Strategy, FluxerError } = require('../src');

// ---------------------------------------------------------------------------------------------
// Fake Fluxer server
// ---------------------------------------------------------------------------------------------

const CLIENT_ID = '1234567890';
const CLIENT_SECRET = 'shh';
let fluxer, fluxerURL;
let issuedCode = null; // { code, challenge, redirect_uri }
const seen = { tokenBodies: [], discovery: 0 };

before(async () => {
  fluxer = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const json = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (url.pathname === '/.well-known/fluxer') {
      seen.discovery++;
      return json(200, { endpoints: { api_public: `${fluxerURL}/` } }); // trailing slash on purpose
    }
    if (url.pathname === '/v1/oauth2/token' && req.method === 'POST') {
      let raw = '';
      for await (const chunk of req) raw += chunk;
      const body = Object.fromEntries(new URLSearchParams(raw));
      seen.tokenBodies.push(body);
      if (body.client_id !== CLIENT_ID || body.client_secret !== CLIENT_SECRET) {
        return json(400, { error: 'invalid_client', error_description: 'bad client' });
      }
      if (body.grant_type === 'refresh_token') {
        return json(200, { access_token: 'at2', token_type: 'Bearer', expires_in: 604800, refresh_token: 'rt2', scope: 'identify' });
      }
      if (!issuedCode || body.code !== issuedCode.code) {
        return json(400, { error: 'invalid_grant', error_description: 'The provided authorization grant is invalid, expired, or revoked' });
      }
      if (body.redirect_uri !== issuedCode.redirect_uri) return json(400, { error: 'invalid_grant', error_description: 'redirect mismatch' });
      const challenge = crypto.createHash('sha256').update(body.code_verifier || '').digest('base64url');
      if (challenge !== issuedCode.challenge) return json(400, { error: 'invalid_grant', error_description: 'pkce mismatch' });
      issuedCode = null; // single use
      return json(200, { access_token: 'at1', token_type: 'Bearer', expires_in: 604800, refresh_token: 'rt1', scope: 'identify email' });
    }
    if (url.pathname === '/v1/oauth2/userinfo') {
      if (req.headers.authorization !== 'Bearer at1') return json(401, { code: 'UNAUTHORIZED', message: 'nope' });
      return json(200, {
        sub: '111222333444555666', id: '111222333444555666', username: 'ana', discriminator: '0000',
        global_name: 'Ana', avatar: 'abc123', email: 'ana@example.com', verified: true, flags: 0,
        avatar_color: 5, bot: false, system: false,
      });
    }
    json(404, { code: 'NOT_FOUND', message: 'unknown' });
  });
  await new Promise((r) => fluxer.listen(0, '127.0.0.1', r));
  fluxerURL = `http://127.0.0.1:${fluxer.address().port}`;
});

after(() => fluxer.close());

// ---------------------------------------------------------------------------------------------
// App under test
// ---------------------------------------------------------------------------------------------

// Builds a listening app with the strategy wired up.
async function boot({ options = {}, verify, authOptions } = {}) {
  const p = new passport.Passport();
  const app = express();
  app.use(session({ secret: 's', resave: false, saveUninitialized: false }));
  app.use(p.initialize());
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;

  const strategy = new Strategy(
    {
      clientID: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      callbackURL: `${base}/callback`,
      instanceURL: fluxerURL,
      scope: ['identify', 'email'],
      ...options,
    },
    verify || ((at, rt, profile, done) => done(null, { id: profile.id, at, rt, profile })),
  );
  p.use(strategy);

  app.get('/login', p.authenticate('fluxer', authOptions));
  app.get('/callback', (req, res, next) =>
    p.authenticate('fluxer', { session: false }, (err, user, info) => {
      if (err) return res.status(500).json({ error: err.message, code: err.code });
      if (!user) return res.status(401).json({ info });
      res.json({ user });
    })(req, res, next),
  );
  return { base, strategy, close: () => server.close() };
}

// Tiny cookie-aware client.
function client() {
  let cookie = '';
  return async (url, init = {}) => {
    const res = await fetch(url, { redirect: 'manual', ...init, headers: { ...(init.headers || {}), cookie } });
    const set = res.headers.getSetCookie?.() || [];
    if (set.length) cookie = set.map((c) => c.split(';')[0]).join('; ');
    return res;
  };
}

// Performs /login and returns what Fluxer would see + a function to simulate the user coming back.
async function startLogin(app, get) {
  const res = await get(`${app.base}/login`);
  assert.equal(res.status, 302);
  const location = new URL(res.headers.get('location'));
  return location;
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

test('constructor validates required options', () => {
  const ok = { clientID: 'a', clientSecret: 'b', callbackURL: 'https://x.test/cb' };
  assert.throws(() => new Strategy({ ...ok, clientID: '' }, () => {}), /clientID/);
  assert.throws(() => new Strategy({ ...ok, callbackURL: 'nope' }, () => {}), /absolute URL/);
  assert.throws(() => new Strategy(ok), /verify/);
  assert.equal(new Strategy(ok, () => {}).name, 'fluxer');
});

test('login redirects to the discovered authorize URL with state + PKCE', async () => {
  const app = await boot();
  try {
    const get = client();
    const loc = await startLogin(app, get);
    assert.equal(`${loc.origin}${loc.pathname}`, `${fluxerURL}/v1/oauth2/authorize`); // trailing slash from discovery stripped
    const q = loc.searchParams;
    assert.equal(q.get('response_type'), 'code');
    assert.equal(q.get('client_id'), CLIENT_ID);
    assert.equal(q.get('redirect_uri'), `${app.base}/callback`);
    assert.equal(q.get('scope'), 'identify email');
    assert.equal(q.get('code_challenge_method'), 'S256');
    assert.ok(q.get('state').length >= 20);
    assert.ok(q.get('code_challenge').length >= 40);
  } finally { app.close(); }
});

test('full flow: callback exchanges the code, loads the profile and calls verify', async () => {
  const app = await boot();
  try {
    const get = client();
    const loc = await startLogin(app, get);
    issuedCode = { code: 'good-code', challenge: loc.searchParams.get('code_challenge'), redirect_uri: `${app.base}/callback` };

    const res = await get(`${app.base}/callback?code=good-code&state=${encodeURIComponent(loc.searchParams.get('state'))}`);
    assert.equal(res.status, 200);
    const { user } = await res.json();
    assert.equal(user.id, '111222333444555666'); // snowflake stays a string
    assert.equal(user.at, 'at1');
    assert.equal(user.rt, 'rt1');
    assert.equal(user.profile.provider, 'fluxer');
    assert.equal(user.profile.displayName, 'Ana');
    assert.equal(user.profile.email, 'ana@example.com');
    assert.equal(user.profile.emailVerified, true);
    assert.deepEqual(user.profile.emails, [{ value: 'ana@example.com', verified: true }]);
  } finally { app.close(); }
});

test('rejects a callback with the wrong state, without calling Fluxer', async () => {
  const app = await boot();
  try {
    const get = client();
    await startLogin(app, get);
    const before = seen.tokenBodies.length;
    const res = await get(`${app.base}/callback?code=whatever&state=forged`);
    assert.equal(res.status, 401);
    assert.match((await res.json()).info.message, /state/i);
    assert.equal(seen.tokenBodies.length, before);
  } finally { app.close(); }
});

test('rejects a callback with no pending login, and the state is single use', async () => {
  const app = await boot();
  try {
    const get = client();
    const noSession = await get(`${app.base}/callback?code=x&state=y`);
    assert.equal(noSession.status, 401);

    const loc = await startLogin(app, get);
    const state = loc.searchParams.get('state');
    await get(`${app.base}/callback?code=bad&state=${state}`); // consumes the state
    const replay = await get(`${app.base}/callback?code=bad&state=${state}`);
    assert.equal(replay.status, 401);
    assert.match((await replay.json()).info.message, /no pending login/);
  } finally { app.close(); }
});

test('surfaces OAuth2 errors from the token endpoint as FluxerError', async () => {
  const app = await boot();
  try {
    const get = client();
    const loc = await startLogin(app, get);
    issuedCode = null;
    const res = await get(`${app.base}/callback?code=expired&state=${loc.searchParams.get('state')}`);
    assert.equal(res.status, 500);
    const body = await res.json();
    assert.equal(body.code, 'invalid_grant');
    assert.match(body.error, /invalid, expired, or revoked/);
  } finally { app.close(); }
});

test('user denying consent is a normal authentication failure, other errors are errors', async () => {
  const app = await boot();
  try {
    const get = client();
    await startLogin(app, get);
    const denied = await get(`${app.base}/callback?error=access_denied&error_description=nope`);
    assert.equal(denied.status, 401);
    assert.equal((await denied.json()).info.message, 'nope');

    const other = await get(`${app.base}/callback?error=consent_required`);
    assert.equal(other.status, 500);
    assert.equal((await other.json()).code, 'consent_required');
  } finally { app.close(); }
});

test('sends the normalized redirect_uri at the token endpoint (bare origin gets a trailing slash)', async () => {
  const strategy = new Strategy(
    { clientID: CLIENT_ID, clientSecret: CLIENT_SECRET, callbackURL: 'https://example.com', apiURL: fluxerURL },
    () => {},
  );
  seen.tokenBodies.length = 0;
  issuedCode = null;
  await assert.rejects(strategy._requestToken({ grant_type: 'authorization_code', code: 'x', redirect_uri: strategy._cfg.callbackURL }));
  assert.equal(seen.tokenBodies.at(-1).redirect_uri, 'https://example.com/');
});

test('discovery is cached across requests; apiURL skips it', async () => {
  const app = await boot();
  try {
    const get = client();
    seen.discovery = 0;
    await startLogin(app, get);
    await startLogin(app, get);
    assert.equal(seen.discovery, 1);
  } finally { app.close(); }

  seen.discovery = 0;
  const direct = await boot({ options: { instanceURL: undefined, apiURL: fluxerURL } });
  try {
    const loc = await startLogin(direct, client());
    assert.equal(loc.origin, fluxerURL);
    assert.equal(seen.discovery, 0);
  } finally { direct.close(); }
});

test('authenticate options: scope, prompt and extra authorize params', async () => {
  const app = await boot({ authOptions: { scope: 'identify guilds', prompt: 'none', authorizationParams: { guild_id: '42', skip: undefined } } });
  try {
    const loc = await startLogin(app, client());
    assert.equal(loc.searchParams.get('scope'), 'identify guilds');
    assert.equal(loc.searchParams.get('prompt'), 'none');
    assert.equal(loc.searchParams.get('guild_id'), '42');
    assert.equal(loc.searchParams.has('skip'), false);
  } finally { app.close(); }
});

test('verify arity: params variant and passReqToCallback + async verify', async () => {
  let captured;
  const app = await boot({
    options: { passReqToCallback: true },
    verify: async (req, at, rt, params, profile, done) => {
      captured = { hasReq: typeof req.url === 'string', scope: params.scope, expires: params.expires_in };
      done(null, { id: profile.id });
    },
  });
  try {
    const get = client();
    const loc = await startLogin(app, get);
    issuedCode = { code: 'c2', challenge: loc.searchParams.get('code_challenge'), redirect_uri: `${app.base}/callback` };
    const res = await get(`${app.base}/callback?code=c2&state=${loc.searchParams.get('state')}`);
    assert.equal(res.status, 200);
    assert.deepEqual(captured, { hasReq: true, scope: 'identify email', expires: 604800 });
  } finally { app.close(); }
});

test('verify can reject the login via done(null, false, info)', async () => {
  const app = await boot({ verify: (at, rt, profile, done) => done(null, false, { message: 'not allowed' }) });
  try {
    const get = client();
    const loc = await startLogin(app, get);
    issuedCode = { code: 'c3', challenge: loc.searchParams.get('code_challenge'), redirect_uri: `${app.base}/callback` };
    const res = await get(`${app.base}/callback?code=c3&state=${loc.searchParams.get('state')}`);
    assert.equal(res.status, 401);
    assert.equal((await res.json()).info.message, 'not allowed');
  } finally { app.close(); }
});

test('missing session gives a clear error instead of a silently insecure flow', async () => {
  const p = new passport.Passport();
  const app = express();
  p.use(new Strategy({ clientID: CLIENT_ID, clientSecret: CLIENT_SECRET, callbackURL: 'http://localhost/cb', apiURL: fluxerURL }, () => {}));
  app.get('/login', (req, res, next) => p.authenticate('fluxer', (err) => res.status(500).json({ error: err && err.message }))(req, res, next));
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const res = await fetch(`http://127.0.0.1:${server.address().port}/login`);
    assert.match((await res.json()).error, /needs a session/);
  } finally { server.close(); }
});

test('refreshToken and userProfile helpers', async () => {
  const strategy = new Strategy({ clientID: CLIENT_ID, clientSecret: CLIENT_SECRET, callbackURL: 'http://localhost/cb', apiURL: fluxerURL }, () => {});
  const t = await strategy.refreshToken('rt1');
  assert.equal(t.refresh_token, 'rt2');
  const profile = await strategy.userProfile('at1');
  assert.equal(profile.username, 'ana');
  await assert.rejects(strategy.userProfile('bad'), (e) => e instanceof FluxerError && e.status === 401 && e.code === 'UNAUTHORIZED');
});

test('discovery failure is reported and not cached forever', async () => {
  const strategy = new Strategy({ clientID: 'a', clientSecret: 'b', callbackURL: 'http://localhost/cb', instanceURL: 'http://127.0.0.1:1', timeout: 500 }, () => {});
  await assert.rejects(strategy.userProfile('x'), /Could not discover/);
  assert.equal(strategy._cache.endpoints, null);
});
