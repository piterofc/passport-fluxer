import type { IncomingMessage } from 'node:http';

/** Minimal request shape (compatible with Express' `Request`). */
export interface Request extends IncomingMessage {
  query?: Record<string, any>;
  session?: Record<string, any>;
}

export interface StrategyOptions {
  /** Application ID (snowflake) from the Fluxer Applications API. */
  clientID: string;
  clientSecret: string;
  /** Absolute URL registered as a redirect URI on the application. */
  callbackURL: string;
  /** Scopes to request. Default: `['identify']`. `email` only works together with `identify`. */
  scope?: string | string[];
  /**
   * Origin of the Fluxer instance, used for `/.well-known/fluxer` discovery.
   * Default: `https://api.fluxer.app`.
   */
  instanceURL?: string;
  /** Skip discovery and use this as the public API base URL (the part before `/v1`). */
  apiURL?: string;
  /** Strategy name used by `passport.authenticate()`. Default: `'fluxer'`. */
  name?: string;
  /** Send and verify an OAuth2 `state` (needs a session). Default: `true`. */
  state?: boolean;
  /** Use PKCE with S256 (needs a session). Default: `true`. */
  pkce?: boolean;
  /** Pass `req` as the first argument of `verify`. */
  passReqToCallback?: boolean;
  /** Timeout for each HTTP request to Fluxer, in ms. Default: `10000`. */
  timeout?: number;
  /** Custom fetch implementation (defaults to the global `fetch`). */
  fetch?: typeof fetch;
  /** Session key for the pending login data. Default: `passport-fluxer:<name>`. */
  sessionKey?: string;
}

export interface AuthenticateOptions {
  /** Override the scopes for this login attempt. */
  scope?: string | string[];
  /** `consent` or `none`. With `none`, Fluxer skips the consent screen when everything was already granted. */
  prompt?: 'consent' | 'none';
  /** Extra raw query parameters for the authorize URL (e.g. `guild_id`, `permissions` with the `bot` scope). */
  authorizationParams?: Record<string, string | number | boolean | null | undefined>;
  [key: string]: any;
}

export interface FluxerUserInfo {
  sub: string;
  id: string;
  username: string;
  discriminator: string;
  global_name: string | null;
  avatar: string | null;
  email?: string | null;
  verified?: boolean | null;
  flags?: number;
  avatar_color: number | null;
  bot: boolean;
  system: boolean;
}

export interface Profile {
  provider: 'fluxer';
  id: string;
  username: string;
  discriminator: string;
  /** `global_name`, falling back to `username`. */
  displayName: string;
  globalName: string | null;
  /** Avatar hash (not a URL). */
  avatar: string | null;
  avatarColor: number | null;
  flags?: number;
  bot: boolean;
  system: boolean;
  /** Only with the `email` scope. */
  email?: string | null;
  emailVerified?: boolean;
  emails?: Array<{ value: string; verified: boolean }>;
  _raw: string;
  _json: FluxerUserInfo;
}

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  /** Access token lifetime in seconds. */
  expires_in: number;
  refresh_token: string;
  /** Granted scopes, separated by spaces. */
  scope: string;
}

export type DoneCallback = (error: any, user?: any, info?: any) => void;

type MaybePromise = void | Promise<void>;

export type VerifyFunction = (accessToken: string, refreshToken: string, profile: Profile, done: DoneCallback) => MaybePromise;
export type VerifyFunctionWithParams = (accessToken: string, refreshToken: string, params: TokenResponse, profile: Profile, done: DoneCallback) => MaybePromise;
export type VerifyFunctionWithRequest = (req: Request, accessToken: string, refreshToken: string, profile: Profile, done: DoneCallback) => MaybePromise;
export type VerifyFunctionWithRequestAndParams = (req: Request, accessToken: string, refreshToken: string, params: TokenResponse, profile: Profile, done: DoneCallback) => MaybePromise;

export class Strategy {
  name: string;
  // Overloads are ordered by verify arity so TypeScript can infer callback parameters.
  constructor(options: StrategyOptions & { passReqToCallback?: false }, verify: VerifyFunction);
  constructor(options: StrategyOptions & { passReqToCallback?: false }, verify: VerifyFunctionWithParams);
  constructor(options: StrategyOptions & { passReqToCallback: true }, verify: VerifyFunctionWithRequest);
  constructor(options: StrategyOptions & { passReqToCallback: true }, verify: VerifyFunctionWithRequestAndParams);
  authenticate(req: Request, options?: AuthenticateOptions): void;
  /** Loads the user from `/v1/oauth2/userinfo`. */
  userProfile(accessToken: string): Promise<Profile>;
  /** Refresh tokens are single use: store the new `refresh_token` immediately. */
  refreshToken(refreshToken: string): Promise<TokenResponse>;
  /** Revokes every token the user has for this application. */
  revokeToken(token: string, hint?: 'access_token' | 'refresh_token'): Promise<void>;
}

export { Strategy as FluxerStrategy };

export class FluxerError extends Error {
  status?: number;
  /** OAuth2 `error` (e.g. `invalid_grant`) or API error `code`. */
  code?: string;
  data?: unknown;
  constructor(message: string, details?: { status?: number; code?: string; data?: unknown; cause?: unknown });
}
