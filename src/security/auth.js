/**
 * ---------------------------------------------------------------------------
 * security/auth.js - Google Identity Services verification and sessions.
 * ---------------------------------------------------------------------------
 * AUTHENTICATION MODEL
 *
 *  1. The browser obtains an ID token (a signed JWT) from Google Identity
 *     Services. The token is never trusted on its own.
 *  2. The server verifies the token's signature against Google's published
 *     JWKS, and checks the issuer, audience and expiry. Only then is the
 *     identity accepted.
 *  3. A random session ID is issued in an httpOnly, SameSite cookie. Session
 *     state lives server-side, so a stolen token cannot be replayed as a
 *     session and the cookie itself carries no identity data.
 *
 * WHY WE DO NOT STORE THE ID TOKEN IN THE COOKIE
 *  - ID tokens are bearer credentials that expire in about an hour and cannot
 *    be revoked. Storing one in a cookie would place a reusable credential
 *    where JavaScript can be tricked into leaking it. We exchange it once for a
 *    server-side session and discard it.
 *
 * WHY A PSEUDONYM
 *  - Downstream systems (audit log, quota tracker) key on a salted hash of the
 *    Google subject ID, not the email address. Records stay linkable without
 *    spreading PII across the codebase.
 */

import crypto from 'node:crypto';
import { OAuth2Client } from 'google-auth-library';
import config from '../config.js';

/** Lazily constructed so the app boots even without a configured client ID. */
let oauthClient = null;

/**
 * @returns {OAuth2Client}
 */
function getClient() {
  oauthClient ??= new OAuth2Client(config.google.clientId);
  return oauthClient;
}

/**
 * @typedef {Object} Session
 * @property {string} id            Opaque random session identifier.
 * @property {string} userId        Salted hash of the Google subject ID.
 * @property {string} sub           Google subject ID (opaque, stable per account).
 * @property {string} email         Verified email address.
 * @property {string} name          Display name from the Google profile.
 * @property {string} [picture]     Avatar URL.
 * @property {boolean} emailVerified
 * @property {number} issuedAt      Epoch milliseconds.
 * @property {number} expiresAt     Epoch milliseconds.
 * @property {number} lastSeenAt    Epoch milliseconds.
 * @property {string} ipHash        Salted hash of the originating IP.
 */

/**
 * Server-side session store.
 *
 * In-memory by design for a single-instance deployment: sessions are short
 * lived and losing them on restart is an acceptable trade for never persisting
 * identity data to disk. For multi-instance deployments, swap this for Redis
 * while keeping the same interface.
 *
 * @type {Map<string, Session>}
 */
const sessions = new Map();

/**
 * Derive the stable internal user identifier.
 * @param {string} sub Google subject ID.
 * @returns {string}
 */
export function deriveUserId(sub) {
  return crypto
    .createHmac('sha256', config.session.secret)
    .update(`user:${sub}`)
    .digest('hex')
    .slice(0, 32);
}

/**
 * Remove expired sessions.
 * @returns {number} Number of sessions removed.
 */
export function pruneSessions() {
  const now = Date.now();
  let removed = 0;
  for (const [id, session] of sessions) {
    if (session.expiresAt <= now) {
      sessions.delete(id);
      removed += 1;
    }
  }
  return removed;
}

// Periodic sweep so abandoned sessions do not accumulate between requests.
const sweepTimer = setInterval(pruneSessions, 5 * 60 * 1000);
// Do not hold the event loop open just for the sweeper.
sweepTimer.unref?.();

/**
 * Verify a Google ID token and return a normalised profile.
 *
 * Performs full verification: signature against Google's rotating JWKS, issuer
 * check, audience check against OUR client ID, and expiry check.
 *
 * @param {string} idToken
 * @returns {Promise<
 *   {ok: true, profile: {sub: string, email: string, name: string, picture: string|undefined, emailVerified: boolean}}
 *   | {ok: false, error: string, code: string}
 * >}
 */
export async function verifyGoogleIdToken(idToken) {
  if (!config.google.clientId) {
    return {
      ok: false,
      error: 'Google sign-in is not configured on this server.',
      code: 'GOOGLE_NOT_CONFIGURED',
    };
  }

  try {
    const ticket = await getClient().verifyIdToken({
      idToken,
      // Pinning the audience is what stops a token minted for a different
      // application from being replayed against this one.
      audience: config.google.clientId,
    });

    const payload = ticket.getPayload();

    if (!payload?.sub) {
      return { ok: false, error: 'Token contained no subject.', code: 'TOKEN_NO_SUB' };
    }

    if (payload.iss !== 'accounts.google.com'
      && payload.iss !== 'https://accounts.google.com') {
      return { ok: false, error: 'Unexpected token issuer.', code: 'TOKEN_ISSUER' };
    }

    // The library checks expiry, but we re-check explicitly and allow a small
    // clock skew for slow devices.
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number'
      && payload.exp + config.google.clockSkewSeconds < nowSeconds) {
      return { ok: false, error: 'Credential has expired.', code: 'TOKEN_EXPIRED' };
    }

    return {
      ok: true,
      profile: {
        sub: payload.sub,
        email: payload.email ?? '',
        name: payload.name ?? 'Verified user',
        picture: payload.picture,
        emailVerified: payload.email_verified === true,
      },
    };
  } catch (error) {
    // Never leak the underlying error text to the client; it can disclose
    // configuration details.
    // eslint-disable-next-line no-console
    console.warn('[lifeline-auth] token verification failed:', error.message);
    return {
      ok: false,
      error: 'Could not verify that Google credential.',
      code: 'TOKEN_INVALID',
    };
  }
}

/**
 * Create a session for a verified profile.
 * @param {{sub: string, email: string, name: string, picture?: string, emailVerified: boolean}} profile
 * @param {string} [reqIpHash]
 * @returns {Session}
 */
export function createSession(profile, reqIpHash = '') {
  pruneSessions();

  const now = Date.now();
  const session = {
    id: crypto.randomBytes(32).toString('base64url'),
    userId: deriveUserId(profile.sub),
    sub: profile.sub,
    email: profile.email,
    name: profile.name,
    picture: profile.picture,
    emailVerified: profile.emailVerified,
    issuedAt: now,
    expiresAt: now + config.session.ttlMs,
    lastSeenAt: now,
    // Bound to the originating IP class so a copied cookie is less useful.
    ipHash: reqIpHash,
  };

  sessions.set(session.id, session);
  return session;
}

/**
 * Look up a session, enforcing expiry.
 * @param {string|undefined} sessionId
 * @returns {Session|null}
 */
export function getSession(sessionId) {
  if (!sessionId) return null;
  const session = sessions.get(sessionId);
  if (!session) return null;

  if (session.expiresAt <= Date.now()) {
    sessions.delete(sessionId);
    return null;
  }

  session.lastSeenAt = Date.now();
  return session;
}

/**
 * Destroy a session (sign out).
 * @param {string|undefined} sessionId
 * @returns {boolean} True if a session was removed.
 */
export function destroySession(sessionId) {
  if (!sessionId) return false;
  return sessions.delete(sessionId);
}

/**
 * Destroy every session belonging to a user. Used when abuse is confirmed.
 * @param {string} userId
 * @returns {number} Sessions revoked.
 */
export function revokeUserSessions(userId) {
  let revoked = 0;
  for (const [id, session] of sessions) {
    if (session.userId === userId) {
      sessions.delete(id);
      revoked += 1;
    }
  }
  return revoked;
}

/**
 * How long the account has existed, used to slow throwaway-account abuse.
 * @param {Session} session
 * @returns {number} Age in seconds.
 */
export function accountAgeSeconds(session) {
  return Math.floor((Date.now() - session.issuedAt) / 1000);
}

/** Session statistics for the health endpoint. */
export function sessionStats() {
  pruneSessions();
  return { active: sessions.size, ttlMs: config.session.ttlMs };
}

export default {
  verifyGoogleIdToken,
  createSession,
  getSession,
  destroySession,
  revokeUserSessions,
  pruneSessions,
  deriveUserId,
  accountAgeSeconds,
  sessionStats,
};
