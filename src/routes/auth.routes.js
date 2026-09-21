/**
 * ---------------------------------------------------------------------------
 * routes/auth.routes.js - Google sign-in, session status and sign-out.
 * ---------------------------------------------------------------------------
 * THE FLOW
 *
 *  1. GET  /api/auth/config   - tells the client whether Google sign-in is
 *                               available, and the public client ID to use.
 *  2. POST /api/auth/google   - receives the ID token the browser obtained from
 *                               Google, verifies it server-side, and issues a
 *                               server-side session cookie.
 *  3. GET  /api/auth/session  - reports who is signed in and their quota.
 *  4. POST /api/auth/signout  - destroys the session server-side.
 *
 * SECURITY REQUIREMENTS ENFORCED HERE
 *  - The ID token is verified against Google's JWKS with OUR client ID pinned as
 *    the audience. A token minted for any other application is rejected.
 *  - The session cookie is httpOnly and SameSite=Strict, so it is neither
 *    readable by JavaScript nor sent on cross-site requests.
 *  - Mutating routes additionally require a valid CSRF token and Origin check.
 *  - Failure responses are deliberately uniform, so they cannot be used to
 *    distinguish "invalid token" from "expired token" and probe server state.
 */

import { Router } from 'express';
import config from '../config.js';
import { authLimiter } from '../security/rateLimiters.js';
import { verifyOrigin, verifyCsrfToken } from '../security/csrf.js';
import { validateIdTokenShape, validateConsent } from '../security/validate.js';
import {
  verifyGoogleIdToken,
  createSession,
  getSession,
  destroySession,
  accountAgeSeconds,
  sessionStats,
} from '../security/auth.js';
import { appendAudit } from '../security/auditLog.js';
import { checkQuota } from '../services/quota.js';
import { hashIp } from '../utils/ip.js';

const router = Router();

/** Cookie options shared by issue and clear, so they cannot drift apart. */
const cookieOptions = {
  httpOnly: true,
  sameSite: 'strict',
  secure: config.isProduction,
  path: '/',
};

/**
 * GET /api/auth/config
 * Public configuration the sign-in UI needs. The client ID is public by design
 * and safe to expose; no secret is ever returned.
 */
router.get('/config', (req, res) => {
  res.json({
    ok: true,
    google: {
      enabled: Boolean(config.google.clientId),
      clientId: config.google.clientId || null,
    },
    session: {
      ttlMs: config.session.ttlMs,
      csrfHeaderName: config.session.csrfHeaderName,
    },
    limits: {
      freeMessagesPerDay: config.limits.freeMessagesPerDay,
      minAccountAgeSeconds: config.limits.minAccountAgeSeconds,
      maxBodyLength: config.sms.maxBodyLength,
    },
    csrfToken: res.locals.csrfToken,
  });
});

/**
 * GET /api/auth/session
 * Report the current session, or that nobody is signed in.
 *
 * Intentionally cheap and never returns 401. It answers "who am I?" rather than
 * "am I allowed?", which keeps the client state machine simple.
 */
router.get('/session', (req, res) => {
  const session = getSession(req.cookies?.[config.session.cookieName]);

  if (!session) {
    res.json({ ok: true, authenticated: false, csrfToken: res.locals.csrfToken });
    return;
  }

  const ageSeconds = accountAgeSeconds(session);

  res.json({
    ok: true,
    authenticated: true,
    user: {
      userId: session.userId,
      email: session.email,
      name: session.name,
      picture: session.picture ?? null,
      emailVerified: session.emailVerified,
    },
    account: {
      ageSeconds,
      // Surfaced so the client can explain why sending is briefly unavailable
      // rather than appearing broken.
      canSendNow: ageSeconds >= config.limits.minAccountAgeSeconds,
      minAgeSeconds: config.limits.minAccountAgeSeconds,
    },
    quota: checkQuota(session.userId),
    expiresAt: session.expiresAt,
    csrfToken: res.locals.csrfToken,
  });
});

/**
 * POST /api/auth/google
 * Exchange a Google ID token for a server-side session.
 */
router.post(
  '/google',
  verifyOrigin,
  verifyCsrfToken,
  authLimiter,
  async (req, res) => {
    const ipHash = hashIp(req.ip);

    const tokenCheck = validateIdTokenShape(req.body?.credential);
    if (!tokenCheck.ok) {
      await appendAudit({ event: 'auth_rejected', ipHash, reasonCode: tokenCheck.code });
      res.status(400).json({ ok: false, error: tokenCheck.error, code: tokenCheck.code });
      return;
    }

    // Explicit consent is required before any account is created. This creates
    // the written record that the user accepted the Acceptable Use Policy,
    // which is the foundation of any enforcement action taken later.
    const consentCheck = validateConsent(req.body?.acceptPolicy, 'Acceptable Use Policy');
    if (!consentCheck.ok) {
      await appendAudit({ event: 'auth_rejected', ipHash, reasonCode: consentCheck.code });
      res.status(400).json({ ok: false, error: consentCheck.error, code: consentCheck.code });
      return;
    }

    const verification = await verifyGoogleIdToken(tokenCheck.value);
    if (!verification.ok) {
      await appendAudit({ event: 'auth_failed', ipHash, reasonCode: verification.code });
      res.status(401).json({ ok: false, error: verification.error, code: verification.code });
      return;
    }

    const session = createSession(verification.profile, ipHash);

    // The session cookie carries ONLY an opaque random identifier. No identity
    // data is stored client-side.
    res.cookie(config.session.cookieName, session.id, {
      ...cookieOptions,
      maxAge: config.session.ttlMs,
    });

    await appendAudit({
      event: 'auth_success',
      userId: session.userId,
      ipHash,
      action: 'login',
      reasonCode: 'google_verified',
      meta: { emailVerified: session.emailVerified },
    });

    res.json({
      ok: true,
      user: {
        userId: session.userId,
        // The email is returned for display only; never used as a database key.
        email: session.email,
        name: session.name,
        picture: session.picture ?? null,
        emailVerified: session.emailVerified,
      },
      quota: checkQuota(session.userId),
      csrfToken: res.locals.csrfToken,
    });
  },
);

/**
 * POST /api/auth/signout
 * Destroy the session server-side and clear the cookie.
 */
router.post('/signout', verifyOrigin, verifyCsrfToken, async (req, res) => {
  const sessionId = req.cookies?.[config.session.cookieName];
  const session = getSession(sessionId);

  if (session) {
    await appendAudit({
      event: 'auth_signout',
      userId: session.userId,
      ipHash: hashIp(req.ip),
      action: 'logout',
      reasonCode: 'user_initiated',
    });
  }

  destroySession(sessionId);

  // `clearCookie` must match the attributes used when the cookie was set, or
  // browsers will ignore it.
  res.clearCookie(config.session.cookieName, cookieOptions);

  res.json({ ok: true, authenticated: false });
});

/**
 * GET /api/auth/stats
 * Anonymous session counters for operational dashboards. Contains no PII.
 */
router.get('/stats', (req, res) => {
  res.json({ ok: true, sessions: sessionStats() });
});

export default router;
