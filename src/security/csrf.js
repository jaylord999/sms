/**
 * ---------------------------------------------------------------------------
 * security/csrf.js - Double-submit cookie CSRF protection.
 * ---------------------------------------------------------------------------
 * WHY THIS IS NEEDED
 *  - The session cookie is sent automatically by the browser on every request
 *    to our origin. Without CSRF protection, a malicious page could silently
 *    submit an SMS send on behalf of a signed-in user. On a service that costs
 *    money per message, that is a direct financial attack.
 *
 * HOW IT WORKS
 *  1. On any GET, we issue a random CSRF token in a NON-httpOnly cookie, so
 *     JavaScript can read it, plus we return it in the body.
 *  2. The client echoes the token back in a custom header on every mutating
 *     request.
 *  3. The server compares the header to the cookie. An attacker on another
 *     origin can force the cookie to be sent but cannot read it, so they cannot
 *     supply a matching header.
 *
 * The custom header requirement is doing double duty: it also means a simple
 * cross-site form POST cannot trigger a mutating request at all, because
 * ordinary HTML forms cannot set custom headers.
 */

import crypto from 'node:crypto';
import config from '../config.js';

/**
 * Generate a new CSRF token.
 * @returns {string}
 */
export function generateCsrfToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Timing-safe comparison so token checks cannot be attacked by measuring
 * response times.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeEqual(a, b) {
  const bufferA = Buffer.from(String(a ?? ''), 'utf8');
  const bufferB = Buffer.from(String(b ?? ''), 'utf8');
  if (bufferA.length !== bufferB.length) return false;
  return crypto.timingSafeEqual(bufferA, bufferB);
}

/**
 * Express middleware that issues a CSRF token if one is missing.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export function issueCsrfToken(req, res, next) {
  const { csrfCookieName } = config.session;

  let token = req.cookies?.[csrfCookieName];
  if (!token || typeof token !== 'string' || token.length < 32) {
    token = generateCsrfToken();
    res.cookie(csrfCookieName, token, {
      // Readable by JS by design: this is the half the client must echo back.
      httpOnly: false,
      sameSite: 'strict',
      secure: config.isProduction,
      path: '/',
      maxAge: config.session.ttlMs,
    });
  }

  // Expose to templates and to the session status endpoint.
  res.locals.csrfToken = token;
  next();
}

/**
 * Verify the CSRF token on a mutating request.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export function verifyCsrfToken(req, res, next) {
  const { csrfCookieName, csrfHeaderName } = config.session;

  const cookieToken = req.cookies?.[csrfCookieName];
  const headerToken = req.get(csrfHeaderName);

  if (!cookieToken || !headerToken || !safeEqual(cookieToken, headerToken)) {
    res.status(403).json({
      ok: false,
      error: 'Your session validation token is missing or invalid. Reload the page and try again.',
      code: 'CSRF_INVALID',
    });
    return;
  }

  next();
}

/**
 * Reject mutating requests whose Origin does not match our own.
 *
 * Defence in depth: even if a token check were bypassed, a cross-site request
 * would still be refused here.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export function verifyOrigin(req, res, next) {
  const method = req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    next();
    return;
  }

  const origin = req.get('origin');
  const referer = req.get('referer');

  // No Origin header: same-origin navigations and some server-to-server calls.
  // We require at least one of Origin or Referer to be present and correct.
  let source = origin;
  if (!source && referer) {
    try {
      source = new URL(referer).origin;
    } catch {
      // Malformed Referer is treated as absent.
      source = null;
    }
  }

  if (!source) {
    res.status(403).json({
      ok: false,
      error: 'Request blocked: missing origin.',
      code: 'ORIGIN_REJECTED',
    });
    return;
  }

  // Accepted origins:
  //   1. The configured APP_ORIGIN, which is authoritative in production.
  //   2. The host this request actually arrived on, which keeps local
  //      development and tests working without extra configuration.
  const expected = new Set([config.appOrigin]);
  const host = req.get('host');
  if (host) {
    expected.add(`${req.protocol}://${host}`);
  }

  if (!expected.has(source)) {
    res.status(403).json({
      ok: false,
      error: 'Request blocked: unexpected origin.',
      code: 'ORIGIN_REJECTED',
    });
    return;
  }

  next();
}

export default { issueCsrfToken, verifyCsrfToken, verifyOrigin, generateCsrfToken };
