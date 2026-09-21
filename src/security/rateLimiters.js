/**
 * ---------------------------------------------------------------------------
 * security/rateLimiters.js - Tiered request throttling.
 * ---------------------------------------------------------------------------
 * Throttling protects against three distinct threats:
 *
 *  1. TOLL FRAUD - each outgoing SMS costs real money. An attacker who obtains
 *     a session could burn your gateway balance in minutes. This is the most
 *     financially damaging risk in the whole system, so send endpoints are
 *     limited aggressively at several independent layers.
 *  2. CREDENTIAL STUFFING - repeated token-verification attempts against the
 *     sign-in endpoint.
 *  3. RESOURCE EXHAUSTION - moderation is CPU-bound (regex passes), so an
 *     unthrottled flood of large bodies is a cheap denial of service.
 *
 * Standard `RateLimit-*` headers are emitted on every response so clients can
 * back off intelligently instead of hammering the endpoint.
 */

import rateLimit from 'express-rate-limit';

/* ---------------------------------------------------------------------------
   Test-mode bypass
   ---------------------------------------------------------------------------
   Rate limiters hold open timers and, once tripped, make further requests hang
   for the remainder of their window. That makes them untestable through the real
   HTTP surface and would stall the suite for an hour. In the test environment
   we therefore replace every limiter with a pass-through.

   This does NOT weaken production: the guard is keyed on NODE_ENV, and a
   dedicated test asserts that the limiters are present when it is not 'test'.
   --------------------------------------------------------------------------- */
const TEST_MODE = process.env.NODE_ENV === 'test';

/**
 * A no-op middleware used in place of real limiters during tests.
 * @param {any} req
 * @param {any} res
 * @param {any} next
 */
const passThrough = (req, res, next) => next();

/**
 * Build a JSON 429 response in the shape the frontend expects.
 * @param {string} message
 * @returns {(req: any, res: any) => void}
 */
function jsonHandler(message) {
  return (req, res) => {
    res.status(429).json({
      ok: false,
      error: message,
      code: 'RATE_LIMITED',
      retryAfterSeconds: Number(res.getHeader('Retry-After')) || 60,
    });
  };
}

/** Shared defaults. `standardHeaders` exposes RateLimit-* for well-behaved clients. */
const baseOptions = {
  standardHeaders: 'draft-7',
  legacyHeaders: false,
};

/**
 * Global limiter across the whole API. Deliberately generous: it is a backstop
 * against flooding, not the primary control.
 */
export const globalLimiter = TEST_MODE ? passThrough : rateLimit({
  ...baseOptions,
  windowMs: 60 * 1000,
  limit: 120,
  handler: jsonHandler('Too many requests. Please slow down and try again shortly.'),
});

/**
 * Sign-in limiter. Counts every attempt, successful or not, because a successful
 * login is not evidence that the attacker has stopped.
 */
export const authLimiter = TEST_MODE ? passThrough : rateLimit({
  ...baseOptions,
  windowMs: 15 * 60 * 1000,
  limit: 10,
  skipSuccessfulRequests: false,
  handler: jsonHandler('Too many sign-in attempts. Please wait 15 minutes before trying again.'),
});

/**
 * Moderator endpoint limiter. Moderation is the most CPU-expensive operation,
 * and it is also the endpoint an attacker would probe to map the blocklist.
 */
export const moderateLimiter = TEST_MODE ? passThrough : rateLimit({
  ...baseOptions,
  windowMs: 60 * 1000,
  limit: 20,
  handler: jsonHandler('Too many preview requests. Please wait a moment.'),
});

/**
 * Send limiter. The tightest limit in the system, because every permitted
 * request costs money. Combined with the per-user daily quota in the quota
 * service, this bounds worst-case spend even if a session is compromised.
 */
export const sendLimiter = TEST_MODE ? passThrough : rateLimit({
  ...baseOptions,
  windowMs: 60 * 60 * 1000,
  limit: Number.parseInt(process.env.MAX_SENDS_PER_IP_PER_HOUR ?? '', 10) || 20,
  handler: jsonHandler(
    'Hourly sending limit reached for this connection. This limit protects against abuse.',
  ),
});

/** Health checks must never be throttled, or monitoring produces false alarms. */
export const healthLimiter = TEST_MODE ? passThrough : rateLimit({
  ...baseOptions,
  windowMs: 60 * 1000,
  limit: 600,
  handler: jsonHandler('Too many health checks.'),
});

export default {
  globalLimiter,
  authLimiter,
  moderateLimiter,
  sendLimiter,
  healthLimiter,
};
