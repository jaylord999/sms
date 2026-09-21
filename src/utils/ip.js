/**
 * ---------------------------------------------------------------------------
 * utils/ip.js - IP address normalisation and pseudonymisation.
 * ---------------------------------------------------------------------------
 * IP addresses are personal data under RA 10173 (Data Privacy Act). Storing
 * them in cleartext in logs creates a privacy liability and, on a service like
 * this, a chilling effect on legitimate use.
 *
 * We therefore never store a raw IP. We store a salted HMAC that still lets us:
 *   - rate limit per connection,
 *   - correlate repeat abuse from the same network,
 *   - without retaining a directly identifying value.
 */

import crypto from 'node:crypto';
import config from '../config.js';

/**
 * Normalise an IP address for comparison.
 *
 * IPv6 addresses are truncated to their /64 prefix, because a single subscriber
 * is typically delegated a /64 and treating each address as a distinct client
 * would defeat per-connection limiting entirely.
 *
 * @param {string|undefined} ip
 * @returns {string}
 */
export function normaliseIp(ip) {
  if (!ip || typeof ip !== 'string') return 'unknown';

  // Express may present IPv4-mapped IPv6, e.g. "::ffff:203.0.113.7".
  const unwrapped = ip.startsWith('::ffff:') ? ip.slice(7) : ip.trim();

  if (!unwrapped.includes(':')) {
    return unwrapped; // Plain IPv4
  }

  const segments = unwrapped.split(':');
  if (segments.length < 3) return unwrapped;

  return `${segments.slice(0, 4).join(':')}::/64`;
}

/**
 * Pseudonymise an IP address.
 *
 * @param {string|undefined} ip
 * @returns {string} 32-character hex digest, or 'unknown'.
 */
export function hashIp(ip) {
  const normalised = normaliseIp(ip);
  if (normalised === 'unknown') return 'unknown';

  return crypto
    .createHmac('sha256', config.audit.hashSalt)
    .update(`ip:${normalised}`)
    .digest('hex')
    .slice(0, 32);
}

/**
 * Extract the best available client IP from a request, honouring the proxy
 * trust setting configured on the app.
 *
 * @param {import('express').Request} req
 * @returns {string}
 */
export function clientIp(req) {
  // `req.ip` already respects `trust proxy`, so it is preferred over reading
  // X-Forwarded-For directly, which a client could forge.
  return req.ip ?? req.socket?.remoteAddress ?? 'unknown';
}

export default { normaliseIp, hashIp, clientIp };
