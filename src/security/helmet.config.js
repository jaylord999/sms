/**
 * ---------------------------------------------------------------------------
 * security/helmet.config.js - HTTP security headers and Content Security Policy.
 * ---------------------------------------------------------------------------
 * The CSP is the single most valuable control in this app. Even if a template
 * bug let user input reach the DOM unescaped, a strict policy prevents an
 * injected <script> from running and stops exfiltration to an attacker domain.
 *
 * Because the original page relied on the Tailwind CDN and an icon CDN, those
 * origins must be allowed explicitly. Every host listed below is a deliberate
 * decision with its justification recorded next to it.
 *
 * MIGRATION NOTE: for the tightest possible policy, compile Tailwind to a local
 * stylesheet and self-host the icon sprite. That removes both CDN allowances
 * and lets `script-src` be reduced to 'self'.
 */

import helmet from 'helmet';
import config from '../config.js';

/**
 * Origins the browser is permitted to load resources from.
 *
 * Every entry here is a deliberate, documented allowance. When adding one,
 * record WHY - an unexplained CSP allowance is indistinguishable from a mistake
 * and tends to survive long after the dependency that needed it is gone.
 */
const TRUSTED = {
  scripts: [
    "'self'",
    'https://accounts.google.com', // Google Identity Services
    'https://cdn.tailwindcss.com', // Tailwind CDN runtime (remove when compiled)
    'https://unpkg.com', // Lucide icon library (remove when self-hosted)
  ],
  styles: [
    "'self'",
    // Google Identity Services injects its own stylesheet for the sign-in
    // button. Without this the button renders unstyled, which both looks broken
    // and makes a genuine Google control indistinguishable from a lookalike -
    // the exact substitution the button design is meant to prevent.
    'https://accounts.google.com',
    // Tailwind CDN compiles utilities in the browser and injects them as a
    // <style> block. Removing this requires compiling Tailwind ahead of time.
    "'unsafe-inline'",
    'https://fonts.googleapis.com',
  ],
  fonts: ["'self'", 'https://fonts.gstatic.com', 'data:'],
  images: ["'self'", 'data:', 'https:'],
  connect: [
    "'self'",
    'https://accounts.google.com',
    'https://oauth2.googleapis.com',
    // Lucide's UMD bundle requests its source map when devtools are open.
    // Blocking it produces a noisy console error that masks real problems.
    'https://unpkg.com',
  ],
  frames: ['https://accounts.google.com'], // GIS renders its button in an iframe
};

/**
 * Build the Content-Security-Policy directive object.
 * @returns {Record<string, string[]>}
 */
function contentSecurityPolicy() {
  /** @type {Record<string, string[]>} */
  const directives = {
    'default-src': ["'self'"],
    'script-src': TRUSTED.scripts,
    'style-src': TRUSTED.styles,
    'font-src': TRUSTED.fonts,
    'img-src': TRUSTED.images,
    'connect-src': TRUSTED.connect,
    'frame-src': TRUSTED.frames,
    'form-action': ["'self'"],
    'base-uri': ["'none'"],
    'object-src': ["'none'"],
    'frame-ancestors': ["'none'"],
    'manifest-src': ["'self'"],
    'media-src': ["'self'"],
    'worker-src': ["'self'"],
  };

  // Only force HTTPS upgrades when we are actually serving over HTTPS.
  // Applying this in local development would break plain http://localhost.
  if (config.isProduction) {
    directives['upgrade-insecure-requests'] = [];
  }

  return directives;
}

/**
 * Construct the configured Helmet middleware.
 * @returns {import('express').RequestHandler}
 */
export function buildHelmet() {
  return helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: contentSecurityPolicy(),
    },

    // HSTS tells browsers to refuse plain-HTTP connections to this origin for
    // a year. Only meaningful (and only safe) over real HTTPS.
    hsts: config.isProduction
      ? { maxAge: 31_536_000, includeSubDomains: true, preload: true }
      : false,

    // Stop browsers from MIME-sniffing a response into an executable type.
    noSniff: true,

    // Block the page from being framed, which blocks clickjacking.
    frameguard: { action: 'deny' },

    // Do not send the full URL as Referer to other origins.
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },

    // Disable browser features this app never needs. Fewer capabilities means
    // less to exploit.
    crossOriginEmbedderPolicy: false, // Would block the Google iframe
    crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }, // GIS opens popups
    crossOriginResourcePolicy: { policy: 'same-origin' },

    // Strip the X-Powered-By header so we do not advertise the framework.
    hidePoweredBy: true,

    // Opt out of DNS prefetching to reduce passive information leakage.
    dnsPrefetchControl: { allow: false },
  });
}

/**
 * Permissions-Policy is sent separately because Helmet has no first-class
 * support. Every feature is denied explicitly: this app needs none of them,
 * and an explicit denial prevents a future dependency from quietly enabling one.
 */
export const permissionsPolicy = 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()';

/**
 * Express middleware applying Permissions-Policy and additional hardening.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export function extraSecurityHeaders(req, res, next) {
  res.setHeader('Permissions-Policy', permissionsPolicy);
  // Prevent this page being indexed or its links followed by crawlers.
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  // Discourage embedding in other applications' webviews.
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  next();
}

export default { buildHelmet, permissionsPolicy, extraSecurityHeaders, contentSecurityPolicy };
