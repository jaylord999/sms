/**
 * ---------------------------------------------------------------------------
 * config.js - Centralised, validated environment configuration.
 * ---------------------------------------------------------------------------
 * Fails fast: if a required secret is missing in production the process exits
 * rather than silently running with insecure defaults.
 */

import 'dotenv/config';
import crypto from 'node:crypto';

const NODE_ENV = process.env.NODE_ENV || 'development';
const isProduction = NODE_ENV === 'production';

/** @param {string|undefined} value @param {number} fallback */
function toInt(value, fallback) {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

/** @param {string|undefined} value @param {boolean} fallback */
function toBool(value, fallback) {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

const SESSION_SECRET = process.env.SESSION_SECRET || '';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const AUDIT_HASH_SALT = process.env.AUDIT_HASH_SALT || '';

/** Collect fatal configuration problems so we can report them all at once. */
const problems = [];

if (isProduction) {
  if (SESSION_SECRET.length < 64) {
    problems.push('SESSION_SECRET must be at least 64 characters in production.');
  }
  if (!GOOGLE_CLIENT_ID || GOOGLE_CLIENT_ID.includes('xxxxxxxx')) {
    problems.push('GOOGLE_CLIENT_ID must be a real OAuth client ID in production.');
  }
  if (!AUDIT_HASH_SALT || AUDIT_HASH_SALT.includes('replace_me')) {
    problems.push('AUDIT_HASH_SALT must be set to a real random value in production.');
  }
}

if (problems.length > 0) {
  // eslint-disable-next-line no-console
  console.error('\n[lifeline-config] FATAL: insecure or incomplete configuration:');
  for (const problem of problems) {
    // eslint-disable-next-line no-console
    console.error(`  - ${problem}`);
  }

  // Detect a hosted PaaS so the guidance points at the right place. Telling
  // someone to edit `.env` on Render is actively unhelpful: the file is not
  // deployed and the variable must be set in the dashboard instead.
  const hosted = process.env.RENDER
    || process.env.RENDER_SERVICE_ID
    || process.env.RAILWAY_ENVIRONMENT
    || process.env.FLY_APP_NAME
    || process.env.DYNO
    || process.env.VERCEL
    || process.env.HEROKU_APP_NAME;

  // eslint-disable-next-line no-console
  console.error('\n  These must be real values. The process refuses to start without');
  // eslint-disable-next-line no-console
  console.error('  them, because a gateway that can send SMS must never run with a');
  // eslint-disable-next-line no-console
  console.error('  guessable session secret or an unverifiable sign-in provider.\n');

  if (hosted) {
    // eslint-disable-next-line no-console
    console.error('  WHERE TO SET THEM (hosted platform detected):');
    // eslint-disable-next-line no-console
    console.error('    Dashboard -> your service -> Environment -> Add Environment Variable');
    // eslint-disable-next-line no-console
    console.error('    A .env file is NOT used here; it is not included in the deploy.\n');
    // eslint-disable-next-line no-console
    console.error('  Remember to also set:');
    // eslint-disable-next-line no-console
    console.error(`    APP_ORIGIN   the public URL of this service, no trailing slash`);
    // eslint-disable-next-line no-console
    console.error('                 (for example https://your-app.onrender.com)');
    // eslint-disable-next-line no-console
    console.error('                 Without it, CSRF origin checks reject every send.\n');
    // eslint-disable-next-line no-console
    console.error('  Generate the secrets with:');
    // eslint-disable-next-line no-console
    console.error('    node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"\n');
  } else {
    // eslint-disable-next-line no-console
    console.error('  Set these in your .env file (see .env.example), or export them');
    // eslint-disable-next-line no-console
    console.error('  as environment variables before starting the process.\n');
  }

  process.exit(1);
}

/**
 * In development we generate ephemeral secrets so the app boots with zero
 * setup. They rotate on every restart, which is exactly what you want locally.
 */
const devSecret = () => crypto.randomBytes(32).toString('hex');

export const config = Object.freeze({
  env: NODE_ENV,
  isProduction,
  port: toInt(process.env.PORT, 3000),
  appOrigin: (process.env.APP_ORIGIN || `http://localhost:${toInt(process.env.PORT, 3000)}`).replace(/\/$/, ''),

  session: Object.freeze({
    secret: SESSION_SECRET || devSecret(),
    /** Session lifetime in milliseconds (2 hours - short, by design). */
    ttlMs: toInt(process.env.SESSION_TTL_MS, 2 * 60 * 60 * 1000),
    cookieName: 'lifeline_sid',
    csrfCookieName: 'lifeline_csrf',
    /** Namespaced CSRF header the client must echo back. */
    csrfHeaderName: 'x-lifeline-csrf',
  }),

  google: Object.freeze({
    clientId: GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    /** Tokens older than this many seconds are rejected on verification. */
    clockSkewSeconds: toInt(process.env.GOOGLE_CLOCK_SKEW_SECONDS, 120),
  }),

  sms: Object.freeze({
    provider: (process.env.SMS_PROVIDER || 'mock').toLowerCase(),
    semaphore: Object.freeze({
      apiKey: process.env.SEMAPHORE_API_KEY || '',
      senderName: process.env.SEMAPHORE_SENDER_NAME || 'LIFELINE',
    }),
    twilio: Object.freeze({
      accountSid: process.env.TWILIO_ACCOUNT_SID || '',
      authToken: process.env.TWILIO_AUTH_TOKEN || '',
      fromNumber: process.env.TWILIO_FROM_NUMBER || '',
    }),
    /** Hard cap mirrored by the textarea maxlength on the client. */
    maxBodyLength: toInt(process.env.SMS_MAX_BODY_LENGTH, 160),
  }),

  limits: Object.freeze({
    freeMessagesPerDay: toInt(process.env.FREE_MESSAGES_PER_DAY, 3),
    maxSendsPerIpHour: toInt(process.env.MAX_SENDS_PER_IP_PER_HOUR, 20),
    minAccountAgeSeconds: toInt(process.env.MIN_ACCOUNT_AGE_SECONDS, 60),
  }),

  moderation: Object.freeze({
    blockThreshold: toInt(process.env.MODERATION_BLOCK_THRESHOLD, 60),
    dryRun: toBool(process.env.MODERATION_DRY_RUN, false),
    ai: Object.freeze({
      endpoint: process.env.AI_GUARD_ENDPOINT || '',
      apiKey: process.env.AI_GUARD_API_KEY || '',
      model: process.env.AI_GUARD_MODEL || 'llama-3.1-8b-instant',
    }),
  }),

  audit: Object.freeze({
    hashSalt: AUDIT_HASH_SALT || devSecret(),
    logPath: process.env.AUDIT_LOG_PATH || './logs/audit.log',
  }),
});

export default config;
