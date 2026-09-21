/**
 * End-to-end API integration test.
 *
 * Boots the real Express app on an ephemeral port and exercises the full request
 * path, including security middleware, moderation, quota and delivery.
 *
 * Because Google sign-in cannot be completed without a real Google account, the
 * test injects a session directly into the auth store. That keeps the test
 * hermetic while still exercising every layer BELOW authentication, which is
 * where all of the moderation and abuse-control logic lives.
 *
 * Run:  node --test tests/
 */

import { strict as assert } from 'node:assert';
import { after, before, describe, it } from 'node:test';
import http from 'node:http';

process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.SESSION_SECRET = 'a'.repeat(64);
process.env.AUDIT_HASH_SALT = 'test-salt-for-audit-hashing-000000';
process.env.AUDIT_LOG_PATH = './logs/test-audit.log';
process.env.SMS_PROVIDER = 'mock';
process.env.MIN_ACCOUNT_AGE_SECONDS = '0';

const { createApp } = await import('../src/app.js');
const { createSession } = await import('../src/security/auth.js');
const { generateCsrfToken } = await import('../src/security/csrf.js');
const { verifyAuditChain } = await import('../src/security/auditLog.js');

/** @type {http.Server} */
let server;
/** @type {string} */
let baseUrl;

const CSRF_COOKIE = 'lifeline_csrf';
const CSRF_TOKEN = generateCsrfToken();

/** Session cookie injected for authenticated requests. */
let sessionCookie;

before(async () => {
  const app = createApp();

  server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));

  const address = /** @type {import('node:net').AddressInfo} */ (server.address());
  baseUrl = `http://127.0.0.1:${address.port}`;

  // Create a session directly, bypassing Google's OAuth round-trip.
  const session = createSession({
    sub: 'test-google-subject-12345',
    email: 'tester@example.com',
    name: 'Test User',
    emailVerified: true,
  }, 'test-ip-hash');

  sessionCookie = `lifeline_sid=${session.id}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

/**
 * Issue a request against the running app.
 *
 * @param {string} path
 * @param {{method?: string, body?: object, authenticated?: boolean, csrf?: boolean}} [options]
 * @returns {Promise<{status: number, headers: Headers, body: any}>}
 */
async function call(path, options = {}) {
  const { method = 'GET', body, authenticated = false, csrf = true } = options;

  const cookies = [`${CSRF_COOKIE}=${CSRF_TOKEN}`];
  if (authenticated) cookies.push(sessionCookie);

  /** @type {Record<string, string>} */
  const headers = {
    'content-type': 'application/json',
    cookie: cookies.join('; '),
    // Origin must match the configured app origin or the request is rejected.
    // APP_ORIGIN is set to baseUrl in `before()` once the port is known.
    origin: baseUrl,
  };

  if (csrf) headers['x-lifeline-csrf'] = CSRF_TOKEN;

  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  let parsed = null;
  try {
    parsed = await response.json();
  } catch {
    parsed = null;
  }

  return { status: response.status, headers: response.headers, body: parsed };
}

/* ===========================================================================
   Security headers
   =========================================================================== */

describe('security headers', () => {
  it('sends a restrictive Content-Security-Policy', async () => {
    const response = await call('/api/health');

    const csp = response.headers.get('content-security-policy');
    assert.ok(csp, 'CSP header must be present');
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /object-src 'none'/);
    assert.match(csp, /base-uri 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
  });

  it('blocks framing, sniffing and referrer leakage', async () => {
    const response = await call('/api/health');

    assert.equal(response.headers.get('x-frame-options'), 'DENY');
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(
      response.headers.get('referrer-policy'),
      'strict-origin-when-cross-origin',
    );
  });

  it('does not advertise the framework', async () => {
    const response = await call('/api/health');
    assert.equal(response.headers.get('x-powered-by'), null);
  });

  it('denies browser features the app does not need', async () => {
    const response = await call('/api/health');
    const policy = response.headers.get('permissions-policy');

    assert.ok(policy);
    assert.match(policy, /camera=\(\)/);
    assert.match(policy, /microphone=\(\)/);
    assert.match(policy, /geolocation=\(\)/);
  });

  it('issues a CSRF cookie that JavaScript can read', async () => {
    // Deliberately sent WITHOUT an existing CSRF cookie, because the server only
    // issues a new one when none is present.
    const response = await fetch(`${baseUrl}/api/auth/config`, {
      headers: { accept: 'application/json' },
    });
    const setCookie = response.headers.get('set-cookie');

    assert.ok(setCookie, 'a CSRF cookie must be issued when none is present');
    assert.match(setCookie, /lifeline_csrf=/);
    // httpOnly must NOT be set on the CSRF cookie, or the client cannot echo it
    // back in the header and every mutating request would fail.
    assert.doesNotMatch(setCookie.split(';').slice(1).join(';'), /HttpOnly/i);
    // SameSite must be strict so the cookie is not sent on cross-site requests.
    assert.match(setCookie, /SameSite=Strict/i);
  });
});

/* ===========================================================================
   CSRF and origin enforcement
   =========================================================================== */

describe('CSRF and origin enforcement', () => {
  it('rejects a mutating request without a CSRF header', async () => {
    const response = await call('/api/sms/preview', {
      method: 'POST',
      body: { body: 'hello' },
      authenticated: true,
      csrf: false,
    });

    assert.equal(response.status, 403);
    assert.equal(response.body.code, 'CSRF_INVALID');
  });

  it('rejects a mutating request with a mismatched CSRF token', async () => {
    const response = await fetch(`${baseUrl}/api/sms/preview`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: `${CSRF_COOKIE}=${CSRF_TOKEN}; ${sessionCookie}`,
        origin: baseUrl,
        'x-lifeline-csrf': 'a'.repeat(43),
      },
      body: JSON.stringify({ body: 'hello' }),
    });

    assert.equal(response.status, 403);
  });

  it('rejects a mutating request from a foreign origin', async () => {
    const response = await fetch(`${baseUrl}/api/sms/preview`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: `${CSRF_COOKIE}=${CSRF_TOKEN}; ${sessionCookie}`,
        origin: 'https://evil.example',
        'x-lifeline-csrf': CSRF_TOKEN,
      },
      body: JSON.stringify({ body: 'hello' }),
    });

    assert.equal(response.status, 403);
  });

  it('allows a GET without a CSRF header', async () => {
    const response = await call('/api/health', { csrf: false });
    assert.equal(response.status, 200);
  });
});

/* ===========================================================================
   Authentication
   =========================================================================== */

describe('authentication', () => {
  it('reports an unauthenticated session when no cookie is sent', async () => {
    const response = await call('/api/auth/session');

    assert.equal(response.status, 200);
    assert.equal(response.body.authenticated, false);
  });

  it('reports the injected session as authenticated', async () => {
    const response = await call('/api/auth/session', { authenticated: true });

    assert.equal(response.body.authenticated, true);
    assert.equal(response.body.user.email, 'tester@example.com');
  });

  it('refuses a send without a session', async () => {
    const response = await call('/api/sms/send', {
      method: 'POST',
      body: { phone: '9171234567', body: 'hello' },
    });

    assert.equal(response.status, 401);
    assert.equal(response.body.code, 'AUTH_REQUIRED');
  });

  it('rejects a malformed credential on sign-in', async () => {
    const response = await call('/api/auth/google', {
      method: 'POST',
      body: { credential: 'not-a-jwt', acceptPolicy: true },
    });

    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'TOKEN_MALFORMED');
  });

  it('rejects sign-in without policy consent', async () => {
    const response = await call('/api/auth/google', {
      method: 'POST',
      // A structurally valid JWT shape, so execution reaches the consent check.
      body: { credential: 'aaa.bbb.ccc', acceptPolicy: false },
    });

    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'CONSENT_REQUIRED');
  });
});

/* ===========================================================================
   Input validation
   =========================================================================== */

describe('input validation', () => {
  it('accepts a valid message for preview', async () => {
    const response = await call('/api/sms/preview', {
      method: 'POST',
      body: { body: 'Ma, pauwi na po.' },
      authenticated: true,
    });

    assert.equal(response.status, 200);
  });

  it('rejects a number that is too short', async () => {
    const response = await call('/api/sms/send', {
      method: 'POST',
      body: { phone: '917123', body: 'hello' },
      authenticated: true,
    });

    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'PHONE_LENGTH');
  });

  it('rejects a number with an unassigned prefix', async () => {
    const response = await call('/api/sms/send', {
      method: 'POST',
      body: { phone: '9011234567', body: 'hello' },
      authenticated: true,
    });

    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'PHONE_UNASSIGNED');
  });

  it('rejects a number containing letters', async () => {
    const response = await call('/api/sms/send', {
      method: 'POST',
      body: { phone: '917abc4567', body: 'hello' },
      authenticated: true,
    });

    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'PHONE_CHARSET');
  });

  it('rejects an empty message body', async () => {
    const response = await call('/api/sms/preview', {
      method: 'POST',
      body: { body: '   ' },
      authenticated: true,
    });

    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'BODY_EMPTY');
  });

  it('rejects an oversized message body', async () => {
    const response = await call('/api/sms/preview', {
      method: 'POST',
      body: { body: 'x'.repeat(400) },
      authenticated: true,
    });

    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'BODY_TOO_LONG');
  });

  it('rejects an oversized JSON payload outright', async () => {
    const response = await fetch(`${baseUrl}/api/sms/preview`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: `${CSRF_COOKIE}=${CSRF_TOKEN}; ${sessionCookie}`,
        origin: baseUrl,
        'x-lifeline-csrf': CSRF_TOKEN,
      },
      body: JSON.stringify({ body: 'x'.repeat(20_000) }),
    });

    assert.equal(response.status, 413);
  });
});

/* ===========================================================================
   Moderation: allowed content
   =========================================================================== */

describe('moderation: ordinary messages are allowed', () => {
  const ALLOWED = [
    'Ma, stranded sa terminal. pauwi na po.',
    'Pa, nasa hospital si lola. punta ka dito.',
    'abort the download please',
    'Nakita ko ang drug store sa kanto',
  ];

  for (const text of ALLOWED) {
    it(`allows: ${text.slice(0, 40)}`, async () => {
      const response = await call('/api/sms/preview', {
        method: 'POST',
        body: { body: text },
        authenticated: true,
      });

      assert.equal(response.status, 200);
      assert.equal(response.body.action, 'allow');
      assert.equal(response.body.deliverable, true);
    });
  }
});

/* ===========================================================================
   Moderation: prohibited content
   =========================================================================== */

describe('moderation: illegal content is blocked', () => {
  const BLOCKED = [
    'benta shabu dito, 5k per gram',
    'kidnap for ransom tayo',
    'dudukutin ko ang bata',
    'papatayin kita pag di ka nagbayad',
    'batang hubad pics send mo',
    'buy unlicensed gun here',
    'nanalo ka ng premyo, padala ang bayad',
    'send me your OTP code now for verification',
    'magpalaglag ako, saan pwede',
    'b u y  s h a b u  n o w',
    'SEND TO ALL BROADCAST THIS MESSAGE!!!!!',
  ];

  for (const text of BLOCKED) {
    it(`blocks: ${text.slice(0, 40)}`, async () => {
      const response = await call('/api/sms/preview', {
        method: 'POST',
        body: { body: text },
        authenticated: true,
      });

      assert.equal(response.status, 200);
      assert.equal(response.body.action, 'block', `expected block for "${text}"`);
      assert.equal(response.body.deliverable, false);
    });
  }

  it('refuses delivery of blocked content', async () => {
    const response = await call('/api/sms/send', {
      method: 'POST',
      body: { phone: '9171234567', body: 'benta shabu dito' },
      authenticated: true,
    });

    assert.equal(response.status, 422);
    assert.equal(response.body.action, 'block');
  });

  it('never echoes the matched terms back to the client', async () => {
    const response = await call('/api/sms/send', {
      method: 'POST',
      body: { phone: '9171234567', body: 'benta shabu dito' },
      authenticated: true,
    });

    // Returning the matched terms would turn the endpoint into an oracle that
    // reveals exactly which words evade the filter.
    const serialised = JSON.stringify(response.body);
    assert.doesNotMatch(serialised, /shabu/i);
    assert.ok(response.body.findings.length > 0, 'category labels should be returned');
  });
});

/* ===========================================================================
   Moderation: crisis handling - the most important behaviour in the system
   =========================================================================== */

describe('moderation: crisis content is delivered, never blocked', () => {
  const CRISIS = [
    'i want to die',
    'gusto ko na mamatay',
    'magpapakamatay na ako',
    'ayaw ko na mabuhay, pabigat lang ako',
    'maghikog ko, kapoy na kaayo ko',
  ];

  for (const text of CRISIS) {
    it(`assists instead of blocking: ${text.slice(0, 40)}`, async () => {
      const response = await call('/api/sms/preview', {
        method: 'POST',
        body: { body: text },
        authenticated: true,
      });

      assert.equal(response.body.action, 'assist', `expected assist for "${text}"`);
      // The crucial assertion: crisis content IS deliverable.
      assert.equal(response.body.deliverable, true);
      assert.equal(response.body.isCrisis, true);
    });
  }

  it('delivers a crisis message and returns support resources', async () => {
    const response = await call('/api/sms/send', {
      method: 'POST',
      body: { phone: '9171234567', body: 'gusto ko na mamatay' },
      authenticated: true,
    });

    assert.equal(response.status, 200);
    assert.equal(response.body.action, 'assist');
    assert.equal(response.body.isCrisis, true);
    assert.ok(response.body.resources.length >= 3, 'support resources must be returned');

    // The hotline numbers are the entire point of the assist path.
    const serialised = JSON.stringify(response.body.resources);
    assert.match(serialised, /1553/);
    assert.match(serialised, /2919/);
  });

  it('does not consume a message credit for a crisis send', async () => {
    const before = await call('/api/sms/limits', { authenticated: true });
    const usedBefore = before.body.quota.used;

    await call('/api/sms/send', {
      method: 'POST',
      body: { phone: '9171234568', body: 'ayaw ko na mabuhay' },
      authenticated: true,
    });

    const afterResponse = await call('/api/sms/limits', { authenticated: true });
    assert.equal(
      afterResponse.body.quota.used,
      usedBefore,
      'a crisis send must not consume quota',
    );
  });
});

/* ===========================================================================
   Policy
   =========================================================================== */

describe('policy', () => {
  it('serves the Acceptable Use Policy with statutes', async () => {
    const response = await call('/api/policy/acceptable-use');

    assert.equal(response.status, 200);
    assert.ok(response.body.prohibited.length >= 10);

    const serialised = JSON.stringify(response.body.prohibited);
    assert.match(serialised, /RA 9165/);
    assert.match(serialised, /RA 9775/);
  });

  it('states that crisis content is always permitted', async () => {
    const response = await call('/api/policy/acceptable-use');

    const ids = response.body.alwaysAllowed.map((entry) => entry.id);
    assert.ok(ids.includes('crisis_support'));
  });

  it('confirms crisis categories are not enforcement categories', async () => {
    const response = await call('/api/policy/categories');

    const crisis = response.body.categories.find((c) => c.id === 'self_harm_crisis');
    assert.ok(crisis, 'crisis category must be listed');
    assert.equal(crisis.blocksDelivery, false);
    assert.equal(crisis.action, 'assist');
  });

  it('covers Filipino-language drug categories', async () => {
    const response = await call('/api/policy/categories');

    const ids = response.body.categories.map((c) => c.id);
    assert.ok(ids.includes('ph_drugs'), 'Filipino drug category must exist');
    assert.ok(ids.includes('ph_kidnap'), 'Filipino kidnapping category must exist');
    assert.ok(ids.includes('ph_kill'), 'Filipino threats category must exist');
  });

  it('exposes crisis resources without authentication', async () => {
    const response = await call('/api/policy/crisis-resources');

    assert.equal(response.status, 200);
    assert.ok(response.body.resources.length >= 3);
  });
});

/* ===========================================================================
   Health, audit and error handling
   =========================================================================== */

describe('health endpoints', () => {
  it('reports healthy', async () => {
    const response = await call('/api/health');

    assert.equal(response.status, 200);
    assert.equal(response.body.status, 'healthy');
  });

  it('reports readiness with subsystem checks', async () => {
    const response = await call('/api/health/ready');

    assert.equal(response.status, 200);
    assert.equal(response.body.checks.moderationEngine.ok, true);
    assert.equal(response.body.checks.smsProvider.ok, true);
  });

  it('reports engine statistics', async () => {
    const response = await call('/api/health/engine');

    assert.equal(response.status, 200);
    assert.ok(response.body.moderation.terms > 500);
    assert.ok(response.body.moderation.detectors > 10);
    assert.equal(response.body.moderation.crisisAssistCategories, 1);
  });

  it('keeps the audit chain intact', async () => {
    const response = await call('/api/health/engine');
    assert.equal(response.status, 200);

    // Verified directly against the log content, not the HTTP response.
    const chain = verifyAuditChain();
    assert.equal(chain.valid, true, chain.reason ?? 'chain must be intact');
    assert.ok(chain.records > 0, 'sends above should have produced audit records');
  });
});

describe('error handling', () => {
  it('returns JSON for an unknown API route', async () => {
    const response = await call('/api/does-not-exist');

    assert.equal(response.status, 404);
    assert.equal(response.body.code, 'NOT_FOUND');
  });

  it('returns 400 for a malformed JSON body', async () => {
    const response = await fetch(`${baseUrl}/api/sms/preview`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: `${CSRF_COOKIE}=${CSRF_TOKEN}; ${sessionCookie}`,
        origin: baseUrl,
        'x-lifeline-csrf': CSRF_TOKEN,
      },
      body: '{ this is not json',
    });

    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.code, 'BAD_JSON');
  });
});
