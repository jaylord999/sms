/**
 * ---------------------------------------------------------------------------
 * services/smsProvider.js - Pluggable SMS gateway adapter.
 * ---------------------------------------------------------------------------
 * The moderation pipeline only ever calls `deliver()`. Which provider actually
 * moves the message is an implementation detail behind this interface, so the
 * same application code drives a mock during development, Semaphore in the
 * Philippines, or Twilio internationally.
 *
 * IMPORTANT: text is ALWAYS visibly marked as coming from this gateway. Every
 * outbound body carries an attribution tag. Recipients must be able to tell
 * that a message came from this service, both so they can judge its
 * trustworthiness and so the platform can never be used to send messages that
 * appear to originate from someone else.
 */

import config from '../config.js';

/** Appended to every outbound message so the origin is always attributable. */
export const GATEWAY_TAG = '[Via LifelineSMS]';

/**
 * @typedef {Object} DeliveryRequest
 * @property {string} to          E.164 number, e.g. +639171234567.
 * @property {string} body        Message text, already moderated.
 * @property {string} reference   Internal correlation id.
 */

/**
 * @typedef {Object} DeliveryResult
 * @property {boolean} ok
 * @property {string} providerId
 * @property {string|null} messageId
 * @property {string} status
 * @property {number} durationMs
 * @property {string} [error]
 * @property {string} [code]
 */

/**
 * Compose the final outbound text, appending the attribution tag and enforcing
 * the provider's length ceiling.
 *
 * @param {string} body
 * @param {number} maxLength
 * @returns {string}
 */
export function composeOutbound(body, maxLength) {
  const suffix = ` ${GATEWAY_TAG}`;
  const room = maxLength - suffix.length;

  if (room <= 0) {
    // Pathological configuration; fail loudly rather than truncate the tag.
    throw new Error('SMS_MAX_BODY_LENGTH is too small to fit the attribution tag.');
  }

  const trimmed = [...body].slice(0, room).join('');
  return `${trimmed}${suffix}`;
}

/**
 * Development provider. Contacts no network and always succeeds.
 * @param {DeliveryRequest} request
 * @returns {Promise<DeliveryResult>}
 */
async function deliverViaMock(request) {
  const startedAt = performance.now();
  // Simulate realistic gateway latency so development timing resembles
  // production, which keeps timeout handling honest.
  await new Promise((resolve) => { setTimeout(resolve, 120 + Math.random() * 180); });

  return {
    ok: true,
    providerId: 'mock',
    messageId: `mock_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
    status: 'queued',
    durationMs: Math.round((performance.now() - startedAt) * 100) / 100,
  };
}

/**
 * Semaphore (Philippines). Sends one message per request, which keeps the blast
 * radius of any single API call small.
 *
 * @param {DeliveryRequest} request
 * @returns {Promise<DeliveryResult>}
 */
async function deliverViaSemaphore(request) {
  const { apiKey, senderName } = config.sms.semaphore;
  const startedAt = performance.now();

  if (!apiKey) {
    return {
      ok: false,
      providerId: 'semaphore',
      messageId: null,
      status: 'failed',
      durationMs: 0,
      error: 'Semaphore API key is not configured.',
      code: 'PROVIDER_NOT_CONFIGURED',
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const response = await fetch('https://api.semaphore.co/api/v4/messages', {
      method: 'POST',
      signal: controller.signal,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        apikey: apiKey,
        number: request.to,
        message: request.body,
        sendername: senderName,
      }),
    });

    const durationMs = Math.round((performance.now() - startedAt) * 100) / 100;

    if (!response.ok) {
      // Read the body for diagnostics but never surface raw provider errors to
      // the user; they can leak account or configuration information.
      const detail = await response.text().catch(() => '');
      // eslint-disable-next-line no-console
      console.error('[lifeline-sms] semaphore rejected the request:', response.status, detail.slice(0, 300));
      return {
        ok: false,
        providerId: 'semaphore',
        messageId: null,
        status: 'failed',
        durationMs,
        error: 'The SMS gateway rejected this message.',
        code: 'PROVIDER_REJECTED',
      };
    }

    const payload = await response.json().catch(() => null);
    const first = Array.isArray(payload) ? payload[0] : payload;

    return {
      ok: true,
      providerId: 'semaphore',
      messageId: first?.message_id ? String(first.message_id) : null,
      status: first?.status ? String(first.status).toLowerCase() : 'queued',
      durationMs,
    };
  } catch (error) {
    return {
      ok: false,
      providerId: 'semaphore',
      messageId: null,
      status: 'failed',
      durationMs: Math.round((performance.now() - startedAt) * 100) / 100,
      error: error.name === 'AbortError'
        ? 'The SMS gateway timed out.'
        : 'Could not reach the SMS gateway.',
      code: error.name === 'AbortError' ? 'PROVIDER_TIMEOUT' : 'PROVIDER_UNREACHABLE',
    };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Twilio. Included for completeness; a local aggregator is far more economical
 * for PH termination, so this is a fallback only.
 *
 * @param {DeliveryRequest} request
 * @returns {Promise<DeliveryResult>}
 */
async function deliverViaTwilio(request) {
  const { accountSid, authToken, fromNumber } = config.sms.twilio;
  const startedAt = performance.now();

  if (!accountSid || !authToken || !fromNumber) {
    return {
      ok: false,
      providerId: 'twilio',
      messageId: null,
      status: 'failed',
      durationMs: 0,
      error: 'Twilio credentials are not configured.',
      code: 'PROVIDER_NOT_CONFIGURED',
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const credentials = Buffer.from(`${accountSid}:${authToken}`).toString('base64');

    const response = await fetch(
      `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(accountSid)}/Messages.json`,
      {
        method: 'POST',
        signal: controller.signal,
        headers: {
          authorization: `Basic ${credentials}`,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          To: request.to,
          From: fromNumber,
          Body: request.body,
        }).toString(),
      },
    );

    const durationMs = Math.round((performance.now() - startedAt) * 100) / 100;

    if (!response.ok) {
      const detail = await response.text().catch(() => '');
      // eslint-disable-next-line no-console
      console.error('[lifeline-sms] twilio rejected the request:', response.status, detail.slice(0, 300));
      return {
        ok: false,
        providerId: 'twilio',
        messageId: null,
        status: 'failed',
        durationMs,
        error: 'The SMS gateway rejected this message.',
        code: 'PROVIDER_REJECTED',
      };
    }

    const payload = await response.json();
    return {
      ok: true,
      providerId: 'twilio',
      messageId: payload.sid ? String(payload.sid) : null,
      status: String(payload.status || 'queued').toLowerCase(),
      durationMs,
    };
  } catch (error) {
    return {
      ok: false,
      providerId: 'twilio',
      messageId: null,
      status: 'failed',
      durationMs: Math.round((performance.now() - startedAt) * 100) / 100,
      error: error.name === 'AbortError'
        ? 'The SMS gateway timed out.'
        : 'Could not reach the SMS gateway.',
      code: error.name === 'AbortError' ? 'PROVIDER_TIMEOUT' : 'PROVIDER_UNREACHABLE',
    };
  } finally {
    clearTimeout(timeout);
  }
}

/** Registry of available providers. Add new adapters here. */
const PROVIDERS = {
  mock: deliverViaMock,
  semaphore: deliverViaSemaphore,
  twilio: deliverViaTwilio,
};

/**
 * Deliver an SMS through the configured provider.
 *
 * @param {DeliveryRequest} request
 * @returns {Promise<DeliveryResult>}
 */
export async function deliver(request) {
  const adapter = PROVIDERS[config.sms.provider];

  if (!adapter) {
    return {
      ok: false,
      providerId: config.sms.provider,
      messageId: null,
      status: 'failed',
      durationMs: 0,
      error: `Unknown SMS provider "${config.sms.provider}".`,
      code: 'PROVIDER_UNKNOWN',
    };
  }

  return adapter(request);
}

/** Provider metadata for the health endpoint. */
export function providerInfo() {
  return {
    provider: config.sms.provider,
    configured: config.sms.provider === 'mock'
      || (config.sms.provider === 'semaphore' && Boolean(config.sms.semaphore.apiKey))
      || (config.sms.provider === 'twilio' && Boolean(config.sms.twilio.accountSid)),
    maxBodyLength: config.sms.maxBodyLength,
    available: Object.keys(PROVIDERS),
  };
}

export default { deliver, composeOutbound, providerInfo, GATEWAY_TAG };
