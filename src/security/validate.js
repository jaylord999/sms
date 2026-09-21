/**
 * ---------------------------------------------------------------------------
 * security/validate.js - Input schema validation (zero dependencies).
 * ---------------------------------------------------------------------------
 * Every field that reaches the server is validated and normalised here before
 * any business logic runs. Two principles:
 *
 *  1. Allowlist, never blocklist. Accept only characters we expect rather than
 *     trying to enumerate dangerous ones.
 *  2. Reject rather than repair. Silently "cleaning" input hides attacks and
 *     produces surprising behaviour; return a precise error instead.
 */

import { digitsOnly } from '../moderation/normalize.js';

/** Number of consecutive digits in a PH mobile subscriber number. */
const PH_SUBSCRIBER_LENGTH = 10;

/**
 * Valid PH mobile prefixes (first three digits, i.e. 9XX). Sourced from NTC
 * allocations. Kept as a prefix set so new ranges are a one-line change.
 */
const PH_MOBILE_PREFIXES = new Set([
  '905', '906', '907', '908', '909', '910', '911', '912', '913', '914',
  '915', '916', '917', '918', '919', '920', '921', '922', '923', '924',
  '925', '926', '927', '928', '929', '930', '931', '932', '933', '934',
  '935', '936', '937', '938', '939', '940', '941', '942', '943', '944',
  '945', '946', '947', '948', '949', '950', '951', '955', '956', '957',
  '958', '959', '960', '961', '962', '963', '964', '965', '966', '967',
  '968', '969', '970', '971', '972', '973', '974', '975', '976', '977',
  '978', '979', '980', '981', '982', '983', '989', '991', '992', '993',
  '994', '995', '996', '997', '998', '999',
]);

/** Carrier attribution, used only for display and log readability. */
const CARRIERS = [
  {
    name: 'Globe / TM',
    prefixes: [
      '905', '906', '915', '916', '917', '926', '927', '935', '936', '945',
      '955', '956', '965', '966', '975', '976', '985', '995', '997',
    ],
  },
  {
    name: 'Smart / TNT / Sun',
    prefixes: [
      '908', '909', '910', '912', '913', '914', '918', '919', '920', '921',
      '928', '929', '930', '938', '939', '940', '946', '947', '948', '949',
      '950', '958', '959', '968', '969', '970', '971', '973', '974', '979',
      '980', '981', '988', '989', '991', '993', '994', '996', '998', '999',
    ],
  },
  {
    name: 'DITO',
    prefixes: [
      '895', '896', '897', '898', '992', '995', '997', '998',
    ],
  },
];

/**
 * The result shape every validator returns.
 * @template T
 * @typedef {{ok: true, value: T} | {ok: false, error: string, code: string}} ValidationResult
 */

/**
 * Validate and normalise a PH mobile number.
 *
 * Accepts the shapes users actually type:
 *   9171234567   09171234567   +639171234567
 *   63 917 123 4567   0917-123-4567   (0917) 123 4567
 *
 * @param {unknown} input
 * @returns {ValidationResult<{national: string, e164: string, carrier: string}>}
 */
export function validatePhone(input) {
  if (typeof input !== 'string') {
    return { ok: false, error: 'Phone number must be text.', code: 'PHONE_TYPE' };
  }

  const raw = input.trim();
  if (raw.length === 0) {
    return { ok: false, error: 'Recipient number is required.', code: 'PHONE_REQUIRED' };
  }
  if (raw.length > 24) {
    return { ok: false, error: 'Phone number is too long.', code: 'PHONE_TOO_LONG' };
  }

  // Reject non-digit characters once separators are removed, so a value such as
  // "+63 917 12ab 4567" cannot slip through.
  if (!/^[+\d\s()\-.]+$/.test(raw)) {
    return {
      ok: false,
      error: 'Phone number contains invalid characters.',
      code: 'PHONE_CHARSET',
    };
  }

  let national = digitsOnly(raw);

  // Strip the country code in its various forms.
  if (national.startsWith('63') && national.length > PH_SUBSCRIBER_LENGTH) {
    national = national.slice(2);
  }
  // Strip a single leading trunk zero.
  if (national.startsWith('0') && national.length > PH_SUBSCRIBER_LENGTH) {
    national = national.slice(1);
  }

  if (national.length !== PH_SUBSCRIBER_LENGTH) {
    return {
      ok: false,
      error: 'Enter a 10-digit PH mobile number, for example 9171234567.',
      code: 'PHONE_LENGTH',
    };
  }

  if (!national.startsWith('9')) {
    return {
      ok: false,
      error: 'PH mobile numbers start with 9 after +63.',
      code: 'PHONE_PREFIX',
    };
  }

  const prefix = national.slice(0, 3);
  if (!PH_MOBILE_PREFIXES.has(prefix)) {
    return {
      ok: false,
      error: `Prefix ${prefix} is not a recognised PH mobile range.`,
      code: 'PHONE_UNASSIGNED',
    };
  }

  const carrier = CARRIERS.find((entry) => entry.prefixes.includes(prefix))?.name
    ?? 'Unknown carrier';

  return { ok: true, value: { national, e164: `+63${national}`, carrier } };
}

/**
 * Validate an SMS body.
 *
 * Counts by Unicode code point, not UTF-16 units, so an emoji or an accented
 * Filipino character is charged as one SMS character rather than two.
 *
 * @param {unknown} input
 * @param {number} maxLength
 * @returns {ValidationResult<{text: string, length: number}>}
 */
export function validateMessageBody(input, maxLength) {
  if (typeof input !== 'string') {
    return { ok: false, error: 'Message body must be text.', code: 'BODY_TYPE' };
  }

  // Normalise newlines so "\r\n" cannot inflate the character count.
  const text = input.replace(/\r\n?/g, '\n').trim();

  if (text.length === 0) {
    return { ok: false, error: 'Message cannot be empty.', code: 'BODY_EMPTY' };
  }

  const length = [...text].length;

  if (length > maxLength) {
    return {
      ok: false,
      error: `Message is ${length} characters; the limit is ${maxLength}.`,
      code: 'BODY_TOO_LONG',
    };
  }

  // Control characters other than newline and tab serve no legitimate purpose
  // in an SMS and are a common smuggling trick.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(text)) {
    return {
      ok: false,
      error: 'Message contains unsupported control characters.',
      code: 'BODY_CONTROL_CHARS',
    };
  }

  return { ok: true, value: { text, length } };
}

/**
 * Validate a Google ID token shape before sending it for verification.
 *
 * This is a cheap pre-check only. It is NOT verification - the token must still
 * be validated against Google's JWKS by the token verifier.
 *
 * @param {unknown} input
 * @returns {ValidationResult<string>}
 */
export function validateIdTokenShape(input) {
  if (typeof input !== 'string') {
    return { ok: false, error: 'Missing credential.', code: 'TOKEN_TYPE' };
  }

  const token = input.trim();

  // A JWT is three base64url segments separated by dots.
  if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
    return { ok: false, error: 'Malformed credential.', code: 'TOKEN_MALFORMED' };
  }

  if (token.length > 8192) {
    return { ok: false, error: 'Credential is too large.', code: 'TOKEN_TOO_LARGE' };
  }

  return { ok: true, value: token };
}

/**
 * Validate a boolean-ish consent flag.
 * @param {unknown} input
 * @param {string} label
 * @returns {ValidationResult<boolean>}
 */
export function validateConsent(input, label) {
  if (input === true || input === 'true' || input === 1 || input === '1') {
    return { ok: true, value: true };
  }
  return {
    ok: false,
    error: `You must accept the ${label} to continue.`,
    code: 'CONSENT_REQUIRED',
  };
}

/**
 * Coerce an arbitrary value to a bounded integer, for limits and pagination.
 * @param {unknown} input
 * @param {number} fallback
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
export function clampInt(input, fallback, min, max) {
  const parsed = Number.parseInt(String(input ?? ''), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

export default {
  validatePhone,
  validateMessageBody,
  validateIdTokenShape,
  validateConsent,
  clampInt,
  PH_MOBILE_PREFIXES,
  CARRIERS,
};
