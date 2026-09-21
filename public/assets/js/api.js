/**
 * ---------------------------------------------------------------------------
 * assets/js/api.js - API client.
 * ---------------------------------------------------------------------------
 * Wraps `fetch` so that every call automatically carries:
 *   - the CSRF header the server requires on mutating requests,
 *   - the session cookie,
 *   - a bounded timeout, so a hung request cannot freeze the UI.
 *
 * It also normalises error handling: every failure becomes a rejected promise
 * carrying a `{code, message}` pair, so callers never inspect HTTP status codes.
 */

/** Header name must match config.session.csrfHeaderName on the server. */
const CSRF_HEADER = 'x-lifeline-csrf';

/** Default request timeout in milliseconds. */
const TIMEOUT_MS = 15_000;

/**
 * Read a cookie by name. Returns null when absent.
 *
 * Names are matched exactly rather than by substring, because a loose check can
 * be confused by a name that is a suffix of another.
 *
 * @param {string} name
 * @returns {string|null}
 */
export function readCookie(name) {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(';')) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      return decodeURIComponent(trimmed.slice(prefix.length));
    }
  }
  return null;
}

/** The CSRF token currently held by the browser. */
let csrfToken = readCookie('lifeline_csrf');

/**
 * Update the cached CSRF token.
 * @param {string|null|undefined} token
 */
export function setCsrfToken(token) {
  if (token) csrfToken = token;
}

/** Error thrown for any non-successful API response. */
export class ApiError extends Error {
  /**
   * @param {string} message
   * @param {string} code
   * @param {number} status
   * @param {object} [payload]
   */
  constructor(message, code, status, payload = {}) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.payload = payload;
  }
}

/**
 * Perform an API request.
 *
 * @param {string} path             Path beginning with /api
 * @param {{ method?: string, body?: object, timeoutMs?: number }} [options]
 * @returns {Promise<any>} Parsed JSON response.
 */
export async function request(path, options = {}) {
  const { method = 'GET', body, timeoutMs = TIMEOUT_MS } = options;

  const headers = { accept: 'application/json' };
  const upperMethod = method.toUpperCase();
  const isMutating = !['GET', 'HEAD', 'OPTIONS'].includes(upperMethod);

  if (body !== undefined) {
    headers['content-type'] = 'application/json';
  }

  // Mutating requests must echo the CSRF token. It is read fresh from the
  // cookie in case it was rotated by a sign-in or sign-out in another tab.
  if (isMutating) {
    csrfToken = readCookie('lifeline_csrf');
    if (csrfToken) headers[CSRF_HEADER] = csrfToken;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(path, {
      method: upperMethod,
      headers,
      // The session cookie is httpOnly and sameSite=strict, so same-origin
      // credentials are sufficient and no cross-site leakage occurs.
      credentials: 'same-origin',
      signal: controller.signal,
      body: body === undefined ? undefined : JSON.stringify(body),
    });

    // A 204 has no body to parse.
    if (response.status === 204) return null;

    let payload = null;
    try {
      payload = await response.json();
    } catch {
      // Non-JSON error responses (a proxy timeout page, for instance) are
      // surfaced with a generic message rather than a parse crash.
      if (!response.ok) {
        throw new ApiError(
          'The server returned an unexpected response.',
          'BAD_RESPONSE',
          response.status,
        );
      }
      return null;
    }

    if (!response.ok) {
      throw new ApiError(
        payload?.error ?? 'The request could not be completed.',
        payload?.code ?? 'REQUEST_FAILED',
        response.status,
        payload ?? {},
      );
    }

    // A rotated CSRF token is adopted automatically so the next call works.
    if (payload?.csrfToken) setCsrfToken(payload.csrfToken);

    return payload;
  } catch (error) {
    if (error instanceof ApiError) throw error;

    if (error.name === 'AbortError') {
      throw new ApiError(
        'The request timed out. Check your connection and try again.',
        'TIMEOUT',
        0,
      );
    }

    throw new ApiError(
      'Could not reach the gateway. Check your connection and try again.',
      'NETWORK_ERROR',
      0,
    );
  } finally {
    clearTimeout(timer);
  }
}

/** Convenience wrappers so call sites read cleanly. */
export const api = {
  /**
   * @param {string} path
   * @param {object} [options]
   */
  get: (path, options = {}) => request(path, { ...options, method: 'GET' }),

  /**
   * @param {string} path
   * @param {object} [body]
   * @param {object} [options]
   */
  post: (path, body, options = {}) => request(path, { ...options, method: 'POST', body }),
};

/* ---------------------------------------------------------------------------
   Endpoint map. Keeps URL construction in one place, so a route rename is a
   single edit rather than a search across the codebase.
   --------------------------------------------------------------------------- */

export const endpoints = {
  health: () => api.get('/api/health'),
  engineInfo: () => api.get('/api/health/engine'),

  authConfig: () => api.get('/api/auth/config'),
  signIn: (credential, acceptPolicy) => api.post('/api/auth/google', { credential, acceptPolicy }),
  session: () => api.get('/api/auth/session'),
  signOut: () => api.post('/api/auth/signout'),

  policy: () => api.get('/api/policy/acceptable-use'),
  crisisResources: () => api.get('/api/policy/crisis-resources'),

  preview: (body) => api.post('/api/sms/preview', { body }),
  send: (phone, body) => api.post('/api/sms/send', { phone, body }),
};

export default api;
