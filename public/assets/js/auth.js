/**
 * ---------------------------------------------------------------------------
 * assets/js/auth.js - Google Identity Services integration.
 * ---------------------------------------------------------------------------
 * REAL SIGN-IN
 * The browser requests an ID token from Google and hands it to the server, which
 * verifies the signature and audience before creating a session. The client
 * never decides whether someone is authenticated; it only reflects what the
 * server reports.
 *
 * SEQUENCE
 *   1. Load /api/auth/config to obtain the public client ID.
 *   2. Render Google's own button (never a lookalike) into the header.
 *   3. On credential callback, POST the token to /api/auth/google.
 *   4. The server verifies, sets the session cookie, and returns the profile.
 *
 * GRACEFUL DEGRADATION
 * When no client ID is configured, or the Google script did not load, the UI is
 * told to explain the situation rather than silently fail. No fake identity is
 * ever created, because a fabricated session would defeat the accountability the
 * whole design exists to provide.
 */

import { endpoints, ApiError } from './api.js';
import { el } from './dom.js';

/**
 * @typedef {Object} AuthUser
 * @property {string} userId
 * @property {string} email
 * @property {string} name
 * @property {string|null} picture
 * @property {boolean} emailVerified
 */

/** Current authentication state. */
export const state = {
  /** @type {AuthUser|null} */
  user: null,
  authenticated: false,
  googleEnabled: false,
  googleClientId: '',
  /** @type {object|null} */
  quota: null,
  /** @type {object|null} */
  account: null,
  /** Set when Google sign-in cannot be used. */
  unavailableReason: /** @type {string|null} */ (null),
  /** Set once the user has accepted the policy in this browser session. */
  policyAccepted: false,
};

/** Observers notified whenever auth state changes. */
/** @type {Array<(s: typeof state) => void>} */
const listeners = [];

/**
 * Subscribe to auth state changes.
 * @param {(s: typeof state) => void} listener
 * @returns {() => void} Unsubscribe function.
 */
export function onAuthChange(listener) {
  listeners.push(listener);
  return () => {
    const index = listeners.indexOf(listener);
    if (index >= 0) listeners.splice(index, 1);
  };
}

/** Notify all observers. */
function emit() {
  for (const listener of listeners) {
    try {
      listener(state);
    } catch (error) {
      // A broken observer must not prevent the others from updating.
      // eslint-disable-next-line no-console
      console.error('[auth] listener failed:', error);
    }
  }
}

/**
 * Fetch public auth configuration from the server.
 * @returns {Promise<{ok: boolean, reason: string|null}>}
 */
export async function loadAuthConfig() {
  try {
    const config = await endpoints.authConfig();

    state.googleEnabled = Boolean(config?.google?.enabled);
    state.googleClientId = config?.google?.clientId ?? '';

    if (!state.googleEnabled) {
      state.unavailableReason
        = 'Google sign-in is not configured on this server. Set GOOGLE_CLIENT_ID to enable it.';
      emit();
      return { ok: false, reason: state.unavailableReason };
    }

    state.unavailableReason = null;
    emit();
    return { ok: true, reason: null };
  } catch {
    state.googleEnabled = false;
    state.unavailableReason = 'Could not reach the sign-in service.';
    emit();
    return { ok: false, reason: state.unavailableReason };
  }
}

/**
 * Handle the credential returned by Google.
 *
 * @param {{credential?: string}} response
 * @returns {Promise<{ok: boolean, error?: string}>}
 */
async function handleCredential(response) {
  const credential = response?.credential;

  if (!credential) {
    return { ok: false, error: 'Google did not return a credential.' };
  }

  if (!state.policyAccepted) {
    return {
      ok: false,
      error: 'Please review and accept the Acceptable Use Policy before signing in.',
    };
  }

  try {
    const result = await endpoints.signIn(credential, true);

    state.user = result.user;
    state.authenticated = true;
    state.quota = result.quota ?? null;
    state.unavailableReason = null;
    emit();

    return { ok: true };
  } catch (error) {
    if (error instanceof ApiError) {
      return { ok: false, error: error.message };
    }
    return { ok: false, error: 'Sign-in failed. Please try again.' };
  }
}

/**
 * Initialise Google Identity Services and render its button.
 *
 * Google renders the button itself rather than us styling our own. That matters
 * beyond branding: it prevents a lookalike control being substituted to harvest
 * credentials, and Google validates the origin it renders into.
 *
 * @returns {{ok: boolean, reason: string|null}}
 */
export function initGoogleSignIn() {
  const host = el('#gsi-button-host');
  const fallback = el('#demo-signin-btn');

  if (!state.googleEnabled) {
    return { ok: false, reason: state.unavailableReason };
  }

  if (!window.google?.accounts?.id) {
    state.unavailableReason
      = 'Google sign-in could not load. Check your connection, or whether a content blocker is active.';
    emit();
    return { ok: false, reason: state.unavailableReason };
  }

  try {
    window.google.accounts.id.initialize({
      client_id: state.googleClientId,
      callback: async (response) => {
        const result = await handleCredential(response);

        if (!result.ok) {
          // This module deliberately renders no UI of its own; it reports the
          // problem and lets the view layer decide how to present it.
          document.dispatchEvent(
            new CustomEvent('lifeline:auth-error', { detail: { message: result.error } }),
          );
        }
      },
      // Do not auto-select a returning account on load. On a service that can
      // send SMS, an accidental signed-in state is a real risk, so an explicit
      // click is worth the extra step.
      auto_select: false,
      cancel_on_tap_outside: true,
    });

    // Google's button renders into this host; the plain button is hidden.
    window.google.accounts.id.renderButton(host, {
      type: 'standard',
      theme: 'filled_black',
      size: 'medium',
      shape: 'pill',
      text: 'signin_with',
      logo_alignment: 'left',
      width: 200,
    });

    host?.classList.remove('hidden');
    fallback?.classList.add('hidden');

    // One Tap is intentionally NOT prompted: it is a frequent source of user
    // confusion and unrequested sign-in attempts on shared devices.
    return { ok: true, reason: null };
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error('[auth] failed to initialise Google sign-in:', error);
    state.unavailableReason = 'Google sign-in could not be initialised.';
    emit();
    return { ok: false, reason: state.unavailableReason };
  }
}

/**
 * Load the existing session from the server.
 *
 * The session cookie is httpOnly, so JavaScript cannot read it. The server is
 * the only source of truth about who is signed in.
 *
 * @returns {Promise<boolean>} True when authenticated.
 */
export async function restoreSession() {
  try {
    const result = await endpoints.session();

    state.authenticated = Boolean(result?.authenticated);
    state.user = result?.user ?? null;
    state.quota = result?.quota ?? null;
    state.account = result?.account ?? null;

    emit();
    return state.authenticated;
  } catch {
    state.authenticated = false;
    state.user = null;
    emit();
    return false;
  }
}

/**
 * Sign out, destroying the session server-side.
 * @returns {Promise<{ok: boolean, error?: string}>}
 */
export async function signOut() {
  try {
    await endpoints.signOut();

    state.user = null;
    state.authenticated = false;
    state.quota = null;
    state.account = null;
    emit();

    // Disable auto-select so the user is not immediately signed back in.
    if (window.google?.accounts?.id) {
      window.google.accounts.id.disableAutoSelect();
    }

    return { ok: true };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof ApiError ? error.message : 'Sign-out failed.',
    };
  }
}

/**
 * Update just the quota portion of the state, after a send.
 * @param {object} quota
 */
export function updateQuota(quota) {
  state.quota = quota;
  emit();
}

/**
 * Mark the policy as accepted for this browser session.
 *
 * This gates the accept button in the policy modal. It is deliberately NOT
 * persisted to localStorage: consent to the policy is recorded server-side at
 * sign-in with a timestamp, and that is the record that matters.
 */
export function markPolicyAccepted() {
  state.policyAccepted = true;
}

export default {
  state,
  loadAuthConfig,
  initGoogleSignIn,
  restoreSession,
  signOut,
  updateQuota,
  onAuthChange,
  markPolicyAccepted,
};
