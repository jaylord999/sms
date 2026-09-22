/**
 * ---------------------------------------------------------------------------
 * assets/js/app.js - Application orchestrator.
 * ---------------------------------------------------------------------------
 * Wires the view, auth and API layers together and owns all user interaction.
 *
 * DESIGN NOTES
 *
 *  - Moderation feedback is DEBOUNCED. Every keystroke would otherwise fire an
 *    API call, which is wasteful and would trip the preview rate limit during
 *    ordinary typing. 600ms after the user stops typing is responsive without
 *    being chatty.
 *
 *  - The send button reflects SERVER state, not client guesses. `deliverable`
 *    comes from the preview response, so the client cannot disagree with the
 *    engine about what is permitted.
 *
 *  - Crisis handling is deliberately prominent, and never framed as an error.
 */

import { endpoints, ApiError } from './api.js';
import { el, setText, setVisible } from './dom.js';
import * as auth from './auth.js';
import * as ui from './ui.js';

/** Debounce delay for the live moderation preview, in milliseconds. */
const PREVIEW_DEBOUNCE_MS = 600;

/** Cached policy document, fetched once. */
let policyCache = null;

/** Latest preview result from the server. */
let lastPreview = null;

/** Handle for the pending debounce timer. */
let previewTimer = /** @type {number|undefined} */ (undefined);

/* ---------------------------------------------------------------------------
   Static tip bubbles (decorative, cycled on a timer)
   --------------------------------------------------------------------------- */

const FLOATING_TIPS = [
  { icon: '🛡️', title: 'Multi-layer filtering', text: 'Over a thousand rules plus pattern detection screen every message before it is sent.' },
  { icon: '👵', title: 'Offline family bridge', text: 'Reach parents who only receive standard SMS, with no data connection needed on their side.' },
  { icon: '📜', title: 'Verified identity', text: 'Google sign-in ties every send to an accountable account, as the SIM Registration Act requires.' },
  { icon: '💙', title: 'Crisis-aware', text: 'Messages about your own distress are always delivered, and free support numbers are shown.' },
];

let tipIndex = 0;

/**
 * Render a tip into one of the floating side bubbles.
 * @param {string} containerId
 * @param {{icon: string, title: string, text: string}} tip
 */
function renderFloatingTip(containerId, tip) {
  const container = el(`#${containerId}`);
  if (!container) return;

  container.replaceChildren();
  container.append(ui.buildTipBubble(tip));
}

/** Start the tip rotation. */
function startTipRotation() {
  const cycle = () => {
    renderFloatingTip('left-floating-bubble', FLOATING_TIPS[tipIndex % FLOATING_TIPS.length]);
    renderFloatingTip('right-floating-bubble', FLOATING_TIPS[(tipIndex + 2) % FLOATING_TIPS.length]);
    tipIndex += 1;
  };

  setTimeout(cycle, 400);
  setInterval(cycle, 9000);
}

/* ---------------------------------------------------------------------------
   Policy modal
   --------------------------------------------------------------------------- */

/**
 * Load and display the Acceptable Use Policy.
 * @param {{acceptMode?: boolean}} [options]
 */
async function openPolicy(options = {}) {
  // The accept button is only meaningful when consent is actually being sought.
  setVisible(el('#policy-accept-btn'), Boolean(options.acceptMode));

  if (policyCache) {
    ui.renderPolicy(policyCache);
    return;
  }

  try {
    policyCache = await endpoints.policy();
    ui.renderPolicy(policyCache);
  } catch (error) {
    ui.toast(
      error instanceof ApiError ? error.message : 'Could not load the policy.',
      'error',
    );
  }
}

/* ---------------------------------------------------------------------------
   Live preview
   --------------------------------------------------------------------------- */

/**
 * Request a moderation preview and reflect the outcome in the UI.
 */
async function runPreview() {
  if (!auth.state.authenticated) return;

  const body = el('#message-body')?.value?.trim() ?? '';

  if (body.length === 0) {
    lastPreview = null;
    ui.renderModerationFeedback(null);
    ui.hideCrisisPanel();
    updateSendButtonState();
    return;
  }

  try {
    const result = await endpoints.preview(body);
    lastPreview = result;

    ui.renderModerationFeedback(result);

    if (result.isCrisis) {
      ui.showCrisisPanel(result.resources);
    } else {
      ui.hideCrisisPanel();
    }

    updateSendButtonState();
  } catch (error) {
    // A failed preview must not block sending. The send endpoint moderates
    // independently and is the authoritative gate.
    if (error instanceof ApiError && error.code === 'RATE_LIMITED') {
      ui.logLine('Preview throttled by the server. Sending is still available.', 'warning');
    }
    lastPreview = null;
    updateSendButtonState();
  }
}

/** Schedule a debounced preview. */
function schedulePreview() {
  clearTimeout(previewTimer);
  previewTimer = window.setTimeout(runPreview, PREVIEW_DEBOUNCE_MS);
}

/* ---------------------------------------------------------------------------
   Send button state
   --------------------------------------------------------------------------- */

/**
 * Enable or disable the send button based on everything the server has told us.
 */
function updateSendButtonState() {
  const button = el('#submit-btn');
  const label = el('#btn-label');
  const consent = el('#send-consent')?.checked ?? false;
  const body = el('#message-body')?.value?.trim() ?? '';
  const phone = el('#phone-number')?.value?.trim() ?? '';

  if (!button || !label) return;

  // A blocked preview is honoured client-side purely as a courtesy. The server
  // re-checks on send regardless, so this is not a security control.
  const blocked = lastPreview ? lastPreview.deliverable === false : false;

  const ready = auth.state.authenticated
    && consent
    && body.length > 0
    && phone.length >= 10
    && !blocked;

  button.disabled = !ready;

  if (blocked) {
    label.textContent = 'Message blocked';
  } else if (lastPreview?.isCrisis) {
    label.textContent = 'Send anyway (support shown)';
  } else {
    label.textContent = 'Send emergency SMS';
  }
}

/* ---------------------------------------------------------------------------
   Character counter
   --------------------------------------------------------------------------- */

/**
 * Update the character counter next to the message field.
 *
 * Counts code points rather than UTF-16 units, so an emoji counts as one
 * character, matching how the server validates length.
 */
function updateCharCount() {
  const textarea = el('#message-body');
  const counter = el('#char-count');
  if (!textarea || !counter) return;

  const max = Number(textarea.getAttribute('maxlength')) || 160;
  const length = [...textarea.value].length;

  counter.textContent = `${length} / ${max}`;

  const nearLimit = length >= max - 15;
  counter.classList.toggle('text-amber-400', nearLimit);
  counter.classList.toggle('font-bold', nearLimit);
}

/* ---------------------------------------------------------------------------
   Phone validation (client-side hint only)
   --------------------------------------------------------------------------- */

/**
 * Show or clear the phone error message.
 * @param {string} [message]
 */
function setPhoneError(message = '') {
  const node = el('#phone-error');
  if (!node) return;

  if (message) {
    setText(node, message);
    setVisible(node, true);
  } else {
    setVisible(node, false);
  }
}

/**
 * Light client-side phone check.
 *
 * This is a UX affordance giving immediate feedback while typing. It is NOT a
 * validation boundary: the server performs the authoritative check, including
 * the assigned-prefix lookup, which is what actually matters.
 *
 * @param {string} value
 */
function checkPhoneLocally(value) {
  const digits = value.replace(/\D/g, '');

  let national = digits;
  if (national.startsWith('63') && national.length > 10) national = national.slice(2);
  if (national.startsWith('0') && national.length > 10) national = national.slice(1);

  if (national.length === 0) {
    setPhoneError('');
    return;
  }

  if (national.length < 10) {
    setPhoneError(`Enter 10 digits after +63 (${national.length}/10 so far).`);
    return;
  }

  if (!national.startsWith('9')) {
    setPhoneError('PH mobile numbers begin with 9 after +63.');
    return;
  }

  setPhoneError('');
}

/* ---------------------------------------------------------------------------
   Send
   --------------------------------------------------------------------------- */

/**
 * Handle the send submission.
 * @param {SubmitEvent} event
 */
async function handleSend(event) {
  event.preventDefault();

  const button = el('#submit-btn');
  const label = el('#btn-label');
  const phone = el('#phone-number')?.value?.trim() ?? '';
  const body = el('#message-body')?.value?.trim() ?? '';

  // --- Pre-flight checks. These mirror the server's own checks; they exist to
  // give fast feedback, not to replace server-side enforcement.
  if (!auth.state.authenticated) {
    ui.toast('Sign in with Google before sending.', 'warning');
    return;
  }

  if (!el('#send-consent')?.checked) {
    ui.toast('Please confirm the message is lawful before sending.', 'warning');
    return;
  }

  if (phone.length < 10) {
    setPhoneError('Enter the full 10-digit number after +63.');
    el('#phone-number')?.focus();
    return;
  }

  if (body.length === 0) {
    ui.toast('Enter a message first.', 'warning');
    return;
  }

  button.disabled = true;
  const originalLabel = label.textContent;
  label.textContent = 'Sending...';
  button.classList.add('opacity-70');

  ui.logLine('Running safety checks on message content...', 'info');

  try {
    const result = await endpoints.send(phone, body);

    // -----------------------------------------------------------------------
    // CRISIS PATH
    // The message was delivered. Support the user; do not show a success toast
    // that treats this like an ordinary send.
    // -----------------------------------------------------------------------
    if (result.isCrisis) {
      ui.logLine('Message delivered. Support resources shown.', 'success');
      ui.logLine('This did not use up a message credit.', 'info');

      ui.showCrisisModal(result.resources);

      // Deliberately phrased as an offer, not an automatic action. Silently
      // alerting a third party about someone's mental state would be a serious
      // privacy violation.
      const wantsAlert = el('#alert-trusted-contact')?.checked ?? false;
      if (wantsAlert) {
        ui.logLine('Trusted-contact alert requested. Follow the support steps to confirm.', 'info');
      }
    } else {
      ui.logLine(`Delivered to ${result.recipient?.masked ?? 'recipient'}.`, 'success');
      ui.logLine(`Gateway response: ${result.delivery?.status ?? 'queued'}.`, 'success');
      ui.toast('Message sent.', 'success');
    }

    // Reflect the new quota the server reported.
    if (result.quota) {
      auth.updateQuota(result.quota);
      ui.renderQuota(result.quota);
    }

    // Clear the composer on success.
    const textarea = el('#message-body');
    if (textarea) textarea.value = '';
    updateCharCount();
    lastPreview = null;
    ui.renderModerationFeedback(null);
    ui.hideCrisisPanel();
  } catch (error) {
    if (error instanceof ApiError) {
      // -------------------------------------------------------------------
      // BLOCKED
      // -------------------------------------------------------------------
      if (error.code === 'prohibited_content' || error.code === 'prohibited_csam') {
        ui.logLine(`Message blocked: ${error.payload?.findings?.[0]?.label ?? 'policy violation'}.`, 'blocked');
        ui.showBlockedModal({
          message: error.message,
          findings: error.payload?.findings ?? [],
        });
      } else if (error.code === 'QUOTA_EXHAUSTED') {
        ui.logLine('Daily message allowance exhausted.', 'warning');
        ui.toast('You have used all your free messages for today.', 'warning');
        if (error.payload?.quota) {
          auth.updateQuota(error.payload.quota);
          ui.renderQuota(error.payload.quota);
        }
      } else if (error.code === 'ACCOUNT_TOO_NEW') {
        ui.logLine('Account still being verified.', 'warning');
        ui.toast(error.message, 'warning');
      } else if (error.code === 'AUTH_REQUIRED') {
        ui.logLine('Session expired. Sign in again.', 'error');
        ui.toast('Your session expired. Please sign in again.', 'warning');
        await auth.signOut();
      } else if (error.code === 'RATE_LIMITED') {
        ui.logLine('Rate limited by the server.', 'warning');
        ui.toast(error.message, 'warning');
      } else {
        ui.logLine(`Send failed: ${error.message}`, 'error');
        ui.toast(error.message, 'error');
      }
    } else {
      ui.logLine('Unexpected error while sending.', 'error');
      ui.toast('Unexpected error. Please try again.', 'error');
    }
  } finally {
    label.textContent = originalLabel;
    button.classList.remove('opacity-70');
    updateSendButtonState();
  }
}

/* ---------------------------------------------------------------------------
   Auth control behaviour
   --------------------------------------------------------------------------- */

/** Handle a click on the header auth control (sign in or sign out). */
async function handleAuthButtonClick() {
  // Signed in: the control becomes sign-out.
  if (auth.state.authenticated) {
    const result = await auth.signOut();
    if (result.ok) {
      ui.logLine('Signed out. Session destroyed on the server.', 'info');
      ui.toast('Signed out.', 'info');
      ui.hideCrisisPanel();
      ui.renderModerationFeedback(null);
      resetSignInGate();
    } else {
      ui.toast(result.error ?? 'Sign-out failed.', 'error');
    }
    return;
  }

  // Signed out: guide the user through policy acceptance before sign-in.
  await openPolicy({ acceptMode: true });
}

/**
 * Begin Google sign-in.
 *
 * Called after the user accepts the policy, because Google renders its own
 * button and we cannot intercept that click to inject the consent step.
 */
function beginGoogleSignIn() {
  const result = auth.initGoogleSignIn();

  if (!result.ok) {
    ui.renderAuthUnavailable(result.reason ?? 'Google sign-in is unavailable.');
    ui.toast(result.reason ?? 'Google sign-in is unavailable.', 'warning');
    return;
  }

  // Focus and scroll to Google's button. Without the scroll the button can sit
  // below the fold, which looks identical to nothing having happened.
  const googleButton = el('#gsi-gate-host button');
  googleButton?.focus();
  el('#gsi-gate-host')?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });

  // Update the heading so the gate visibly changes state. Silence here is what
  // made a working flow look broken.
  const heading = el('#auth-gate h3');
  if (heading) heading.textContent = 'Choose your Google account to continue';

  ui.logLine('Policy accepted. Google sign-in is ready.', 'success');
}

/**
 * Reset the gate back to its pre-consent appearance.
 * Used on sign-out so the user can accept and sign in again.
 */
function resetSignInGate() {
  const heading = el('#auth-gate h3');
  if (heading) heading.textContent = 'Sign-in required before sending';

  setVisible(el('#gsi-gate-host'), false);
  setVisible(el('#gate-signin-btn'), true);
  setVisible(el('#demo-signin-btn'), true);
  setVisible(el('#auth-gate-note'), false);
}

/**
 * Handle a click on the pre-consent gate button.
 *
 * Before consent it opens the policy. After consent it must NOT reopen the
 * policy, or the user is trapped in a loop with no way to reach Google's
 * button - which is exactly what happened when the button and the real Google
 * control lived in different parts of the page.
 */
async function handleGateButtonClick() {
  if (auth.state.policyAccepted) {
    // Consent already given; the only reason this button is still visible is
    // that Google's button failed to render. Retry, and explain if it fails.
    const result = auth.initGoogleSignIn();

    if (!result.ok) {
      ui.renderAuthUnavailable(result.reason ?? 'Google sign-in is unavailable.');
      ui.toast(result.reason ?? 'Google sign-in is unavailable.', 'warning');
    }
    return;
  }

  await openPolicy({ acceptMode: true });
}

/* ---------------------------------------------------------------------------
   Event wiring
   --------------------------------------------------------------------------- */

/** Attach all event listeners. */
function bindEvents() {
  el('#sms-form')?.addEventListener('submit', handleSend);

  el('#demo-signin-btn')?.addEventListener('click', handleAuthButtonClick);
  el('#gate-signin-btn')?.addEventListener('click', handleGateButtonClick);

  el('#view-policy-btn')?.addEventListener('click', () => openPolicy());
  el('#consent-policy-link')?.addEventListener('click', () => openPolicy());

  el('#policy-close-btn')?.addEventListener('click', () => ui.closeModal(el('#policy-modal')));
  el('#policy-accept-btn')?.addEventListener('click', () => {
    auth.markPolicyAccepted();
    ui.closeModal(el('#policy-modal'));
    ui.logLine('Acceptable Use Policy accepted. You may now sign in.', 'info');
    beginGoogleSignIn();
  });

  el('#block-close-btn')?.addEventListener('click', () => ui.closeModal(el('#block-modal')));
  el('#crisis-modal-close-btn')?.addEventListener('click', () => ui.closeModal(el('#crisis-modal')));

  // --- Message field
  const textarea = el('#message-body');
  textarea?.addEventListener('input', () => {
    updateCharCount();
    updateSendButtonState();
    schedulePreview();
  });

  // --- Phone field: strip anything that is not a digit or a separator
  const phoneInput = el('#phone-number');
  phoneInput?.addEventListener('input', () => {
    const cleaned = phoneInput.value.replace(/[^\d+\s()-]/g, '');
    if (cleaned !== phoneInput.value) phoneInput.value = cleaned;

    checkPhoneLocally(phoneInput.value);
    updateSendButtonState();
  });

  el('#send-consent')?.addEventListener('change', updateSendButtonState);

  el('#reset-btn')?.addEventListener('click', () => {
    if (textarea) textarea.value = '';
    if (phoneInput) phoneInput.value = '';

    const consent = el('#send-consent');
    if (consent) consent.checked = false;

    updateCharCount();
    setPhoneError('');
    ui.renderModerationFeedback(null);
    ui.hideCrisisPanel();
    lastPreview = null;
    updateSendButtonState();
    textarea?.focus();
  });

  // --- Close modals with Escape
  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    for (const id of ['#policy-modal', '#block-modal', '#crisis-modal']) {
      const modal = el(id);
      if (modal && !modal.classList.contains('hidden')) ui.closeModal(modal);
    }
  });

  // --- Close a modal when its backdrop is clicked
  for (const id of ['#policy-modal', '#block-modal', '#crisis-modal']) {
    el(id)?.addEventListener('click', (event) => {
      if (event.target === event.currentTarget) {
        ui.closeModal(/** @type {HTMLElement} */ (event.currentTarget));
      }
    });
  }

  // --- Surface sign-in errors raised by the auth module
  document.addEventListener('lifeline:auth-error', (event) => {
    const message = event.detail?.message ?? 'Sign-in failed.';
    ui.logLine(`Sign-in failed: ${message}`, 'error');
    ui.toast(message, 'error');
  });

  // --- React to auth state changes
  auth.onAuthChange((state) => {
    ui.renderAuthState(state);
    ui.renderQuota(state.quota);
    updateSendButtonState();
  });
}

/* ---------------------------------------------------------------------------
   Bootstrap
   --------------------------------------------------------------------------- */

/**
 * Initialise the application.
 *
 * Order matters: engine metadata, then the session, then the UI. Resolving the
 * session before rendering prevents the page from briefly showing a signed-out
 * state to someone who is already signed in.
 */
async function boot() {
  // Dress the server-rendered placeholders with Lucide icons.
  if (typeof window.lucide?.createIcons === 'function') window.lucide.createIcons();

  startTipRotation();
  bindEvents();

  ui.logLine('Initialising gateway client...', 'info');

  // --- Moderation engine metadata for the status bar
  try {
    const engine = await endpoints.engineInfo();
    ui.renderDetectorCount(engine?.moderation?.detectors ?? 0);
    ui.logLine(
      `Guardrails armed: ${engine?.moderation?.terms ?? 0} rules, `
      + `${engine?.moderation?.detectors ?? 0} pattern detectors.`,
      'success',
    );
  } catch {
    ui.logLine('Could not load guardrail metadata.', 'warning');
  }

  // --- Resolve the existing session before rendering auth UI
  const authenticated = await auth.restoreSession();

  if (authenticated) {
    ui.logLine(`Signed in as ${auth.state.user?.email ?? 'verified user'}.`, 'success');
  } else {
    ui.logLine('Awaiting sign-in. Google identity is required to send.', 'info');
  }

  // --- Configure Google sign-in
  const configResult = await auth.loadAuthConfig();

  if (!configResult.ok) {
    ui.renderAuthUnavailable(configResult.reason ?? 'Google sign-in is unavailable.');
    ui.logLine('Google sign-in is not configured on this server.', 'warning');
  } else if (!authenticated) {
    // Google's button is only rendered once the policy has been accepted, which
    // is why it is not initialised eagerly here.
    ui.logLine('Google sign-in available. Review the policy to continue.', 'info');
  }

  ui.renderQuota(auth.state.quota);
}

// Start once the document is parsed. The module is deferred by default so the
// DOM is ready by the time this runs, but the check keeps it robust if the
// script is ever moved into the head.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
