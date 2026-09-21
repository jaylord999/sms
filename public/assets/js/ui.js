/**
 * ---------------------------------------------------------------------------
 * assets/js/ui.js - View layer.
 * ---------------------------------------------------------------------------
 * All DOM rendering lives here. The rule this module follows without exception:
 *
 *   USER-CONTROLLED TEXT IS ALWAYS INSERTED WITH textContent, NEVER innerHTML.
 *
 * Message bodies, phone numbers, provider errors and account names all pass
 * through this file, so treating every one of them as text rather than markup is
 * what closes the cross-site scripting hole present in the original page.
 */

import {
  el, create, setText, setVisible, openModal, closeModal, clear,
  timestamp, refreshIcons,
} from './dom.js';

/* ---------------------------------------------------------------------------
   Toasts
   --------------------------------------------------------------------------- */

/** Colour treatment per toast kind. */
const TOAST_STYLES = {
  success: { border: 'border-emerald-500/50', icon: 'check-circle-2', colour: 'text-emerald-400' },
  error: { border: 'border-red-500/50', icon: 'alert-circle', colour: 'text-red-400' },
  warning: { border: 'border-amber-500/50', icon: 'alert-triangle', colour: 'text-amber-400' },
  info: { border: 'border-sky-500/50', icon: 'info', colour: 'text-sky-400' },
};

/**
 * Show a transient toast notification.
 * @param {string} message
 * @param {'success'|'error'|'warning'|'info'} [kind]
 * @param {number} [durationMs]
 */
export function toast(message, kind = 'info', durationMs = 4500) {
  const host = el('#toast-host');
  if (!host) return;

  const style = TOAST_STYLES[kind] ?? TOAST_STYLES.info;

  const iconNode = create('i', {
    'data-lucide': style.icon,
    class: `w-4 h-4 shrink-0 mt-0.5 ${style.colour}`,
    'aria-hidden': 'true',
  });

  // The message becomes a text node, so text containing markup is displayed
  // literally rather than parsed and executed.
  const textNode = create('p', { class: 'flex-1 text-slate-200' }, [message]);

  const node = create('div', {
    class: `pointer-events-auto glass-card border ${style.border} rounded-xl p-3 shadow-xl `
      + 'flex items-start space-x-2.5 animate-enter',
  }, [iconNode, textNode]);

  host.append(node);
  refreshIcons();

  setTimeout(() => {
    node.style.transition = 'opacity 0.25s ease';
    node.style.opacity = '0';
    setTimeout(() => node.remove(), 260);
  }, durationMs);
}

/* ---------------------------------------------------------------------------
   Dispatch feed
   --------------------------------------------------------------------------- */

let feedEvents = 0;

/**
 * Append a line to the gateway dispatch feed.
 *
 * @param {string} message
 * @param {'info'|'success'|'error'|'warning'|'blocked'} [level]
 */
export function logLine(message, level = 'info') {
  const box = el('#log-box');
  if (!box) return;

  // Remove the placeholder shown before the first real event arrives.
  if (feedEvents === 0) clear(box);

  /** @type {Record<string, string>} */
  const colours = {
    info: 'text-slate-300',
    success: 'text-emerald-300',
    warning: 'text-amber-300',
    error: 'text-red-300',
    blocked: 'text-red-400',
  };

  const isBad = level === 'error' || level === 'blocked';

  const arrow = create('span', {
    class: `font-bold ${isBad ? 'text-red-500' : 'text-emerald-500'}`,
    text: '>',
  });

  const stamp = create('span', { class: 'text-slate-600', text: `[${timestamp()}]` });
  const body = create('span', { class: colours[level] ?? colours.info }, [message]);

  box.append(create('div', { class: 'flex items-start space-x-2 animate-enter' }, [
    arrow, stamp, body,
  ]));

  // Keep the feed bounded so a long session cannot grow the DOM without limit.
  while (box.children.length > 60) box.removeChild(box.firstChild);

  box.scrollTop = box.scrollHeight;

  feedEvents += 1;
  setText(el('#feed-count'), `${feedEvents} event${feedEvents === 1 ? '' : 's'}`);
}

/** Reset the feed counter. Used when the composer is cleared. */
export function resetFeedCounter() {
  feedEvents = 0;
}

/* ---------------------------------------------------------------------------
   Floating tip bubbles
   --------------------------------------------------------------------------- */

/**
 * Build a floating tip bubble element.
 *
 * @param {{icon: string, title: string, text: string}} tip
 * @returns {HTMLElement}
 */
export function buildTipBubble(tip) {
  const tail = create('div', {
    class: 'absolute -bottom-2 left-6 w-4 h-4 bg-slate-900 border-r border-b '
      + 'border-emerald-500/30 transform rotate-45',
    'aria-hidden': 'true',
  });

  const header = create('div', { class: 'flex items-center space-x-2.5 mb-1.5' }, [
    create('span', { class: 'text-base', text: tip.icon, 'aria-hidden': 'true' }),
    create('h4', { class: 'text-xs font-bold text-white tracking-tight', text: tip.title }),
  ]);

  return create('div', {
    class: 'bubble-anim glass-card rounded-2xl p-4 shadow-2xl border border-emerald-500/30 '
      + 'relative text-left',
  }, [
    tail,
    header,
    create('p', { class: 'text-[11px] text-slate-300 leading-relaxed', text: tip.text }),
  ]);
}

/* ---------------------------------------------------------------------------
   Auth presentation
   --------------------------------------------------------------------------- */

/**
 * Render the header auth control to match the current auth state.
 * @param {import('./auth.js').state} state
 */
export function renderAuthState(state) {
  const btnText = el('#auth-text');
  const authBtn = el('#demo-signin-btn');
  const host = el('#gsi-button-host');
  const gate = el('#auth-gate');

  const signedIn = state.authenticated && state.user;

  if (signedIn) {
    const firstName = String(state.user.name || 'Connected').split(' ')[0];
    setText(btnText, `${firstName} (signed in)`);

    authBtn?.classList.remove('bg-slate-800/90', 'border-slate-700/80');
    authBtn?.classList.add('bg-emerald-950/90', 'border-emerald-500/50', 'text-emerald-300');
    authBtn?.setAttribute('title', 'Click to sign out');
    authBtn?.setAttribute('aria-label', 'Sign out');

    // Hide Google's button while signed in: offering sign-in again would be
    // confusing, because the header control now means sign-out.
    host?.classList.add('hidden');
    setVisible(gate, false);
  } else {
    setText(btnText, 'Sign in with Google');

    authBtn?.classList.add('bg-slate-800/90', 'border-slate-700/80');
    authBtn?.classList.remove('bg-emerald-950/90', 'border-emerald-500/50', 'text-emerald-300');
    authBtn?.setAttribute('title', 'Sign in with Google');
    authBtn?.setAttribute('aria-label', 'Sign in with Google');

    setVisible(gate, true);
  }

  refreshIcons();
}

/**
 * Show why sign-in is unavailable, and disable the controls that depend on it.
 * @param {string} reason
 */
export function renderAuthUnavailable(reason) {
  const note = el('#auth-gate-note');
  const gateBtn = el('#gate-signin-btn');

  if (note) {
    setText(note, reason);
    setVisible(note, true);
  }

  if (gateBtn) {
    gateBtn.disabled = true;
    gateBtn.classList.add('opacity-50', 'cursor-not-allowed');
  }
}

/* ---------------------------------------------------------------------------
   Quota and engine status
   --------------------------------------------------------------------------- */

/**
 * Render the quota counter.
 * @param {{limit: number, used: number, remaining: number}|null} quota
 */
export function renderQuota(quota) {
  const node = el('#msg-counter');
  if (!node || !quota) {
    setText(node, '-/-');
    return;
  }

  setText(node, `${quota.used}/${quota.limit}`);

  // Warn visually as the allowance runs out.
  node.classList.toggle('text-amber-400', quota.remaining === 0);
  node.classList.toggle('text-emerald-400', quota.remaining > 0);
}

/**
 * Render the count of loaded moderation rules in the status bar.
 * @param {number} detectors
 */
export function renderDetectorCount(detectors) {
  setText(el('#detector-count'), String(detectors));
}

/* ---------------------------------------------------------------------------
   Live moderation feedback
   --------------------------------------------------------------------------- */

/**
 * Render live moderation feedback beneath the composer.
 *
 * Three distinct states, and the difference between them matters:
 *   allowed  - neutral. Nothing to tell the user.
 *   assist   - crisis detected. Supportive, and explicit that the message WILL
 *              still be sent. This must never read like a rejection.
 *   blocked  - refused. Explains the category without naming matched terms.
 *
 * @param {{action: string, deliverable: boolean, isCrisis: boolean,
 *          findings: Array<{category: string, label: string, statute: string|null}>,
 *          message: string}|null} result
 */
export function renderModerationFeedback(result) {
  const box = el('#moderation-feedback');
  if (!box) return;

  if (!result) {
    setVisible(box, false);
    return;
  }

  box.className = 'mt-2 rounded-lg p-2.5 text-[11px] leading-relaxed animate-enter';

  if (result.isCrisis) {
    box.classList.add('bg-sky-950/60', 'border', 'border-sky-500/40', 'text-sky-100');
    replace(box, [
      'Your message will still be sent. Support is available - see the panel above.',
    ]);
    setVisible(box, true);
    return;
  }

  if (!result.deliverable) {
    box.classList.add('bg-red-950/50', 'border', 'border-red-500/40', 'text-red-200');
    replace(box, [result.message || 'This message cannot be sent.']);
    setVisible(box, true);
    return;
  }

  // Clean: keep the UI quiet.
  setVisible(box, false);
}

/* ---------------------------------------------------------------------------
   Blocked-message modal
   --------------------------------------------------------------------------- */

/**
 * Open the blocked-message modal.
 * @param {{message: string, findings: Array<{label: string, statute: string|null}>}} payload
 */
export function showBlockedModal(payload) {
  const modal = el('#block-modal');
  const reason = el('#block-reason');
  const list = el('#block-categories');

  setText(reason, payload?.message || 'This message appears to involve illegal activity.');
  clear(list);

  for (const finding of payload?.findings ?? []) {
    const children = [
      create('p', { class: 'text-[11px] font-semibold text-red-200', text: finding.label }),
    ];

    // Citing the statute is what makes a refusal explainable and reviewable.
    if (finding.statute) {
      children.push(create('p', {
        class: 'text-[10px] text-slate-500 mt-0.5',
        text: finding.statute,
      }));
    }

    list.append(create('div', {
      class: 'rounded-lg border border-red-500/20 bg-red-950/30 p-2.5',
    }, children));
  }

  openModal(modal);
  refreshIcons();
}

/* ---------------------------------------------------------------------------
   Crisis support
   --------------------------------------------------------------------------- */

/**
 * Render a list of crisis support resources.
 *
 * Every field arrives from our own API, but it is still inserted as text: the
 * shortlist of values we happen to trust today is not a security boundary.
 *
 * @param {HTMLElement|null} target
 * @param {Array<{id: string, name: string, contact: string, hours: string, note: string}>} resources
 */
function renderResourceList(target, resources) {
  if (!target) return;
  clear(target);

  for (const resource of resources ?? []) {
    const name = create('p', { class: 'text-[11px] font-bold text-sky-100', text: resource.name });
    const contact = create('p', {
      class: 'text-xs font-mono text-sky-300 mt-0.5',
      text: resource.contact,
    });

    const meta = resource.hours
      ? create('p', { class: 'text-[10px] text-sky-200/60 mt-0.5', text: resource.hours })
      : null;

    const note = resource.note
      ? create('p', { class: 'text-[10px] text-sky-200/70 mt-1 leading-relaxed', text: resource.note })
      : null;

    target.append(create('li', {
      class: 'rounded-lg border border-sky-500/25 bg-sky-950/40 p-2.5',
    }, [name, contact, meta, note]));
  }
}

/**
 * Show the inline crisis support panel above the composer.
 * @param {Array<object>} resources
 */
export function showCrisisPanel(resources) {
  renderResourceList(el('#crisis-resource-list'), resources);
  setVisible(el('#crisis-panel'), true);
  refreshIcons();
}

/** Hide the inline crisis panel. */
export function hideCrisisPanel() {
  setVisible(el('#crisis-panel'), false);
  const checkbox = el('#alert-trusted-contact');
  if (checkbox) checkbox.checked = false;
}

/**
 * Show the post-delivery crisis support modal.
 * @param {Array<object>} resources
 */
export function showCrisisModal(resources) {
  renderResourceList(el('#crisis-modal-list'), resources);
  openModal(el('#crisis-modal'));
  refreshIcons();
}

/* ---------------------------------------------------------------------------
   Policy modal
   --------------------------------------------------------------------------- */

/**
 * Render the Acceptable Use Policy into the modal.
 * @param {object} policy
 */
export function renderPolicy(policy) {
  const body = el('#policy-body');
  if (!body) return;

  clear(body);
  setText(el('#policy-version'), `Version ${policy.version} - updated ${policy.updated}`);
  body.append(create('p', { class: 'text-slate-300', text: policy.summary }));

  // --- Always permitted. Placed FIRST and visually distinct: a user in distress
  // must see that their message will be delivered before reading a list of
  // prohibitions, or they may not send it at all.
  if (policy.alwaysAllowed?.length) {
    const section = create('section');
    section.append(create('h3', {
      class: 'text-xs font-bold text-sky-300 uppercase tracking-wider mb-2',
      text: 'Always permitted',
    }));

    for (const item of policy.alwaysAllowed) {
      section.append(create('div', {
        class: 'rounded-lg border border-sky-500/25 bg-sky-950/40 p-3 mb-2',
      }, [
        create('p', { class: 'text-[11px] font-bold text-sky-200', text: item.title }),
        create('p', {
          class: 'text-[11px] text-sky-100/80 mt-1 leading-relaxed',
          text: item.detail,
        }),
      ]));
    }

    body.append(section);
  }

  // --- Prohibited
  if (policy.prohibited?.length) {
    const section = create('section');
    section.append(create('h3', {
      class: 'text-xs font-bold text-red-300 uppercase tracking-wider mb-2',
      text: 'Prohibited',
    }));

    for (const item of policy.prohibited) {
      section.append(create('div', {
        class: 'rounded-lg border border-slate-800 bg-slate-950/50 p-3 mb-2',
      }, [
        create('p', { class: 'text-[11px] font-bold text-slate-100', text: item.title }),
        create('p', { class: 'text-[11px] text-slate-400 mt-1 leading-relaxed', text: item.detail }),
        create('p', { class: 'text-[10px] text-slate-600 mt-1 font-mono', text: item.statute }),
      ]));
    }

    body.append(section);
  }

  // --- Enforcement and data handling
  if (policy.enforcement) {
    const section = create('section');
    section.append(create('h3', {
      class: 'text-xs font-bold text-slate-400 uppercase tracking-wider mb-2',
      text: 'How this is enforced',
    }));

    const list = create('ul', { class: 'space-y-1.5 mb-3' });
    for (const step of policy.enforcement.process ?? []) {
      list.append(create('li', { class: 'text-[11px] text-slate-300 flex gap-2' }, [
        create('span', { class: 'text-emerald-500 font-bold', text: '\u2022' }),
        create('span', { text: step }),
      ]));
    }
    section.append(list);

    section.append(create('p', {
      class: 'text-[11px] text-slate-400 leading-relaxed mb-2',
      text: policy.enforcement.dataHandling,
    }));

    section.append(create('p', {
      class: 'text-[11px] text-slate-400 leading-relaxed',
      text: policy.enforcement.appeals,
    }));

    body.append(section);
  }

  openModal(el('#policy-modal'));
  refreshIcons();
}

export { openModal, closeModal };
