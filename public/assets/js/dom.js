/**
 * ---------------------------------------------------------------------------
 * assets/js/dom.js - DOM helpers with built-in XSS safety.
 * ---------------------------------------------------------------------------
 * The original single-file page built log lines by concatenating user text into
 * `innerHTML`. That is a cross-site scripting hole: a message body containing
 * markup would execute in the operator's browser.
 *
 * Every function here that inserts text uses `textContent`, which treats input
 * as text and never as markup. There is deliberately NO general-purpose
 * "set innerHTML" helper in this module, so unsafe insertion requires writing
 * `innerHTML` explicitly and is therefore visible in code review.
 */

/**
 * Shorthand for querySelector.
 * @param {string} selector
 * @param {ParentNode} [scope]
 * @returns {HTMLElement|null}
 */
export function el(selector, scope = document) {
  return scope.querySelector(selector);
}

/**
 * Shorthand for querySelectorAll, returned as a real array.
 * @param {string} selector
 * @param {ParentNode} [scope]
 * @returns {HTMLElement[]}
 */
export function els(selector, scope = document) {
  return [...scope.querySelectorAll(selector)];
}

/**
 * Create an element with attributes and safely-appended text children.
 *
 * `text` children are always inserted via textContent, so passing untrusted
 * data is safe by construction.
 *
 * @param {string} tag
 * @param {Record<string, string>} [attributes]
 * @param {Array<Node|string>} [children]
 * @returns {HTMLElement}
 */
export function create(tag, attributes = {}, children = []) {
  const node = document.createElement(tag);

  for (const [key, value] of Object.entries(attributes)) {
    if (value === undefined || value === null) continue;

    // `class` and `for` are reserved words in some contexts, so set them via
    // the DOM property that actually reflects the attribute.
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else node.setAttribute(key, value);
  }

  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }

  return node;
}

/**
 * Set text content safely.
 * @param {HTMLElement|null} node
 * @param {string} text
 */
export function setText(node, text) {
  if (node) node.textContent = text ?? '';
}

/**
 * Toggle an element's visibility using Tailwind's `hidden` utility.
 * @param {HTMLElement|null} node
 * @param {boolean} visible
 */
export function setVisible(node, visible) {
  if (!node) return;
  node.classList.toggle('hidden', !visible);
}

/**
 * Show a modal. Modals in this app are flex containers that are `hidden` when
 * closed, so opening means swapping `hidden` for `flex`.
 * @param {HTMLElement|null} modal
 */
export function openModal(modal) {
  if (!modal) return;
  modal.classList.remove('hidden');
  modal.classList.add('flex');

  // Move focus into the dialog so keyboard and screen-reader users land inside.
  const focusTarget = modal.querySelector(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
  );
  focusTarget?.focus();
}

/**
 * Hide a modal.
 * @param {HTMLElement|null} modal
 */
export function closeModal(modal) {
  if (!modal) return;
  modal.classList.add('hidden');
  modal.classList.remove('flex');
}

/**
 * Remove every child of a node without using innerHTML.
 * @param {HTMLElement|null} node
 */
export function clear(node) {
  if (!node) return;
  while (node.firstChild) node.removeChild(node.firstChild);
}

/**
 * Replace a node's children with the provided list.
 * @param {HTMLElement|null} node
 * @param {Array<Node|string>} children
 */
export function replace(node, children) {
  clear(node);
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
}

/**
 * Format a timestamp for the dispatch feed.
 * @param {Date} [date]
 * @returns {string}
 */
export function timestamp(date = new Date()) {
  return date.toLocaleTimeString('en-PH', { hour12: false });
}

/**
 * Render an inline SVG icon from the Lucide library.
 * Lucide replaces `[data-lucide]` placeholders on demand, so newly inserted
 * markup must ask it to run again.
 *
 * @param {string} name
 * @param {string} [className]
 * @returns {HTMLElement}
 */
export function icon(name, className = 'w-4 h-4') {
  const node = create('i', { 'data-lucide': name, class: className });
  return node;
}

/**
 * Ask Lucide to convert any pending `[data-lucide]` placeholders into SVG.
 * Safe to call when the library failed to load; it simply does nothing.
 */
export function refreshIcons() {
  if (typeof window.lucide?.createIcons === 'function') {
    window.lucide.createIcons();
  }
}

export default {
  el,
  els,
  create,
  setText,
  setVisible,
  openModal,
  closeModal,
  clear,
  replace,
  timestamp,
  icon,
  refreshIcons,
};
