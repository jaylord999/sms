/**
 * ---------------------------------------------------------------------------
 * moderation/normalize.js - Text de-obfuscation layer.
 * ---------------------------------------------------------------------------
 * Bad actors rarely type "kidnap". They type "k1dnap", "k i d n a p",
 * "k!dn@p", "k\u200Bidnap" or "kïdnap". This module collapses every common
 * evasion technique into a canonical form BEFORE keyword matching runs.
 *
 * Strategy: produce several views of the same input and match keywords against
 * all of them. Never destructively modify - always keep the raw text intact for
 * the audit record.
 */

/**
 * Unicode homoglyph map. Maps visually-similar characters (Cyrillic, Greek,
 * fullwidth, mathematical alphanumerics) onto their Latin equivalents.
 * @type {Record<string, string>}
 */
const HOMOGLYPHS = {
  // Cyrillic
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0455': 's', '\u04BB': 'h',
  '\u0432': 'b', '\u043A': 'k', '\u043C': 'm', '\u043D': 'h', '\u0442': 't',
  // Greek
  '\u03B1': 'a', '\u03B2': 'b', '\u03B5': 'e', '\u03B7': 'n', '\u03B9': 'i',
  '\u03BA': 'k', '\u03BC': 'm', '\u03BD': 'v', '\u03BF': 'o', '\u03C1': 'p',
  '\u03C3': 'o', '\u03C4': 't', '\u03C5': 'u', '\u03C7': 'x', '\u03C9': 'w',
  // Fullwidth Latin (U+FF21..U+FF5A) handled procedurally below.
  // Mathematical alphanumerics / lookalikes
  '\u0269': 'i', '\u026A': 'i', '\u0274': 'n', '\u0299': 'b', '\u1D0F': 'o',
  '\u01A7': 's', '\u0131': 'i', '\u017F': 's', '\u010D': 'c', '\u0192': 'f',
};

/**
 * Leet-speak digit/symbol substitutions.
 * @type {Record<string, string>}
 */
const LEET = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
  '@': 'a', '$': 's', '!': 'i', '|': 'l', '+': 't', '(': 'c', '<': 'c',
  'Ё': 'e', '3': 'e', '9': 'g', '6': 'g', '2': 'z',
};

/**
 * Characters commonly used as visual separators inside obfuscated words.
 * These are stripped for the "compact" view so that "d*r*u*g*s" -> "drugs".
 */
const SEPARATORS = /[\s._\-*~^`'",;:!?/\\|()[\]{}=<>+&#%$@]/g;

/**
 * Zero-width and bidi-control characters. Attackers inject these to break
 * naive `includes()` checks.
 * https://unicode.org/reports/tr11/  https://www.unicode.org/reports/tr9/
 */
const INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u206A-\u206F\uFEFF\u00AD]/g;

/** Combining diacritical marks, removed after NFD decomposition. */
const DIACRITICS = /[\u0300-\u036f]/g;

/**
 * Convert fullwidth ASCII (U+FF01..U+FF5E) to normal ASCII.
 * @param {string} input
 * @returns {string}
 */
function foldFullwidth(input) {
  let out = '';
  for (const ch of input) {
    const code = ch.codePointAt(0);
    if (code >= 0xff01 && code <= 0xff5e) {
      out += String.fromCodePoint(code - 0xfee0);
    } else if (code === 0x3000) {
      out += ' '; // ideographic space
    } else {
      out += ch;
    }
  }
  return out;
}

/**
 * Replace homoglyphs with their Latin lookalikes.
 * @param {string} input
 * @returns {string}
 */
function foldHomoglyphs(input) {
  let out = '';
  for (const ch of input) {
    out += HOMOGLYPHS[ch] ?? ch;
  }
  return out;
}

/**
 * Remove accents/diacritics: "kidñap" -> "kidnap".
 * @param {string} input
 * @returns {string}
 */
function stripDiacritics(input) {
  return input.normalize('NFD').replace(DIACRITICS, '');
}

/**
 * Collapse runs of 3+ identical characters: "druuuugs" -> "drugs".
 * Length-2 runs are preserved because they are legitimate in English
 * ("ball", "seen", "good").
 * @param {string} input
 * @returns {string}
 */
function collapseRepeats(input) {
  return input.replace(/(.)\1{2,}/gu, '$1');
}

/**
 * Build the canonical lowercase base form.
 * @param {string} raw
 * @returns {string}
 */
export function baseNormalize(raw) {
  if (typeof raw !== 'string') return '';
  let text = raw;
  text = text.normalize('NFKC');
  text = foldFullwidth(text);
  text = text.replace(INVISIBLE, '');
  text = stripDiacritics(text);
  text = foldHomoglyphs(text);
  return text.toLowerCase().trim();
}

/**
 * Produce every relevant view of an input string for keyword matching.
 *
 * @param {string} raw Untrusted user input.
 * @returns {{
 *   raw: string,
 *   base: string,
 *   compact: string,
 *   deleet: string,
 *   spaced: string,
 *   reversed: string,
 *   tokens: string[]
 * }}
 */
export function buildViews(raw) {
  const base = baseNormalize(raw);

  // Numeric/symbol de-leeting applied first so separators like '.' survive
  // long enough to be stripped consistently afterwards.
  let deleet = '';
  for (const ch of base) {
    deleet += LEET[ch] ?? ch;
  }

  const compact = deleet.replace(SEPARATORS, '');
  const collapsed = collapseRepeats(compact);

  // Token list for multi-word phrase matching ("bring the drugs").
  const tokens = base.split(/[^a-z0-9]+/).filter(Boolean);

  return {
    raw: typeof raw === 'string' ? raw : '',
    base,
    // "c o c a i n e" and "c.o.c.a.i.n.e" both collapse to "cocaine" here.
    compact: collapsed,
    deleet: deleet.replace(/\s+/g, ' ').trim(),
    spaced: deleet.replace(/\s+/g, ''),
    // Catches "seniacc" (reversed) style evasion.
    reversed: collapsed.split('').reverse().join(''),
    tokens,
  };
}

/**
 * Strip everything that is not a digit. Used for phone-number normalisation.
 * @param {string} raw
 * @returns {string}
 */
export function digitsOnly(raw) {
  return String(raw ?? '').replace(/\D+/g, '');
}

export default { baseNormalize, buildViews, digitsOnly };
