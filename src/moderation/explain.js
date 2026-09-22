/**
 * ---------------------------------------------------------------------------
 * moderation/explain.js - User-facing explanations for moderation decisions.
 * ---------------------------------------------------------------------------
 * THE PROBLEM THIS SOLVES
 *
 * A block message that says only "prohibited content" is useless: the user
 * cannot tell which part of their message tripped the filter, so they cannot
 * fix it. They will either resend the same text or give up.
 *
 * THE TENSION
 *
 * Returning the exact matched terms would turn the endpoint into a blocklist
 * oracle. An attacker could binary-search word by word until they found text
 * that passes, which converts the filter from a control into a guide.
 *
 * THE RESOLUTION
 *
 * Return a REDACTED CONTEXT EXCERPT. The user sees the shape and position of
 * the problem - enough to recognise and correct it - while the specific trigger
 * term is masked. We keep the first and last character so it is recognisable to
 * the person who wrote it, but not copy-pasteable as a working reference.
 *
 * We also never name the internal rule id, because rule ids are stable across
 * deployments and would let an attacker build a durable map of the blocklist.
 */

/**
 * Mask a matched term for display, preserving its recognisable shape.
 *
 * "shabu"  -> "sh**u"
 * "kidnap" -> "ki**p"
 * "a"      -> "*"
 * "ab"     -> "a*"
 *
 * Short terms are masked almost entirely, because revealing a 2-3 character
 * trigger gives away nearly the whole rule.
 *
 * @param {string} term
 * @returns {string}
 */
export function maskTerm(term) {
  const chars = [...String(term ?? '')];

  if (chars.length <= 1) return '*';
  if (chars.length === 2) return `${chars[0]}*`;
  if (chars.length <= 4) return `${chars[0]}**${chars[chars.length - 1]}`;

  const tail = chars[chars.length - 1];
  const stars = '*'.repeat(Math.min(4, Math.max(2, chars.length - 3)));
  return `${chars.slice(0, 2).join('')}${stars}${tail}`;
}

/**
 * Build a redacted excerpt showing the user roughly where the problem is.
 *
 * @param {string} rawBody      The original message text.
 * @param {string} matchedTerm  The normalised term that fired.
 * @returns {string} Excerpt containing the masked term.
 */
export function buildExcerpt(rawBody, matchedTerm) {
  const term = String(matchedTerm ?? '');
  const masked = maskTerm(term);

  if (!rawBody || !term) return `\u2026${masked}\u2026`;

  // The engine matches against a normalised view, so the raw text may differ in
  // case or spacing. Search case-insensitively over the raw text first.
  const haystack = rawBody.toLowerCase();
  let index = haystack.indexOf(term.toLowerCase());

  // Multi-word terms may have lost their spacing during normalisation, so fall
  // back to locating just the first word.
  if (index === -1 && term.includes(' ')) {
    index = haystack.indexOf(term.split(' ')[0].toLowerCase());
  }

  // If it cannot be located, return the masked term alone rather than guessing
  // at a position and showing an excerpt that does not contain it.
  if (index === -1) return `\u2026${masked}\u2026`;

  const window = 24;
  const start = Math.max(0, index - window);
  const end = Math.min(rawBody.length, index + term.length + window);

  const prefix = start > 0 ? '\u2026' : '';
  const suffix = end < rawBody.length ? '\u2026' : '';

  return `${prefix}${rawBody.slice(start, index)}${masked}${rawBody.slice(index + term.length, end)}${suffix}`;
}

/**
 * Turn an engine result into copy the user can actually act on.
 *
 * @param {{
 *   findings: Array<{id: string, label: string, statute: string|null, matches: string[]}>,
 *   action: string,
 *   score: number
 * }} result
 * @param {string} rawBody
 * @returns {{
 *   reason: string,
 *   detail: string,
 *   excerpts: Array<{label: string, excerpt: string, statute: string|null}>,
 *   guidance: string[],
 *   retryable: boolean
 * }}
 */
export function explainDecision(result, rawBody) {
  const findings = result?.findings ?? [];

  // Group by category so a message that trips the same rule four times shows
  // one entry with one excerpt, rather than four near-identical rows.
  /** @type {Map<string, {label: string, excerpt: string, statute: string|null}>} */
  const grouped = new Map();

  for (const finding of findings) {
    // Internal scoring signals are not user-actionable and would only confuse.
    if (finding.id.startsWith('soft_')) continue;
    if (grouped.has(finding.id)) continue;

    const firstMatch = finding.matches?.[0];

    grouped.set(finding.id, {
      label: finding.label,
      excerpt: firstMatch ? buildExcerpt(rawBody, firstMatch) : '',
      statute: finding.statute,
    });
  }

  const excerpts = [...grouped.values()];

  // ---------------------------------------------------------------------------
  // Crisis content is never framed as a failure.
  // ---------------------------------------------------------------------------
  if (result?.action === 'assist') {
    return {
      reason: 'Your message was sent',
      detail:
        'It mentioned thoughts of self-harm, so free support numbers are shown below. '
        + 'The message itself was delivered normally.',
      excerpts: [],
      guidance: [
        'Your message reached the recipient.',
        'This did not use up your daily allowance.',
      ],
      retryable: false,
    };
  }

  // ---------------------------------------------------------------------------
  // Prohibited content.
  // ---------------------------------------------------------------------------
  const isCsam = findings.some((f) => f.id === 'csam' || f.id === 'ph_csam');

  return {
    reason: isCsam
      ? 'Blocked: child exploitation content'
      : 'Blocked: this appears to involve illegal activity',

    detail: isCsam
      ? 'Content involving the sexual exploitation of children is a serious crime under '
        + 'RA 9775. It cannot be sent through this gateway and has been reported.'
      : 'Your message matched rules that prohibit arranging, encouraging or facilitating '
        + 'illegal activity. Nothing was sent.',

    excerpts,

    guidance: isCsam
      ? [
        'This is not a filter error. Do not resend it.',
        'Content of this kind is reportable to the authorities under RA 9775.',
      ]
      : [
        'Rewrite the message without the highlighted part, then press send again.',
        'If you were quoting someone else, describe it in your own words instead of '
          + 'repeating their exact wording.',
        'If you believe this is a mistake, contact support with the time of this attempt.',
      ],

    retryable: !isCsam,
  };
}

export default { maskTerm, buildExcerpt, explainDecision };
