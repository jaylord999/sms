/**
 * ---------------------------------------------------------------------------
 * moderation/patterns.js - Regex layer for obfuscation and behavioural signals.
 * ---------------------------------------------------------------------------
 * Layer 2 of the moderation pipeline. Catches structural abuse a keyword list
 * cannot see: URLs, wallet addresses, mass-send requests, contact harvesting,
 * and the "c0c@1ne!!!" style evasions that survive normalisation.
 *
 * No lookbehind is used, so these patterns run on every supported Node version.
 */

/**
 * @typedef {Object} Detector
 * @property {string} id        Stable identifier for audit records.
 * @property {string} label     Human-readable reason.
 * @property {RegExp} regex     Compiled pattern (global, case-insensitive).
 * @property {number} weight    Severity contribution when matched.
 * @property {string} group     Reporting group.
 * @property {string} [statute] Optional legal reference.
 * @property {(m: RegExpMatchArray, text: string) => boolean} [guard]
 *   Optional extra predicate. Match loosely, then filter precisely.
 */

/** Link shorteners frequently abused for smishing payloads. */
const SUSPICIOUS_HOSTS = [
  'bit\\.ly', 'tinyurl\\.com', 'cutt\\.ly', 'is\\.gd', 'shorturl', 'rebrand\\.ly',
  't\\.co', 'goo\\.gl', 'ow\\.ly', 'buff\\.ly', 'adf\\.ly', 'shorte\\.st',
  'bit\\.do', 'surl\\.li', 'clck\\.ru', 'rb\\.gy',
].join('|');

/** @type {Detector[]} */
export const DETECTORS = [
  // -------------------------------------------------------------------------
  // Obfuscation: "d.r.u.g.s", "k-i-d-n-a-p", "c o c a i n e".
  // -------------------------------------------------------------------------
  {
    id: 'obfuscated_token',
    label: 'Character-separated word pattern (evasion attempt)',
    group: 'obfuscation',
    weight: 45,
    statute: 'RA 10175 Sec. 4(a)(1) - misuse of device / evasion',
    regex: /\b(?:[a-z0-9][\s._*\-]{1,3}){4,}[a-z0-9]\b/g,
    /**
     * Only flag when the collapsed form looks like a real word. Prevents
     * firing on legitimate prose such as "a. b. c. d."
     * @param {RegExpMatchArray} m
     */
    guard: (m) => {
      const collapsed = m[0].replace(/[\s._*\-]/g, '');
      return collapsed.length >= 5 && /[a-z]{3,}/.test(collapsed);
    },
  },

  // -------------------------------------------------------------------------
  // Obfuscation: "sh@bu", "dr#gs".
  // -------------------------------------------------------------------------
  {
    id: 'symbol_substitution',
    label: 'Symbol-substituted keyword pattern',
    group: 'obfuscation',
    weight: 40,
    regex: /\b[a-z]{2,}[@$!#]{1,3}[a-z]{2,}\b/g,
  },

  // -------------------------------------------------------------------------
  // Links. Unsolicited SMS links are the primary smishing vector.
  // -------------------------------------------------------------------------
  {
    id: 'url_generic',
    label: 'URL present in message',
    group: 'link',
    weight: 30,
    statute: 'NPC Advisory - unsolicited text links',
    regex: /\b(?:https?:\/\/|www\.)[^\s]+/gi,
  },
  {
    id: 'url_shortener',
    label: 'URL shortener detected (common in smishing)',
    group: 'link',
    weight: 55,
    statute: 'RA 10175 Sec. 4(b)(3) - phishing',
    regex: new RegExp(`(?:https?:\\/\\/)?(?:${SUSPICIOUS_HOSTS})\\/[^\\s]*`, 'gi'),
  },
  {
    id: 'bare_ip_link',
    label: 'Bare IP-address link',
    group: 'link',
    weight: 45,
    statute: 'RA 10175 Sec. 4(b)(3) - phishing',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?:\/\S*)?\b/g,
  },

  // -------------------------------------------------------------------------
  // Financial rails used for extortion, drug sales and scam payouts.
  // -------------------------------------------------------------------------
  {
    id: 'crypto_wallet',
    label: 'Cryptocurrency wallet address',
    group: 'financial',
    weight: 60,
    statute: 'RA 10175 / AMLA - unaccounted fund transfer',
    regex: /\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b/g,
  },
  {
    id: 'ewallet_pressure',
    label: 'E-wallet transfer instruction',
    group: 'financial',
    weight: 35,
    statute: 'RA 10175 - online fraud',
    regex: /\b(?:send|padala|transfer|bayad|deposito)\b[^.!?]{0,40}\b(?:gcash|maya|paymaya|coins\.ph|shopeepay)\b|\b(?:gcash|maya|paymaya|coins\.ph|shopeepay)\b[^.!?]{0,40}\b(?:send|padala|transfer|bayad|deposito|number)\b/gi,
  },
  {
    id: 'credential_ask',
    label: 'Request for PIN, OTP or banking credentials',
    group: 'financial',
    weight: 75,
    statute: 'RA 10175 Sec. 4(b)(3) phishing / RA 8484 Access Devices',
    // Verb-then-credential OR credential-then-verb. Both orders are common:
    // "send me your OTP" and "your OTP, send it" are equally abusive.
    regex: /\b(?:send|ibigay|give|share|ipadala|hatag|ihatag|reply|text|ilagay|provide|enter|confirm|verify|surrender)\b[^.!?]{0,30}\b(?:otp|one[\s-]?time[\s-]?(?:pin|password|code)|cvv|pin\s*code|card\s*number|account\s*number|password|passcode|mpin|m-pin|verification\s*code)\b|\b(?:otp|one[\s-]?time[\s-]?(?:pin|password|code)|cvv|pin\s*code|card\s*number|account\s*number|password|passcode|mpin|m-pin|verification\s*code)\b[^.!?]{0,30}\b(?:send|ibigay|give|share|ipadala|hatag|ihatag|reply|text|ilagay|provide|enter|confirm|verify|surrender)\b/gi,
  },
  {
    id: 'money_demand',
    label: 'Demand for immediate payment',
    group: 'financial',
    weight: 45,
    statute: 'RPC Art. 293 Robbery / Art. 294 Extortion',
    regex: /\b(?:padala\s+mo\s+na|padala\s+na\s+agad|send\s+money\s+now|bayad\s+o\s+(?:patay|sasaktan)|bayad\s+muna\s+bago|deposito\s+muna|downpayment\s+muna|magbayad\s+ka\s+ngayon|bayri\s+o\s+patyon)\b/gi,
  },

  // -------------------------------------------------------------------------
  // Mass-delivery abuse: turning an emergency gateway into a spam cannon.
  // -------------------------------------------------------------------------
  {
    id: 'bulk_send',
    label: 'Bulk / broadcast send request',
    group: 'abuse',
    // Weight sits above the default 60 threshold because turning an emergency
    // gateway into a spam cannon is an abuse of the service itself, not a
    // borderline judgement call. One confident hit is sufficient.
    weight: 75,
    statute: 'RA 10175 Sec. 4(c)(3) - unsolicited mass communication',
    regex: /\b(?:send\s+to\s+all|broadcast|blast|mass\s*send|bulk\s*send|send\s+to\s+everyone|send\s+sa\s+lahat|padala\s+sa\s+lahat|spam\s+this|spam\s+all|send\s+to\s+\d{2,}|ipadala\s+sa\s+lahat|padalhan\s+lahat|blast\s+all|mass\s+text|bulk\s+text)\b/gi,
  },
  {
    id: 'chain_letter',
    label: 'Chain-letter / forward-to-N-contacts pattern',
    group: 'abuse',
    weight: 50,
    statute: 'RA 10175 Sec. 4(c)(3) - unsolicited mass communication',
    regex: /\b(?:forward\s+(?:this\s+)?to\s+\d+|send\s+to\s+\d+\s+(?:friends|contacts|people)|padala\s+mo\s+sa\s+\d+|i-?forward\s+mo\s+sa\s+\d+)\b/gi,
  },
  {
    id: 'contact_harvest',
    label: 'Request to harvest contact list',
    group: 'abuse',
    weight: 55,
    statute: 'RA 10173 Data Privacy Act - unauthorised processing',
    regex: /\b(?:send\s+me\s+(?:your|ur)\s+contacts|send\s+mo\s+(?:ang\s+)?(?:mga\s+)?contact|share\s+(?:your|ur)\s+contacts|ibigay\s+mo\s+mga\s+number|ihatag\s+ang\s+mga\s+numero)\b/gi,
  },

  // -------------------------------------------------------------------------
  // Phishing / social-engineering phrasing.
  // -------------------------------------------------------------------------
  {
    id: 'prize_bait',
    label: 'Prize or raffle bait phrasing',
    group: 'social_engineering',
    weight: 65,
    statute: 'RA 10175 Sec. 4(b)(3) - phishing',
    regex: /\b(?:you(?:'ve|\s+have)?\s+won|congratulations\s+you\s+won|nanalo\s+ka|panalo\s+ka|nakadaog\s+ka|daog\s+ka|claim\s+your\s+(?:prize|reward)|kunin\s+ang\s+premyo|claim\s+mo\s+na\s+premyo)\b/gi,
  },
  {
    id: 'urgency_bait',
    label: 'Artificial urgency phrasing',
    group: 'social_engineering',
    weight: 40,
    statute: 'RA 10175 Sec. 4(b)(3) - phishing',
    regex: /\b(?:act\s+now|last\s+chance|today\s+only|bilisan\s+mo|ngayon\s+na|hanggang\s+ngayon\s+lang|expires?\s+(?:today|in\s+\d+))\b/gi,
  },
  {
    id: 'impersonation',
    label: 'Impersonation of an institution or official',
    group: 'social_engineering',
    weight: 60,
    statute: 'RPC Art. 177 Usurpation of Authority / RA 10175',
    regex: /\b(?:i\s+am\s+(?:from|with)\s+(?:nbi|pnp|bsp|dti|sec|bdo|bpi|landbank|gcash|maya|dswd|doh|philhealth|sss|pag-?ibig)|taga\s+(?:nbi|pnp|bsp|dti|bdo|bpi|dswd|philhealth|sss|pag-?ibig)|(?:official|legal)\s+notice\s+from\s+(?:nbi|pnp|bsp|bdo|bpi))\b/gi,
  },

  // -------------------------------------------------------------------------
  // Commercial and political solicitation on an emergency channel.
  // -------------------------------------------------------------------------
  {
    id: 'political_solicitation',
    label: 'Political campaign solicitation',
    group: 'abuse',
    weight: 55,
    statute: 'COMELEC Res. 11130 - unsolicited political e-messaging',
    regex: /\b(?:vote\s+for|iboto\s+mo|iboto\s+ninyo|bumoto\s+kayo|botar\s+kamo|vote\s+straight|sample\s+ballot|miting\s+de\s+avance)\b/gi,
  },
  {
    id: 'loan_solicitation',
    label: 'Unsolicited lending solicitation',
    group: 'abuse',
    weight: 50,
    statute: 'RA 9474 Lending Company Regulation Act / SEC Advisory',
    regex: /\b(?:instant\s+cash\s+loan|quick\s+loan\s+approval|loan\s+approved|sangla\s+(?:atm|titulo|phone|cellphone)|5[\s-]?6\s+lending|bumbay|magpapautang|pautang|utang\s+na\s+approved)\b/gi,
  },

  // -------------------------------------------------------------------------
  // Bulk-blast artefacts.
  // -------------------------------------------------------------------------
  {
    id: 'shouting',
    label: 'Excessive capitalisation (mass-blast style)',
    group: 'abuse',
    weight: 20,
    regex: /\b[A-Z]{8,}\b/g,
    guard: (m, text) => {
      const letters = text.replace(/[^A-Za-z]/g, '');
      if (letters.length < 12) return false;
      const upper = text.replace(/[^A-Z]/g, '').length;
      return upper / letters.length > 0.75;
    },
  },
  {
    id: 'char_flood',
    label: 'Repeated character flooding',
    group: 'abuse',
    weight: 20,
    regex: /(.)\1{5,}/g,
  },
  {
    id: 'phrase_repeat',
    label: 'Same phrase repeated many times',
    group: 'abuse',
    weight: 45,
    regex: /\b(\w{3,}(?:\s+\w{1,12}){0,3})\b(?:\s+\1\b){2,}/gi,
  },

  // -------------------------------------------------------------------------
  // PII exposure: someone else's identifying data.
  // -------------------------------------------------------------------------
  {
    id: 'gov_id_number',
    label: 'Government ID number pattern',
    group: 'pii',
    weight: 40,
    statute: 'RA 10173 Data Privacy Act',
    regex: /\b(?:umid|sss|gsis|tin|philhealth|pag-?ibig|drivers?\s+licen[cs]e|passport)\b[\s:no.#-]{0,12}\d{6,16}\b/gi,
  },
  {
    id: 'bank_card',
    label: 'Payment card number pattern',
    group: 'pii',
    weight: 50,
    statute: 'RA 8484 Access Devices Regulation Act',
    regex: /\b(?:\d[ -]?){13,19}\b/g,
    guard: (m) => {
      const digits = m[0].replace(/\D/g, '');
      return digits.length >= 13 && digits.length <= 19;
    },
  },
];

/** Detector ids indexed by reporting group. */
export const DETECTOR_GROUPS = Object.freeze(
  DETECTORS.reduce((acc, detector) => {
    (acc[detector.group] ||= []).push(detector.id);
    return acc;
  }, /** @type {Record<string, string[]>} */ ({})),
);

/**
 * Run every detector against the provided text views.
 *
 * Detectors run against the raw text (URLs and numbers must NOT be
 * de-obfuscated) and against the compact view (to catch separator-injected
 * evasion such as "b u y g u n").
 *
 * @param {ReturnType<import('./normalize.js').buildViews>} views
 * @returns {Array<{id: string, label: string, group: string, weight: number, statute: string|null, matches: string[]}>}
 */
export function runDetectors(views) {
  /** @type {Array<{id: string, label: string, group: string, weight: number, statute: string|null, matches: string[]}>} */
  const findings = [];

  const haystacks = [views.raw, views.compact].filter(Boolean);

  for (const detector of DETECTORS) {
    /** @type {Set<string>} */
    const matches = new Set();

    for (const text of haystacks) {
      // Every detector regex is global, so reset lastIndex before each pass.
      detector.regex.lastIndex = 0;
      const found = text.match(detector.regex);
      if (!found) continue;

      for (const hit of found) {
        if (detector.guard && !detector.guard([hit], text)) continue;
        matches.add(hit.length > 120 ? `${hit.slice(0, 117)}...` : hit);
      }
    }

    if (matches.size > 0) {
      findings.push({
        id: detector.id,
        label: detector.label,
        group: detector.group,
        weight: detector.weight,
        statute: detector.statute ?? null,
        matches: [...matches].slice(0, 5),
      });
    }
  }

  return findings;
}

export default { DETECTORS, DETECTOR_GROUPS, runDetectors };
