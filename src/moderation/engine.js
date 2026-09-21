/**
 * ---------------------------------------------------------------------------
 * moderation/engine.js - Tiered content moderation orchestrator.
 * ---------------------------------------------------------------------------
 * ARCHITECTURE: three outcomes, not two.
 *
 *   ALLOW   - content is acceptable, deliver normally.
 *   BLOCK   - prohibited content, refuse delivery and record a violation.
 *   ASSIST  - crisis content. DELIVER THE MESSAGE, then surface support.
 *
 * Crisis content is never blocked. See the policy note in keywords.js.
 *
 * PERFORMANCE: tiers exist so the expensive path is rarely taken.
 *
 *   Tier 0  Fast reject    nothing matched                     ~0.2 ms -> ALLOW
 *   Tier 1  Deterministic  hard category or score >= threshold ~0.5 ms -> BLOCK
 *   Tier 1b Crisis         assist category matched             ~0.5 ms -> ASSIST
 *   Tier 2  Ambiguous      soft signals only, low score        +AI RTT -> resolve
 *
 * The AI layer (Tier 2) is consulted only when the deterministic layers cannot
 * decide. That keeps cost and latency near zero for normal traffic while still
 * catching novel wording no keyword list anticipates.
 */

import config from '../config.js';
import { buildViews } from './normalize.js';
import { TERM_INDEX, SOFT_SIGNAL_LIST, ACTION, keywordStats } from './keywords.js';
import { runDetectors, DETECTORS, DETECTOR_GROUPS } from './patterns.js';

/**
 * @typedef {Object} Finding
 * @property {string} source      'keyword' | 'pattern' | 'ai'
 * @property {string} id          Category or detector id.
 * @property {string} label       Human-readable reason.
 * @property {number} weight      Severity contribution.
 * @property {string|null} statute Legal reference, if any.
 * @property {string[]} matches   Matched fragments (truncated, for operators).
 */

/**
 * @typedef {Object} CrisisResource
 * @property {string} id
 * @property {string} name
 * @property {string} contact
 * @property {string} hours
 * @property {string} note
 */

/**
 * @typedef {Object} ModerationResult
 * @property {string} action                  ALLOW | BLOCK | ASSIST
 * @property {number} score                   0-100 cumulative severity.
 * @property {Finding[]} findings             Everything that fired.
 * @property {boolean} isCrisis               True when the ASSIST path fired.
 * @property {string} reasonCode              Stable code for audit records.
 * @property {string} userMessage             Safe, non-enumerating user copy.
 * @property {CrisisResource[]} resources     Support resources for crisis path.
 * @property {boolean} usedAi                 True when Tier 2 was consulted.
 * @property {number} durationMs              Time spent moderating.
 * @property {string[]} auditTags             Tags written to the audit trail.
 * @property {boolean} [dryRun]               True when enforcement was skipped.
 */

/**
 * Support resources surfaced on the crisis path. Verified PH hotlines.
 * @type {ReadonlyArray<CrisisResource>}
 */
export const CRISIS_RESOURCES = Object.freeze([
  {
    id: 'ncmh',
    name: 'NCMH Crisis Hotline',
    contact: '1553 (nationwide, toll-free)',
    hours: '24/7',
    note: 'National Center for Mental Health - trained crisis responders.',
  },
  {
    id: 'hopeline',
    name: 'Hopeline Philippines',
    contact: '2919 (toll-free for Globe/TM) or (02) 8804-4673',
    hours: '24/7',
    note: 'Free, confidential counselling for anyone in distress.',
  },
  {
    id: 'emergency',
    name: 'National Emergency Hotline',
    contact: '911',
    hours: '24/7',
    note: 'If you or someone else is in immediate physical danger.',
  },
  {
    id: 'dswd',
    name: 'DSWD Crisis Intervention',
    contact: '8888 Citizens Complaint Hotline',
    hours: '24/7',
    note: 'Social welfare assistance and intervention referrals.',
  },
]);

/** Copy shown to users. Deliberately non-enumerating. */
const USER_MESSAGES = Object.freeze({
  ALLOW: 'Message cleared for delivery.',
  CRISIS:
    'Your message has been sent. You are not alone - support is available right now.',
  BLOCK_GENERIC:
    'This message cannot be sent because it appears to involve illegal activity. '
    + 'Your account has been flagged for review.',
  BLOCK_CSAM:
    'This message cannot be sent. Content involving the sexual exploitation of '
    + 'children is a serious crime and has been reported.',
});

/**
 * Score the keyword layer.
 *
 * @param {ReturnType<typeof buildViews>} views
 * @returns {{findings: Finding[], score: number, isCrisis: boolean, hardHit: boolean}}
 */
function scanKeywords(views) {
  /** @type {Finding[]} */
  const findings = [];
  /** @type {Set<string>} */
  const matched = new Set();

  /** @type {Array<{term: string, entry: typeof TERM_INDEX extends Map<string, infer V> ? V : never}>} */
  const candidates = [];

  for (const [term, entry] of TERM_INDEX) {
    if (views.compact.includes(term)) {
      candidates.push({ term, entry });
    } else if (term.includes(' ') && views.deleet.includes(term)) {
      // Multi-word terms can lose their spacing in the compact view.
      candidates.push({ term, entry });
    }
  }

  // Longest-first ordering matters: "buy cytotec" must win over "cytotec" so
  // the more specific (and more severe) category is attributed.
  candidates.sort((a, b) => b.term.length - a.term.length);

  let score = 0;
  let isCrisis = false;
  let hardHit = false;

  for (const { term, entry } of candidates) {
    if (matched.has(term)) continue;
    matched.add(term);

    // A context-gated category only counts when one of its own hints is also
    // present. This is what stops "abort the download" from firing.
    if (entry.requiresContext) {
      const hintPresent = entry.contextHints.some((hint) => {
        const compactHint = hint.replace(/\s+/g, '');
        return views.compact.includes(compactHint) || views.base.includes(hint);
      });
      if (!hintPresent) continue;
    }

    findings.push({
      source: 'keyword',
      id: entry.categoryId,
      label: entry.label,
      weight: entry.weight,
      statute: entry.statute,
      matches: [term],
    });

    if (entry.assistOnly) {
      // Crisis content. Recorded for duty-of-care evidence, never scored as a
      // violation, and never allowed to contribute to a block decision.
      isCrisis = true;
      continue;
    }

    if (entry.hard) {
      hardHit = true;
      score = 100;
      continue;
    }

    score += entry.weight;
  }

  return { findings, score, isCrisis, hardHit };
}

/**
 * Score the pattern layer.
 * @param {ReturnType<typeof buildViews>} views
 * @returns {{findings: Finding[], score: number}}
 */
function scanPatterns(views) {
  const raw = runDetectors(views);

  const findings = raw.map((detector) => ({
    source: /** @type {'pattern'} */ ('pattern'),
    id: detector.id,
    label: detector.label,
    weight: detector.weight,
    statute: detector.statute,
    matches: detector.matches,
  }));

  // Scoring model for patterns:
  //   primary = the single strongest detector hit. A clear, high-confidence
  //             signal (bulk blast, OTP request, hard link) must be decisive
  //             on its own and not watered down by averaging.
  //   bonus   = bounded contribution from additional corroborating hits.
  const weights = raw.map((detector) => detector.weight).sort((a, b) => b - a);
  const primary = weights[0] ?? 0;
  const bonus = weights.slice(1).reduce((sum, w) => sum + w, 0);
  const score = primary === 0
    ? 0
    : Math.min(100, Math.round(primary + bonus * 0.25));

  return { findings, score };
}

/**
 * Score co-occurring soft signals. These never block on their own.
 * @param {string} base
 * @param {string} compact
 * @returns {{findings: Finding[], score: number}}
 */
function scanSoftSignals(base, compact) {
  /** @type {Finding[]} */
  const findings = [];
  /** @type {Map<string, string[]>} */
  const byGroup = new Map();

  for (const { group, phrase } of SOFT_SIGNAL_LIST) {
    const normalized = phrase.replace(/\s+/g, '');
    if (compact.includes(normalized) || base.includes(phrase)) {
      const list = byGroup.get(group) ?? [];
      list.push(phrase);
      byGroup.set(group, list);
    }
  }

  let score = 0;
  for (const [group, phrases] of byGroup) {
    // Each distinct group adds a small, capped contribution.
    const contribution = Math.min(15, phrases.length * 6);
    score += contribution;
    findings.push({
      source: 'keyword',
      id: `soft_${group}`,
      label: `Weak signal: ${group.replace(/_/g, ' ')}`,
      weight: contribution,
      statute: null,
      matches: phrases.slice(0, 4),
    });
  }

  return { findings, score: Math.min(45, score) };
}

/**
 * Tier 2: consult an optional LLM classifier for ambiguous messages.
 *
 * Disabled by default. When enabled, this is only reached for messages that
 * produced soft signals but did not cross the deterministic threshold.
 *
 * @param {string} body
 * @param {Finding[]} context
 * @returns {Promise<{label: string, confidence: number, reason: string}|null>}
 */
async function consultAiGuard(body, context) {
  const { endpoint, apiKey, model } = config.moderation.ai;
  if (!endpoint) return null;

  const controller = new AbortController();
  // Hard timeout: a slow classifier must never hang message delivery.
  const timeout = setTimeout(() => controller.abort(), 4000);

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'content-type': 'application/json',
        ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}),
      },
      body: JSON.stringify({
        model,
        temperature: 0,
        max_tokens: 120,
        response_format: { type: 'json_object' },
        messages: [
          {
            role: 'system',
            content: [
              'You are a content-safety classifier for a Philippine emergency SMS gateway.',
              'Classify the message as one of:',
              'BLOCK - illegal activity such as drug dealing, kidnapping, trafficking,',
              'weapons, terrorism, fraud, or child exploitation.',
              'ASSIST - suicidal ideation or self-harm; the person needs support, NOT',
              'censorship. Crisis messages are always delivered.',
              'ALLOW - ordinary personal communication, including family emergencies.',
              'Filipino, Tagalog, Bisaya and Taglish messages are common.',
              'Reply with JSON only:',
              '{"label":"BLOCK|ASSIST|ALLOW","confidence":0-1,"reason":"short"}',
            ].join(' '),
          },
          {
            role: 'user',
            content: `Message: ${JSON.stringify(body)}\n`
              + `Weak signals already detected: ${context.map((f) => f.id).join(', ') || 'none'}`,
          },
        ],
      }),
    });

    if (!response.ok) return null;

    const data = await response.json();
    const content = data?.choices?.[0]?.message?.content;
    if (!content) return null;

    const parsed = JSON.parse(content);
    const label = String(parsed.label || '').toUpperCase();
    if (!['BLOCK', 'ASSIST', 'ALLOW'].includes(label)) return null;

    return {
      label,
      confidence: Number(parsed.confidence) || 0,
      reason: String(parsed.reason || '').slice(0, 200),
    };
  } catch {
    // Fail open: an unavailable classifier must never block legitimate messages.
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Build the standard crisis-path result. Shared by the keyword and AI routes so
 * the two can never drift apart.
 *
 * @param {Finding[]} findings
 * @param {boolean} usedAi
 * @param {number} startedAt
 * @param {string} reasonCode
 * @returns {ModerationResult}
 */
function crisisResult(findings, usedAi, startedAt, reasonCode) {
  return {
    action: ACTION.ASSIST,
    score: 0,
    findings,
    isCrisis: true,
    reasonCode,
    userMessage: USER_MESSAGES.CRISIS,
    resources: [...CRISIS_RESOURCES],
    usedAi,
    durationMs: Math.round((performance.now() - startedAt) * 100) / 100,
    auditTags: ['assist', 'delivered', usedAi ? 'ai_crisis' : 'keyword_crisis'],
  };
}

/**
 * Moderate an outgoing SMS body.
 *
 * @param {string} rawBody   Untrusted message text.
 * @param {{ forceAi?: boolean }} [options]
 * @returns {Promise<ModerationResult>}
 */
export async function moderate(rawBody, options = {}) {
  const startedAt = performance.now();
  const views = buildViews(rawBody);

  /** @type {Finding[]} */
  const findings = [];
  let usedAi = false;

  const keywordResult = scanKeywords(views);
  findings.push(...keywordResult.findings);

  // ---------------------------------------------------------------------------
  // CRISIS PATH - evaluated first, and it always wins.
  // Crisis messages are delivered, never treated as violations, and never
  // consume the sender's quota.
  // ---------------------------------------------------------------------------
  if (keywordResult.isCrisis) {
    findings.push(...scanPatterns(views).findings);
    return crisisResult(findings, false, startedAt, 'crisis_support_offered');
  }

  const patternResult = scanPatterns(views);
  findings.push(...patternResult.findings);

  const hardBlock = keywordResult.hardHit;

  // Explicit escalation only. Normal requests rely on the threshold logic below.
  const preAi = options.forceAi && !hardBlock
    ? await consultAiGuard(rawBody, findings)
    : null;
  if (preAi) usedAi = true;

  if (preAi?.label === 'ASSIST' && preAi.confidence >= 0.6) {
    findings.push({
      source: 'ai',
      id: 'ai_crisis',
      label: preAi.reason || 'AI classified as crisis content',
      weight: 0,
      statute: null,
      matches: [],
    });
    return crisisResult(findings, true, startedAt, 'crisis_support_offered');
  }

  const softResult = scanSoftSignals(views.base, views.compact);
  findings.push(...softResult.findings);

  // Combined severity: the strongest deterministic layer dominates, while weak
  // signals add a bounded increment. Hard-category hits always max out.
  const deterministicScore = Math.max(keywordResult.score, patternResult.score);
  const score = hardBlock
    ? 100
    : Math.min(100, deterministicScore + softResult.score);

  const crossedThreshold = score >= config.moderation.blockThreshold;

  // ---------------------------------------------------------------------------
  // Tier 2 - consulted only when the deterministic layers are inconclusive.
  // Messages with weak signals but no clear verdict are the only ones that pay
  // the AI round-trip.
  // ---------------------------------------------------------------------------
  let aiVerdict = preAi;
  if (!aiVerdict && !crossedThreshold && !hardBlock && softResult.findings.length > 0) {
    aiVerdict = await consultAiGuard(rawBody, findings);
    if (aiVerdict) usedAi = true;
  }

  const aiBlocks = aiVerdict?.label === 'BLOCK' && aiVerdict.confidence >= 0.7;
  const shouldBlock = hardBlock || crossedThreshold || aiBlocks;

  const durationMs = Math.round((performance.now() - startedAt) * 100) / 100;

  if (shouldBlock) {
    if (aiVerdict?.label === 'BLOCK') {
      findings.push({
        source: 'ai',
        id: 'ai_block',
        label: aiVerdict.reason || 'AI classified as prohibited content',
        weight: 0,
        statute: null,
        matches: [],
      });
    }

    const isCsam = findings.some((f) => f.id === 'csam' || f.id === 'ph_csam');

    return {
      action: ACTION.BLOCK,
      score,
      findings,
      isCrisis: false,
      reasonCode: isCsam ? 'prohibited_csam' : 'prohibited_content',
      userMessage: isCsam ? USER_MESSAGES.BLOCK_CSAM : USER_MESSAGES.BLOCK_GENERIC,
      resources: isCsam
        ? []
        : [{
          id: 'aup',
          name: 'Acceptable Use Policy',
          contact: '/acceptable-use',
          hours: 'Always available',
          note: 'Review what this gateway may and may not be used for.',
        }],
      usedAi,
      durationMs,
      auditTags: [
        'block',
        ...new Set(findings.filter((f) => f.source === 'keyword').map((f) => f.id)),
      ],
      dryRun: config.moderation.dryRun,
    };
  }

  return {
    action: ACTION.ALLOW,
    score,
    findings,
    isCrisis: false,
    reasonCode: 'clean',
    userMessage: USER_MESSAGES.ALLOW,
    resources: [],
    usedAi,
    durationMs,
    auditTags: ['allow'],
  };
}

/**
 * Expose engine metadata for the health endpoint and admin panel.
 * @returns {{stats: ReturnType<typeof keywordStats>, threshold: number, dryRun: boolean, aiEnabled: boolean, detectors: number}}
 */
export function engineInfo() {
  return {
    stats: keywordStats(),
    threshold: config.moderation.blockThreshold,
    dryRun: config.moderation.dryRun,
    aiEnabled: Boolean(config.moderation.ai.endpoint),
    detectors: DETECTORS.length,
    detectorGroups: DETECTOR_GROUPS,
  };
}

export default { moderate, engineInfo, CRISIS_RESOURCES, ACTION };
