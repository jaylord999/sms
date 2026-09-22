/**
 * ---------------------------------------------------------------------------
 * routes/sms.routes.js - Message moderation, preview and delivery.
 * ---------------------------------------------------------------------------
 * THE CENTRAL RULE: a message is only delivered when the moderation engine
 * returns ALLOW or ASSIST. ASSIST is treated as deliverable because crisis
 * content must reach the recipient by design - see the policy note in
 * moderation/keywords.js.
 *
 * ENDPOINT ORDER OF OPERATIONS (send)
 *   1. Origin + CSRF verification      - is this request from our own page?
 *   2. Authentication                  - is there a valid session?
 *   3. Account age check               - slow throwaway-account abuse
 *   4. Input validation                - shape, length, phone prefix
 *   5. Moderation                      - the safety gate
 *   6. Quota handling                  - crisis sends bypass quota entirely
 *   7. Delivery via provider adapter
 *   8. Audit record                    - written regardless of outcome
 *
 * Every step that can fail writes an audit record before responding, so the
 * log is a complete account of what the system did and why.
 */

import { Router } from 'express';
import config from '../config.js';
import { moderate } from '../moderation/engine.js';
import { explainDecision } from '../moderation/explain.js';
import { ACTION } from '../moderation/keywords.js';
import { verifyOrigin, verifyCsrfToken } from '../security/csrf.js';
import { sendLimiter, moderateLimiter } from '../security/rateLimiters.js';
import { validatePhone, validateMessageBody } from '../security/validate.js';
import { getSession, accountAgeSeconds } from '../security/auth.js';
import { appendAudit, hashBody } from '../security/auditLog.js';
import {
  checkQuota,
  consumeCredit,
  refundCredit,
  recordCrisisDelivery,
  recordBlock,
  isUnderReview,
} from '../services/quota.js';
import { deliver, composeOutbound, providerInfo } from '../services/smsProvider.js';
import { clientIp, hashIp } from '../utils/ip.js';

const router = Router();

/**
 * Resolve the authenticated session, or respond with 401.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @returns {import('../security/auth.js').Session|null}
 */
function requireSession(req, res) {
  const session = getSession(req.cookies?.[config.session.cookieName]);

  if (!session) {
    res.status(401).json({
      ok: false,
      error: 'Sign in with Google to send a message.',
      code: 'AUTH_REQUIRED',
    });
    return null;
  }

  return session;
}

/**
 * Reduce engine findings to the fields that are safe and useful to surface.
 *
 * NOTE: the specific matched terms are deliberately NOT returned. Returning
 * them would turn the preview endpoint into a blocklist oracle, letting a
 * determined user binary-search exactly which words to avoid.
 *
 * @param {import('../moderation/engine.js').ModerationResult} result
 * @returns {Array<{category: string, label: string, statute: string|null}>}
 */
function publicFindings(result) {
  const seen = new Set();
  const output = [];

  for (const finding of result.findings) {
    // Skip internal bookkeeping signals; they are not user-actionable.
    if (finding.id.startsWith('soft_') || finding.id.startsWith('ai_')) continue;
    if (seen.has(finding.id)) continue;
    seen.add(finding.id);

    output.push({
      category: finding.id,
      label: finding.label,
      statute: finding.statute,
    });
  }

  return output;
}

/**
 * GET /api/sms/limits
 * Report the current user's quota and provider capability.
 */
router.get('/limits', (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;

  res.json({
    ok: true,
    quota: checkQuota(session.userId),
    review: isUnderReview(session.userId),
    provider: providerInfo(),
    maxBodyLength: config.sms.maxBodyLength,
  });
});

/**
 * POST /api/sms/preview
 * Run moderation WITHOUT sending anything.
 *
 * This powers the live feedback in the composer. It is rate limited more
 * tightly than sending because it is CPU-bound (the regex layer runs on every
 * call) and because it is the endpoint an attacker would use to map the
 * blocklist.
 */
router.post('/preview', verifyOrigin, verifyCsrfToken, moderateLimiter, async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;

  const bodyCheck = validateMessageBody(req.body?.body, config.sms.maxBodyLength);
  if (!bodyCheck.ok) {
    res.status(400).json({ ok: false, error: bodyCheck.error, code: bodyCheck.code });
    return;
  }

  const result = await moderate(bodyCheck.value.text);

  res.json({
    ok: true,
    action: result.action,
    // `deliverable` is the single flag the client needs to enable the send
    // button. Both ALLOW and ASSIST are deliverable.
    deliverable: result.action !== ACTION.BLOCK,
    isCrisis: result.isCrisis,
    score: result.score,
    findings: publicFindings(result),
    // Crisis resources are returned here so the composer can surface support
    // before the user even presses send.
    resources: result.isCrisis ? result.resources : [],
    message: result.userMessage,
    durationMs: result.durationMs,
    // Human-readable explanation with redacted excerpts, so the user can see
    // roughly what tripped the filter without learning a working bypass.
    explanation: result.action === ACTION.BLOCK
      ? explainDecision(result, bodyCheck.value.text)
      : null,
  });
});

/**
 * Mask a phone number for display and logging.
 * Shows enough to confirm the right recipient was selected without putting the
 * full number on screen, which matters when someone is composing in public.
 *
 * @param {string} e164
 * @returns {string}
 */
function maskPhone(e164) {
  const digits = e164.replace(/\D/g, '');
  if (digits.length < 7) return '\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
  return `+${digits.slice(0, 4)}\u2022\u2022\u2022${digits.slice(-4)}`;
}


/**
 * POST /api/sms/send
 * Moderate and deliver a message.
 */
router.post('/send', verifyOrigin, verifyCsrfToken, sendLimiter, async (req, res) => {
  const ipHash = hashIp(clientIp(req));

  const session = requireSession(req, res);
  if (!session) return;

  const userId = session.userId;

  // --- Step 3: account age -------------------------------------------------
  // A queue of freshly created Google accounts is the cheapest way to farm
  // quota. Requiring a short minimum account age raises the cost of that attack
  // without inconveniencing a genuine user, who will not be sending an
  // emergency SMS within the first minute of setting the app up anyway.
  const ageSeconds = accountAgeSeconds(session);
  if (ageSeconds < config.limits.minAccountAgeSeconds) {
    const wait = config.limits.minAccountAgeSeconds - ageSeconds;

    await appendAudit({
      event: 'send_rejected',
      userId,
      ipHash,
      reasonCode: 'account_too_new',
      meta: { ageSeconds, waitSeconds: wait },
    });

    res.status(403).json({
      ok: false,
      error: `Your account is still being verified. Try again in ${wait} second${wait === 1 ? '' : 's'}.`,
      code: 'ACCOUNT_TOO_NEW',
      retryAfterSeconds: wait,
    });
    return;
  }

  // --- Step 4: input validation -------------------------------------------
  const phoneCheck = validatePhone(req.body?.phone);
  if (!phoneCheck.ok) {
    await appendAudit({ event: 'send_rejected', userId, ipHash, reasonCode: phoneCheck.code });
    res.status(400).json({ ok: false, error: phoneCheck.error, code: phoneCheck.code });
    return;
  }

  const bodyCheck = validateMessageBody(req.body?.body, config.sms.maxBodyLength);
  if (!bodyCheck.ok) {
    await appendAudit({ event: 'send_rejected', userId, ipHash, reasonCode: bodyCheck.code });
    res.status(400).json({ ok: false, error: bodyCheck.error, code: bodyCheck.code });
    return;
  }

  // --- Step 5: moderation --------------------------------------------------
  const moderation = await moderate(bodyCheck.value.text);

  // phoneCheck.value is { national, e164, carrier }.
  const phone = phoneCheck.value;

  const categories = [...new Set(moderation.findings.map((f) => f.id))];
  const statutes = [...new Set(moderation.findings.map((f) => f.statute).filter(Boolean))];

  // -------------------------------------------------------------------------
  // BLOCKED
  // -------------------------------------------------------------------------
  if (moderation.action === ACTION.BLOCK) {
    const blockCount = recordBlock(userId);

    await appendAudit({
      event: 'message_blocked',
      userId,
      ipHash,
      phoneHash: phone.e164,
      bodyHash: hashBody(bodyCheck.value.text),
      action: 'block',
      score: moderation.score,
      reasonCode: moderation.reasonCode,
      categories,
      statutes,
      durationMs: moderation.durationMs,
      usedAi: moderation.usedAi,
      meta: { blockCount, dryRun: Boolean(moderation.dryRun) },
    });

    // DRY RUN still refuses delivery. It exists to tune thresholds without
    // changing what users experience, never to let prohibited content through.
    res.status(422).json({
      ok: false,
      error: moderation.userMessage,
      code: moderation.reasonCode,
      action: ACTION.BLOCK,
      // Category labels are returned so the user understands why, but the
      // matched terms are never echoed back.
      findings: publicFindings(moderation),
      // Actionable explanation: reason, redacted excerpts, and next steps.
      explanation: explainDecision(moderation, bodyCheck.value.text),
      review: isUnderReview(userId),
    });
    return;
  }

  // -------------------------------------------------------------------------
  // CRISIS PATH
  // The message IS DELIVERED. It does not consume a credit, is not recorded as
  // abuse, and the response carries support resources.
  // -------------------------------------------------------------------------
  if (moderation.isCrisis) {
    const composed = composeOutbound(bodyCheck.value.text, config.sms.maxBodyLength);
    const delivery = await deliver({
      to: phone.e164,
      body: composed,
      reference: `crisis_${Date.now().toString(36)}`,
    });

    const crisisTotal = recordCrisisDelivery(userId);

    await appendAudit({
      event: 'crisis_message_delivered',
      userId,
      ipHash,
      phoneHash: phone.e164,
      bodyHash: hashBody(bodyCheck.value.text),
      action: 'assist',
      score: 0,
      reasonCode: 'crisis_support_offered',
      categories: ['self_harm_crisis'],
      statutes,
      durationMs: delivery.durationMs,
      usedAi: moderation.usedAi,
      meta: {
        delivered: delivery.ok,
        provider: delivery.providerId,
        // Evidence that support was OFFERED, not merely that a message moved.
        resourcesOffered: moderation.resources.map((resource) => resource.id),
        crisisTotal,
      },
    });

    res.json({
      ok: true,
      action: ACTION.ASSIST,
      isCrisis: true,
      message: moderation.userMessage,
      resources: moderation.resources,
      delivery: {
        status: delivery.status,
        messageId: delivery.messageId,
        provider: delivery.providerId,
      },
      recipient: { masked: maskPhone(phone.e164), carrier: phone.carrier },
      // Crisis sends never touch the quota, so this number is unchanged.
      quota: checkQuota(userId),
      support: {
        offerTrustedContact: true,
        note: 'If you are in immediate danger, call 911.',
      },
    });
    return;
  }

  // -------------------------------------------------------------------------
  // NORMAL DELIVERY
  // -------------------------------------------------------------------------
  const quotaBefore = checkQuota(userId);
  if (quotaBefore.remaining <= 0) {
    await appendAudit({
      event: 'send_rejected',
      userId,
      ipHash,
      reasonCode: 'quota_exhausted',
      meta: { resetsAt: quotaBefore.resetsAt },
    });

    res.status(429).json({
      ok: false,
      error: 'Your free message allowance for today is used up.',
      code: 'QUOTA_EXHAUSTED',
      quota: quotaBefore,
    });
    return;
  }

  const credit = consumeCredit(userId);
  if (!credit.granted) {
    res.status(429).json({
      ok: false,
      error: 'Your free message allowance for today is used up.',
      code: 'QUOTA_EXHAUSTED',
      quota: quotaBefore,
    });
    return;
  }

  const composed = composeOutbound(bodyCheck.value.text, config.sms.maxBodyLength);
  const delivery = await deliver({
    to: phone.e164,
    body: composed,
    reference: `msg_${Date.now().toString(36)}`,
  });

  if (!delivery.ok) {
    // Hand the credit back: a provider outage is not the user's fault.
    refundCredit(userId);

    await appendAudit({
      event: 'delivery_failed',
      userId,
      ipHash,
      phoneHash: phone.e164,
      bodyHash: hashBody(bodyCheck.value.text),
      action: 'allow',
      reasonCode: delivery.code ?? 'PROVIDER_ERROR',
      categories,
      statutes,
      durationMs: delivery.durationMs,
      meta: { provider: delivery.providerId },
    });

    res.status(502).json({
      ok: false,
      error: delivery.error ?? 'The SMS gateway could not deliver this message.',
      code: delivery.code ?? 'PROVIDER_ERROR',
      quota: checkQuota(userId),
    });
    return;
  }

  await appendAudit({
    event: 'message_delivered',
    userId,
    ipHash,
    phoneHash: phone.e164,
    bodyHash: hashBody(bodyCheck.value.text),
    action: 'allow',
    score: moderation.score,
    reasonCode: 'clean',
    categories,
    statutes,
    durationMs: delivery.durationMs,
    usedAi: moderation.usedAi,
    meta: { provider: delivery.providerId, carrier: phone.carrier },
  });

  res.json({
    ok: true,
    action: ACTION.ALLOW,
    isCrisis: false,
    message: 'Message sent.',
    delivery: {
      status: delivery.status,
      messageId: delivery.messageId,
      provider: delivery.providerId,
    },
    recipient: { masked: maskPhone(phone.e164), carrier: phone.carrier },
    quota: checkQuota(userId),
  });
});

/**
 * POST /api/sms/report
 * Report a message that was received and appears abusive.
 *
 * This closes the loop: users can flag harmful content sent to them, and the
 * reports feed the abuse-review queue. Without a reporting path, the platform
 * has no way to learn about abuse it did not itself see.
 */
router.post('/report', verifyOrigin, verifyCsrfToken, sendLimiter, async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;

  const reason = String(req.body?.reason ?? '').slice(0, 200);
  const reportedBody = String(req.body?.body ?? '').slice(0, config.sms.maxBodyLength);
  const senderNumber = String(req.body?.sender ?? '').slice(0, 24);

  await appendAudit({
    event: 'abuse_reported',
    userId: session.userId,
    ipHash: hashIp(clientIp(req)),
    phoneHash: senderNumber || undefined,
    bodyHash: reportedBody ? hashBody(reportedBody) : undefined,
    action: 'report',
    reasonCode: 'user_report',
    meta: { reason },
  });

  res.json({
    ok: true,
    message: 'Thank you. Your report has been recorded for review.',
  });
});

export default router;
