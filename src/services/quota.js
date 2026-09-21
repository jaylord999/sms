/**
 * ---------------------------------------------------------------------------
 * services/quota.js - Per-user message quota enforcement.
 * ---------------------------------------------------------------------------
 * Two concepts, deliberately kept separate:
 *
 *   CREDITS - how many messages a user may send in a rolling 24-hour window.
 *             Consumed on successful delivery only.
 *
 *   CRISIS DELIVERIES - crisis-path messages. These are tracked for reporting
 *             but NEVER counted against the quota, and never blocked by it. A
 *             person in distress must not be stopped by a rate limit.
 *
 * The quota exists to bound cost and deter bulk abuse, not to ration help.
 */

import config from '../config.js';

/** Rolling window length in milliseconds. */
const WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * @typedef {Object} QuotaRecord
 * @property {number[]} deliveredAt  Timestamps of consumed credits.
 * @property {number} crisisCount    Crisis-path sends (informational only).
 * @property {number} blockedCount   Blocked attempts, for abuse detection.
 * @property {number} lastBlockedAt
 */

/** @type {Map<string, QuotaRecord>} */
const quotas = new Map();

/**
 * Get or create a quota record.
 * @param {string} userId
 * @returns {QuotaRecord}
 */
function getRecord(userId) {
  let record = quotas.get(userId);
  if (!record) {
    record = { deliveredAt: [], crisisCount: 0, blockedCount: 0, lastBlockedAt: 0 };
    quotas.set(userId, record);
  }
  return record;
}

/**
 * Drop timestamps that have fallen outside the rolling window.
 * @param {QuotaRecord} record
 * @param {number} now
 */
function pruneWindow(record, now) {
  const cutoff = now - WINDOW_MS;
  record.deliveredAt = record.deliveredAt.filter((timestamp) => timestamp > cutoff);
}

/**
 * Inspect the remaining quota without consuming anything.
 * @param {string} userId
 * @returns {{limit: number, used: number, remaining: number, resetsAt: number, crisisCount: number}}
 */
export function checkQuota(userId) {
  const now = Date.now();
  const record = getRecord(userId);
  pruneWindow(record, now);

  const used = record.deliveredAt.length;
  const oldest = record.deliveredAt[0];

  return {
    limit: config.limits.freeMessagesPerDay,
    used,
    remaining: Math.max(0, config.limits.freeMessagesPerDay - used),
    // When the oldest credit expires, one slot opens up.
    resetsAt: oldest ? oldest + WINDOW_MS : now,
    crisisCount: record.crisisCount,
  };
}

/**
 * Consume one credit.
 * @param {string} userId
 * @returns {{granted: boolean, remaining: number, resetsAt: number}}
 */
export function consumeCredit(userId) {
  const now = Date.now();
  const record = getRecord(userId);
  pruneWindow(record, now);

  if (record.deliveredAt.length >= config.limits.freeMessagesPerDay) {
    const oldest = record.deliveredAt[0];
    return { granted: false, remaining: 0, resetsAt: oldest + WINDOW_MS };
  }

  record.deliveredAt.push(now);

  return {
    granted: true,
    remaining: Math.max(0, config.limits.freeMessagesPerDay - record.deliveredAt.length),
    resetsAt: now + WINDOW_MS,
  };
}

/**
 * Refund a credit when delivery fails after it was consumed, so a provider
 * outage does not silently eat a user's daily allowance.
 * @param {string} userId
 */
export function refundCredit(userId) {
  const record = quotas.get(userId);
  if (!record || record.deliveredAt.length === 0) return;
  record.deliveredAt.pop();
}

/**
 * Record a crisis-path delivery. Never consumes a credit.
 * @param {string} userId
 * @returns {number} Cumulative crisis deliveries for this user.
 */
export function recordCrisisDelivery(userId) {
  const record = getRecord(userId);
  record.crisisCount += 1;
  return record.crisisCount;
}

/**
 * Record a blocked attempt. Repeated blocks are a strong signal of deliberate
 * abuse and are surfaced to operators.
 * @param {string} userId
 * @returns {number} Cumulative blocked attempts.
 */
export function recordBlock(userId) {
  const record = getRecord(userId);
  record.blockedCount += 1;
  record.lastBlockedAt = Date.now();
  return record.blockedCount;
}

/**
 * Whether a user has accumulated enough blocks to warrant review.
 * @param {string} userId
 * @returns {{flagged: boolean, blockedCount: number}}
 */
export function isUnderReview(userId) {
  const record = getRecord(userId);
  return { flagged: record.blockedCount >= 5, blockedCount: record.blockedCount };
}

/**
 * Aggregate statistics for the health endpoint.
 * @returns {{trackedUsers: number, messagesToday: number, crisisToday: number, blockedToday: number}}
 */
export function quotaStats() {
  const now = Date.now();
  let messagesToday = 0;
  let crisisToday = 0;
  let blockedToday = 0;

  for (const record of quotas.values()) {
    pruneWindow(record, now);
    messagesToday += record.deliveredAt.length;
    crisisToday += record.crisisCount;
    blockedToday += record.blockedCount;
  }

  return { trackedUsers: quotas.size, messagesToday, crisisToday, blockedToday };
}

export default {
  checkQuota,
  consumeCredit,
  refundCredit,
  recordCrisisDelivery,
  recordBlock,
  isUnderReview,
  quotaStats,
};
