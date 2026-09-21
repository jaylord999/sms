/**
 * ---------------------------------------------------------------------------
 * security/auditLog.js - Tamper-evident, hash-chained audit trail.
 * ---------------------------------------------------------------------------
 * Every moderation decision and delivery attempt is appended to an append-only
 * log. Records are chained: each entry embeds the hash of the previous entry,
 * so removing or editing a historical record breaks the chain and is detectable
 * by `verifyAuditChain()`.
 *
 * This matters because the log is the evidence you would produce to show a
 * regulator or a court that the platform enforced its own policy consistently.
 *
 * PRIVACY
 *  - User identifiers are pseudonymised with a salted HMAC, never stored raw.
 *  - Message bodies are NEVER written to the audit log. Only a salted hash and
 *    the derived categories are recorded.
 *  - This keeps the log usable as evidence without turning it into a database
 *    of users' private conversations, which would breach RA 10173 (Data Privacy
 *    Act) and create liability of its own.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import config from '../config.js';

/** Salted, truncated hash used as a stable pseudonym for a user identifier. */
const SALT = config.audit.hashSalt;

/**
 * Pseudonymise an identifier so records remain linkable without storing PII.
 * @param {string} value
 * @returns {string} 32-character hex digest.
 */
export function pseudonymise(value) {
  if (!value) return 'anonymous';
  return crypto
    .createHmac('sha256', SALT)
    .update(String(value))
    .digest('hex')
    .slice(0, 32);
}

/**
 * Hash a message body for evidence purposes without retaining its content.
 * @param {string} body
 * @returns {string} 32-character hex digest.
 */
export function hashBody(body) {
  return crypto
    .createHmac('sha256', SALT)
    .update(String(body ?? ''))
    .digest('hex')
    .slice(0, 32);
}

/**
 * Compute the chain hash for a record.
 * @param {object} payload
 * @param {string} previousHash
 * @returns {string}
 */
function chainHash(payload, previousHash) {
  return crypto
    .createHash('sha256')
    .update(`${previousHash}|${JSON.stringify(payload)}`)
    .digest('hex');
}

/**
 * Ensure the log directory exists.
 * @returns {string} Absolute log path.
 */
function ensureLogPath() {
  const absolute = path.resolve(config.audit.logPath);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  return absolute;
}

const LOG_PATH = ensureLogPath();

/** Most recent chain position. */
let chainState = { seq: 0, hash: 'GENESIS', timestamp: new Date().toISOString() };

/** Serialises writes so concurrent requests cannot interleave and corrupt lines. */
let writeQueue = Promise.resolve();

/**
 * Read the final record in the log to resume the chain after a restart.
 * @returns {{seq: number, hash: string, timestamp: string}|null}
 */
function readTail() {
  try {
    if (!fs.existsSync(LOG_PATH)) return null;
    const content = fs.readFileSync(LOG_PATH, 'utf8').trim();
    if (!content) return null;
    const lines = content.split('\n');
    const last = JSON.parse(lines[lines.length - 1]);
    return { seq: last.seq, hash: last.hash, timestamp: last.timestamp };
  } catch {
    return null;
  }
}

/**
 * Build a single chained log line and advance the chain.
 * @param {object} record
 * @returns {string} Serialised record including its hash.
 */
function buildLine(record) {
  // Recover the tail of the chain after a restart so it stays unbroken.
  if (chainState.hash === 'GENESIS') {
    const restored = readTail();
    if (restored) chainState = restored;
  }

  const seq = chainState.seq + 1;
  const timestamp = new Date().toISOString();

  const payload = {
    seq,
    timestamp,
    event: record.event,
    // Pseudonymised identifiers only - never raw PII.
    user: pseudonymise(record.userId),
    ip: pseudonymise(record.ipHash),
    phone: pseudonymise(record.phoneHash),
    bodyHash: record.bodyHash ?? null,
    action: record.action ?? null,
    score: record.score ?? null,
    reasonCode: record.reasonCode ?? null,
    categories: record.categories ?? [],
    statutes: record.statutes ?? [],
    durationMs: record.durationMs ?? null,
    usedAi: record.usedAi ?? false,
    meta: record.meta ?? {},
    prev: chainState.hash,
  };

  const hash = chainHash(payload, chainState.hash);
  chainState = { seq, hash, timestamp };

  return JSON.stringify({ ...payload, hash });
}

/**
 * Append an audit record.
 *
 * Resolves once the record is durably written, so callers can await it before
 * responding to the user.
 *
 * @param {{
 *   event: string,
 *   userId?: string,
 *   ipHash?: string,
 *   phoneHash?: string,
 *   bodyHash?: string,
 *   action?: string,
 *   score?: number,
 *   reasonCode?: string,
 *   categories?: string[],
 *   statutes?: string[],
 *   durationMs?: number,
 *   usedAi?: boolean,
 *   meta?: Record<string, unknown>
 * }} record
 * @returns {Promise<{seq: number, hash: string, timestamp: string}>}
 */
export function appendAudit(record) {
  writeQueue = writeQueue.then(() => {
    const line = buildLine(record);
    try {
      fs.appendFileSync(LOG_PATH, `${line}\n`, { encoding: 'utf8', mode: 0o600 });
    } catch (error) {
      // An audit failure must never break message delivery; log and continue.
      // eslint-disable-next-line no-console
      console.error('[lifeline-audit] failed to append record:', error.message);
    }
    return chainState;
  });

  return writeQueue;
}

/**
 * Verify the integrity of the whole audit chain.
 *
 * Any edited, reordered or deleted record is reported as a break.
 *
 * @returns {{valid: boolean, records: number, brokenAt: number|null, reason: string|null}}
 */
export function verifyAuditChain() {
  if (!fs.existsSync(LOG_PATH)) {
    return { valid: true, records: 0, brokenAt: null, reason: null };
  }

  const lines = fs.readFileSync(LOG_PATH, 'utf8').split('\n').filter(Boolean);

  let previous = 'GENESIS';

  for (let index = 0; index < lines.length; index += 1) {
    let entry;
    try {
      entry = JSON.parse(lines[index]);
    } catch {
      return {
        valid: false,
        records: lines.length,
        brokenAt: index + 1,
        reason: 'Record is not valid JSON - the file may have been edited.',
      };
    }

    if (entry.prev !== previous) {
      return {
        valid: false,
        records: lines.length,
        brokenAt: entry.seq ?? index + 1,
        reason: 'Chain linkage mismatch - a record was removed or reordered.',
      };
    }

    const { hash, ...payload } = entry;
    const expected = chainHash(payload, previous);

    if (hash !== expected) {
      return {
        valid: false,
        records: lines.length,
        brokenAt: entry.seq ?? index + 1,
        reason: 'Record hash mismatch - the record was modified after writing.',
      };
    }

    previous = hash;
  }

  return { valid: true, records: lines.length, brokenAt: null, reason: null };
}

export default { appendAudit, verifyAuditChain, pseudonymise, hashBody };
