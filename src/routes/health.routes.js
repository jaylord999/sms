/**
 * ---------------------------------------------------------------------------
 * routes/health.routes.js - Liveness, readiness and engine introspection.
 * ---------------------------------------------------------------------------
 * These endpoints are intentionally public: an uptime monitor must be able to
 * reach them without credentials. They therefore expose operational metadata
 * only - never keys, tokens, user data or the blocklist itself.
 */

import { Router } from 'express';
import config from '../config.js';
import { engineInfo } from '../moderation/engine.js';
import { providerInfo } from '../services/smsProvider.js';
import { verifyAuditChain } from '../security/auditLog.js';
import { sessionStats } from '../security/auth.js';
import { quotaStats } from '../services/quota.js';
import { healthLimiter } from '../security/rateLimiters.js';

const router = Router();

/**
 * GET /api/health
 * Cheap liveness probe. Confirms the process is up and configuration loaded.
 * Deliberately does no I/O so it cannot time out under load.
 */
router.get('/', healthLimiter, (req, res) => {
  res.json({
    ok: true,
    status: 'healthy',
    service: 'lifelinesms-gateway',
    version: '2.0.0',
    environment: config.env,
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /api/health/ready
 * Readiness probe. Reports whether the subsystems a send depends on are usable.
 * Returns 503 when a hard dependency is unavailable, so a load balancer can
 * take this instance out of rotation instead of serving failing requests.
 */
router.get('/ready', healthLimiter, (req, res) => {
  const provider = providerInfo();
  const moderation = engineInfo();

  const checks = {
    moderationEngine: { ok: moderation.stats.terms > 0, terms: moderation.stats.terms },
    smsProvider: { ok: provider.configured, provider: provider.provider },
    auditChain: (() => {
      const result = verifyAuditChain();
      return { ok: result.valid, records: result.records };
    })(),
  };

  const ready = Object.values(checks).every((check) => check.ok);

  res.status(ready ? 200 : 503).json({
    ok: ready,
    status: ready ? 'ready' : 'degraded',
    checks,
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /api/health/engine
 * Reports moderation engine configuration. This is what makes the system
 * auditable: an operator can confirm which layers are active and how many
 * rules are loaded, without exposing the rules themselves.
 */
router.get('/engine', healthLimiter, (req, res) => {
  const info = engineInfo();

  res.json({
    ok: true,
    moderation: {
      categories: info.stats.categories,
      terms: info.stats.terms,
      detectors: info.detectors,
      detectorGroups: Object.keys(info.detectorGroups),
      hardBlockCategories: info.stats.hardCategories,
      crisisAssistCategories: info.stats.assistCategories,
      softSignals: info.stats.softSignals,
      blockThreshold: info.threshold,
      dryRun: info.dryRun,
      aiLayerEnabled: info.aiEnabled,
    },
    provider: providerInfo(),
    sessions: sessionStats(),
    quota: quotaStats(),
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /api/health/audit
 * Verifies the integrity of the audit chain.
 *
 * In production this is deliberately vague to unauthenticated callers: it
 * reports only whether the chain is intact, not where it broke or how many
 * records exist. That detail would itself be useful to an attacker probing for
 * gaps in the evidence trail.
 */
router.get('/audit', healthLimiter, (req, res) => {
  const result = verifyAuditChain();

  if (config.isProduction) {
    res.json({ ok: result.valid, chainIntact: result.valid });
    return;
  }

  res.json({
    ok: result.valid,
    chainIntact: result.valid,
    records: result.records,
    brokenAt: result.brokenAt,
    reason: result.reason,
    timestamp: new Date().toISOString(),
  });
});

export default router;
