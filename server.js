/**
 * ---------------------------------------------------------------------------
 * server.js - Process entry point.
 * ---------------------------------------------------------------------------
 * Responsibilities, in order:
 *   1. Start the HTTP server.
 *   2. Print a startup banner that makes the active safety posture visible.
 *   3. Handle graceful shutdown so in-flight writes (especially audit records)
 *      complete before the process exits.
 *   4. Fail loudly on startup errors rather than serving a broken instance.
 */

import http from 'node:http';
import config from './src/config.js';
import { createApp } from './src/app.js';
import { engineInfo } from './src/moderation/engine.js';
import { providerInfo } from './src/services/smsProvider.js';
import { verifyAuditChain, appendAudit } from './src/security/auditLog.js';

const app = createApp();
const server = http.createServer(app);

/**
 * Print the active configuration so an operator can confirm at a glance that
 * the safety systems are on and no secret has been left at its default.
 */
function printBanner() {
  const engine = engineInfo();
  const provider = providerInfo();
  const audit = verifyAuditChain();
  const onOff = (value) => (value ? 'ON ' : 'OFF');

  const lines = [
    '',
    '  ==========================================================================',
    '   LifelineSMS Gateway  v2.0.0',
    '  ==========================================================================',
    `   Environment            : ${config.env}`,
    `   Listening              : ${config.appOrigin}`,
    '',
    '   CONTENT MODERATION',
    `     Prohibited categories: ${engine.stats.categories - engine.stats.assistCategories}`,
    `     Crisis-support cats  : ${engine.stats.assistCategories}  (never blocked)`,
    `     Blocklist terms      : ${engine.stats.terms}`,
    `     Pattern detectors    : ${engine.detectors}`,
    `     Weak signals         : ${engine.stats.softSignals}`,
    `     Block threshold      : ${engine.threshold} / 100`,
    `     AI second opinion    : ${onOff(engine.aiEnabled)}`,
    `     Dry run              : ${onOff(engine.dryRun)}`,
    '',
    '   SECURITY',
    `     Google sign-in       : ${onOff(Boolean(config.google.clientId))}`,
    '     CSP + security hdrs  : ON',
    '     CSRF double-submit   : ON',
    `     Session TTL          : ${Math.round(config.session.ttlMs / 60000)} minutes`,
    '     Rate limiting        : ON',
    `     Audit chain          : ${audit.valid ? 'INTACT' : 'BROKEN'} (${audit.records} records)`,
    '     Message bodies stored: NO  (salted hashes only)',
    '',
    '   DELIVERY',
    `     Provider             : ${provider.provider}${provider.configured ? '' : '  *** NOT CONFIGURED ***'}`,
    `     Max body length      : ${provider.maxBodyLength} characters`,
    `     Free messages / day  : ${config.limits.freeMessagesPerDay}`,
    `     Min account age      : ${config.limits.minAccountAgeSeconds}s`,
    '',
    '  ==========================================================================',
  ];

  if (!config.isProduction) {
    lines.push('   DEVELOPMENT MODE. Set NODE_ENV=production before deploying.');
  }
  if (config.sms.provider === 'mock') {
    lines.push('   MOCK PROVIDER ACTIVE. No real SMS is being sent.');
  }
  if (!config.google.clientId) {
    lines.push('   GOOGLE_CLIENT_ID unset. Sign-in will report as unavailable.');
  }
  lines.push('  ==========================================================================');
  lines.push('');

  // eslint-disable-next-line no-console
  console.log(lines.join('\n'));
}

server.listen(config.port, () => {
  printBanner();
  // eslint-disable-next-line no-console
  console.log(`  Ready. Open ${config.appOrigin}\n`);
});

/**
 * Graceful shutdown.
 *
 * The audit log is written synchronously, so the main risk is an in-flight
 * delivery. We stop accepting new connections, let existing ones finish, and
 * force exit if they do not complete within a bounded window.
 */
let shuttingDown = false;

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;

  // eslint-disable-next-line no-console
  console.log(`\n[lifeline] ${signal} received. Shutting down gracefully...`);

  const forceExit = setTimeout(() => {
    // eslint-disable-next-line no-console
    console.error('[lifeline] Forced exit after 10s; some requests did not drain.');
    process.exit(1);
  }, 10_000);
  forceExit.unref();

  server.close(async () => {
    try {
      await appendAudit({
        event: 'server_shutdown',
        reasonCode: signal,
        meta: { uptimeSeconds: Math.round(process.uptime()) },
      });
      // eslint-disable-next-line no-console
      console.log('[lifeline] Shutdown complete.');
    } catch {
      // Nothing more can be done; the process is ending regardless.
    }
    clearTimeout(forceExit);
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

/**
 * Last-resort handlers.
 *
 * An unhandled rejection leaves the process in an undefined state. On a service
 * that makes moderation decisions, serving requests from a process we no longer
 * trust is worse than stopping, so we record the event and exit.
 */
process.on('unhandledRejection', async (reason) => {
  // eslint-disable-next-line no-console
  console.error('[lifeline] Unhandled promise rejection:', reason);
  await appendAudit({
    event: 'unhandled_rejection',
    meta: { message: String(reason).slice(0, 300) },
  }).catch(() => {});
  process.exit(1);
});

process.on('uncaughtException', async (error) => {
  // eslint-disable-next-line no-console
  console.error('[lifeline] Uncaught exception:', error);
  await appendAudit({
    event: 'uncaught_exception',
    meta: { message: String(error.message).slice(0, 300) },
  }).catch(() => {});
  process.exit(1);
});

export default server;
