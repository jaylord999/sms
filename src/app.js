/**
 * ---------------------------------------------------------------------------
 * app.js - Express application factory.
 * ---------------------------------------------------------------------------
 * Middleware order matters a great deal here. The sequence is:
 *
 *   1. Security headers      - applied before anything can respond
 *   2. Body parsing          - strict size caps, so parsing cannot be abused
 *   3. Cookie parsing        - needed by CSRF and session lookup
 *   4. Rate limiting         - cheap rejection before expensive work
 *   5. CSRF token issuance   - every response can carry a token
 *   6. Static assets         - served without further processing
 *   7. Routes                - origin + CSRF checks applied per mutating route
 *   8. 404 and error handler - last, and never leaks internals
 */

import express from 'express';
import cookieParser from 'cookie-parser';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import config from './config.js';
import { buildHelmet, extraSecurityHeaders } from './security/helmet.config.js';
import { globalLimiter } from './security/rateLimiters.js';
import { issueCsrfToken } from './security/csrf.js';
import { appendAudit } from './security/auditLog.js';

import authRoutes from './routes/auth.routes.js';
import smsRoutes from './routes/sms.routes.js';
import healthRoutes from './routes/health.routes.js';
import policyRoutes from './routes/policy.routes.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Build the configured Express application.
 * @returns {import('express').Express}
 */
export function createApp() {
  const app = express();

  // Do not advertise the framework.
  app.disable('x-powered-by');
  // Trust the first proxy so rate limiting keys on the real client IP when
  // deployed behind a load balancer or reverse proxy.
  app.set('trust proxy', 1);

  // --- 1. Security headers -------------------------------------------------
  app.use(buildHelmet());
  app.use(extraSecurityHeaders);

  // --- 2. Body parsing with strict caps ------------------------------------
  // The limit is deliberately tight: an SMS is at most a few hundred bytes, so
  // anything larger is either a bug or an attack.
  app.use(express.json({ limit: '8kb', strict: true }));
  app.use(express.urlencoded({ extended: false, limit: '8kb' }));

  // --- 3. Cookies ----------------------------------------------------------
  app.use(cookieParser());

  // --- 4. Global rate limiting --------------------------------------------
  app.use('/api', globalLimiter);

  // --- 5. CSRF token issuance ---------------------------------------------
  app.use(issueCsrfToken);

  // --- 6. Static assets ----------------------------------------------------
  app.use(express.static(path.join(__dirname, '..', 'public'), {
    // Do not serve dotfiles, and never allow directory listings.
    dotfiles: 'deny',
    index: 'index.html',
    etag: true,
    lastModified: true,
    setHeaders(res, filePath) {
      // HTML must never be cached, so a security fix reaches users immediately.
      if (filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-store, must-revalidate');
      }
      // Serve JS as modules with the correct type.
      if (filePath.endsWith('.js')) {
        res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
      }
    },
  }));

  // --- 7. Routes -----------------------------------------------------------
  app.use('/api/health', healthRoutes);
  app.use('/api/auth', authRoutes);
  app.use('/api/sms', smsRoutes);
  app.use('/api/policy', policyRoutes);

  // --- 8. 404 --------------------------------------------------------------
  app.use('/api', (req, res) => {
    res.status(404).json({
      ok: false,
      error: 'Endpoint not found.',
      code: 'NOT_FOUND',
    });
  });

  // Any non-API path falls back to the single page application shell.
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
  });

  // --- 9. Central error handler -------------------------------------------
  // Express identifies error handlers by arity, so all four parameters are
  // required even though `next` is unused.
  // eslint-disable-next-line no-unused-vars
  app.use(async (error, req, res, next) => {
    // Log the real cause internally, but never return it to the client:
    // stack traces and driver messages disclose internal structure.
    // eslint-disable-next-line no-console
    console.error('[lifeline-error]', error);

    await appendAudit({
      event: 'server_error',
      meta: { path: req.path, method: req.method, message: String(error.message).slice(0, 200) },
    }).catch(() => {});

    if (res.headersSent) return;

    // A malformed JSON body is a client error, not a server fault.
    if (error.type === 'entity.parse.failed') {
      res.status(400).json({
        ok: false,
        error: 'Malformed request body.',
        code: 'BAD_JSON',
      });
      return;
    }

    if (error.type === 'entity.too.large') {
      res.status(413).json({
        ok: false,
        error: 'Request body is too large.',
        code: 'PAYLOAD_TOO_LARGE',
      });
      return;
    }

    res.status(500).json({
      ok: false,
      error: 'Something went wrong on our side. Please try again.',
      code: 'INTERNAL_ERROR',
    });
  });

  return app;
}

export default createApp;
