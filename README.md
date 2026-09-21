# LifelineSMS Gateway

A zero-load emergency SMS gateway for the Philippines, with **server-side
multi-layer content moderation**, **verified Google identity**, and a hard
separation between *enforcement* and *duty of care*.

> **Status:** demonstration deployment. The default provider is a simulator, so
> no real SMS is transmitted. Configure a real provider before going live.

---

## The one design decision that matters most

Most content filters have two outcomes: allow or block. This one has **three**.

| Outcome | Applies to | Behaviour |
| --- | --- | --- |
| `ALLOW` | Ordinary messages | Delivered normally |
| `BLOCK` | Actual crimes - drugs, kidnapping, CSAM, trafficking, weapons, terrorism, fraud, scams, bulk abuse | Refused, recorded, account flagged |
| `ASSIST` | **Suicidal ideation and self-harm** | **The message IS delivered.** Support resources are shown. No quota consumed. Never recorded as a violation. |

### Why crisis content is never blocked

Blocking *"gusto ko na mamatay"* is not a safety feature. It is a duty-of-care
failure that creates the exact liability it claims to prevent:

1. If a distressed person is refused service and is then harmed, the operator
   carries real civil and moral liability - and the refusal is on the record.
2. The product promise is *"reach family in an emergency."* For someone in
   crisis, the outgoing message **is** the emergency.
3. RA 11036 (Philippine Mental Health Act) frames the obligation as providing
   access to care, not as censorship.
4. A blocked *"I want to die"* teaches the user the system will not help them,
   and they will not try again.

So the crisis path delivers the message, surfaces free 24/7 hotlines, and offers
an opt-in alert to a trusted contact. The event is logged as
`crisis_support_offered` - evidence that help was given, not that a rule broke.

This is enforced in code, not just in policy: `keywords.js` marks the category
`assistOnly: true`, and `engine.js` evaluates the crisis path **first**, before
any scoring can block it. A test asserts it stays that way.

---

## Stack

| Layer | Choice | Why |
| --- | --- | --- |
| Runtime | Node.js 20+ | Native `fetch`, `node:test`, ESM |
| Server | Express 4 | Stable, well-understood middleware model |
| Security headers | Helmet | CSP as an HTTP header, which injected markup cannot strip |
| Rate limiting | express-rate-limit | Tiered per-route limits |
| Auth | `google-auth-library` | Real JWKS signature verification |
| Frontend | Vanilla ES modules | No build step, no bundler, no framework |
| Styling | Tailwind (CDN) + one small stylesheet | Matches the original design language |
| Tests | `node:test` | Zero extra dependencies |

---

## Moderation pipeline

Four layers, ordered so the expensive path is rarely taken.

```
Tier 0  Fast reject    nothing matched                    ~0.2 ms  -> ALLOW
Tier 1  Deterministic  hard category or score >= 60       ~0.5 ms  -> BLOCK
Tier 1b Crisis         assist category matched            ~0.5 ms  -> ASSIST
Tier 2  Ambiguous      soft signals only, low score       +AI RTT  -> resolve
```

**Layer 1 - Normalisation** (`normalize.js`)
De-obfuscates before matching: leet substitution, homoglyphs (Cyrillic, Greek,
fullwidth, mathematical alphanumerics), zero-width and bidi characters,
diacritics, separator injection, and repeated-character collapse.
`"d.r.u.g.s"`, `"sh@bu"` and `"kidnap"` with an injected zero-width space all
resolve to their canonical form.

**Layer 2 - Keyword blocklist** (`keywords.js`)
**1,059 terms across 24 categories**, each mapped to its Philippine legal basis.

13 English categories plus **11 Filipino/Bisaya categories** - because most
illegal SMS traffic in the Philippines is written in Taglish or Bisaya, and an
English-only filter misses the overwhelming majority of real local abuse:

`ph_drugs` (benta shabu, tulak, durugista) · `ph_kidnap` (dukot, agaw bata,
pantubos) · `ph_kill` (papatayin kita, ipapa salvage, patyon tika) ·
`ph_abortion` (pampalaglag, cytotec) · `ph_csam` (bata hubad) ·
`ph_trafficking` (bugaw, benta bata) · `ph_violence` (holdap, kikilan) ·
`ph_scam` (nanalo ka, gcash otp) · `ph_gambling` (jueteng, sabong taya) ·
`ph_selfharm` · `ph_hate`

Context-gated categories (`abortion`, `weapons`, `illegal_trade`, `gambling`)
only fire when a co-occurring hint is present, so *"abort the download"* is not
flagged while *"pampalaglag"* is.

**Layer 3 - Pattern detectors** (`patterns.js`)
22 regex detectors across 6 groups: obfuscation, links, financial rails
(crypto wallets, e-wallet payment pressure, credential harvesting), abuse
(bulk-send, chain letters, contact harvesting), social engineering (prize bait,
impersonation), and PII exposure.

**Layer 4 - AI second opinion** (`engine.js`) - *optional, off by default*
Only consulted when the deterministic layers are inconclusive. Deliberately
gated this way: the keyword list is fast, free and auditable, so it handles the
clear cases and the LLM only sees genuine ambiguity.

---

## Security controls

| Control | Implementation |
| --- | --- |
| Content Security Policy | HTTP header via Helmet; `object-src`, `base-uri`, `frame-ancestors` all `'none'` |
| Clickjacking | `X-Frame-Options: DENY` + `frame-ancestors 'none'` |
| MIME sniffing | `X-Content-Type-Options: nosniff` |
| HSTS | Enabled in production only |
| Browser features | `Permissions-Policy` denies camera, mic, geolocation, USB, payment |
| CSRF | Double-submit cookie + custom header. A cross-site form POST cannot set a custom header, so it cannot trigger a mutation at all |
| Origin check | Every mutating request validated against `APP_ORIGIN` and the request host |
| Auth | Google ID token verified against JWKS with **our** client ID pinned as audience |
| Sessions | Opaque random ID in an `httpOnly`, `SameSite=Strict` cookie; state is server-side |
| XSS | All user-controlled text inserted via `textContent`. `ui.js` contains no `innerHTML` for user data |
| Rate limiting | Global, auth (10/15min), preview (20/min), send (20/hour) |
| Payload limits | 8 KB JSON cap; message bodies capped at 160 characters |
| Input validation | Allowlist character sets; PH prefix validated against NTC allocations |
| Toll-fraud control | Per-user daily quota + per-IP hourly cap, so a compromised session cannot drain the gateway balance |
| Audit trail | Hash-chained append-only log. Editing or deleting a record breaks the chain, detectable by `verifyAuditChain()` |
| Privacy | User IDs pseudonymised with a salted HMAC. **Message bodies are never stored** - only salted hashes and the categories that fired |

### Why the audit log does not store message text

The log must be usable as *evidence* without becoming a database of private
conversations, which would itself breach RA 10173 (Data Privacy Act). A salted
hash plus the derived categories proves what the system did while revealing
nothing about what the user actually said.

### Why the session cookie holds no identity

Google ID tokens are bearer credentials that expire in about an hour and cannot
be revoked. Storing one in a cookie would put a reusable credential where
JavaScript can be tricked into leaking it. The token is exchanged once for a
server-side session, then discarded, so a stolen cookie yields an opaque random
ID rather than a replayable credential.

---

## Layout

```
sms/
|- server.js                      Entry point, startup banner, graceful shutdown
|- .env.example                   Secrets template (never commit .env)
|- src/
|  |- config.js                   Validated env config; fails fast in production
|  |- app.js                      Express factory, middleware order
|  |- moderation/
|  |  |- normalize.js             De-obfuscation layer
|  |  |- keywords.js              1,059 terms, 24 categories, PH legal basis
|  |  |- patterns.js              22 regex detectors, 6 groups
|  |  |- engine.js                Tiered orchestrator + crisis path
|  |- security/
|  |  |- helmet.config.js         CSP and security headers
|  |  |- rateLimiters.js          Tiered throttling
|  |  |- auth.js                  Google token verification, sessions
|  |  |- csrf.js                  Double-submit cookie CSRF
|  |  |- validate.js              Input schemas, PH phone validation
|  |  |- auditLog.js              Hash-chained tamper-evident log
|  |- routes/                     auth, sms, policy, health
|  |- services/
|  |  |- smsProvider.js           Pluggable gateway: mock | semaphore | twilio
|  |  |- quota.js                 Credits vs crisis deliveries
|  |- utils/ip.js                 IP normalisation and pseudonymisation
|- public/                        Vanilla ES-module frontend
|  |- index.html
|  |- assets/css/app.css
|  |- assets/js/{app,api,auth,dom,ui}.js
|- tests/api.test.js              56 integration tests
|- scripts/smoke-moderation.js    Standalone moderation smoke test
|- lifelinesms_web_application.html   Original single-file prototype (archived)
```

---

## Running it

```bash
npm install
cp .env.example .env      # then edit .env
npm start                 # http://localhost:3000
```

The app boots with **zero configuration** in development: secrets are generated
ephemerally, the mock provider is used, and Google sign-in reports itself as
unavailable rather than failing silently.

### Enabling real Google sign-in

1. Create an OAuth 2.0 **Web application** client at
   <https://console.cloud.google.com/apis/credentials>
2. Add your origin (e.g. `http://localhost:3000`) as an **Authorised JavaScript
   origin**
3. Put the client ID in `.env` as `GOOGLE_CLIENT_ID`

The client ID is public and safe to expose. Never put the client *secret* in
frontend code.

### Going to production

```bash
NODE_ENV=production
```

`config.js` then **refuses to start** unless `SESSION_SECRET` (64+ chars),
`GOOGLE_CLIENT_ID` and `AUDIT_HASH_SALT` are all set to real values. This is
intentional: silent insecure defaults are how these systems get breached.

Then:
- Set `SMS_PROVIDER=semaphore` (or `twilio`) with credentials
- Set `APP_ORIGIN` to your real HTTPS origin
- **Compile Tailwind to a local stylesheet and self-host the icon sprite**, then
  remove both CDN allowances from `helmet.config.js` and drop `'unsafe-inline'`
  from `script-src`. That is the highest-value hardening step remaining.
- Put the app behind a reverse proxy that terminates TLS

### Commands

```bash
npm start                          # run the server
npm run dev                        # run with --watch
npm test                           # 56 integration tests
node scripts/smoke-moderation.js   # moderation-only smoke test
```

---

## Health and introspection

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | Liveness. No I/O, so it cannot time out under load |
| `GET /api/health/ready` | Readiness with per-subsystem checks; 503 when degraded |
| `GET /api/health/engine` | Rule counts, threshold, detector inventory |
| `GET /api/health/audit` | Audit chain integrity (deliberately vague in production) |
| `GET /api/policy/acceptable-use` | The policy the user must accept |
| `GET /api/policy/categories` | Machine-readable category + statute inventory |
| `GET /api/policy/crisis-resources` | Hotlines, public and unauthenticated |

`/api/policy/crisis-resources` is intentionally public: someone in distress
should not have to sign in to see a phone number.

---

## Operations you will need if this goes live

These are **not implemented**, and are the real gaps between this and a
production service:

1. **Session store.** Sessions are in-memory, so they are lost on restart and
   cannot be shared across instances. Move to Redis before scaling horizontally.
2. **Quota store.** Same issue - the daily counter resets on redeploy.
3. **Reported-abuse queue.** `/api/sms/report` records reports, but there is no
   reviewer interface yet.
4. **CSAM reporting workflow.** The engine flags and blocks CSAM and cites
   RA 9775, but a legal obligation to report implies a documented process,
   defined retention, and a named responsible officer.
5. **Blocklist tuning loop.** Review which rules fire and which produce false
   positives. The audit log has what you need, and `MODERATION_DRY_RUN=true`
   lets you measure before you enforce.
6. **Legal review.** The statutes cited throughout are a starting point for a
   Philippine lawyer, not a substitute for one.

---

## A note on the blocklist approach

A manually curated list has real limitations, and it is worth being honest about
them: it will miss novel slang, it needs ongoing maintenance, and broad terms
can produce false positives (`pusil` is Bisaya for gun *and* a surname).

That is exactly why the list is **the fast first pass**, not the whole system.
Its real value is not coverage - it is **legal defensibility**. When a regulator
asks how prohibited content is blocked, *"we have an auditable list of 1,059
rules mapped to specific statutes"* is a far stronger answer than *"an LLM felt
it was probably bad."* Keyword hits are reproducible evidence; LLM outputs are
not. The AI layer sits behind the deterministic layers to catch what the list
misses, and the list keeps the system compliant and cheap when the AI is
unavailable.

---

**Not legal advice.** The statutes referenced are provided as a starting point
for review by qualified Philippine counsel.
