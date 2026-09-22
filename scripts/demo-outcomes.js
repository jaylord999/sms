/**
 * Demo script: print exactly what the UI receives for each outcome.
 * Run:  node scripts/demo-outcomes.js
 */

process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'a'.repeat(64);
process.env.AUDIT_HASH_SALT = 'demo-salt';
process.env.AUDIT_LOG_PATH = './logs/demo.log';
process.env.MIN_ACCOUNT_AGE_SECONDS = '0';

const { createApp } = await import('../src/app.js');
const { createSession } = await import('../src/security/auth.js');
const { generateCsrfToken } = await import('../src/security/csrf.js');
const http = await import('node:http');

const server = http.createServer(createApp());
await new Promise((resolve) => server.listen(0, resolve));
const base = `http://127.0.0.1:${server.address().port}`;

const token = generateCsrfToken();
const session = createSession({
  sub: 'demo', email: 'demo@example.com', name: 'Demo', emailVerified: true,
}, 'ip');

const headers = {
  'content-type': 'application/json',
  cookie: `lifeline_csrf=${token}; lifeline_sid=${session.id}`,
  origin: base,
  'x-lifeline-csrf': token,
};

/**
 * @param {string} label
 * @param {string} body
 */
async function show(label, body) {
  const response = await fetch(`${base}/api/sms/send`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ phone: '9171234567', body }),
  });
  const result = await response.json();

  console.log(`\n${'='.repeat(74)}`);
  console.log(`INPUT: "${body}"`);
  console.log(`HTTP ${response.status}  action=${result.action ?? 'block'}`);
  console.log('='.repeat(74));

  if (result.action === 'allow' || result.isCrisis) {
    console.log(`  TITLE : ${result.isCrisis ? 'Message sent (support shown)' : 'Message sent'}`);
    console.log(`  TO     : ${result.recipient?.masked}  (${result.recipient?.carrier})`);
    console.log(`  STATUS : ${result.delivery?.status}   ref=${result.delivery?.messageId}`);
    if (result.isCrisis) {
      console.log('  NOTE   : crisis path - delivered, no credit used');
      console.log(`  SUPPORT: ${result.resources.map((r) => `${r.name} ${r.contact}`).join(' | ')}`);
    }
    return;
  }

  const explanation = result.explanation;
  console.log(`  TITLE    : ${explanation.reason}`);
  console.log(`  DETAIL   : ${explanation.detail}`);
  console.log('  EXCERPTS :');
  for (const item of explanation.excerpts) {
    console.log(`     + ${item.label}`);
    console.log(`       "${item.excerpt}"`);
    console.log(`       ${item.statute}`);
  }
  console.log('  GUIDANCE :');
  for (const step of explanation.guidance) console.log(`     - ${step}`);
  console.log(`  RETRYABLE: ${explanation.retryable}`);
}

console.log('\n### ORDINARY MESSAGE');
await show('allow', 'Ma, stranded sa terminal. pauwi na po.');

console.log('\n### CRISIS MESSAGE');
await show('crisis', 'gusto ko na mamatay');

console.log('\n### BLOCKED - drugs');
await show('block', 'benta shabu dito, 5k per gram');

console.log('\n### BLOCKED - kidnapping');
await show('block', 'papatayin kita pag di ka nagbayad');

console.log('\n### BLOCKED - CSAM (not retryable)');
await show('block', 'batang hubad pics send mo');

console.log('\n### BLOCKED - obfuscated evasion');
await show('block', 'b u y  s h a b u  n o w');

console.log('');
server.close();
process.exit(0);
