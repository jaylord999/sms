/**
 * Quick manual smoke test for the moderation engine.
 * Run:  node scripts/smoke-moderation.js
 */

import { moderate, engineInfo } from '../src/moderation/engine.js';

const CASES = [
  // --- MUST be allowed: ordinary family SMS ---
  { text: 'Ma, stranded sa terminal. pauwi na po.', expect: 'allow' },
  { text: 'Pa, nasa hospital si lola. punta ka dito.', expect: 'allow' },
  { text: 'Mom im on my way home, traffic sa edsa', expect: 'allow' },
  { text: 'abort the download please', expect: 'allow' },
  { text: 'Nakita ko ang drug store sa kanto', expect: 'allow' },

  // --- MUST be ASSIST (delivered + support), NOT blocked ---
  { text: 'i want to die', expect: 'assist' },
  { text: 'gusto ko na mamatay', expect: 'assist' },
  { text: 'magpapakamatay na ako', expect: 'assist' },
  { text: 'ayaw ko na mabuhay, pabigat lang ako', expect: 'assist' },
  { text: 'maghikog ko, kapoy na kaayo ko', expect: 'assist' },
  { text: 'paalam na po sa lahat, huling mensahe ko', expect: 'assist' },

  // --- MUST be blocked: illegal activity ---
  { text: 'benta shabu dito, 5k per gram', expect: 'block' },
  { text: 'may shabu ako pm me', expect: 'block' },
  { text: 'kidnap for ransom tayo', expect: 'block' },
  { text: 'dudukutin ko ang bata', expect: 'block' },
  { text: 'papatayin kita pag di ka nagbayad', expect: 'block' },
  { text: 'batang hubad pics send mo', expect: 'block' },
  { text: 'buy unlicensed gun here', expect: 'block' },
  { text: 'padala ang bayad para sa premyo mo, nanalo ka', expect: 'block' },
  { text: 'send me your OTP code now for verification', expect: 'block' },
  { text: 'magpalaglag ako, saan pwede', expect: 'block' },

  // --- Obfuscation evasion ---
  { text: 'b u y  s h a b u  n o w', expect: 'block' },
  { text: 'buy shabu at bit.ly/xkcd', expect: 'block' },
  { text: 'I want to kill myself', expect: 'assist' },

  // --- Bulk abuse ---
  { text: 'SEND TO ALL BROADCAST THIS MESSAGE!!!!!', expect: 'block' },
];

let pass = 0;
let fail = 0;

const info = engineInfo();
console.log('='.repeat(78));
console.log('LifelineSMS moderation engine - smoke test');
console.log('='.repeat(78));
console.log(`Categories: ${info.stats.categories}  Terms: ${info.stats.terms}  `
  + `Detectors: ${info.detectors}`);
console.log(`Assist-only categories: ${info.stats.assistCategories}  `
  + `Hard-block categories: ${info.stats.hardCategories}`);
console.log(`Block threshold: ${info.threshold}  AI layer: ${info.aiEnabled ? 'on' : 'off'}`);
console.log('='.repeat(78));

for (const testCase of CASES) {
  const result = await moderate(testCase.text);
  const ok = result.action === testCase.expect;
  if (ok) pass += 1; else fail += 1;

  const mark = ok ? 'PASS' : 'FAIL';
  console.log(
    `[${mark}] ${result.action.toUpperCase().padEnd(6)} (want ${testCase.expect.toUpperCase().padEnd(6)}) `
    + `score=${String(result.score).padStart(3)} ${result.durationMs}ms  "${testCase.text}"`,
  );

  if (!ok || result.findings.length > 0) {
    for (const finding of result.findings.slice(0, 4)) {
      console.log(`         -> [${finding.source}] ${finding.id} `
        + `(w=${finding.weight}) ${finding.matches.join(', ').slice(0, 60)}`);
    }
  }
}

console.log('='.repeat(78));
console.log(`RESULT: ${pass} passed, ${fail} failed, ${CASES.length} total`);
console.log('='.repeat(78));

process.exitCode = fail === 0 ? 0 : 1;
