import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/engine.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const RULES = ['shell-injection', 'path-traversal', 'caller-executable', 'argument-injection', 'capability-mismatch'];

function caseDirs(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir).sort()) {
    const full = path.join(dir, entry);
    if (!fs.statSync(full).isDirectory()) continue;
    if (fs.existsSync(path.join(full, 'expected.json'))) out.push(full);
    else out.push(...caseDirs(full));
  }
  return out;
}

export function run() {
  const rows = [];
  for (const dir of caseDirs(path.join(here, 'cases'))) {
    const name = path.relative(path.join(here, 'cases'), dir).split(path.sep).join('/');
    const spec = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
    const got = scan(dir, { only: RULES }).findings.map((f) => `${f.rule}/${f.severity}`);
    const want = spec.expect;
    const ok = got.length === want.length && want.every((w) => got.includes(w));
    rows.push({ case: name, rule: spec.rule, ok, want, got, extra: got.filter((g) => !want.includes(g)) });
  }
  return rows;
}

export function summarize(rows) {
  const positives = rows.filter((r) => r.want.length > 0);
  const tp = positives.filter((r) => r.ok).length;
  const fn = positives.length - tp;
  const fp = rows.filter((r) => r.extra.length > 0).length;
  const tn = rows.filter((r) => r.want.length === 0 && r.ok).length;
  const pct = (n, d) => (d === 0 ? 'n/a' : `${((n / d) * 100).toFixed(0)}%`);
  return {
    cases: rows.length,
    tp,
    fn,
    fp,
    tn,
    precision: pct(tp, tp + fp),
    recall: pct(tp, tp + fn),
    accuracy: pct(tp + tn, rows.length),
    failed: rows.filter((r) => !r.ok),
  };
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
  const rows = run();
  const s = summarize(rows);
  for (const r of rows) {
    console.log(`${r.ok ? 'pass' : 'FAIL'}  ${r.case.padEnd(34)} want ${r.want.join(',') || '-'}  got ${r.got.join(',') || '-'}`);
  }
  console.log('');
  console.log(`precision ${s.precision}  recall ${s.recall}  accuracy ${s.accuracy}  (${s.tp} tp / ${s.fp} fp / ${s.fn} fn / ${s.tn} tn)`);
  process.exit(s.failed.length ? 1 : 0);
}