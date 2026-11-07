import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/engine.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const RULES = ['shell-injection', 'path-traversal', 'caller-executable', 'argument-injection', 'capability-mismatch'];
const MARKER = /\/\* @mcpbench:([\w-]+):(start|end) \*\//g;

class Malformed extends Error {}

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

function maskMarkers(source) {
  const spans = new Map();
  let out = '';
  let cursor = 0;
  for (const m of source.matchAll(MARKER)) {
    out += source.slice(cursor, m.index);
    const [, id, edge] = m;
    out += ' '.repeat(m[0].length);
    if (edge === 'start') {
      if (spans.has(id)) throw new Malformed(`duplicate marker ${id}`);
      spans.set(id, { startOffset: out.length, endOffset: null });
    } else {
      const span = spans.get(id);
      if (!span) throw new Malformed(`end marker ${id} with no start`);
      if (span.endOffset !== null) throw new Malformed(`marker ${id} closed twice`);
      span.endOffset = out.length;
    }
    cursor = m.index + m[0].length;
  }
  out += source.slice(cursor);
  for (const [id, span] of spans) {
    if (span.endOffset === null) throw new Malformed(`marker ${id} never closed`);
    if (span.endOffset <= span.startOffset) throw new Malformed(`marker ${id} is empty`);
  }
  return { text: out, spans };
}

function sources(dir) {
  const out = new Map();
  for (const entry of fs.readdirSync(dir).sort()) {
    if (entry === 'expected.json') continue;
    const full = path.join(dir, entry);
    if (!fs.statSync(full).isFile()) continue;
    const { text, spans } = maskMarkers(fs.readFileSync(full, 'utf8'));
    out.set(entry, { text, spans });
  }
  if (out.size === 0) throw new Malformed('case has no source file');
  return out;
}

function load(dir) {
  const spec = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
  if (spec.schemaVersion !== 2) throw new Malformed('expected.json must be schemaVersion 2');
  if (!spec.family) throw new Malformed('expected.json needs a family');
  const found = sources(dir);
  const files = new Map([...found].map(([name, f]) => [name, f.text]));
  const used = new Set();
  const expected = [];
  for (const want of spec.expectedFindings ?? []) {
    if (!want.id) throw new Malformed('expected finding needs an id');
    if (!want.anchor?.file) throw new Malformed(`${want.id}: needs anchor.file`);
    const source = found.get(want.anchor.file);
    if (!source) throw new Malformed(`${want.id}: no file ${want.anchor.file}`);
    const span = source.spans.get(want.anchor.marker);
    if (!span) throw new Malformed(`${want.id}: no marker ${want.anchor.marker} in ${want.anchor.file}`);
    if (used.has(`${want.anchor.file}#${want.anchor.marker}`)) throw new Malformed(`${want.id}: marker reused`);
    used.add(`${want.anchor.file}#${want.anchor.marker}`);
    expected.push({
      ...want,
      rule: want.rule ?? spec.family,
      span: { file: want.anchor.file, ...span },
    });
  }
  return { spec, expected, files };
}

function scanCase(dir, fileMap) {
  const scratch = fs.mkdtempSync(path.join(here, '.run-'));
  try {
    for (const [name, text] of fileMap) {
      fs.mkdirSync(path.dirname(path.join(scratch, name)), { recursive: true });
      fs.writeFileSync(path.join(scratch, name), text);
    }
    return scan(scratch, { only: RULES }).findings.map((f) => ({
      rule: f.rule,
      severity: f.severity,
      file: f.file,
      line: f.line,
      start: f.location?.startOffset ?? -1,
      end: f.location?.endOffset ?? -1,
    }));
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

function eligible(want, got) {
  return (
    want.rule === got.rule &&
    want.span.file === got.file &&
    got.start >= want.span.startOffset &&
    got.end <= want.span.endOffset
  );
}

function exactCase(row) {
  const pairs = row.pairs ?? [];
  const want = row.expected?.length ?? 0;
  return (
    pairs.length === want &&
    pairs.length === (row.reported?.length ?? 0) &&
    pairs.every((p) => p.exactSeverity)
  );
}

function match(expected, reported) {
  const pairs = [];
  const usedWant = new Set();
  const usedGot = new Set();
  const rank = (w, g) => (w.severity === g.severity ? 2 : 1);

  while (true) {
    let best = null;
    for (const w of expected) {
      if (usedWant.has(w.id)) continue;
      for (const g of reported) {
        if (usedGot.has(g.id) || !eligible(w, g)) continue;
        const score = rank(w, g);
        if (!best || score > best.score) best = { w, g, score };
      }
    }
    if (!best) break;
    usedWant.add(best.w.id);
    usedGot.add(best.g.id);
    pairs.push({ want: best.w, got: best.g, exactSeverity: best.w.severity === best.g.severity });
  }

  return {
    pairs,
    tp: pairs.length,
    fn: expected.length - pairs.length,
    fp: reported.length - usedGot.size,
  };
}

const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function run() {
  const rows = [];
  for (const dir of caseDirs(path.join(here, 'cases'))) {
    const name = path.relative(path.join(here, 'cases'), dir).split(path.sep).join('/');
    const { spec, expected, files } = load(dir);
    const reported = scanCase(dir, files).map((r, i) => ({ ...r, id: i }));
    const m = match(expected.map((e, i) => ({ ...e, id: i })), reported);
    const exact = exactCase(m, expected.length);
    const drift = m.pairs.filter((p) => !p.exactSeverity).map((p) => ({
      want: p.want.severity,
      got: p.got.severity,
      direction: RANK[p.got.severity] < RANK[p.want.severity] ? 'under' : 'over',
    }));
    rows.push({ case: name, family: spec.family, type: spec.caseType, exact, ...m, drift, expected, reported });
  }
  return rows;
}

function ratio(n, d) {
  return d === 0 ? null : n / d;
}

export function summarize(rows) {
  const count = (r) => ({
    tp: r.pairs.length,
    fp: r.reported.length - r.pairs.length,
    fn: r.expected.length - r.pairs.length,
  });
  const sum = (list) => list.reduce((a, r) => {
    const c = count(r);
    return { tp: a.tp + c.tp, fp: a.fp + c.fp, fn: a.fn + c.fn };
  }, { tp: 0, fp: 0, fn: 0 });
  const overall = sum(rows);
  const families = [...new Set(rows.map((r) => r.family))].sort();
  const matched = rows.flatMap((r) => r.pairs);
  return {
    cases: rows.length,
    exact: rows.filter((r) => exactCase(r)).length,
    ...overall,
    precision: ratio(overall.tp, overall.tp + overall.fp),
    recall: ratio(overall.tp, overall.tp + overall.fn),
    severity: matched.length ? matched.filter((p) => p.exactSeverity).length / matched.length : null,
    under: rows.flatMap((r) => r.drift).filter((d) => d.direction === 'under').length,
    over: rows.flatMap((r) => r.drift).filter((d) => d.direction === 'over').length,
    perFamily: Object.fromEntries(
      families.map((f) => {
        const s = sum(rows.filter((r) => r.family === f));
        const set = rows.filter((r) => r.family === f);
        return [f, { cases: set.length, exact: set.filter((r) => exactCase(r)).length, ...s, precision: ratio(s.tp, s.tp + s.fp), recall: ratio(s.tp, s.tp + s.fn) }];
      }),
    ),
    failed: rows.filter((r) => !exactCase(r)),
  };
}

export function manifestDigest(rows) {
  const body = rows.map((r) => `${r.case}:${r.expected.length}`).join('\n');
  return crypto.createHash('sha256').update(body).digest('hex').slice(0, 16);
}

const pct = (v) => (v === null ? 'n/a' : `${(v * 100).toFixed(0)}%`);
function tally(rows, key) {
  return rows.filter((r) => r.type === key).length;
}

export function report(rows, out = (line) => console.log(line)) {
  const s = summarize(rows);
  const families = [...new Set(rows.map((r) => r.family))].sort();
  const bar = '='.repeat(56);
  out('MCP-AUDIT BENCHMARK REPORT');
  out(bar);
  out('');
  out('Profile: MAINTAINER REGRESSION');
  out('');
  out('Corpus:');
  out(`  Cases:                 ${s.cases}`);
  out(`  Expected findings:     ${s.tp + s.fn}`);
  out(`  Rule families:         ${families.length}`);
  out(`  Positive cases:        ${tally(rows, 'positive')}`);
  out(`  Negative cases:        ${tally(rows, 'negative')}`);
  out(`  Bypass cases:          ${tally(rows, 'bypass')}`);
  out(`  Corpus digest:         ${manifestDigest(rows)}`);
  out('');
  out('PROVENANCE:');
  out('  Corpus authors:        Project maintainers');
  out('  Rule authors overlap:  YES');
  out('  Independent cases:     0');
  out('  Held-out cases:        0');
  out('  External evaluation:   NOT AVAILABLE');
  out('');
  out('RESULTS:');
  out(`  Exact-case:            ${s.exact}/${s.cases}`);
  out(`  Precision:             ${pct(s.precision)}`);
  out(`  Recall:                ${pct(s.recall)}`);
  out(`  Severity agreement:    ${pct(s.severity)}`);
  out(`  Severity drift:        ${s.under} under, ${s.over} over`);
  out('');
  out('BY FAMILY:');
  for (const f of families) {
    const row = s.perFamily[f];
    out(
      `  ${f.padEnd(22)} exact ${String(row.exact).padStart(2)}/${String(row.cases).padEnd(2)}  ` +
        `P ${pct(row.precision).padStart(4)}  R ${pct(row.recall).padStart(4)}`,
    );
  }
  out('');
  out('INTERPRETATION:');
  out('  These are maintainer-authored regression fixtures.');
  out('  A clean run means no regression against shapes the');
  out('  rules were written to see, not real-world accuracy.');
  out('');
  out('KNOWN LIMITATIONS:');
  out('  - Regex-based analysis, no AST');
  out('  - Limited interprocedural data flow');
  out('  - Incomplete symlink modelling');
  out('  - No independently authored holdout corpus');
  out('');

  if (s.failed.length) {
    out('FAILURES:');
    for (const r of s.failed) {
      const detail = [];
      if (r.fn) detail.push(`${r.fn} missed`);
      if (r.fp) detail.push(`${r.fp} unexpected`);
      const drifted = r.drift.map((d) => `${d.got} not ${d.want}`);
      if (drifted.length) detail.push(`severity ${drifted.join(', ')}`);
      out(`  ${r.case} (${r.type}): ${detail.join('; ')}`);
      for (const p of r.pairs.filter((x) => !x.exactSeverity)) {
        out(`      line ${p.got.line}: expected ${p.want.severity}, reported ${p.got.severity}`);
      }
      for (const e of r.expected.filter((w) => !r.pairs.some((p) => p.want.id === w.id))) {
        out(`      missed: ${e.id} (${e.rule}, expected ${e.severity})`);
      }
      for (const g of r.reported.filter((x) => !r.pairs.some((p) => p.got.id === x.id))) {
        out(`      unexpected: ${g.rule}/${g.severity} line ${g.line}`);
      }
    }
    out('');
  }
  out(bar);
  return s;
}

export function main(argv = process.argv.slice(2)) {
  let rows;
  try {
    rows = run();
  } catch (err) {
    if (err instanceof Malformed) {
      console.error(`benchmark invalid: ${err.message}`);
      return 2;
    }
    console.error(err?.stack ?? String(err));
    return 2;
  }

  if (argv.includes('--json')) {
    const s = summarize(rows);
    console.log(JSON.stringify({ ...s, failed: s.failed.map((r) => r.case), digest: manifestDigest(rows) }, null, 2));
    return s.failed.length ? 1 : 0;
  }

  const s = report(rows);
  return s.failed.length ? 1 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
