import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/engine.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const CASES = path.join(here, 'cases');
const LOCK = path.join(here, 'manifest.lock.json');
const RULES = ['shell-injection', 'path-traversal', 'caller-executable', 'argument-injection', 'capability-mismatch'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const TYPES = ['positive', 'negative', 'bypass'];
const MARKER = /\/\* @mcpbench:([\w-]+):(start|end) \*\//g;

class Malformed extends Error {}
class Integrity extends Error {}

const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');

const label = (full) => path.relative(CASES, full).split(path.sep).join('/') || 'benchmark/cases';

function statNoLink(full, where) {
  const stat = fs.lstatSync(full);
  if (stat.isSymbolicLink()) throw new Malformed(`symlink not permitted at ${where}; bytes are not hashed`);
  return stat;
}

function readFile(full, where) {
  const stat = fs.lstatSync(full);
  if (stat.isSymbolicLink()) throw new Malformed(`symlink not permitted at ${where}; bytes are not hashed`);
  if (!stat.isFile()) throw new Malformed(`${where} is not a regular file`);
  return fs.readFileSync(full);
}

function entries(dir) {
  statNoLink(dir, label(dir));
  return fs
    .readdirSync(dir)
    .sort()
    .map((entry) => {
      const full = path.join(dir, entry);
      const stat = statNoLink(full, label(full));
      return { entry, full, isDir: stat.isDirectory() };
    });
}

function caseDirs(dir) {
  const out = [];
  for (const { full, isDir } of entries(dir)) {
    if (!isDir) continue;
    if (fs.existsSync(path.join(full, 'expected.json'))) out.push(full);
    else out.push(...caseDirs(full));
  }
  return out;
}

function relCase(dir) {
  return path.relative(CASES, dir).split(path.sep).join('/');
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

function sourceFiles(dir) {
  const out = [];
  for (const { entry, isDir, full } of entries(dir)) {
    if (entry === 'expected.json') continue;
    if (isDir) {
      throw new Malformed(`nested directory ${entry} inside a case; flatten it or it is not hashed`);
    }
    out.push(entry);
  }
  if (!out.length) throw new Malformed('case has no source file');
  return out;
}

function overlaps(expected) {
  const groups = new Map();
  for (const want of expected) {
    const key = `${want.anchor.file}\u0000${want.rule}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(want);
  }
  for (const [key, list] of groups) {
    for (let i = 0; i < list.length; i += 1) {
      for (let j = i + 1; j < list.length; j += 1) {
        const a = list[i].span;
        const b = list[j].span;
        if (a.startOffset < b.endOffset && b.startOffset < a.endOffset) {
          throw new Malformed(
            `${list[i].id} and ${list[j].id} overlap on ${key.split('\u0000')[0]} for the same rule; ` +
              'nested anchors make the match ambiguous',
          );
        }
      }
    }
  }
}

function load(dir) {
  const name = relCase(dir);
  const spec = JSON.parse(readFile(path.join(dir, 'expected.json'), `${name}/expected.json`).toString('utf8'));
  if (spec.schemaVersion !== 2) throw new Malformed(`${name}: expected.json must be schemaVersion 2`);
  if (spec.id !== name) throw new Malformed(`${name}: spec.id says ${spec.id}`);
  if (!RULES.includes(spec.family)) throw new Malformed(`${name}: unknown family ${spec.family}`);
  if (!TYPES.includes(spec.caseType)) throw new Malformed(`${name}: caseType must be ${TYPES.join('|')}`);
  if (!Array.isArray(spec.expectedFindings)) throw new Malformed(`${name}: expectedFindings must be an array`);

  const names = sourceFiles(dir);
  const found = new Map();
  for (const entry of names) found.set(entry, maskMarkers(readFile(path.join(dir, entry), `${name}/${entry}`).toString('utf8')));
  const files = new Map([...found].map(([file, parsed]) => [file, parsed.text]));

  const ids = new Set();
  const markers = new Set();
  const expected = [];
  for (const want of spec.expectedFindings) {
    const where = `${name}/${want.id ?? '<no id>'}`;
    if (!want.id) throw new Malformed(`${name}: expected finding needs an id`);
    if (ids.has(want.id)) throw new Malformed(`${where}: duplicate expected finding id`);
    ids.add(want.id);
    if (!want.anchor?.file) throw new Malformed(`${where}: needs anchor.file`);
    if (!want.anchor.marker) throw new Malformed(`${where}: needs anchor.marker`);
    const source = found.get(want.anchor.file);
    if (!source) throw new Malformed(`${where}: no file ${want.anchor.file}`);
    const span = source.spans.get(want.anchor.marker);
    if (!span) throw new Malformed(`${where}: no marker ${want.anchor.marker} in ${want.anchor.file}`);
    const key = `${want.anchor.file}\u0000${want.anchor.marker}`;
    if (markers.has(key)) throw new Malformed(`${where}: marker ${want.anchor.marker} reused`);
    markers.add(key);
    const rule = want.rule ?? spec.family;
    if (!RULES.includes(rule)) throw new Malformed(`${where}: unknown rule ${rule}`);
    if (!SEVERITIES.includes(want.severity)) throw new Malformed(`${where}: severity must be ${SEVERITIES.join('|')}`);
    expected.push({ ...want, rule, span: { file: want.anchor.file, ...span } });
  }

  if (spec.caseType === 'negative' && expected.length) throw new Malformed(`${name}: a negative case expects nothing`);
  if (expected.length && !expected.every((e) => e.anchor.file)) throw new Malformed(`${name}: anchor without file`);
  overlaps(expected);

  return { name, spec, expected, files };
}

function scanCase(fileMap) {
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
  return (
    pairs.length === (row.expected?.length ?? 0) &&
    pairs.length === (row.reported?.length ?? 0) &&
    pairs.every((p) => p.exactSeverity)
  );
}

function match(expected, reported) {
  const edges = expected.map((want) =>
    reported
      .map((got, gi) => ({ gi, got, agree: want.severity === got.severity }))
      .filter((edge) => eligible(want, edge.got))
      .sort((a, b) => Number(b.agree) - Number(a.agree)),
  );

  const ownerOf = new Array(reported.length).fill(-1);
  const assigned = new Array(expected.length).fill(-1);

  function assign(wi, seen) {
    for (const edge of edges[wi]) {
      if (seen[edge.gi]) continue;
      seen[edge.gi] = true;
      if (ownerOf[edge.gi] === -1 || assign(ownerOf[edge.gi], seen)) {
        ownerOf[edge.gi] = wi;
        assigned[wi] = edge.gi;
        return true;
      }
    }
    return false;
  }

  for (let wi = 0; wi < expected.length; wi += 1) assign(wi, new Array(reported.length).fill(false));

  const pairs = [];
  for (let wi = 0; wi < expected.length; wi += 1) {
    const gi = assigned[wi];
    if (gi === -1) continue;
    pairs.push({ want: expected[wi], got: reported[gi], exactSeverity: expected[wi].severity === reported[gi].severity });
  }

  return { pairs, tp: pairs.length, fn: expected.length - pairs.length, fp: reported.length - pairs.length };
}

const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function parseAll() {
  return caseDirs(CASES).map((dir) => ({ dir, ...load(dir) }));
}

function score(parsed) {
  const out = [];
  for (const { name, spec, expected, files } of parsed) {
    const reported = scanCase(files).map((r, i) => ({ ...r, id: i }));
    const m = match(expected, reported);
    const drift = m.pairs
      .filter((p) => !p.exactSeverity)
      .map((p) => ({
        want: p.want.severity,
        got: p.got.severity,
        direction: RANK[p.got.severity] < RANK[p.want.severity] ? 'under' : 'over',
      }));
    const row = { case: name, family: spec.family, type: spec.caseType, expected, reported, drift, ...m };
    row.exact = exactCase(row);
    out.push(row);
  }
  return out;
}

function caseDigest(files) {
  const chunks = [];
  for (const name of [...files.keys()].sort()) {
    const body = files.get(name);
    chunks.push(Buffer.from(`${Buffer.byteLength(name)}:${name}${sha256(body)}`, 'utf8'));
  }
  return sha256(Buffer.concat(chunks));
}

function rawFiles(dir) {
  const map = new Map();
  for (const { entry, isDir, full } of entries(dir)) {
    if (isDir) continue;
    map.set(entry, readFile(full, `${relCase(dir)}/${entry}`));
  }
  return map;
}

export function buildManifest() {
  const cases = caseDirs(CASES).map((dir) => {
    const files = rawFiles(dir);
    const hashes = {};
    for (const name of [...files.keys()].sort()) hashes[name] = sha256(files.get(name));
    const spec = JSON.parse(readFile(path.join(dir, 'expected.json'), `${relCase(dir)}/expected.json`).toString('utf8'));
    return {
      id: relCase(dir),
      path: `cases/${relCase(dir)}`,
      family: spec.family,
      caseType: spec.caseType,
      files: hashes,
      sha256: caseDigest(files),
    };
  });
  return { schemaVersion: 1, algorithm: 'sha256', caseCount: cases.length, cases };
}

function readManifest() {
  if (!fs.existsSync(LOCK)) throw new Integrity('benchmark/manifest.lock.json is missing; run npm run bench:update-lock');
  const manifest = JSON.parse(readFile(LOCK, 'benchmark/manifest.lock.json').toString('utf8'));
  if (manifest.schemaVersion !== 1 || manifest.algorithm !== 'sha256') throw new Integrity('manifest header is unknown');
  if (!Array.isArray(manifest.cases)) throw new Integrity('manifest has no case list');
  return manifest;
}

function verify(manifest) {
  const onDisk = new Map(caseDirs(CASES).map((dir) => [relCase(dir), dir]));
  const locked = new Map(manifest.cases.map((c) => [c.id, c]));

  const problems = [];
  for (const [id, entry] of locked) {
    const dir = onDisk.get(id);
    if (!dir) {
      problems.push(`${id}: locked case is gone`);
      continue;
    }
    const files = rawFiles(dir);
    for (const name of Object.keys(entry.files).sort()) {
      if (!files.has(name)) problems.push(`${id}: locked file ${name} is gone`);
      else if (sha256(files.get(name)) !== entry.files[name]) problems.push(`${id}: ${name} changed since the lock`);
    }
    for (const name of files.keys()) if (!(name in entry.files)) problems.push(`${id}: new file ${name} is not in the lock`);
    if (!problems.length && caseDigest(files) !== entry.sha256) problems.push(`${id}: case digest changed`);
  }
  for (const id of onDisk.keys()) if (!locked.has(id)) problems.push(`${id}: case is not in the lock`);
  if (manifest.caseCount !== manifest.cases.length) problems.push(`manifest says ${manifest.caseCount} cases but lists ${manifest.cases.length}`);

  if (problems.length) {
    const head = problems.slice(0, 20).map((p) => `  ${p}`).join('\n');
    const more = problems.length > 20 ? `\n  ... and ${problems.length - 20} more` : '';
    throw new Integrity(`${problems.length} integrity problem(s):\n${head}${more}`);
  }
}

export function run() {
  const parsed = parseAll();
  verify(readManifest());
  return score(parsed);
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
  const sum = (list) =>
    list.reduce(
      (a, r) => {
        const c = count(r);
        return { tp: a.tp + c.tp, fp: a.fp + c.fp, fn: a.fn + c.fn };
      },
      { tp: 0, fp: 0, fn: 0 },
    );
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
        return [
          f,
          { cases: set.length, exact: set.filter((r) => exactCase(r)).length, ...s, precision: ratio(s.tp, s.tp + s.fp), recall: ratio(s.tp, s.tp + s.fn) },
        ];
      }),
    ),
    failed: rows.filter((r) => !exactCase(r)),
  };
}

export function corpusDigest(manifest = buildManifest()) {
  return sha256(manifest.cases.map((c) => `${c.id}:${c.sha256}`).join('\n'));
}

const pct = (v) => (v === null ? 'n/a' : `${(v * 100).toFixed(0)}%`);
const tally = (rows, key) => rows.filter((r) => r.type === key).length;

export function report(rows, out = (line) => console.log(line)) {
  const s = summarize(rows);
  const manifest = readManifest();
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
  out(`  Manifest:              verified (${manifest.caseCount} cases)`);
  out(`  Corpus digest:         ${corpusDigest(manifest).slice(0, 16)}`);
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
  out('  These are maintainer-authored regression fixtures,');
  out('  hashed in a lock file so the corpus cannot drift');
  out('  silently. A clean run means no regression against');
  out('  shapes the rules were written to see.');
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

function writeLock() {
  parseAll();
  const manifest = buildManifest();
  fs.writeFileSync(LOCK, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`wrote benchmark/manifest.lock.json (${manifest.caseCount} cases, ${corpusDigest(manifest).slice(0, 16)})`);
}

export function main(argv = process.argv.slice(2)) {
  if (argv.includes('--update-lock')) {
    try {
      writeLock();
      return 0;
    } catch (err) {
      console.error(`benchmark invalid: ${err.message}`);
      return 2;
    }
  }

  if (argv.includes('--check-lock')) {
    try {
      parseAll();
      verify(readManifest());
      console.log('benchmark manifest matches the corpus');
      return 0;
    } catch (err) {
      if (err instanceof Integrity) {
        console.error(`benchmark integrity failure (exit 3):\n${err.message}`);
        return 3;
      }
      console.error(`benchmark invalid: ${err.message}`);
      return 2;
    }
  }

  let rows;
  try {
    rows = run();
  } catch (err) {
    if (err instanceof Integrity) {
      console.error(`benchmark integrity failure (exit 3):\n${err.message}`);
      console.error('\nIf the fixture change is intended, run npm run bench:update-lock and commit the manifest.');
      return 3;
    }
    if (err instanceof Malformed) {
      console.error(`benchmark invalid: ${err.message}`);
      return 2;
    }
    console.error(err?.stack ?? String(err));
    return 2;
  }

  if (argv.includes('--json')) {
    const s = summarize(rows);
    console.log(JSON.stringify({ ...s, failed: s.failed.map((r) => r.case), digest: corpusDigest() }, null, 2));
    return s.failed.length ? 1 : 0;
  }

  const s = report(rows);
  return s.failed.length ? 1 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
