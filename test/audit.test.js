import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, grade, score } from '../src/engine.js';
import { renderSarif } from '../src/report.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);
const ids = (result) => new Set(result.findings.map((f) => f.rule));

test('bad server is graded poorly', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(result.score < 60, `expected weak score, got ${result.score}`);
  assert.equal(grade(result.score).letter, 'F');
});

test('good server is graded well', () => {
  const result = scan(fixture('good-server'));
  assert.ok(result.score >= 90, `expected strong score, got ${result.score}`);
  assert.equal(grade(result.score).letter, 'A');
});

test('good server has no high or critical findings', () => {
  const result = scan(fixture('good-server'));
  const bad = result.findings.filter((f) => f.severity === 'high' || f.severity === 'critical');
  assert.deepEqual(bad, [], `unexpected: ${bad.map((f) => f.rule).join(', ')}`);
});

test('detects shell execution with shell:true as critical', () => {
  const result = scan(fixture('bad-server'));
  const found = result.findings.filter((f) => f.rule === 'shell-exec');
  assert.ok(found.some((f) => f.severity === 'critical'), 'expected a critical shell finding');
});

test('detects prompt injection inside a tool description', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(ids(result).has('injection-in-description'));
});

test('collapses a multi-part description into one finding', () => {
  const result = scan(fixture('bad-server'));
  const count = result.findings.filter((f) => f.rule === 'injection-in-description').length;
  assert.equal(count, 1, `expected 1 finding for 1 description, got ${count}`);
});

test('does not flag process.env as credential file access', () => {
  const result = scan(fixture('good-server'));
  assert.ok(!ids(result).has('reads-credentials'));
});

test('detects hidden unicode and confusable names', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(ids(result).has('hidden-unicode'), 'expected zero-width character detection');
  assert.ok(ids(result).has('homoglyph-names'), 'expected read_file vs read_fi1e detection');
});

test('detects unpinned and git dependencies', () => {
  const result = scan(fixture('bad-server'));
  const supply = [...ids(result)];
  assert.ok(supply.includes('unpinned-dependency'));
  assert.ok(supply.includes('git-dependency'));
});

test('detects curl piped to shell in an install script', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(ids(result).has('curl-pipe-shell'));
});

test('detects a bypassable command allowlist', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(ids(result).has('weak-allowlist'));
});

test('flags a hardcoded credential literal', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(ids(result).has('hardcoded-secret'));
});

test('--only limits the rule set', () => {
  const result = scan(fixture('bad-server'), { only: ['shell-exec'] });
  assert.deepEqual([...ids(result)], ['shell-exec']);
});

test('--disable removes a rule', () => {
  const result = scan(fixture('bad-server'), { disable: ['shell-exec'] });
  assert.ok(!ids(result).has('shell-exec'));
});

test('--min-severity filters findings', () => {
  const result = scan(fixture('bad-server'), { minSeverity: 'critical' });
  assert.ok(result.findings.every((f) => f.severity === 'critical'));
});

test('exclude skips paths', () => {
  const result = scan(fixture('bad-server'), { exclude: ['package.json'] });
  assert.ok(result.findings.every((f) => f.file !== 'package.json'));
});

test('findings carry file, line and evidence', () => {
  const result = scan(fixture('bad-server'));
  for (const f of result.findings) {
    assert.equal(typeof f.file, 'string');
    assert.ok(f.line >= 1);
    assert.equal(typeof f.evidence, 'string');
    assert.ok(f.why.length > 20, 'every finding needs an explanation');
    assert.ok(f.fix.length > 5, 'every finding needs a fix');
  }
});

test('findings are ordered by severity', () => {
  const result = scan(fixture('bad-server'));
  const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  for (let i = 1; i < result.findings.length; i += 1) {
    assert.ok(rank[result.findings[i - 1].severity] >= rank[result.findings[i].severity]);
  }
});

test('score is bounded and monotonic', () => {
  assert.equal(score([], 1), 100);
  const few = score([{ severity: 'high' }], 10);
  const many = score([{ severity: 'high' }, { severity: 'high' }], 10);
  assert.ok(few > many);
  assert.ok(many >= 0);
});

test('an empty directory scans clean', () => {
  const result = scan(path.join(here, 'fixtures', 'empty'));
  assert.equal(result.findings.length, 0);
  assert.equal(result.score, 100);
});

test('sarif is valid and carries evidence, not a dangling dash', () => {
  const result = scan(fixture('bad-server'));
  const sarif = JSON.parse(renderSarif(result, { version: '0.0.0' }));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].results.length, result.findings.length);
  for (const r of sarif.runs[0].results) {
    assert.ok(r.message.text.length > 0);
    assert.ok(!r.message.text.endsWith('—'), `dangling dash: ${r.message.text}`);
    assert.ok(r.locations[0].physicalLocation.region.startLine >= 1);
  }
});
