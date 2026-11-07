import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, ALL_RULES } from '../src/engine.js';

const here = path.dirname(fileURLToPath(import.meta.url));

test('the rules that anchor findings all report a source span', () => {
  const anchored = ['shell-injection', 'path-traversal', 'caller-executable', 'argument-injection', 'capability-mismatch', 'unused-allowlist'];
  const result = scan(path.join(here, 'fixtures', 'bad-server'), { only: anchored });
  assert.ok(result.findings.length > 0);
  for (const f of result.findings) {
    assert.ok(f.location, `${f.rule} has no location`);
    assert.ok(f.location.endOffset > f.location.startOffset, `${f.rule} has an empty span`);
    assert.ok(f.location.startLine >= 1);
    assert.equal(f.location.startLine, f.line, `${f.rule} span disagrees with its line`);
  }
});

test('every rule id the benchmark scores is exported', () => {
  for (const id of ['shell-injection', 'path-traversal', 'caller-executable', 'argument-injection', 'capability-mismatch']) {
    assert.ok(ALL_RULES.some((r) => r.id === id), `missing ${id}`);
  }
});