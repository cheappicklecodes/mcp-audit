import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { loadConfig, mergeConfig, CONFIG_NAME } from '../src/config.js';

const here = path.dirname(fileURLToPath(import.meta.url));

function temp(contents) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-audit-cfg-'));
  if (contents !== undefined) fs.writeFileSync(path.join(dir, CONFIG_NAME), contents);
  return dir;
}

test('missing config loads empty', () => {
  assert.deepEqual(loadConfig(temp()), {});
});

test('config parses known keys', () => {
  const dir = temp(JSON.stringify({ exclude: ['dist/**'], failOn: 'high', minSeverity: 'low' }));
  assert.deepEqual(loadConfig(dir), { exclude: ['dist/**'], failOn: 'high', minSeverity: 'low' });
});

test('invalid json is rejected clearly', () => {
  assert.throws(() => loadConfig(temp('{ nope')), /not valid JSON/);
});

test('unknown keys are rejected', () => {
  assert.throws(() => loadConfig(temp(JSON.stringify({ excludes: [] }))), /unknown key/);
});

test('non-array list is rejected', () => {
  assert.throws(() => loadConfig(temp(JSON.stringify({ exclude: 'dist' }))), /must be an array/);
});

test('cli flags append to config excludes', () => {
  const merged = mergeConfig({ exclude: ['b'], only: [], include: [], disable: [] }, { exclude: ['a'] });
  assert.deepEqual(merged.exclude, ['a', 'b']);
});

test('cli flags win over config scalars', () => {
  const merged = mergeConfig({ failOn: 'critical' }, { failOn: 'high' });
  assert.equal(merged.failOn, 'critical');
});

test('config scalars apply when the flag is absent', () => {
  const merged = mergeConfig({ failOn: null }, { failOn: 'high' });
  assert.equal(merged.failOn, 'high');
});