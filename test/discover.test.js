import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { discover, SKIP_FILES } from '../src/discover.js';
import { scan } from '../src/engine.js';
import { checkLock } from '../src/check.js';
import { LOCK_NAME, emptyLock, writeLock, fingerprint, serverKey } from '../src/lock.js';

const here = path.dirname(fileURLToPath(import.meta.url));

function tempCopy(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-audit-dbg-'));
  fs.cpSync(path.join(here, 'fixtures', name), dir, { recursive: true });
  return dir;
}

test('the lock file is never scanned', () => {
  assert.ok(SKIP_FILES.has(LOCK_NAME));
  const dir = tempCopy('good-server');
  fs.writeFileSync(path.join(dir, LOCK_NAME), '{"lockfileVersion":1,"servers":{}}');
  const names = discover(dir, {}).files.map((f) => f.name);
  assert.ok(!names.includes(LOCK_NAME));
});

test('writing a lock then checking is stable', () => {
  const dir = tempCopy('good-server');
  const result = scan(dir);
  const { files } = discover(dir, {});
  const lock = emptyLock();
  lock.servers[serverKey(dir)] = { fingerprint: fingerprint(dir, files), score: result.score, counts: {} };
  writeLock(path.join(dir, LOCK_NAME), lock);
  assert.equal(checkLock(dir, { quiet: true }), 0);
});

test('scanning the repo root is deterministic', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-audit-det-'));
  fs.cpSync(path.join(here, '..', 'src'), path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"x","version":"1.0.0"}');
  const a = scan(dir).findings.map((f) => `${f.rule}:${f.file}:${f.line}`);
  const b = scan(dir).findings.map((f) => `${f.rule}:${f.file}:${f.line}`);
  assert.deepEqual(a, b);
});