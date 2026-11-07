import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/engine.js';
import { checkLock } from '../src/check.js';
import { LOCK_NAME, emptyLock, readLock, writeLock, fingerprint, serverKey, diffLock } from '../src/lock.js';
import { discover } from '../src/discover.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);
const quiet = { quiet: true };

function tempCopy(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-audit-'));
  fs.cpSync(fixture(name), dir, { recursive: true });
  return dir;
}

function lock(dir) {
  const result = scan(dir);
  const { files } = discover(dir, {});
  const next = emptyLock();
  next.servers[serverKey(dir)] = { fingerprint: fingerprint(dir, files), score: result.score, counts: {} };
  writeLock(path.join(dir, LOCK_NAME), next);
}

test('lock file is written and read back', () => {
  const dir = tempCopy('good-server');
  lock(dir);
  const read = readLock(path.join(dir, LOCK_NAME));
  assert.equal(read.lockfileVersion, 1);
  assert.ok(Object.keys(read.servers).length === 1);
});

test('check passes when nothing changed', () => {
  const dir = tempCopy('good-server');
  lock(dir);
  assert.equal(checkLock(dir, quiet), 0);
});

test('check fails when code changed', () => {
  const dir = tempCopy('good-server');
  lock(dir);
  fs.appendFileSync(path.join(dir, 'index.js'), '\nconst ADDED = 1;\n');
  assert.equal(checkLock(dir, quiet), 1);
});

test('check fails when the tree disappears', () => {
  const dir = tempCopy('good-server');
  assert.equal(checkLock(dir, quiet), 2);
});

test('fingerprint ignores file order but tracks content', () => {
  const files = [
    { relative: 'a.js', text: 'one' },
    { relative: 'b.js', text: 'two' },
  ];
  const reversed = [...files].reverse();
  assert.equal(fingerprint('x', files), fingerprint('x', reversed));
  assert.notEqual(fingerprint('x', files), fingerprint('x', [{ relative: 'a.js', text: 'three' }, files[1]]));
});

test('diffLock reports add, change and remove', () => {
  const changes = diffLock(
    { servers: { a: { fingerprint: '1' }, b: { fingerprint: '2' } } },
    { servers: { b: { fingerprint: '9' }, c: { fingerprint: '3' } } },
  );
  assert.deepEqual(changes.map((c) => `${c.kind}:${c.server}`).sort(), ['added:c', 'changed:b', 'removed:a']);
});

test('a malformed lock is treated as missing', () => {
  const dir = tempCopy('good-server');
  fs.writeFileSync(path.join(dir, LOCK_NAME), '{ not json');
  assert.equal(readLock(path.join(dir, LOCK_NAME)), null);
  assert.equal(checkLock(dir, quiet), 2);
});

test("line endings do not change the fingerprint", () => {
  const dir = tempCopy("good-server");
  const file = path.join(dir, "index.js");
  const lf = fs.readFileSync(file, "utf8").replace(/\r\n/g, "\n");
  fs.writeFileSync(file, lf);
  const before = fingerprint(dir, discover(dir, {}).files);
  fs.writeFileSync(file, lf.replace(/\n/g, "\r\n"));
  const after = fingerprint(dir, discover(dir, {}).files);
  assert.equal(before, after);
});
