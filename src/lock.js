import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

export const LOCK_NAME = 'agents.lock';
export const LOCK_VERSION = 1;

export function serverKey(root) {
  const name = path.basename(path.resolve(root));
  return name.replace(/[^a-z0-9._-]/gi, '-').toLowerCase();
}

export function readLock(file) {
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (data?.lockfileVersion !== LOCK_VERSION) return null;
    return data;
  } catch {
    return null;
  }
}

export function emptyLock() {
  return { lockfileVersion: LOCK_VERSION, generatedBy: 'mcp-audit', servers: {} };
}

export function writeLock(file, lock) {
  const sorted = Object.fromEntries(Object.entries(lock.servers).sort(([a], [b]) => a.localeCompare(b)));
  const out = { ...lock, servers: sorted };
  fs.writeFileSync(file, `${JSON.stringify(out, null, 2)}\n`);
}

export function fingerprint(root, files) {
  const hash = createHash('sha256');
  const sorted = [...files].sort((a, b) => a.relative.localeCompare(b.relative));
  for (const file of sorted) {
    hash.update(file.relative);
    hash.update('\0');
    hash.update(file.text);
    hash.update('\0');
  }
  return hash.digest('hex');
}

export function diffLock(previous, next) {
  const changes = [];
  const before = previous?.servers ?? {};
  const after = next?.servers ?? {};
  for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
    const a = before[key];
    const b = after[key];
    if (!a) changes.push({ server: key, kind: 'added', current: b });
    else if (!b) changes.push({ server: key, kind: 'removed', previous: a });
    else if (a.fingerprint !== b.fingerprint) changes.push({ server: key, kind: 'changed', previous: a, current: b });
  }
  return changes;
}