import fs from 'node:fs';
import path from 'node:path';

export const SEVERITY = {
  critical: { rank: 4, label: 'CRITICAL', ansi: '\x1b[41;97m' },
  high: { rank: 3, label: 'HIGH', ansi: '\x1b[91m' },
  medium: { rank: 2, label: 'MEDIUM', ansi: '\x1b[93m' },
  low: { rank: 1, label: 'LOW', ansi: '\x1b[96m' },
  info: { rank: 0, label: 'INFO', ansi: '\x1b[90m' },
};

export function severityRank(sev) {
  return SEVERITY[seqv(sev)]?.rank ?? 0;
}

function seqv(sev) {
  return sev;
}

export function makeFinding(rule, file, line, evidence, extra = {}) {
  return {
    rule: rule.id,
    title: rule.title,
    severity: rule.severity,
    why: rule.why,
    fix: rule.fix,
    file,
    line,
    evidence: String(evidence ?? '').slice(0, 400),
    ...extra,
  };
}

export function rel(root, abs) {
  const r = path.relative(root, abs);
  return r.split(path.sep).join('/');
}

export function lineOf(source, index) {
  if (!source || index < 0) return 0;
  let line = 1;
  for (let i = 0; i < index && i < source.length; i += 1) {
    if (source.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

export function snippet(source, index, radius = 40) {
  let start = Math.max(0, index - radius);
  const at = Math.min(source.length, index + radius);
  while (start > 0 && /[\w$."'\x60-]/.test(source[start - 1])) start -= 1;
  let end = at;
  while (end < source.length && /[\w$."'\x60-]/.test(source[end])) end += 1;
  const text = source.slice(start, end).replace(/\s+/g, ' ').trim();
  return text.length > 120 ? `${text.slice(0, 117)}…` : text;
}

export function readText(abs) {
  try {
    const buf = fs.readFileSync(abs);
    if (buf.length > 2 * 1024 * 1024) return null;
    if (buf.includes(0)) return null;
    return buf.toString('utf8').replace(/\r\n/g, '\n');
  } catch {
    return null;
  }
}

export function exists(abs) {
  try {
    fs.accessSync(abs);
    return true;
  } catch {
    return false;
  }
}

export function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function globToRegExp(glob) {
  let out = '^';
  for (let i = 0; i < glob.length; i += 1) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        out += '.*';
        i += 1;
        if (glob[i + 1] === '/') i += 1;
      } else {
        out += '[^/]*';
      }
    } else if (c === '?') {
      out += '[^/]';
    } else if ('\\^$.|+()[]{}'.includes(c)) {
      out += `\\${c}`;
    } else {
      out += c;
    }
  }
  return new RegExp(`${out}$`);
}

export function isLocalHost(host) {
  if (!host) return true;
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  return (
    h === 'localhost' ||
    h === '0.0.0.0' ||
    h === '127.0.0.1' ||
    h === '::1' ||
    h.startsWith('127.') ||
    h.endsWith('.local') ||
    h.endsWith('.internal')
  );
}