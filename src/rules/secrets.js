import { makeFinding, lineOf, snippet } from '../util.js';

const SECRET_LITERALS = [
  { re: /\b(sk-[A-Za-z0-9]{20,})/g, note: 'OpenAI-style key' },
  { re: /\b(gh[pousr]_[A-Za-z0-9]{20,})/g, note: 'GitHub token' },
  { re: /\b(xox[abposr]-[A-Za-z0-9-]{10,})/g, note: 'Slack token' },
  { re: /\b(AKIA[0-9A-Z]{16})/g, note: 'AWS access key id' },
  { re: /\b(glpat-[A-Za-z0-9_-]{18,})/g, note: 'GitLab token' },
  { re: /\b(sk_live_[A-Za-z0-9]{20,})/g, note: 'Stripe live key' },
];

export const hardcodedSecret = {
  id: 'hardcoded-secret',
  group: 'secrets',
  title: 'Credential appears as a literal',
  severity: 'high',
  why: 'A committed key is shared with everyone who reads the repo and never rotates itself.',
  fix:
    'Rotate it at the provider — assume it is already public — then read it from an env var or `.env` that is ' +
    'gitignored. Deleting the line is not enough; the value lives on in history.',
  check(file) {
    const out = [];
    for (const { re, note } of SECRET_LITERALS) {
      for (const m of file.text.matchAll(re)) {
        out.push(
          makeFinding(this, file.relative, lineOf(file.text, m.index), `${m[1].slice(0, 14)}…`, { detail: note }),
        );
      }
    }
    return out.slice(0, 5);
  },
};

export const envFallback = {
  id: 'hardcoded-credential-default',
  group: 'secrets',
  title: 'Credential falls back to a baked-in default',
  severity: 'medium',
  why:
    '`process.env.TOKEN || "abc123"` means the server works without configuration, which hides that it is running ' +
    'on a shared or demo credential.',
  fix: 'Document the default, or fail loudly when the variable is missing.',
  check(file) {
    const re = /process\.env\.[A-Z0-9_]+\s*(?:\|\||\?\?)\s*["'`]([^"'`]{6,})["'`]|os\.environ\.get\(\s*["'][A-Z0-9_]+["']\s*,\s*["']([^"']{6,})["']/g;
    const out = [];
    for (const m of file.text.matchAll(re)) {
      const value = m[1] ?? m[2];
      if (/^(true|false|localhost|development|production|\/)/i.test(value)) continue;
      out.push(makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 55)));
      if (out.length >= 3) break;
    }
    return out;
  },
};

export const rules = [hardcodedSecret, envFallback];