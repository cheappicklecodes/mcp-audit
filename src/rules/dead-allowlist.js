import { makeFinding, lineOf, snippet, spanOf } from '../util.js';
import { stripComments } from './_scope.js';

const DECL = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\[\s*(\/|\n)/g;
const ALLOWISH = /allow|ALLOW/;
const ALL_CAPS = /^[A-Z][A-Z0-9_]{2,}$/;

export const unusedAllowlist = {
  id: 'unused-allowlist',
  group: 'capability',
  title: 'Allowlist is declared but never applied',
  severity: 'medium',
  why:
    'A control nothing calls is decoration. It reads as "there is a whitelist" so a reviewer stops looking, ' +
    'while every command runs unvalidated — the worst of both, because it is trusted and inert.',
  fix: 'Apply it immediately before exec, and treat a miss as a rejection rather than a warning.',
  check(file) {
    if (!/\.(js|mjs|cjs|ts|mts|cts|py|rb)$/.test(file.ext)) return [];
    const text = stripComments(file.text);
    const out = [];
    for (const m of text.matchAll(DECL)) {
      const name = m[1];
      if (!ALLOWISH.test(name) && !ALL_CAPS.test(name)) continue;
      const uses = text.split(new RegExp('\\b' + name + '\\b')).length - 1;
      if (uses > 1) continue;
      out.push(
        makeFinding(this, file.relative, lineOf(text, m.index), snippet(text, m.index, 55), {
          detail: name + ' is defined and never referenced',
          location: spanOf(text, m.index, m.index + name.length),
        }),
      );
      if (out.length >= 2) break;
    }
    return out;
  },
};

export const rules = [unusedAllowlist];

