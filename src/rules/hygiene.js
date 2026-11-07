import { makeFinding, lineOf, snippet } from '../util.js';

export const leftoverDebug = {
  id: 'leftover-debug',
  group: 'hygiene',
  title: 'Debug logging left enabled',
  severity: 'low',
  why: 'Debug output often includes full tool arguments — tokens, paths, and file bodies — into a log file shared with support.',
  fix: 'Gate verbose logging behind an env flag.',
  check(file) {
    const re = /console\.(log|debug)\s*\(\s*(?:JSON\.stringify\s*\(\s*)?(args|params|input|request|toolArgs|body)/g;
    const out = [];
    for (const m of file.text.matchAll(re)) {
      out.push(makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 45)));
      if (out.length >= 3) break;
    }
    return out;
  },
};

export const permissiveCors = {
  id: 'permissive-cors',
  group: 'hygiene',
  title: 'Wildcard CORS',
  severity: 'medium',
  why: '`Access-Control-Allow-Origin: *` on an authenticated-less HTTP server lets any web page in the browser reach it.',
  fix: 'Allow only the origins you use.',
  check(file) {
    const m = /(allow-origin["'\s:,=]+\*|cors\(\s*\)|CORS\([^)]*allow_origins\s*=\s*\[\s*["']\*["'])/i.exec(file.text);
    if (!m) return [];
    return [makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 50))];
  },
};

export const prototypePollution = {
  id: 'object-merge',
  group: 'hygiene',
  title: 'Merges caller-supplied objects',
  severity: 'medium',
  why: 'Naive `Object.assign`/spread merging lets `__proto__` in tool arguments reach the prototype chain.',
  fix: 'Filter `__proto__`, or use a merge that blocks it.',
  check(file) {
    const re = /\b(Object\.assign\(|deepMerge\(|merge\(target|_\.merge\()/g;
    const out = [];
    for (const m of file.text.matchAll(re)) {
      if (/__proto__/.test(file.text)) {
        out.push(makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 40), {
          severity: 'low',
          detail: '__proto__ mentioned, appears handled',
        }));
      } else {
        out.push(makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 40)));
      }
      if (out.length >= 2) break;
    }
    return out;
  },
};

export const rules = [leftoverDebug, permissiveCors, prototypePollution];