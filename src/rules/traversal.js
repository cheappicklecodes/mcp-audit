import { makeFinding, lineOf, snippet } from '../util.js';

const CALLER_PATH = /\b(?:args|arguments|params|req|request|input|body)\s*(?:\.|\[)/;
const JOIN = /\bpath\.(?:join|resolve)\s*\(/g;
const PY_JOIN = /(?:\bPath\s*\([^)\n]*\)|\b(?:ROOT|ROOT_DIR|BASE|BASE_DIR|base|baseDir|root|home)\b)\s*\/\s*(?:[\w$]+|\[)/g;

const GUARDS = [
  /includes\(\s*["'\`]\.\.["'\`]/,
  /path\.relative\(/,
  /realpath/,
  /startsWith\(|startswith\(/i,
];

export const pathTraversal = {
  id: 'path-traversal',
  group: 'reach',
  title: 'Joins caller-supplied paths without a containment check',
  severity: 'high',
  why:
    '\`path.join(ROOT, args.path)\` looks confined but is not: \`../../etc/passwd\` walks straight out of ROOT, ' +
    'and an absolute segment can discard the prefix entirely. The model writes that string, and so does anything ' +
    'else that can call the tool.',
  fix:
    'Resolve, then clamp: \`const p = path.resolve(ROOT, input); if (!p.startsWith(ROOT + path.sep)) throw\`. ' +
    'Apply it to every argument that becomes a path, not just the obvious one.',
  check(file) {
    if (!/\.(js|mjs|cjs|ts|mts|cts|py|rb|go|rs)$/.test(file.ext)) return [];
    if (GUARDS.some((re) => re.test(file.text))) return [];
    const out = [];
    const py = /\.py$/.test(file.ext);
    const hits = py
      ? [...file.text.matchAll(new RegExp(PY_JOIN.source, 'g'))]
      : [...file.text.matchAll(new RegExp(JOIN.source, 'g'))];
    for (const m of hits) {
      const call = file.text.slice(m.index, m.index + 160);
      const open = call.indexOf('(');
      if (!py && !CALLER_PATH.test(call.slice(open, open + 90))) continue;
      out.push(
        makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 55), {
          detail: 'root is joined to caller input, never clamped',
        }),
      );
      if (out.length >= 3) break;
    }
    return out;
  },
};

export const rules = [pathTraversal];

