import { makeFinding, lineOf, snippet } from '../util.js';

const IMPERATIVE = [
  /ignore (all )?(previous|prior|above|earlier)/i,
  /do not (tell|mention|inform|reveal|report)/i,
  /before (using|calling|invoking) (this|any) tool/i,
  /always (call|run|use) /i,
  /you (must|should) /i,
  /system prompt/i,
  /do not (ask|confirm)/i,
  /never (ask|confirm)/i,
];

const UNICODE_TRICKS = [
  { re: /[\u200B-\u200D\uFEFF]/, note: 'zero-width character' },
  { re: /\\u(?:200[BCD]|FEFF)/i, note: 'zero-width character (escaped)' },
  { re: /[\u202A-\u202E\u2066-\u2069]/, note: 'bidirectional override' },
  { re: /\\u(?:202[ABCDE]|206[6-9])/i, note: 'bidirectional override (escaped)' },
  { re: /[\uE000-\uF8FF]/, note: 'private use area glyph' },
];

export const descriptionInjection = {
  id: 'injection-in-description',
  group: 'poisoning',
  title: 'Tool description contains instructions to the model',
  severity: 'high',
  why:
    'Tool descriptions are injected into the model context with high trust. Anything written there is an ' +
    'instruction, so a server can steer the agent without the user ever seeing it.',
  fix: 'Read the description as if it were prompt text. Keep behavioural claims short and check them against the code.',
  check(file) {
    if (!/\.(json|jsonc|ya?ml|ts|js|mjs|py)$/.test(file.ext)) return [];
    const out = [];
    for (const { value, index } of descriptionValues(file.text)) {
      if (value.length < 40) continue;
      const hits = IMPERATIVE.filter((re) => re.test(value));
      if (hits.length < 2) continue;
      out.push(
        makeFinding(this, file.relative, lineOf(file.text, index), snippet(file.text, index, 80), {
          detail: `${hits.length} imperatives in one description`,
        }),
      );
    }
    return out;
  },
};

function descriptionValues(text) {
  const out = [];
  const startRe = /["']?(?:description|summary|title|instructions?)["']?\s*:\s*/gi;
  let m;
  while ((m = startRe.exec(text))) {
    const from = startRe.lastIndex;
    const stop = Math.min(text.length, from + 2400);
    let cursor = from;
    let buffer = '';
    while (cursor < stop) {
      while (cursor < stop && /\s/.test(text[cursor])) cursor += 1;
      if (text[cursor] === '+' ) { cursor += 1; continue; }
      const quote = text[cursor];
      if (quote !== '"' && quote !== "'" && quote !== '`') break;
      let i = cursor + 1;
      let closed = false;
      while (i < stop) {
        if (text[i] === '\\') { buffer += text[i]; buffer += text[i + 1] ?? ''; i += 2; continue; }
        if (text[i] === quote) { closed = true; i += 1; break; }
        buffer += text[i];
        i += 1;
      }
      if (!closed) break;
      cursor = i;
      const next = text.slice(cursor).match(/^\s*\+/);
      if (!next) break;
      cursor += next[0].length;
    }
    if (buffer) out.push({ value: buffer, index: m.index });
  }
  return out;
}

export const unicodeSmuggling = {
  id: 'hidden-unicode',
  group: 'poisoning',
  title: 'Invisible or reordered unicode inside metadata',
  severity: 'medium',
  why:
    'Zero-width and bidi characters render as nothing but survive into the model context. They are used to hide ' +
    'instructions from human review and to make identifiers look identical to trusted ones.',
  fix: 'Strip or normalize them; check strings byte-for-byte rather than by eye.',
  check(file, ctx) {
    const out = [];
    for (const trick of UNICODE_TRICKS) {
      const m = trick.re.exec(file.text);
      if (!m) continue;
      out.push(
        makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index), {
          detail: trick.note,
        }),
      );
      if (out.length > 4) break;
    }
    return out;
  },
};

export const homoglyphToolNames = {
  id: 'homoglyph-names',
  group: 'poisoning',
  title: 'Confusable tool or server names',
  severity: 'medium',
  why:
    'A tool named `read_file` next to `read_fi1e`, or a Cyrillic `а` in `read_file`, lets a shadow tool win ' +
    'a call the user believes went elsewhere.',
  fix: 'Prefix third-party tools and avoid latin lookalikes in names.',
  check(file) {
    if (!/\.(json|jsonc|ya?ml|ts|js|mjs|py)$/.test(file.ext)) return [];
    const names = [...file.text.matchAll(/["']?name["']?\s*:\s*["']([\w.\-:\u200B-\u200D]{2,64})["']/g)].map((m) => ({
      name: m[1],
      index: m.index,
    }));
    const out = [];
    const seen = new Map();
    for (const { name, index } of names) {
      const folded = name.replace(/[^\x00-\x7F]/g, (c) => foldChar(c)).replace(/[1lI|]/g, '1').replace(/0O/g, '0');
      if (seen.has(folded) && seen.get(folded) !== name) {
        out.push(
          makeFinding(this, file.relative, lineOf(file.text, index), `${seen.get(folded)} vs ${name}`, {
            detail: 'names collapse to the same string after normalisation',
          }),
        );
      }
      seen.set(folded, name);
    }
    return out;
  },
};

const CONFUSABLE = { а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ѕ: 's', ј: 'j' };

function foldChar(c) {
  return CONFUSABLE[c] ?? c;
}

export function stringLiterals(text) {
  const out = [];
  const re = /(["'`])((?:\\[\s\S]|(?!\1)[^\\])*)\1/g;
  let m;
  while ((m = re.exec(text))) {
    if (m.index > 0 && /[\w$]/.test(text[m.index - 1]) && m[1] === '"') continue;
    out.push({ value: m[2], index: m.index });
  }
  return out;
}

export const rules = [descriptionInjection, unicodeSmuggling, homoglyphToolNames];