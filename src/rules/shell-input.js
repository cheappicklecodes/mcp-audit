import { makeFinding, lineOf, snippet } from '../util.js';
import { stripComments, enclosingBlock, matchesBalanced } from './_scope.js';

const SHELL_EXEC = /\b(execSync|exec)\s*\(/g;
const FILE_EXEC = /\b(execFileSync|execFile)\s*\(/g;
const SPAWN = /\bspawn(Sync)?\s*\(/g;

const CALLER = /\b(?:args|arguments|params|req|request|input|body|ctx|context)\b\s*(?:\.|\[)/;
const GATE = /\.(?:test|exec|some|every|find|includes)\s*\(/;
const DIRECT_VAR = /^\s*(?:[\w$.]*\b)?(?:command|cmd|shell|executable|bin|program)\b\s*[,)]?\s*$/;

const shellInjection = {
  id: 'shell-injection',
  group: 'capability',
  title: 'Caller-controlled string reaches a shell',
  severity: 'critical',
  why:
    'The shell parses the string, so everything in it is syntax: `;`, `&&`, `$()` and backticks all run. ' +
    'When the caller writes that string, the caller is writing code, and the tool description is the only boundary.',
  fix:
    'Either validate against an allowlist that matches the whole command and fails closed, or move to `execFile` ' +
    'with an argv array so nothing is parsed.',
  check(file) {
    if (!/\.[mc]?[jt]s$|\.[jt]s$/.test(file.ext)) return [];
    const text = stripComments(file.text);
    const out = [];
    for (const m of text.matchAll(new RegExp(SHELL_EXEC.source, 'g'))) {
      const open = text.indexOf('(', m.index);
      const arg = matchesBalanced(text, open).trim();
      const caller = firstArgIsCaller(arg, text, m.index);
      if (!caller) continue;
      const forcedShell = /shell\s*:\s*true/.test(text.slice(open, open + 160));
      if (gated(text, m.index)) continue;
      out.push(
        makeFinding(this, file.relative, lineOf(text, m.index), snippet(text, m.index, 55), {
          severity: 'critical',
          detail: forcedShell ? 'string executed by a shell, ungated' : 'string executed by stdio, ungated',
        }),
      );
      if (out.length >= 3) break;
    }
    return out;
  },
};

const executableControl = {
  id: 'caller-executable',
  group: 'capability',
  title: 'Caller chooses which program runs',
  severity: 'high',
  why:
    'With execFile there is no shell parser, so the arguments are mostly safe, but the program name ' +
    'still belongs to the caller. git becomes sh if the caller says so, and the argv you intended ' +
    'never applies.',
  fix: 'Pin the program and take only arguments from the caller, or check the requested name against a fixed set.',
  check(file) {
    if (!/\.[mc]?[jt]s$|\.[jt]s$/.test(file.ext)) return [];
    const text = stripComments(file.text);
    const out = [];
    for (const m of text.matchAll(new RegExp(FILE_EXEC.source, 'g'))) {
      const open = text.indexOf('(', m.index);
      const arg = matchesBalanced(text, open).trim();
      if (!firstArgIsCaller(arg, text, m.index)) continue;
      if (gated(text, m.index)) continue;
      out.push(
        makeFinding(this, file.relative, lineOf(text, m.index), snippet(text, m.index, 55), {
          detail: 'executable name comes from the caller, no fixed program',
        }),
      );
      if (out.length >= 3) break;
    }
    return out;
  },
};

const argumentInjection = {
  id: 'argument-injection',
  group: 'capability',
  title: 'Caller arguments passed without an `--` terminator',
  severity: 'low',
  why:
    'No shell, but argv parsing is still fragile: a value beginning with `-` is read as a flag, so a file ' +
    'named `--output=/etc/x` changes the command. Only matters when the earlier argv is literal.',
  fix: 'Insert `"--"` before caller-supplied arguments, or validate the leading character.',
  check(file) {
    if (!/\.[mc]?[jt]s$|\.[jt]s$/.test(file.ext)) return [];
    const text = stripComments(file.text);
    const out = [];
    for (const m of text.matchAll(new RegExp(SPAWN.source, 'g'))) {
      const open = text.indexOf('(', m.index);
      const args = matchesBalanced(text, open);
      const literalProgram = /^\s*["'`]/.test(args) && !firstArgIsCaller(args, text, m.index);
      if (!literalProgram) continue;
      const array = matchesBalanced(text, text.indexOf('[', open), 300);
      if (!array || !CALLER.test(array)) continue;
      if (/["'`]--["'`]/.test(array)) continue;
      out.push(
        makeFinding(this, file.relative, lineOf(text, m.index), snippet(text, m.index, 55), {
          detail: 'fixed program, caller args, no --',
        }),
      );
      if (out.length >= 3) break;
    }
    return out;
  },
};

function firstArgIsCaller(arg, text, index) {
  const first = arg.split(',')[0].trim();
  if (CALLER.test(first)) return true;
  if (DIRECT_VAR.test(first) && !/^["'`]/.test(first)) {
    return /(?:const|let|var)s+{?s*w*[Cc]ommandw*s*}?s*=/.test(text.slice(0, index)) ||
      /consts+w+s*=s*(?:req|args|params|arguments)/.test(text.slice(0, index + 200));
  }
  return false;
}

function gated(text, index) {
  const [start, end] = enclosingBlock(text, index);
  const before = text.slice(start, index);
  return GATE.test(before);
}

export const rules = [shellInjection, executableControl, argumentInjection];
