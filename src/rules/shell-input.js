import { makeFinding, lineOf, snippet } from '../util.js';
import { stripComments, matchesBalanced } from './_scope.js';
import { isCaller, isCallerish, symbolOf, tracesToCaller, guardFor } from './_flow.js';

const SHELL_EXEC = /\b(execSync|exec)\s*\(/g;
const FILE_EXEC = /\b(execFileSync|execFile)\s*\(/g;
const SPAWN = /\bspawn(Sync)?\s*\(/g;
const DIRECT_VAR = /^\s*[\w$.]*\b(?:command|cmd|shell|executable|exec|bin|program|prog)\b\s*$/;

const CALLER_ARG = (text, arg, index) => {
  const first = arg.split(',')[0].trim();
  if (isCaller(first)) return true;
  if (!first || /^["'`]/.test(first)) return false;
  if (isCallerish(text, first, index)) return true;
  return DIRECT_VAR.test(first) && tracesToCaller(text, first.replace(/[^\w$]/g, ''), index);
};

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
    if (!/\.[mc]?[jt]s$/.test(file.ext)) return [];
    const text = stripComments(file.text);
    const out = [];
    for (const m of text.matchAll(new RegExp(SHELL_EXEC.source, 'g'))) {
      const open = text.indexOf('(', m.index);
      const arg = matchesBalanced(text, open).trim();
      if (!CALLER_ARG(text, arg, m.index)) continue;
      const symbol = symbolOf(arg);
      const guard = guardFor(text, m.index, symbol);
      if (guard.state === 'strong') continue;
      const forcedShell = /shell\s*:\s*true/.test(text.slice(open, open + 160));
      out.push(
        makeFinding(this, file.relative, lineOf(text, m.index), snippet(text, m.index, 55), {
          severity: guard.state === 'partial' ? 'high' : 'critical',
          detail: describe(guard, forcedShell),
        }),
      );
      if (out.length >= 3) break;
    }
    return out;
  },
};

function describe(guard, forcedShell) {
  if (guard.state === 'partial') return 'validated, but nothing stops execution on a miss';
  if (guard.state === 'unrelated') return `an allowlist is checked (${guard.other}), not the command passed here`;
  return forcedShell ? 'string executed by a shell, ungated' : 'string executed by stdio, ungated';
}

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
    if (!/\.[mc]?[jt]s$/.test(file.ext)) return [];
    const text = stripComments(file.text);
    const out = [];
    for (const m of text.matchAll(new RegExp(FILE_EXEC.source, 'g'))) {
      const open = text.indexOf('(', m.index);
      const arg = matchesBalanced(text, open).trim();
      if (!CALLER_ARG(text, arg, m.index)) continue;
      const guard = guardFor(text, m.index, symbolOf(arg));
      if (guard.state === 'strong') continue;
      out.push(
        makeFinding(this, file.relative, lineOf(text, m.index), snippet(text, m.index, 55), {
          severity: guard.state === 'partial' ? 'medium' : 'high',
          detail: guard.state === 'partial' ? 'validated, nothing rejects an unknown program' : 'executable name comes from the caller',
        }),
      );
      if (out.length >= 3) break;
    }
    return out;
  },
};

const TERMINATOR_PROGRAM = /^["'`](?:git|grep|rg|ls|cat|head|tail|find|tar|ssh|docker|kubectl|npm|pnpm|yarn|python3?|node|sed|awk)["'`]/;

const argumentInjection = {
  id: 'argument-injection',
  group: 'capability',
  title: 'Caller arguments before a fixed program, with no terminator',
  severity: 'low',
  why:
    'No shell here, but argv parsing is still fragile: a value beginning with `-` is read as a flag, so a path ' +
    'named `--output=/etc/x` rewrites the command. Only meaningful for programs that honour `--`.',
  fix: 'Insert `"--"` before the caller arguments where the program supports it, or reject a leading `-`.',
  check(file) {
    if (!/\.[mc]?[jt]s$/.test(file.ext)) return [];
    const text = stripComments(file.text);
    const out = [];
    for (const m of text.matchAll(new RegExp(SPAWN.source + '|' + FILE_EXEC.source, 'g'))) {
      const open = text.indexOf('(', m.index);
      const call = matchesBalanced(text, open);
      const program = call.split(',')[0].trim();
      if (!TERMINATOR_PROGRAM.test(program)) continue;
      const bracket = text.indexOf('[', open);
      if (bracket < 0) continue;
      const array = matchesBalanced(text, bracket, 300);
      if (!array || !isCallerish(text, array, m.index)) continue;
      if (/["'`]--["'`]/.test(array)) continue;
      out.push(
        makeFinding(this, file.relative, lineOf(text, m.index), snippet(text, m.index, 55), {
          detail: `${program.replace(/["'`]/g, '')} honours --, caller args, no terminator`,
        }),
      );
      if (out.length >= 3) break;
    }
    return out;
  },
};

export const rules = [shellInjection, executableControl, argumentInjection];
