import { makeFinding, lineOf, snippet } from '../util.js';

const EXEC_CALL = /\b(execSync|exec|spawnSync|spawn|execFileSync|execFile)\s*\(/g;
const CALLER_ARG = /^\s*(?:req\.)?(?:params\.)?(?:arguments|args|input|command|cmd)\b/;
const GATE = /\.(?:test|exec)\s*\(|\.some\s*\(|\.every\s*\(|\.find\s*\(/;

export const rawShellInterpolation = {
  id: 'raw-shell-interpolation',
  group: 'capability',
  title: 'Shell command comes straight from the caller, ungated',
  severity: 'high',
  why:
    'Having a shell is one risk; letting the model author the command line is another. With nothing between ' +
    'the argument and the shell, every \`;\`, \`&&\` and \`$()\` the caller types is executed, and the tool ' +
    'description becomes the only boundary.',
  fix:
    'Validate against an allowlist before exec, or switch to \`execFile\` with an argv array so the shell is ' +
    'never the parser. Fail closed when nothing matches.',
  check(file) {
    if (!/\.(js|mjs|cjs|ts|mts|cts|py|rb|sh|ps1)$/.test(file.ext)) return [];
    if (GATE.test(file.text)) return [];
    const out = [];
    for (const m of file.text.matchAll(new RegExp(EXEC_CALL.source, 'g'))) {
      const call = file.text.slice(m.index, m.index + 120);
      const open = call.indexOf('(');
      if (!CALLER_ARG.test(call.slice(open + 1))) continue;
      const shell = /shell\s*:\s*true/.test(call);
      out.push(
        makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 55), {
          severity: shell ? 'critical' : 'high',
          detail: shell ? 'caller string reaches a shell' : 'caller argv, no allowlist in front of it',
        }),
      );
      if (out.length >= 3) break;
    }
    return out;
  },
};

export const rules = [rawShellInterpolation];

