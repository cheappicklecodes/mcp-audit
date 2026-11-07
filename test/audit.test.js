import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { scan, grade, score, ALL_RULES } from '../src/engine.js';
import { renderSarif } from '../src/report.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, 'fixtures', name);
const ids = (result) => new Set(result.findings.map((f) => f.rule));

test('bad server is graded poorly', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(result.score < 60, `expected weak score, got ${result.score}`);
  assert.equal(grade(result.score).letter, 'F');
});

test('good server is graded well', () => {
  const result = scan(fixture('good-server'));
  assert.ok(result.score >= 90, `expected strong score, got ${result.score}`);
  assert.equal(grade(result.score).letter, 'A');
});

test('good server has no high or critical findings', () => {
  const result = scan(fixture('good-server'));
  const bad = result.findings.filter((f) => f.severity === 'high' || f.severity === 'critical');
  assert.deepEqual(bad, [], `unexpected: ${bad.map((f) => f.rule).join(', ')}`);
});

test('detects shell execution with shell:true as critical', () => {
  const result = scan(fixture('bad-server'));
  const found = result.findings.filter((f) => f.rule === 'shell-exec');
  assert.ok(found.some((f) => f.severity === 'critical'), 'expected a critical shell finding');
});

test('detects prompt injection inside a tool description', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(ids(result).has('injection-in-description'));
});

test('collapses a multi-part description into one finding', () => {
  const result = scan(fixture('bad-server'));
  const count = result.findings.filter((f) => f.rule === 'injection-in-description').length;
  assert.equal(count, 1, `expected 1 finding for 1 description, got ${count}`);
});

test('does not flag process.env as credential file access', () => {
  const result = scan(fixture('good-server'));
  assert.ok(!ids(result).has('reads-credentials'));
});

test('detects hidden unicode and confusable names', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(ids(result).has('hidden-unicode'), 'expected zero-width character detection');
  assert.ok(ids(result).has('homoglyph-names'), 'expected read_file vs read_fi1e detection');
});

test('detects unpinned and git dependencies', () => {
  const result = scan(fixture('bad-server'));
  const supply = [...ids(result)];
  assert.ok(supply.includes('unpinned-dependency'));
  assert.ok(supply.includes('git-dependency'));
});

test('detects curl piped to shell in an install script', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(ids(result).has('curl-pipe-shell'));
});

test('detects a bypassable command allowlist', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(ids(result).has('weak-allowlist'));
});

test('flags a hardcoded credential literal', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(ids(result).has('hardcoded-secret'));
});

test('detects an unclamped join of caller input to a root', () => {
  const result = scan(fixture('bad-server'));
  const found = result.findings.filter((f) => f.rule === 'path-traversal');
  assert.ok(found.length >= 2, `expected joins for read, list and write, got ${found.length}`);
  assert.ok(found.every((f) => f.line >= 1));
});

test('does not flag a join that resolves and clamps', () => {
  const result = scan(fixture('good-server'));
  assert.ok(!ids(result).has('path-traversal'));
});

test('detects a caller string reaching the shell ungated', () => {
  const result = scan(fixture('bad-server'));
  const found = result.findings.filter((f) => f.rule === 'shell-injection');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'critical');
});

test('shell-exec alone does not imply an ungated command', () => {
  const plain = scan(fixture('bad-server'), { only: ['shell-exec'] });
  assert.ok(!ids(plain).has('shell-injection'));
});

test('detects empty capabilities next to a served tool list', () => {
  const result = scan(fixture('bad-server'));
  assert.ok(ids(result).has('capability-mismatch'));
});

test('does not flag capabilities on a server that declares them', () => {
  const result = scan(fixture('good-server'));
  assert.ok(!ids(result).has('capability-mismatch'));
});

test('detects an allowlist that is never applied', () => {
  const result = scan(fixture('bad-server'));
  const found = result.findings.filter((f) => f.rule === 'unused-allowlist');
  assert.equal(found.length, 1);
  assert.match(found[0].evidence, /ALLOWED_COMMANDS/);
});

test('a used allowlist is not reported as dead', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-audit-allow-'));
  fs.writeFileSync(
    path.join(dir, 'index.js'),
    'const ALLOWED = [/^ls/];\nif (!ALLOWED.some((r) => r.test(cmd))) throw new Error("no");\nexecSync(cmd);\n',
  );
  const result = scan(dir, { only: ['unused-allowlist'] });
  assert.equal(result.findings.length, 0);
});


function tmpFile(name, body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-audit-case-'));
  fs.writeFileSync(path.join(dir, name), body);
  return dir;
}

const NEW_RULES = [
  'path-traversal',
  'shell-injection',
  'caller-executable',
  'argument-injection',
  'capability-mismatch',
  'unused-allowlist',
];

test('python root / join is caught when unclamped', () => {
  const bad = scan(tmpFile('main.py', 'from pathlib import Path\nROOT = Path("/srv")\ndef r(p):\n    return (ROOT / p).read_text()\n'), { only: NEW_RULES });
  assert.equal(bad.findings.filter((f) => f.rule === 'path-traversal')[0].severity, 'high');
});

test('python is_relative_to clears the rule, bare startswith only downgrades it', () => {
  const strong = scan(
    tmpFile('main.py', 'from pathlib import Path\nROOT = Path("/srv").resolve()\ndef r(p):\n    t = (ROOT / p).resolve()\n    if not t.is_relative_to(ROOT):\n        raise ValueError\n    return t\n'),
    { only: NEW_RULES },
  );
  assert.ok(!ids(strong).has('path-traversal'));

  const weak = scan(
    tmpFile('main.py', 'from pathlib import Path\nROOT = Path("/srv").resolve()\ndef r(p):\n    t = (ROOT / p).resolve()\n    if not str(t).startswith(str(ROOT)):\n        raise ValueError\n    return t\n'),
    { only: NEW_RULES },
  );
  const found = weak.findings.filter((f) => f.rule === 'path-traversal');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'medium');
});

test('execFile with a fixed program is not shell injection', () => {
  const result = scan(tmpFile('a.ts', 'const out = execFileSync("ls", ["-la", dir]);\n'), { only: NEW_RULES });
  assert.ok(!ids(result).has('shell-injection'));
  assert.ok(!ids(result).has('caller-executable'));
});

test('an allowlist that is applied clears both allowlist rules', () => {
  const result = scan(
    tmpFile('b.ts', 'const ALLOWED = [/^ls/];\nif (!ALLOWED.some((r) => r.test(cmd))) throw new Error("no");\nexecSync(cmd);\n'),
    { only: NEW_RULES },
  );
  assert.deepEqual([...ids(result)], []);
});

test('a bare capabilities block with served tools is caught', () => {
  const result = scan(tmpFile('c.ts', 'const s = new Server({name:"x"},{capabilities:{}});\ns.setRequestHandler("tools/list", async()=>({}));\n'), { only: NEW_RULES });
  assert.ok(ids(result).has('capability-mismatch'));
});

test('declared capabilities plus a tools/call handler is clean', () => {
  const body = 'const s = new Server({name:"x"},{capabilities:{tools:{listChanged:true}}});\n' +
    's.setRequestHandler("tools/list", async()=>({}));\ns.setRequestHandler("tools/call", async()=>({}));\n';
  const result = scan(tmpFile('d.ts', body), { only: NEW_RULES });
  assert.ok(!ids(result).has('capability-mismatch'));
});


test('an unrelated clamp elsewhere in the file does not hide a bad join', () => {
  const body =
    'function one(a) {\n  const p = a.q;\n  if (!p.startsWith("/safe/")) throw 1;\n  return p;\n}\n' +
    'function two() {\n  return path.join(ROOT, args.path);\n}\n';
  const result = scan(tmpFile('e.js', body), { only: NEW_RULES });
  const found = result.findings.filter((f) => f.rule === 'path-traversal');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'high');
});

test('one clamped operation does not cover a second unclamped one', () => {
  const body =
    'function a() {\n  const p = path.resolve(ROOT, args.path);\n  if (!p.startsWith(ROOT + path.sep)) throw 1;\n  return p;\n}\n' +
    'function b() {\n  return path.join(ROOT, args.other);\n}\n';
  const result = scan(tmpFile('f.js', body), { only: NEW_RULES });
  const found = result.findings.filter((f) => f.rule === 'path-traversal');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'high');
});

test('separator-less startsWith is downgraded, not cleared', () => {
  const body = 'const p = path.resolve(ROOT, args.path);\nif (!p.startsWith(ROOT)) throw 1;\n';
  const result = scan(tmpFile('g.js', body), { only: NEW_RULES });
  const found = result.findings.filter((f) => f.rule === 'path-traversal');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'medium');
  assert.match(found[0].detail, /safe-evil|separator/);
});

test('a clamp on an unrelated variable is downgraded', () => {
  const body = 'const p = path.resolve(ROOT, args.path);\nif (!other.startsWith("/srv/")) throw 1;\n';
  const result = scan(tmpFile('h.js', body), { only: NEW_RULES });
  const found = result.findings.filter((f) => f.rule === 'path-traversal');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'medium');
});

test('a clamp in a comment does not count', () => {
  const body = '// if (!p.startsWith(ROOT + path.sep)) throw 1;\nreturn path.join(ROOT, args.path);\n';
  const result = scan(tmpFile('i.js', body), { only: NEW_RULES });
  assert.equal(result.findings.filter((f) => f.rule === 'path-traversal')[0].severity, 'high');
});

test('an unrelated .test() call does not hide a raw execSync', () => {
  const body = 'function v(x) {\n  return /^a/.test(x);\n}\nfunction run() {\n  return execSync(args.command, { shell: true });\n}\n';
  const result = scan(tmpFile('j.ts', body), { only: NEW_RULES });
  const found = result.findings.filter((f) => f.rule === 'shell-injection');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'critical');
});

test('a gate in the same block clears shell injection', () => {
  const body = 'if (!ALLOWED.some((r) => r.test(cmd))) throw new Error("no");\nexecSync(args.command);\n';
  const result = scan(tmpFile('k.ts', body), { only: NEW_RULES });
  assert.ok(!ids(result).has('shell-injection'));
});

test('spawn with a caller-controlled executable reports executable control', () => {
  const result = scan(tmpFile('l.ts', 'execFile(args.program, ["--version"]);\n'), { only: NEW_RULES });
  assert.ok(ids(result).has('caller-executable'));
  assert.ok(!ids(result).has('shell-injection'));
});

test('fixed program with caller args and no -- terminator is argument injection', () => {
  const result = scan(tmpFile('m.ts', 'spawn("git", [args.ref, args.file]);\n'), { only: NEW_RULES });
  const found = result.findings.filter((f) => f.rule === 'argument-injection');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'low');
});

test('a -- terminator clears argument injection', () => {
  const result = scan(tmpFile('n.ts', 'spawn("git", ["--", args.file]);\n'), { only: NEW_RULES });
  assert.ok(!ids(result).has('argument-injection'));
});

test('a literal command string is not caller-controlled', () => {
  const result = scan(tmpFile('o.ts', 'execSync("ls -la");\n'), { only: NEW_RULES });
  assert.deepEqual([...ids(result)], []);
});

test('dynamic registration is reported as inconclusive, not safe', () => {
  const body = 'const server = new Server({name:"x"}, { capabilities: base });\nfor (const t of tools) server.registerTool(t);\n';
  const result = scan(tmpFile('p.ts', body), { only: NEW_RULES });
  const found = result.findings.filter((f) => f.rule === 'capability-mismatch');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'info');
  assert.match(found[0].detail, /inconclusive/);
});

test('tools advertised without a tools/call handler is reported', () => {
  const body = 'const s = new Server({name:"x"},{capabilities:{tools:{listChanged:true}}});\ns.setRequestHandler("tools/list", async()=>({}));\n';
  const result = scan(tmpFile('q.ts', body), { only: NEW_RULES });
  const found = result.findings.filter((f) => f.rule === 'capability-mismatch');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'low');
});

test('an allowlist named only in a comment is still unused', () => {
  const body = 'const ALLOWED_COMMANDS = [/^ls/];\n// referenced here only: ALLOWED_COMMANDS\nexecSync(args.command);\n';
  const result = scan(tmpFile('r.ts', body), { only: NEW_RULES });
  assert.ok(ids(result).has('unused-allowlist'));
});

test('review A: an unrelated includes() in the same block does not clear the shell finding', () => {
  const body =
    'const command = args.command;\nif (allowedCommands.includes("ls")) {\n  console.log("validated");\n}\nexecSync(command, { shell: true });\n';
  const result = scan(tmpFile('ra.ts', body), { only: NEW_RULES });
  const found = result.findings.filter((f) => f.rule === 'shell-injection');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'critical');
  assert.match(found[0].detail, /not the command/);
});

test('review A: a guard that mentions the value but never rejects is only likely', () => {
  const body = 'const cmd = args.command;\nif (!ALLOWED.some((r) => r.test(cmd))) {\n  console.warn("warn");\n}\nexecSync(cmd, { shell: true });\n';
  const result = scan(tmpFile('rb.ts', body), { only: NEW_RULES });
  const found = result.findings.filter((f) => f.rule === 'shell-injection');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'high');
});

test('review B: execFile with caller args on a flag program is argument injection', () => {
  const result = scan(tmpFile('rc.ts', 'execFile("tar", ["-czf", args.out, args.dir]);\n'), { only: NEW_RULES });
  const found = result.findings.filter((f) => f.rule === 'argument-injection');
  assert.equal(found.length, 1);
  assert.match(found[0].detail, /tar honours --/);
});

test('review B: a program with no -- convention is not reported', () => {
  const result = scan(tmpFile('rd.ts', 'execFile("my-tool", [args.x]);\n'), { only: NEW_RULES });
  assert.ok(!ids(result).has('argument-injection'));
});

test('review C: an unrelated switch does not prove a tools/call handler exists', () => {
  const body =
    'const s = new Server({name:"x"},{capabilities:{tools:{listChanged:true}}});\n' +
    's.setRequestHandler("tools/list", async()=>({}));\nswitch (mode) { case "fast": break; }\n';
  const result = scan(tmpFile('re.ts', body), { only: NEW_RULES });
  const found = result.findings.filter((f) => f.rule === 'capability-mismatch');
  assert.equal(found.length, 1);
  assert.equal(found[0].confidence, 'inconclusive');
});

test("review C: a banner comment naming tools/call does not count as a handler", () => {
  const body = '// setRequestHandler("tools/call", ...) comes later\nconst s = new Server({name:"x"},{capabilities:{tools:{listChanged:true}}});\ns.setRequestHandler("tools/list", async()=>({}));\n';
  const result = scan(tmpFile('rf.ts', body), { only: NEW_RULES });
  assert.equal(result.findings.length, 1);
  assert.ok(ids(result).has('capability-mismatch'));
});

test('path clamp must belong to the same value and carry a separator', () => {
  const same = scan(tmpFile('rg.ts', 'const p = path.resolve(ROOT, args.path);\nif (!p.startsWith(ROOT + path.sep)) throw 1;\n'), { only: NEW_RULES });
  assert.ok(!ids(same).has('path-traversal'));

  const sibling = scan(tmpFile('rh.ts', 'const ROOT = "/srv/app";\nconst p = path.resolve(ROOT, args.path);\nif (!p.startsWith("/srv/app-sibling")) throw 1;\n'), { only: NEW_RULES });
  assert.equal(sibling.findings[0].severity, 'medium');
});

test('a parameter is caller data even without an args prefix', () => {
  const result = scan(tmpFile('ri.ts', 'function read(pathInput) {\n  return path.join(ROOT, pathInput);\n}\n'), { only: NEW_RULES });
  assert.ok(ids(result).has('path-traversal'));
});
test('the new rules are reachable from the exported ruleset', () => {
  for (const id of ['path-traversal', 'shell-injection', 'caller-executable', 'argument-injection', 'capability-mismatch', 'unused-allowlist']) {
    assert.ok(ALL_RULES.some((r) => r.id === id), `missing rule ${id}`);
  }
});

test('--only limits the rule set', () => {
  const result = scan(fixture('bad-server'), { only: ['shell-exec'] });
  assert.deepEqual([...ids(result)], ['shell-exec']);
});

test('--disable removes a rule', () => {
  const result = scan(fixture('bad-server'), { disable: ['shell-exec'] });
  assert.ok(!ids(result).has('shell-exec'));
});

test('--min-severity filters findings', () => {
  const result = scan(fixture('bad-server'), { minSeverity: 'critical' });
  assert.ok(result.findings.every((f) => f.severity === 'critical'));
});

test('exclude skips paths', () => {
  const result = scan(fixture('bad-server'), { exclude: ['package.json'] });
  assert.ok(result.findings.every((f) => f.file !== 'package.json'));
});

test('findings carry file, line and evidence', () => {
  const result = scan(fixture('bad-server'));
  for (const f of result.findings) {
    assert.equal(typeof f.file, 'string');
    assert.ok(f.line >= 1);
    assert.equal(typeof f.evidence, 'string');
    assert.ok(f.why.length > 20, 'every finding needs an explanation');
    assert.ok(f.fix.length > 5, 'every finding needs a fix');
  }
});

test('findings are ordered by severity', () => {
  const result = scan(fixture('bad-server'));
  const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  for (let i = 1; i < result.findings.length; i += 1) {
    assert.ok(rank[result.findings[i - 1].severity] >= rank[result.findings[i].severity]);
  }
});

test('score is bounded and monotonic', () => {
  assert.equal(score([], 1), 100);
  const few = score([{ severity: 'high' }], 10);
  const many = score([{ severity: 'high' }, { severity: 'high' }], 10);
  assert.ok(few > many);
  assert.ok(many >= 0);
});

test('an empty directory scans clean', () => {
  const result = scan(path.join(here, 'fixtures', 'empty'));
  assert.equal(result.findings.length, 0);
  assert.equal(result.score, 100);
});

test('sarif is valid and carries evidence, not a dangling dash', () => {
  const result = scan(fixture('bad-server'));
  const sarif = JSON.parse(renderSarif(result, { version: '0.0.0' }));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].results.length, result.findings.length);
  for (const r of sarif.runs[0].results) {
    assert.ok(r.message.text.length > 0);
    assert.ok(!r.message.text.endsWith('—'), `dangling dash: ${r.message.text}`);
    assert.ok(r.locations[0].physicalLocation.region.startLine >= 1);
  }
});

test('a repository url is not reported as a git dependency', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-audit-repo-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({
      name: 'x',
      repository: { type: 'git', url: 'git+https://github.com/someone/x.git' },
      dependencies: { pinned: 'git+https://github.com/someone/y.git#0123456789abcdef0123456789abcdef01234567' },
    }),
  );
  const result = scan(dir, { only: ['git-dependency'] });
  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0].evidence, /pinned/);
  assert.equal(result.findings[0].severity, 'low');
});
