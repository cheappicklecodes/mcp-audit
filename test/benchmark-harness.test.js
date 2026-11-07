import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const repo = process.cwd();

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bench-"));
  fs.cpSync(path.join(repo, "benchmark"), path.join(dir, "benchmark"), { recursive: true });
  fs.cpSync(path.join(repo, "src"), path.join(dir, "src"), { recursive: true });
  return dir;
}

function bench(dir) {
  const out = spawnSync(process.execPath, [path.join(dir, "benchmark", "bench.mjs")], { encoding: "utf8" });
  return { code: out.status, text: `${out.stdout}${out.stderr}` };
}

function edit(dir, file, change) {
  const full = path.join(dir, "benchmark", "cases", file);
  fs.writeFileSync(full, change(fs.readFileSync(full, "utf8")));
}

function json(dir, file, change) {
  edit(dir, file, (text) => {
    const spec = JSON.parse(text);
    change(spec);
    return JSON.stringify(spec, null, 2) + "\n";
  });
}

function withSandbox(fn) {
  const dir = sandbox();
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("an untouched copy of the corpus passes", () => {
  withSandbox((dir) => {
    const { code } = bench(dir);
    assert.equal(code, 0);
  });
});

test("editing a source file without changing expectations exits 3", () => {
  withSandbox((dir) => {
    edit(dir, "shell/literal/index.ts", (t) => `${t}// note\n`);
    const { code, text } = bench(dir);
    assert.equal(code, 3);
    assert.match(text, /changed since the lock/);
  });
});

test("deleting a case exits 3", () => {
  withSandbox((dir) => {
    fs.rmSync(path.join(dir, "benchmark", "cases", "args", "spread"), { recursive: true });
    const { code, text } = bench(dir);
    assert.equal(code, 3);
    assert.match(text, /locked case is gone/);
  });
});

test("adding a case without locking it exits 3", () => {
  withSandbox((dir) => {
    fs.cpSync(path.join(dir, "benchmark", "cases", "shell", "literal"), path.join(dir, "benchmark", "cases", "shell", "extra"), { recursive: true });
    json(dir, "shell/extra/expected.json", (s) => {
      s.id = "shell/extra";
    });
    const { code, text } = bench(dir);
    assert.equal(code, 3);
    assert.match(text, /not in the lock/);
  });
});

test("a missing manifest exits 3", () => {
  withSandbox((dir) => {
    fs.rmSync(path.join(dir, "benchmark", "manifest.lock.json"));
    const { code, text } = bench(dir);
    assert.equal(code, 3);
    assert.match(text, /manifest\.lock\.json is missing/);
  });
});

test("--update-lock rewrites the manifest and the corpus passes again", () => {
  withSandbox((dir) => {
    edit(dir, "shell/literal/index.ts", (t) => `${t}// note\n`);
    assert.equal(bench(dir).code, 3);
    const relock = spawnSync(process.execPath, [path.join(dir, "benchmark", "bench.mjs"), "--update-lock"], { encoding: "utf8" });
    assert.equal(relock.status, 0);
    assert.equal(bench(dir).code, 0);
  });
});

test("a schemaVersion 1 expectation exits 2, not 3", () => {
  withSandbox((dir) => {
    json(dir, "shell/literal/expected.json", (s) => {
      s.schemaVersion = 1;
    });
    const { code, text } = bench(dir);
    assert.equal(code, 2);
    assert.match(text, /schemaVersion 2/);
  });
});

test("a dangling marker exits 2", () => {
  withSandbox((dir) => {
    json(dir, "path/join-bare/expected.json", (s) => {
      s.expectedFindings[0].anchor.marker = "nope";
    });
    const { code, text } = bench(dir);
    assert.equal(code, 2);
    assert.match(text, /no marker nope/);
  });
});

test("duplicate expected ids exit 2", () => {
  withSandbox((dir) => {
    json(dir, "path/join-bare/expected.json", (s) => {
      s.expectedFindings.push({ ...s.expectedFindings[0], anchor: { file: "index.ts", marker: "path-0" } });
    });
    const { code, text } = bench(dir);
    assert.equal(code, 2);
    assert.match(text, /duplicate expected finding id|marker path-0 reused/);
  });
});

test("an unknown severity exits 2", () => {
  withSandbox((dir) => {
    json(dir, "path/join-bare/expected.json", (s) => {
      s.expectedFindings[0].severity = "severe";
    });
    const { code, text } = bench(dir);
    assert.equal(code, 2);
    assert.match(text, /severity must be/);
  });
});

test("an unknown family exits 2", () => {
  withSandbox((dir) => {
    json(dir, "path/join-bare/expected.json", (s) => {
      s.family = "made-up";
    });
    const { code, text } = bench(dir);
    assert.equal(code, 2);
    assert.match(text, /unknown family/);
  });
});

test("a spec id that disagrees with its directory exits 2", () => {
  withSandbox((dir) => {
    json(dir, "path/join-bare/expected.json", (s) => {
      s.id = "path/elsewhere";
    });
    const { code, text } = bench(dir);
    assert.equal(code, 2);
    assert.match(text, /spec\.id says/);
  });
});

test("a negative case carrying an expectation exits 2", () => {
  withSandbox((dir) => {
    edit(dir, "shell/literal/index.ts", (t) => t.replace("ls -la", "/* @mcpbench:shell-0:start */ls -la/* @mcpbench:shell-0:end */"));
    json(dir, "shell/literal/expected.json", (s) => {
      s.expectedFindings.push({
        id: "x",
        rule: "shell-injection",
        severity: "low",
        anchor: { file: "index.ts", marker: "shell-0" },
      });
    });
    const { code, text } = bench(dir);
    assert.equal(code, 2);
    assert.match(text, /negative case expects nothing/);
  });
});

test("overlapping anchors for one rule exit 2", () => {
  withSandbox((dir) => {
    edit(dir, "path/join-bare/index.ts", (t) => t.replace(
      "path.join(ROOT, args.file)",
      "/* @mcpbench:outer:start */path.join(ROOT, args.file)/* @mcpbench:outer:end */",
    ));
    json(dir, "path/join-bare/expected.json", (s) => {
      s.expectedFindings.push({ id: "outer", rule: "path-traversal", severity: "high", anchor: { file: "index.ts", marker: "outer" } });
    });
    const { code, text } = bench(dir);
    assert.equal(code, 2);
    assert.match(text, /overlap/);
  });
});
