import { makeFinding, lineOf, snippet, parseJson } from '../util.js';

export const shellPipeExec = {
  id: 'curl-pipe-shell',
  group: 'supply-chain',
  title: 'Remote script piped into a shell',
  severity: 'high',
  why:
    'The installer runs whatever the host serves at call time. No version, no digest, no review. If that URL is ' +
    'ever re-pointed, you get new code with your existing permissions.',
  fix: 'Pin a tag and verify a checksum, or vendor the script.',
  check(file) {
    if (!/\.(sh|bash|ps1|md|ya?ml|json|toml|mdx)$/.test(file.ext)) return [];
    const re = /(curl|wget)\s+[^\n|]*\b(https?:\/\/[^\s"'|)]+)[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/g;
    const out = [];
    let m;
    while ((m = re.exec(file.text))) {
      out.push(
        makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 70), {
          detail: m[2],
        }),
      );
    }
    return out;
  },
};

export const installLifecycleScripts = {
  id: 'install-script',
  group: 'supply-chain',
  title: 'Package runs code at install time',
  severity: 'medium',
  why:
    'preinstall/install/postinstall executes before you have run anything, with your user permissions. ' +
    'This is the standard vector for a compromised dependency.',
  fix: 'Read the script. Pin the version and check it has no network access.',
  check(file) {
    if (file.name !== 'package.json') return [];
    const pkg = parseJson(file.text);
    if (!pkg || typeof pkg.scripts !== 'object') return [];
    const out = [];
    for (const key of ['preinstall', 'install', 'postinstall', 'prepare']) {
      const cmd = pkg.scripts?.[key];
      if (typeof cmd !== 'string') continue;
      const idx = file.text.indexOf(`"${key}"`);
      out.push(
        makeFinding(this, file.relative, lineOf(file.text, idx), `${key}: ${cmd}`, {
          detail: 'executes on npm install',
        }),
      );
    }
    return out;
  },
};

export const unpinnedDependencies = {
  id: 'unpinned-dependency',
  group: 'supply-chain',
  title: 'Dependency ranges that can float',
  severity: 'medium',
  why:
    'A caret or star range means today’s install and tomorrow’s install can be different code. For a component ' +
    'that holds credentials and runs commands, that is unearned trust.',
  fix: 'Pin exact versions, or at minimum commit a lockfile and install with `npm ci`.',
  check(file) {
    const out = [];
    if (file.name === 'package.json') {
      const pkg = parseJson(file.text);
      if (!pkg) return [];
      for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
        for (const [dep, range] of Object.entries(pkg[field] ?? {})) {
          if (typeof range !== 'string') continue;
          if (/^(\*|latest|next|beta|canary)$/.test(range) || /^[\^~]/.test(range)) {
            const idx = file.text.indexOf(`"${dep}"`);
            out.push(
              makeFinding(this, file.relative, lineOf(file.text, idx), `${dep}: ${range}`, {
                detail: range.startsWith('^') || range.startsWith('~') ? 'floating range' : 'floating tag',
              }),
            );
          }
        }
      }
      return out;
    }

    if (file.name === 'requirements.txt') {
      file.text.split(/\r?\n/).forEach((line, i) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) return;
        if (/git\+|https?:\/\/|^-e /.test(trimmed)) return;
        const name = trimmed.split(/[<>=!~ ]/)[0];
        if (!name) return;
        if (/==/.test(trimmed) || /@/.test(trimmed)) return;
        out.push(makeFinding(this, file.relative, i + 1, trimmed, { detail: 'no exact pin' }));
      });
      return out;
    }

    if (file.name === 'pyproject.toml') {
      file.text.split(/\r?\n/).forEach((line, i) => {
        const m = /^\s*"?([A-Za-z0-9_.\-]+)"?\s*[>=~^]*\s*[>=~^]*\s*$/.exec(line);
        if (!m) return;
        out.push(makeFinding(this, file.relative, i + 1, line.trim(), { detail: 'no exact pin' }));
      });
    }
    return out;
  },
};

export const gitDependency = {
  id: 'git-dependency',
  group: 'supply-chain',
  title: 'Dependency installed straight from git',
  severity: 'medium',
  why: 'Branch and tag refs move; a git dependency without a commit SHA gives you unreviewed, mutable code.',
  fix: 'Pin to a full 40-character commit SHA.',
  check(file) {
    if (!/\.(json|toml|txt)$/.test(file.ext)) return [];
    const re = /(git\+ssh:\/\/|git\+https:\/\/|git:\/\/|https:\/\/github\.com\/[^"'\s]+\/tarball\/)[^"'\s]*/g;
    const out = [];
    let m;
    while ((m = re.exec(file.text))) {
      const spec = m[0];
      const hasSha = /[0-9a-f]{40}/.test(spec);
      out.push(
        makeFinding(this, file.relative, lineOf(file.text, m.index), spec, {
          severity: hasSha ? 'low' : this.severity,
          detail: hasSha ? 'pinned to a commit' : 'ref can move',
        }),
      );
    }
    return out;
  },
};

export const rules = [shellPipeExec, installLifecycleScripts, unpinnedDependencies, gitDependency];