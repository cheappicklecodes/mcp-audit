import fs from 'node:fs';
import path from 'node:path';
import { globToRegExp, readText } from './util.js';

export const CODE_EXT = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx',
  '.py', '.rb', '.go', '.rs', '.sh', '.bash', '.ps1', '.zsh',
]);

export const CONFIG_EXT = new Set(['.json', '.jsonc', '.yaml', '.yml', '.toml', '.ini']);

export const SKIP_FILES = new Set(['agents.lock']);

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage',
  '.next', '.venv', 'venv', '__pycache__', '.mypy_cache', '.pytest_cache',
  '.turbo', '.cache', 'vendor', 'target', '.idea', '.vscode',
]);

const MAX_FILES = 4000;
const MAX_DEPTH = 14;

export function discover(root, { exclude = [], include = [] } = {}) {
  const excluded = exclude.map(globToRegExp);
  const included = include.length ? include.map(globToRegExp) : null;
  const files = [];
  let truncated = false;

  const walk = (dir, depth) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (files.length >= MAX_FILES) {
        truncated = true;
        return;
      }
      const abs = path.join(dir, entry.name);
      const relative = path.relative(root, abs).split(path.sep).join('/');

      if (excluded.some((re) => re.test(relative) || re.test(entry.name))) continue;

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (depth >= MAX_DEPTH) continue;
        walk(abs, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      if (SKIP_FILES.has(entry.name)) continue;

      const ext = path.extname(entry.name).toLowerCase();
      const isManifest = MANIFESTS.has(entry.name);
      const isCode = CODE_EXT.has(ext);
      const isConfig = CONFIG_EXT.has(ext);
      if (!isManifest && !isCode && !isConfig) continue;
      if (included && !included.some((re) => re.test(relative))) continue;

      const text = readText(abs);
      if (text === null) continue;
      files.push({ abs, relative, ext, name: entry.name, text });
    }
  };

  walk(root, 0);
  return { files, truncated };
}

export const MANIFESTS = new Set([
  'package.json', 'pyproject.toml', 'requirements.txt', 'setup.py',
  'Gemfile', 'go.mod', 'Cargo.toml', 'Dockerfile', 'docker-compose.yml',
  'mcp.json', 'server.json', 'claude_desktop_config.json',
  '.mcp.json', 'compose.yaml', 'Makefile',
]);