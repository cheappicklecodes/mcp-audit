function read(args) {
  const p = path.resolve(ROOT, args.file);
  if (path.relative(ROOT, p).startsWith('..')) throw new Error('out');
  return fs.readFileSync(p, 'utf8');
}
