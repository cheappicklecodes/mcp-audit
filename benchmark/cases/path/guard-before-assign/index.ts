function read(args) {
  if (!isInside(args.file)) throw new Error('out');
  return fs.readFileSync(path.join(ROOT, args.file), 'utf8');
}
