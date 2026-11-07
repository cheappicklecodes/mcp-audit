function read(args) {
  return fs.readFileSync(path.normalize(path.join(ROOT, args.file)), 'utf8');
}
