function read(args) {
  if (!isInside(args.file)) throw new Error('out');
  return fs.readFileSync(/* @mcpbench:path-0:start */path.join(ROOT, args.file)/* @mcpbench:path-0:end */, 'utf8');
}
