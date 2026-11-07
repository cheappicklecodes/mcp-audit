export function read(args) {
  const p = /* @mcpbench:path-0:start */path.resolve(ROOT, args.file)/* @mcpbench:path-0:end */;
  if (!other.startsWith(ROOT + path.sep)) throw new Error("outside");
  return fs.readFileSync(p, "utf8");
}
