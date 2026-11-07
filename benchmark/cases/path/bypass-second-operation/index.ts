export function one(args) {
  const p = path.resolve(ROOT, args.a);
  if (!p.startsWith(ROOT + path.sep)) throw new Error("outside");
  return p;
}
export function two(args) {
  return /* @mcpbench:path-0:start */path.join(ROOT, args.b)/* @mcpbench:path-0:end */;
}
