export function one(args) {
  const p = path.resolve(ROOT, args.a);
  if (!p.startsWith(ROOT + path.sep)) throw new Error("outside");
  return p;
}
export function two(args) {
  return path.join(ROOT, args.b);
}
