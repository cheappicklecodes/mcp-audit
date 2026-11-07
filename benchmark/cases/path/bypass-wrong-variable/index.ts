export function read(args) {
  const p = path.resolve(ROOT, args.file);
  if (!other.startsWith(ROOT + path.sep)) throw new Error("outside");
  return fs.readFileSync(p, "utf8");
}
