const ROOT = "/srv/app";
export function read(args) {
  const p = path.resolve(ROOT, args.file);
  if (!p.startsWith("/srv/app")) throw new Error("outside");
  return fs.readFileSync(p, "utf8");
}
