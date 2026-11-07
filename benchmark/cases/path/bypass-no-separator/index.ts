const ROOT = "/srv/app";
export function read(args) {
  const p = /* @mcpbench:path-0:start */path.resolve(ROOT, args.file)/* @mcpbench:path-0:end */;
  if (!p.startsWith("/srv/app")) throw new Error("outside");
  return fs.readFileSync(p, "utf8");
}
