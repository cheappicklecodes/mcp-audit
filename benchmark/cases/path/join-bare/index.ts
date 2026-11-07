export function read(args) {
  return fs.readFileSync(/* @mcpbench:path-0:start */path.join(ROOT, args.file)/* @mcpbench:path-0:end */, "utf8");
}
