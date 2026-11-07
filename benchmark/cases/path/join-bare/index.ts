export function read(args) {
  return fs.readFileSync(path.join(ROOT, args.file), "utf8");
}
