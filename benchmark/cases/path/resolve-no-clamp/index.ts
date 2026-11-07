export function read(args) {
  return fs.readFileSync(path.resolve(ROOT, args.file), "utf8");
}
