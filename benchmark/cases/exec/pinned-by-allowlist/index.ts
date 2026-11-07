const PROGRAMS = ["git", "ls"];
export function run(args) {
  if (!PROGRAMS.includes(args.tool)) throw new Error("unknown");
  execFile(args.tool, ["status"]);
}
