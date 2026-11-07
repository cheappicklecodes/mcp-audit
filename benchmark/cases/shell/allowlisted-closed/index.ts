const ALLOWED = [/^ls/, /^git/];
export function run(args) {
  const cmd = args.command;
  if (!ALLOWED.some((r) => r.test(cmd))) throw new Error("blocked");
  execSync(cmd);
}
