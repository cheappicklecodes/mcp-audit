const ALLOWED = [/^ls/];
export function run(args) {
  const cmd = args.command;
  if (!ALLOWED.some((r) => r.test(cmd))) console.warn("unknown");
  execSync(cmd);
}
