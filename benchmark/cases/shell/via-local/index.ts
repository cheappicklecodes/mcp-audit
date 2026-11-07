export function run(args) {
  const cmd = args.command;
  execSync(cmd);
}
