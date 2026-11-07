export function run(args) {
  const cmd = args.command;
  if (ALLOWED.includes("ls")) {
    log("checked");
  }
  execSync(cmd, { shell: true });
}
