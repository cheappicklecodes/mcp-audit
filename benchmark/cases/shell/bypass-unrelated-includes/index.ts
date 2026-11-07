export function run(args) {
  const cmd = args.command;
  if (ALLOWED.includes("ls")) {
    log("checked");
  }
  /* @mcpbench:shell-0:start */execSync(cmd, { shell: true })/* @mcpbench:shell-0:end */;
}
