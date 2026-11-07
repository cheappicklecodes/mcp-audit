export function run(args) {
  const cmd = args.command;
  /* @mcpbench:shell-0:start */execSync(cmd)/* @mcpbench:shell-0:end */;
}
