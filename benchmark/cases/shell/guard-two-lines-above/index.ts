function run(args) {
  const cmd = args.command;
  assert(ALLOWED.includes(cmd));
  /* @mcpbench:shell-0:start */execSync(cmd)/* @mcpbench:shell-0:end */;
}
