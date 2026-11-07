export function run(args) {
  /* @mcpbench:shell-0:start */execSync(args.command, { shell: true })/* @mcpbench:shell-0:end */;
}
