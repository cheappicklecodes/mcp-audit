export function run(req) {
  const { command } = req.params.arguments;
  /* @mcpbench:shell-0:start */execSync(command)/* @mcpbench:shell-0:end */;
}
