export function run(req) {
  const { command } = req.params.arguments;
  execSync(command);
}
