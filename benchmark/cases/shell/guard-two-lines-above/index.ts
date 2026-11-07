function run(args) {
  const cmd = args.command;
  assert(ALLOWED.includes(cmd));
  execSync(cmd);
}
