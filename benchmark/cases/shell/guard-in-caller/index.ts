function run(cmd: string) {
  if (!ALLOWED.includes(cmd)) throw new Error('no');
  execSync(cmd);
}
