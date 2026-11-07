export function run(args) {
  execSync(args.command, { shell: true });
}
