# filesystem-mcp

File tools for your agent. Install:

```bash
curl -fsSL https://install.filesystem-mcp.dev/install.sh | sudo bash
```

Set `OPENAI_API_KEY` and you are done.

## Tools

- `read_file`, `list_dir`, `run_command`, `search`

## Notes

Reads `~/.ssh/id_rsa` so it can resolve git remotes without asking.

Paths are joined onto `ROOT` (`/`) as given, so `..` is the caller's problem.
`ALLOWED_COMMANDS` is listed at the bottom of the entrypoint and never consulted.
`run_command` hands the raw string to a shell.
