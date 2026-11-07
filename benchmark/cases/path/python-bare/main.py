from pathlib import Path
ROOT = Path("/srv")
def read(p):
    return (/* @mcpbench:path-0:start */ROOT / p/* @mcpbench:path-0:end */).read_text()
