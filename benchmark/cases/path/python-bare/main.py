from pathlib import Path
ROOT = Path("/srv")
def read(p):
    return (ROOT / p).read_text()
