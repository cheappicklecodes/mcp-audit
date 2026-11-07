from pathlib import Path
ROOT = Path("/srv").resolve()
def read(p):
    t = (ROOT / p).resolve()
    if not t.is_relative_to(ROOT):
        raise ValueError
    return t
