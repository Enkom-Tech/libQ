import re
from pathlib import Path

root = Path("reference")
n = 0
for p in root.rglob("Cargo.toml"):
    t = p.read_text(encoding="utf-8")
    t2 = re.sub(r', version = "0\.0\.2"', "", t)
    if t2 != t:
        p.write_text(t2, encoding="utf-8")
        n += 1
print("reverted", n, "files under reference/")
