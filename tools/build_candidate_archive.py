"""Archive a generated candidate tree without PowerShell exclusive file locks."""
from pathlib import Path
import sys
import zipfile

root = Path(sys.argv[1]).resolve(strict=True)
archive = Path(sys.argv[2]).resolve()
if archive.is_relative_to(root):
    raise ValueError("archive must be outside payload")
with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED) as output:
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("generated package contains a link")
        if path.is_file():
            output.write(path, path.relative_to(root.parent))
