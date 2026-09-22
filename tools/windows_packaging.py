"""Run PyInstaller without unrelated application DLL directories from PATH."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


def build_environment(environment: dict[str, str], python: str, base_python: str) -> dict[str, str]:
    result = dict(environment)
    windows = Path(environment["SystemRoot"])
    directories = [Path(python).parent, Path(base_python).parent, windows / "System32", windows]
    result["PATH"] = os.pathsep.join(dict.fromkeys(str(path) for path in directories))
    for name in ("PYTHONPATH", "PYTHONHOME", "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH"):
        result.pop(name, None)
    return result


def main() -> int:
    if sys.platform != "win32":
        raise SystemExit("Windows packaging requires Windows")
    environment = build_environment(dict(os.environ), sys.executable, sys._base_executable)
    return subprocess.run([sys.executable, "-m", "PyInstaller", *sys.argv[1:]], env=environment).returncode


if __name__ == "__main__":
    raise SystemExit(main())
