"""Run archived Beta1 contracts in an isolated compatibility workspace, without starting services."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    scratch = Path(tempfile.mkdtemp(prefix="BCSentinel-beta1-compat-"))
    archive = scratch / "runtime.zip"
    subprocess.run(
        ["git", "archive", "--format=zip", f"--output={archive}", "7d90b682955b49c03b677f6b318b0c7fb80306fb", "sentinel", "tools"],
        cwd=repo, check=True,
    )
    with zipfile.ZipFile(archive) as source:
        source.extractall(scratch)
    for folder in ("sentinel", "tools"):
        for source in (repo / folder).glob("*.py"):
            shutil.copy2(source, scratch / folder / source.name)
    (scratch / "tests").mkdir()
    for source in (repo / "tests" / "historical").glob("test_v011_beta1_*.py"):
        shutil.copy2(source, scratch / "tests" / source.name)
    for commit, name in (
        ("15702be", "RETEST-V011-BETA1-WINDOWS-PERF.ps1"),
        ("6c68027", "TEST-V011-BETA1-ADMIN-PHASE.ps1"),
    ):
        content = subprocess.check_output(["git", "show", f"{commit}:{name}"], cwd=repo)
        (scratch / name).write_bytes(content)
    env = dict(os.environ, PYTHONPATH=str(scratch), QT_QPA_PLATFORM="offscreen")
    patch = (
        "from tools.v011_service_update_windows_compat import apply_compat_patch; "
        "from tools.v011_threat_package_windows_compat import apply_compat_patch as packages; "
        "print(apply_compat_patch()); print(packages())"
    )
    subprocess.run([sys.executable, "-c", patch], cwd=scratch, env=env, check=True)
    print(f"Compatibility workspace retained at {scratch}", flush=True)
    print("Historical PowerShell scripts are inspected as text, never executed.", flush=True)
    return subprocess.call(
        [sys.executable, "-m", "pytest", "tests", "-q", "--basetemp", str(scratch / "test-temp")],
        cwd=scratch, env=env,
    )


if __name__ == "__main__":
    raise SystemExit(main())
