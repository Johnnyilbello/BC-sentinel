from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
from time import sleep
from typing import Any

PROFILE = "v0.11.0-beta.2-diagnostic-cleanup-v6"
MARKER_TRACE = "bc-sentinel-v011-beta2-marker-trace-v1"
QUEUE_TRACE = "bc-sentinel-v011-beta2-queue-scan-trace-v4"
OBSERVATION_MARKER = "bc-sentinel-v011-beta2-watchdog-file-observation-v1"
ADMISSION_MARKER = "bc-sentinel-v011-beta2-watchdog-edr-admission-v2"

TARGETS = (
    Path("sentinel") / "watchdog_coalescing.py",
    Path("sentinel") / "realtime.py",
    Path("sentinel") / "protection_service_core.py",
    Path("sentinel") / "edr_adapter.py",
    Path("sentinel") / "edr_service_bridge.py",
)


def _atomic_replace(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".v011-beta2-diagnostic-cleanup.tmp")
    tmp.write_text(text, encoding="utf-8")
    last: BaseException | None = None
    for attempt in range(8):
        try:
            os.replace(tmp, path)
            return
        except OSError as exc:
            last = exc
            if attempt + 1 < 8:
                sleep(min(0.05 * (2**attempt), 0.8))
    try:
        tmp.unlink(missing_ok=True)
    except Exception:
        pass
    raise RuntimeError(f"atomic promotion failed for {path}: {last}")


def _backup_for(path: Path) -> Path:
    return path.with_name(path.name + ".pre-v011-beta2-marker-trace.bak")


def _is_instrumented(text: str) -> bool:
    return MARKER_TRACE in text or QUEUE_TRACE in text or "from .b2_diagnostic_trace import" in text


def _validate_backup(path: Path, backup_text: str) -> None:
    ast.parse(backup_text)
    if MARKER_TRACE in backup_text or QUEUE_TRACE in backup_text:
        raise RuntimeError(f"diagnostic backup is itself instrumented: {path.name}")
    if "from .b2_diagnostic_trace import" in backup_text:
        raise RuntimeError(f"diagnostic trace import unexpectedly present in backup: {path.name}")
    if path.name == "realtime.py" and OBSERVATION_MARKER not in backup_text:
        raise RuntimeError("realtime diagnostic backup predates required B2 observation bridge")
    if path.name == "protection_service_core.py":
        if OBSERVATION_MARKER not in backup_text:
            raise RuntimeError("core diagnostic backup predates required B2 observation bridge")
        if ADMISSION_MARKER not in backup_text:
            raise RuntimeError("core diagnostic backup predates required bounded admission v2")


def apply(root: Path) -> dict[str, Any]:
    root = root.resolve()
    results: dict[str, Any] = {}
    for rel in TARGETS:
        path = root / rel
        if not path.is_file():
            raise RuntimeError(f"required source missing: {rel}")
        current = path.read_text(encoding="utf-8")
        instrumented = _is_instrumented(current)
        if not instrumented:
            ast.parse(current)
            results[str(rel)] = {"changed": False, "status": "already_clean"}
            continue

        backup = _backup_for(path)
        if not backup.is_file():
            raise RuntimeError(f"cannot safely clean {rel}: marker-trace backup missing")
        backup_text = backup.read_text(encoding="utf-8")
        _validate_backup(path, backup_text)
        _atomic_replace(path, backup_text)
        restored = path.read_text(encoding="utf-8")
        ast.parse(restored)
        if _is_instrumented(restored):
            raise RuntimeError(f"diagnostic cleanup verification failed for {rel}")
        results[str(rel)] = {
            "changed": True,
            "status": "restored_pre_marker_trace_backup",
            "backup": str(backup),
        }

    return {
        "profile": PROFILE,
        "checkpoint": "B2-diagnostic-cleanup-before-final-fix",
        "passed": True,
        "automatic_destructive_action": False,
        "targets": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely remove temporary B2 marker diagnostics using their exact pre-instrumentation backups")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    result = apply(Path(args.root))
    changed = sum(1 for item in result["targets"].values() if item["changed"])
    print(f"v0.11 Beta2 B2 diagnostic cleanup V6: PASS | restored={changed}/{len(TARGETS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
