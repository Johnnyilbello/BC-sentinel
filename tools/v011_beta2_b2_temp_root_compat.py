from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REALTIME_TARGET = ROOT / "sentinel" / "realtime.py"
PROFILE = "v0.11.0-beta.2-interactive-temp-root-v1"

_OLD_HELPER = '''def _watchdog_recursive_for_root(path: Path) -> bool:
    try:
        target = canonical_path(path)
    except Exception:
        return True
    high_churn = set()
    for raw in (os.getenv("TEMP", ""), os.getenv("APPDATA", "")):
        if not raw:
            continue
        try:
            high_churn.add(canonical_path(Path(raw)))
        except Exception:
            continue
    return target not in high_churn
'''

_NEW_HELPER = '''def _watchdog_recursive_for_root(path: Path) -> bool:
    try:
        target = canonical_path(path)
    except Exception:
        return True
    high_churn = set()
    for raw in (os.getenv("TEMP", ""), os.getenv("APPDATA", "")):
        if not raw:
            continue
        try:
            high_churn.add(canonical_path(Path(raw)))
        except Exception:
            continue
    if target in high_churn:
        return False

    # Windows services commonly run under a different account from the
    # interactive user. Service TEMP/APPDATA can therefore differ from roots
    # already present in monitored_dirs. Detect the well-known high-churn roots
    # structurally so the low-CPU policy remains account-independent. Setting
    # recursive=False still preserves events for direct children of the root.
    parts = [
        part.casefold()
        for part in str(target).replace("/", "\\\\").rstrip("\\\\").split("\\\\")
        if part
    ]
    suffixes = (
        ("appdata", "local", "temp"),
        ("appdata", "roaming"),
        ("windows", "temp"),
    )
    if any(len(parts) >= len(suffix) and tuple(parts[-len(suffix):]) == suffix for suffix in suffixes):
        return False
    return True
'''


def is_structural_high_churn_root(raw_path: str) -> bool:
    """Account-independent classifier mirrored by the injected runtime helper."""
    parts = [
        part.casefold()
        for part in str(raw_path or "").replace("/", "\\").rstrip("\\").split("\\")
        if part
    ]
    suffixes = (
        ("appdata", "local", "temp"),
        ("appdata", "roaming"),
        ("windows", "temp"),
    )
    return any(
        len(parts) >= len(suffix) and tuple(parts[-len(suffix):]) == suffix
        for suffix in suffixes
    )


def apply_interactive_temp_root_fix(path: Path = REALTIME_TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"realtime.py missing: {path}")

    text = path.read_text(encoding="utf-8")
    if _NEW_HELPER in text:
        return {
            "patched": False,
            "already_compatible": True,
            "path": str(path),
            "profile": PROFILE,
        }

    if text.count(_OLD_HELPER) != 1:
        raise RuntimeError(
            "Unexpected watchdog recursion helper shape; refusing B2 TEMP-root compatibility patch"
        )

    updated = text.replace(_OLD_HELPER, _NEW_HELPER, 1)
    path.write_text(updated, encoding="utf-8")

    verify = path.read_text(encoding="utf-8")
    required = (
        "if target in high_churn:",
        '("appdata", "local", "temp")',
        '("appdata", "roaming")',
        '("windows", "temp")',
        'str(target).replace("/", "\\\\").rstrip("\\\\").split("\\\\")',
        "return False\n    return True",
    )
    missing = [marker for marker in required if marker not in verify]
    if missing:
        raise RuntimeError("B2 TEMP-root compatibility patch incomplete: " + "; ".join(missing))

    return {
        "patched": True,
        "already_compatible": False,
        "path": str(path),
        "profile": PROFILE,
    }


def main() -> int:
    result = apply_interactive_temp_root_fix()
    if result["patched"]:
        print(
            "v0.11 Beta2 B2 watchdog compatibility: interactive-user TEMP/AppData roots "
            "are now classified independently of the service account environment"
        )
    else:
        print("v0.11 Beta2 B2 watchdog compatibility: interactive TEMP-root fix already canonical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
