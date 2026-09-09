from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import re

from sentinel.config import APP_VERSION
from sentinel.service_update import validate_update_source


def _is_admin() -> bool:
    if os.name != "nt": return False
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception: return False


def _classify_update_error(exc: Exception) -> dict[str, str]:
    match = re.search(r"upgrade target ([^ ]+) must be newer than ([^ ]+)", str(exc))
    if not match:
        return {}
    source_version, current_version = match.groups()
    result = {"source_version": source_version, "current_version": current_version}
    if source_version == current_version:
        result.update({
            "classification": "same_version_upgrade_rejected",
            "recommended_mode": "repair",
        })
    else:
        result.update({
            "classification": "downgrade_rejected",
            "recommended_action": "use_a_build_newer_than_the_installed_version",
        })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel side-effect-free protected update plan acceptance")
    parser.add_argument("--source", type=Path, default=Path("dist") / "BC-Sentinel-Protection")
    parser.add_argument("--target", type=Path)
    parser.add_argument("--mode", choices=("upgrade", "repair"), default="upgrade")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    target = args.target or (Path(os.getenv("ProgramFiles", r"C:\Program Files")) / "BC Sentinel" / "Protection")
    result = {"product": "BC Sentinel", "version": APP_VERSION, "is_admin": _is_admin(), "mode": args.mode, "passed": False}
    try:
        if os.name != "nt": raise RuntimeError("windows_only")
        if not result["is_admin"]: raise RuntimeError("administrator_required_for_machine_integrity_key")
        plan = validate_update_source(args.source, target, mode=args.mode)
        result["plan"] = plan.to_dict()
        result["passed"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        # Keep anti-downgrade fail-closed, but make operator mistakes explicit.
        result.update(_classify_update_error(exc))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.output: args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
