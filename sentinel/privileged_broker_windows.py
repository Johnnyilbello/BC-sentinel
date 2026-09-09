from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys

from .protection_client import ProtectionServiceClient


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel one-action privileged broker")
    parser.add_argument("--ticket", required=True, help="Opaque one-time ticket issued by Protection Service")
    args = parser.parse_args(argv)
    if os.name != "nt":
        print(json.dumps({"ok": False, "error": "windows_only"}))
        return 2
    if not _is_admin():
        print(json.dumps({"ok": False, "error": "elevation_required"}))
        return 3
    client = ProtectionServiceClient(timeout=3.0)
    result = client.execute_privileged_ticket(args.ticket)
    print(json.dumps(result, ensure_ascii=False))
    action_ok = bool(result.get("ok") and result.get("action_ok", True))
    return 0 if action_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
