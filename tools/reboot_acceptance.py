from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path

import psutil

from sentinel.config import APP_VERSION
from sentinel.protection_client import ProtectionServiceClient


def arm(path: Path) -> dict:
    client = ProtectionServiceClient(timeout=2.0)
    status = client.status()
    hardening = client.hardening_status()
    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "armed_utc": datetime.now(timezone.utc).isoformat(),
        "boot_time": psutil.boot_time(),
        "service_pid": (status or {}).get("pid"),
        "service_health": (status or {}).get("health"),
        "hardening_ok": bool((hardening or {}).get("ok")),
    }
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def verify(path: Path) -> dict:
    if not path.exists():
        return {"passed": False, "error": f"state file not found: {path}"}
    prior = json.loads(path.read_text(encoding="utf-8"))
    current_boot = psutil.boot_time()
    client = ProtectionServiceClient(timeout=3.0)
    status = client.status()
    hardening = client.hardening_status()
    rebooted = current_boot > float(prior.get("boot_time") or current_boot) + 1.0
    passed = bool(
        rebooted
        and status
        and status.get("health") in {"HEALTHY", "DEGRADED"}
        and (hardening or {}).get("ok")
        and status.get("transport") == "windows_named_pipe"
    )
    return {
        "passed": passed,
        "reboot_detected": rebooted,
        "previous_boot_time": prior.get("boot_time"),
        "current_boot_time": current_boot,
        "service": status,
        "hardening": hardening,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.6.1 reboot persistence acceptance")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--arm", action="store_true")
    group.add_argument("--verify", action="store_true")
    parser.add_argument("--state", type=Path, default=Path("acceptance-v061-reboot-state.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        result = {"passed": False, "error": "Windows-only acceptance"}
    elif args.arm:
        result = arm(args.state)
        result["passed"] = bool(result.get("service_health") in {"HEALTHY", "DEGRADED"} and result.get("hardening_ok"))
    else:
        result = verify(args.state)
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
