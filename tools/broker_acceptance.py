from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path

from sentinel.config import APP_VERSION
from sentinel.protection_client import ProtectionServiceClient


def _is_admin() -> bool:
    if os.name != "nt": return False
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception: return False


def run() -> dict:
    result = {"product": "BC Sentinel", "version": APP_VERSION, "is_admin": _is_admin(), "passed": False}
    if os.name != "nt":
        result["error"] = "windows_only"
        return result
    if result["is_admin"]:
        result["error"] = "run_from_standard_powershell"
        result["detail"] = "Broker acceptance must start from a non-elevated process so direct privileged IPC is rejected before UAC."
        return result

    client = ProtectionServiceClient(timeout=2.0)
    before = client.status()
    if not isinstance(before, dict) or before.get("health") != "HEALTHY":
        result["error"] = client.last_error or "service_not_healthy"
        return result
    hardening = client.hardening_status() or {}
    if not hardening.get("ok"):
        result["error"] = "hardening_not_healthy"
        return result
    current_network = bool(before.get("network"))
    metrics_before = dict(before.get("privileged_broker") or {})

    direct = client.request("set_network_collection", enabled=current_network)
    if client._error_code(direct) != "admin_required":
        result["error"] = "direct_standard_user_gate_failed"
        result["direct"] = direct
        return result

    action = client._privileged_request("set_network_collection", enabled=current_network)
    after = client.status() or {}
    metrics_after = dict(after.get("privileged_broker") or {})
    result.update({
        "direct_gate": "admin_required",
        "action": action,
        "network_before": current_network,
        "network_after": bool(after.get("network")),
        "health_after": after.get("health"),
        "broker_before": metrics_before,
        "broker_after": metrics_after,
        "hardening_after": client.hardening_status(),
    })
    result["passed"] = bool(
        action.get("ok")
        and bool(after.get("network")) == current_network
        and after.get("health") == "HEALTHY"
        and (result["hardening_after"] or {}).get("ok")
        and int(metrics_after.get("completed") or 0) >= int(metrics_before.get("completed") or 0) + 1
        and int(metrics_after.get("consumed") or 0) >= int(metrics_before.get("consumed") or 0) + 1
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel standard-user -> UAC one-action broker acceptance")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.output: args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
