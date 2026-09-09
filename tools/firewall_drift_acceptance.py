from __future__ import annotations

import argparse
import ctypes
import gc
import json
import os
from pathlib import Path
import time

from sentinel.config import APP_VERSION
from sentinel.firewall_windows import WindowsFirewallBackend
from sentinel.protection_client import ProtectionServiceClient

TEST_NET_ADDRESS = "192.0.2.88"
POLL_SECONDS = 0.20
TIMEOUT_SECONDS = 5.0


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _wait_for_drift(client: ProtectionServiceClient, rule_id: str, issue_type: str, present: bool) -> tuple[bool, dict]:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    last: dict = {}
    while True:
        last = client.firewall_drift() or {}
        found = any(
            str(item.get("rule_id") or "") == rule_id and str(item.get("type") or "") == issue_type
            for item in (last.get("issues") or [])
        )
        if found is present:
            return True, last
        if time.monotonic() >= deadline:
            return False, last
        time.sleep(POLL_SECONDS)


def _externally_disable_owned_rule(rule_id: str) -> bool:
    backend = WindowsFirewallBackend()
    changed = False
    with backend._policy() as policy:
        rule = None
        with backend._materialized_rules(policy) as rules:
            for rule in rules:
                if not backend._is_owned(rule):
                    continue
                if backend._rule_id_from_rule(rule) != rule_id:
                    continue
                rule.Enabled = False
                changed = True
                break
            rule = None
        gc.collect()
    return changed


def run() -> dict:
    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "is_admin": _is_admin(),
        "test_remote_address": TEST_NET_ADDRESS,
        "passed": False,
    }
    if os.name != "nt":
        result["error"] = "windows_only"
        return result
    if not result["is_admin"]:
        result["error"] = "administrator_required"
        result["detail"] = "The drift acceptance intentionally simulates an external administrator changing one BC Sentinel-owned rule."
        return result

    client = ProtectionServiceClient(timeout=2.0)
    status = client.status() or {}
    firewall = client.firewall_status() or {}
    if status.get("health") != "HEALTHY":
        result["error"] = client.last_error or "service_not_healthy"
        return result
    if firewall.get("enforcement_ready") is not True:
        result["error"] = "firewall_enforcement_not_ready"
        result["firewall"] = firewall
        return result

    baseline = client.firewall_rules(limit=500)
    baseline_ids = {str(x.get("rule_id") or "") for x in baseline if x.get("rule_id")}
    result["baseline_rule_ids"] = sorted(baseline_ids)

    rule_id = ""
    try:
        added = client.request(
            "firewall_block_remote",
            remote_address=TEST_NET_ADDRESS,
            direction="outbound",
            protocol="any",
            reason="BC Sentinel v0.7.1 drift acceptance probe",
            incident_id="BCI-FIREWALL-DRIFT-ACCEPTANCE",
            approved=True,
        )
        result["add"] = added
        if not added.get("ok"):
            result["error"] = "firewall_add_failed"
            return result
        rule_id = str((added.get("rule") or {}).get("rule_id") or "")
        result["rule_id"] = rule_id
        if not rule_id:
            result["error"] = "missing_rule_id"
            return result

        if not _externally_disable_owned_rule(rule_id):
            result["error"] = "external_disable_failed"
            return result
        result["external_mutation"] = "disabled"

        seen, drift = _wait_for_drift(client, rule_id, "disabled", True)
        result["drift_after_external_disable"] = drift
        result["disabled_drift_observed"] = seen
        if not seen:
            result["error"] = "disabled_drift_not_observed"
            return result

        repaired = client.request("firewall_reconcile", approved=True)
        result["reconcile"] = repaired
        if not repaired.get("ok") or not (repaired.get("reconciliation") or {}).get("ok"):
            result["error"] = "reconciliation_failed"
            return result

        cleared, after = _wait_for_drift(client, rule_id, "disabled", False)
        result["drift_after_reconcile"] = after
        result["drift_cleared"] = cleared and bool(after.get("ok"))
        if not result["drift_cleared"]:
            result["error"] = "drift_not_cleared"
            return result

        result["passed"] = True
        return result
    finally:
        if rule_id:
            removed = client.request("firewall_remove_rule", rule_id=rule_id, approved=True)
            result["cleanup"] = removed
        final_rules = client.firewall_rules(limit=500)
        final_ids = {str(x.get("rule_id") or "") for x in final_rules if x.get("rule_id")}
        result["baseline_restored"] = final_ids == baseline_ids
        if result.get("passed") and not result["baseline_restored"]:
            result["passed"] = False
            result["error"] = "baseline_not_restored"


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.7.1 native firewall drift acceptance")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
