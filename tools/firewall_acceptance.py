from __future__ import annotations

import argparse
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import time

from sentinel.config import APP_VERSION
from sentinel.firewall_policy import MANAGED_FIREWALL_GROUP
from sentinel.protection_client import ProtectionServiceClient

TEST_NET_ADDRESS = "192.0.2.77"  # TEST-NET-1 documentation range; never a real Internet host.
OBSERVABILITY_TIMEOUT_SECONDS = 5.0
OBSERVABILITY_POLL_SECONDS = 0.20


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _rules(client: ProtectionServiceClient) -> list[dict]:
    value = client.firewall_rules(limit=500)
    return list(value) if isinstance(value, list) else []


def _canonical_network(value: object) -> tuple[int, int, int] | None:
    """Canonicalize a single Windows Firewall remote address for comparison.

    INetFwRule may round-trip an IPv4 host as either ``192.0.2.77``,
    ``192.0.2.77/32`` or ``192.0.2.77/255.255.255.255``.  Those are the
    same network and must not produce a false observability failure.
    """
    raw = str(value or "").strip()
    if not raw or "," in raw:
        return None
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None
    return network.version, int(network.network_address), network.prefixlen


def _remote_address_matches(expected: object, observed: object) -> bool:
    left = _canonical_network(expected)
    right = _canonical_network(observed)
    return left is not None and left == right


def _rule_matches_probe(item: dict, rule_id: str) -> bool:
    return bool(
        str(item.get("rule_id") or "") == rule_id
        and str(item.get("managed_group") or "") == MANAGED_FIREWALL_GROUP
        and _remote_address_matches(TEST_NET_ADDRESS, item.get("remote_address"))
        and str(item.get("direction") or "").casefold() == "outbound"
        and str(item.get("protocol") or "").casefold() == "any"
        and item.get("remote_port") in (None, "")
        and not str(item.get("application_path") or "").strip()
        and bool(item.get("enabled"))
    )


def _wait_for_rule(client: ProtectionServiceClient, rule_id: str, *, present: bool) -> tuple[bool, list[dict]]:
    deadline = time.monotonic() + OBSERVABILITY_TIMEOUT_SECONDS
    last: list[dict] = []
    while True:
        last = _rules(client)
        found = any(str(item.get("rule_id") or "") == rule_id for item in last)
        if found is present:
            return True, last
        if time.monotonic() >= deadline:
            return False, last
        time.sleep(OBSERVABILITY_POLL_SECONDS)


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
    if result["is_admin"]:
        result["error"] = "run_from_standard_powershell"
        result["detail"] = "Firewall broker acceptance must begin from a non-elevated PowerShell."
        return result

    client = ProtectionServiceClient(timeout=2.0)
    before = client.status()
    firewall_before = client.firewall_status()
    hardening_before = client.hardening_status() or {}
    if not isinstance(before, dict) or before.get("health") != "HEALTHY":
        result["error"] = client.last_error or "service_not_healthy"
        return result
    if not isinstance(firewall_before, dict) or not firewall_before.get("available"):
        result["error"] = "firewall_backend_unavailable"
        result["firewall_before"] = firewall_before
        return result
    if firewall_before.get("enforcement_ready") is not True:
        result["error"] = "firewall_enforcement_not_ready"
        result["firewall_before"] = firewall_before
        result["detail"] = "Windows Firewall must be enabled on active profiles and local policy must be effective; BC Sentinel will not override Group Policy or global firewall state."
        return result
    if not hardening_before.get("ok"):
        result["error"] = "hardening_not_healthy"
        return result

    baseline_rules = _rules(client)
    baseline_ids = {str(item.get("rule_id") or "") for item in baseline_rules if item.get("rule_id")}
    result["baseline_managed_rules"] = len(baseline_rules)
    result["baseline_rule_ids"] = sorted(baseline_ids)

    direct = client.request(
        "firewall_block_remote",
        remote_address=TEST_NET_ADDRESS,
        direction="outbound",
        protocol="any",
        reason="BC Sentinel v0.7 firewall acceptance probe",
        incident_id="BCI-FIREWALL-ACCEPTANCE",
        approved=True,
    )
    if client._error_code(direct) != "admin_required":
        result["error"] = "direct_standard_user_gate_failed"
        result["direct"] = direct
        return result
    result["direct_gate"] = "admin_required"

    rule_id = ""
    added: dict = {}
    present = False
    removed: dict = {}
    absent = False
    primary_error = ""

    try:
        added = client.firewall_block_remote(
            TEST_NET_ADDRESS,
            approved=True,
            direction="outbound",
            protocol="any",
            reason="BC Sentinel v0.7 firewall acceptance probe",
            incident_id="BCI-FIREWALL-ACCEPTANCE",
        )
        result["add"] = added
        if not isinstance(added, dict) or not added.get("ok"):
            primary_error = "firewall_add_failed"
            return result

        rule = dict(added.get("rule") or {})
        rule_id = str(rule.get("rule_id") or "")
        result["rule_id"] = rule_id
        if not rule_id:
            primary_error = "firewall_add_returned_no_rule_id"
            return result

        observed, rules_after_add = _wait_for_rule(client, rule_id, present=True)
        matching = next(
            (item for item in rules_after_add if str(item.get("rule_id") or "") == rule_id),
            None,
        )
        present = bool(observed and matching and _rule_matches_probe(matching, rule_id))
        result["present_after_add"] = present
        if matching:
            result["observed_rule_after_add"] = matching
        if not present:
            primary_error = "firewall_rule_not_observable_after_add"
            return result
    finally:
        # Transactional acceptance: if ADD returned an owned logical rule id, a
        # REMOVE is attempted regardless of any subsequent assertion failure.
        if rule_id:
            removed = client.firewall_remove_rule(rule_id, approved=True)
            result["remove"] = removed
            observed_absent, rules_after_remove = _wait_for_rule(client, rule_id, present=False)
            absent = bool(observed_absent)
            result["absent_after_remove"] = absent
            result["managed_rules_after_cleanup"] = len(rules_after_remove)
            if not absent:
                result["cleanup_required_rule_id"] = rule_id

        after = client.status() or {}
        hardening_after = client.hardening_status() or {}
        firewall_after = client.firewall_status() or {}
        final_rules = _rules(client)
        final_ids = {str(item.get("rule_id") or "") for item in final_rules if item.get("rule_id")}
        result.update({
            "health_after": after.get("health"),
            "hardening_after": hardening_after,
            "firewall_after": firewall_after,
            "final_managed_rules": len(final_rules),
            "baseline_restored": final_ids == baseline_ids,
        })
        if primary_error:
            result["error"] = primary_error

        result["passed"] = bool(
            added.get("ok")
            and present
            and removed.get("ok")
            and removed.get("removed") is True
            and absent
            and final_ids == baseline_ids
            and after.get("health") == "HEALTHY"
            and hardening_after.get("ok")
            and firewall_after.get("available")
            and firewall_after.get("enforcement_ready") is True
        )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BC Sentinel v0.7 standard-user -> UAC -> Windows Firewall block/remove acceptance"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
