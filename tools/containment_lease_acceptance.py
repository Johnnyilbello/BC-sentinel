from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path

from sentinel.config import APP_VERSION
from sentinel.protection_client import ProtectionServiceClient

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_PATH = ROOT / "rules" / "ioc-denylist-v1.safe-fixture.json"
SIGNATURE_PATH = ROOT / "rules" / "ioc-denylist-v1.safe-fixture.sig"
TEST_NET_ADDRESS = "192.0.2.240"


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run() -> dict:
    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "is_admin": _is_admin(),
        "test_remote_address": TEST_NET_ADDRESS,
        "harmless_fixture": True,
        "qualification": "signed_ioc",
        "passed": False,
    }
    if os.name != "nt":
        result["error"] = "windows_only"
        return result
    if not result["is_admin"]:
        result["error"] = "administrator_required"
        return result

    client = ProtectionServiceClient(timeout=3.0)
    status = client.status() or {}
    if status.get("health") != "HEALTHY":
        result["error"] = client.last_error or "service_not_healthy"
        return result

    # Ensure the harmless signed TEST-NET IOC exists. Import is idempotent at
    # the same signed sequence/digest and does not mutate the firewall itself.
    bundle = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))
    signature = SIGNATURE_PATH.read_text(encoding="utf-8").strip()
    imported = client.import_ioc_bundle(bundle, signature, approved=True)
    result["ioc_import"] = imported
    if not imported.get("ok"):
        result["error"] = client.last_error or "ioc_import_failed"
        return result

    baseline = client.firewall_rules(limit=500)
    baseline_ids = {str(x.get("rule_id") or "") for x in baseline if x.get("rule_id")}
    result["baseline_rule_ids"] = sorted(baseline_ids)

    lease_id = ""
    rule_id = ""
    try:
        created = client.containment_lease_create(
            TEST_NET_ADDRESS,
            ttl_seconds=60,
            approved=True,
            reason="BC Sentinel v0.7.1 beta.3 containment acceptance",
            incident_id="",
        )
        result["create"] = created
        if not created.get("ok"):
            result["error"] = client.last_error or "containment_create_failed"
            return result
        lease = created.get("lease") or {}
        lease_id = str(lease.get("lease_id") or "")
        rule_id = str(lease.get("rule_id") or "")
        result["lease_id"] = lease_id
        result["rule_id"] = rule_id
        observed = client.firewall_rules(limit=500)
        matching = next((x for x in observed if str(x.get("rule_id") or "") == rule_id), None)
        active = client.containment_leases()
        result["rule_present"] = bool(
            matching
            and bool(matching.get("enabled"))
            and str(matching.get("direction") or "").casefold() == "outbound"
        )
        result["lease_persisted"] = any(str(x.get("lease_id") or "") == lease_id for x in active)
        if not result["rule_present"] or not result["lease_persisted"]:
            result["error"] = "lease_not_observable"
            return result

        released = client.containment_lease_release(lease_id, approved=True)
        result["release"] = released
        if not released.get("ok"):
            result["error"] = client.last_error or "containment_release_failed"
            return result
        final = client.firewall_rules(limit=500)
        final_ids = {str(x.get("rule_id") or "") for x in final if x.get("rule_id")}
        result["rule_absent_after_release"] = rule_id not in final_ids
        result["baseline_restored"] = final_ids == baseline_ids
        result["passed"] = bool(
            lease_id and rule_id and result["rule_present"] and result["lease_persisted"]
            and result["rule_absent_after_release"] and result["baseline_restored"]
        )
        return result
    finally:
        if lease_id and not result.get("rule_absent_after_release"):
            cleanup = client.containment_lease_release(lease_id, approved=True)
            result["cleanup"] = cleanup
        final = client.firewall_rules(limit=500)
        final_ids = {str(x.get("rule_id") or "") for x in final if x.get("rule_id")}
        result["baseline_restored"] = final_ids == baseline_ids
        if result.get("passed") and not result["baseline_restored"]:
            result["passed"] = False
            result["error"] = "baseline_not_restored"


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.7.1 beta.3 reversible containment lease acceptance")
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
