from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path

from sentinel.config import APP_VERSION
from sentinel.ioc_denylist import IOCBundleError, SignedIOCVerifier
from sentinel.protection_client import ProtectionServiceClient

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_PATH = ROOT / "rules" / "ioc-denylist-v1.safe-fixture.json"
SIGNATURE_PATH = ROOT / "rules" / "ioc-denylist-v1.safe-fixture.sig"
EXPECTED_SEQUENCE = 1
EXPECTED_ACTIVE = 2
EXPECTED_NETWORK = "192.0.2.240"
EXPECTED_EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _load_fixture() -> tuple[dict, str]:
    return (
        json.loads(BUNDLE_PATH.read_text(encoding="utf-8")),
        SIGNATURE_PATH.read_text(encoding="utf-8").strip(),
    )


def run(*, native_service: bool = True) -> dict:
    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "is_admin": _is_admin(),
        "harmless_fixture": True,
        "passed": False,
    }
    bundle, signature = _load_fixture()
    verifier = SignedIOCVerifier()
    verified = verifier.verify(bundle, signature)
    result["signature_verified"] = True
    result["payload_sha256"] = verified.payload_sha256
    result["bundle_id"] = verified.bundle_id
    result["sequence"] = verified.sequence
    result["entries"] = len(verified.entries)

    tampered = json.loads(json.dumps(bundle))
    tampered["bundle_id"] = str(tampered["bundle_id"]) + ".tampered"
    try:
        verifier.verify(tampered, signature)
    except IOCBundleError:
        result["tamper_rejected"] = True
    else:
        result["tamper_rejected"] = False
        result["error"] = "tampered_bundle_was_accepted"
        return result

    if not native_service:
        result["native_service_check"] = "not_requested"
        result["passed"] = bool(result["signature_verified"] and result["tamper_rejected"])
        return result
    if os.name != "nt":
        result["native_service_check"] = "windows_only_skipped"
        result["passed"] = bool(result["signature_verified"] and result["tamper_rejected"])
        return result
    if not result["is_admin"]:
        result["error"] = "administrator_required"
        return result

    client = ProtectionServiceClient(timeout=3.0)
    status = client.status() or {}
    if status.get("health") != "HEALTHY":
        result["error"] = client.last_error or "service_not_healthy"
        return result

    before_rules = client.firewall_rules(limit=500)
    before_ids = {str(x.get("rule_id") or "") for x in before_rules if x.get("rule_id")}
    response = client.import_ioc_bundle(bundle, signature, approved=True)
    result["import"] = response
    if not response.get("ok"):
        result["error"] = client.last_error or "ioc_import_failed"
        return result

    feed = client.ioc_status() or {}
    entries = client.ioc_entries(limit=100)
    after_rules = client.firewall_rules(limit=500)
    after_ids = {str(x.get("rule_id") or "") for x in after_rules if x.get("rule_id")}
    result["feed_status"] = feed
    result["active_entries"] = len(entries)
    result["eicar_present"] = any(
        str(item.get("kind") or "") == "sha256" and str(item.get("value") or "").casefold() == EXPECTED_EICAR_SHA256
        for item in entries
    )
    result["test_net_present"] = any(
        str(item.get("kind") or "") == "network" and str(item.get("value") or "") == EXPECTED_NETWORK
        for item in entries
    )
    result["firewall_baseline_unchanged"] = after_ids == before_ids
    result["passed"] = all([
        result["signature_verified"],
        result["tamper_rejected"],
        bool(feed.get("installed")),
        int(feed.get("sequence") or 0) == EXPECTED_SEQUENCE,
        int(feed.get("active_entries") or 0) == EXPECTED_ACTIVE,
        result["eicar_present"],
        result["test_net_present"],
        result["firewall_baseline_unchanged"],
    ])
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.7.1 beta.3 signed IOC acceptance")
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
