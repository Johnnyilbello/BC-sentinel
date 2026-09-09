from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
import time

from sentinel.config import APP_VERSION
from sentinel.database import Database
from sentinel.firewall_policy import FirewallManager, InMemoryFirewallBackend
from sentinel.protection_client import ProtectionServiceClient
from sentinel.protection_service_core import ProtectionRuntime
from sentinel.web_protection import DNSCorrelationCache, WebProtectionEngine


def _ioc(db: Database, kind: str, value: str):
    db.execute(
        """INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
           VALUES(?,?,?,?,?,?)""",
        (kind, value, "critical", "BC Sentinel harmless Beta2 web response IOC simulation", time.time() + 3600, "web-response-acceptance"),
    )


def _runtime(root: Path) -> ProtectionRuntime:
    root.mkdir(parents=True, exist_ok=True)
    runtime = ProtectionRuntime.__new__(ProtectionRuntime)
    runtime.db = Database(root / "web-response.sqlite")
    runtime.web_protection = WebProtectionEngine(runtime.db)
    runtime.dns_cache = DNSCorrelationCache(ttl_seconds=120)
    runtime.firewall = FirewallManager(InMemoryFirewallBackend(), desired_state_store=runtime.db)
    return runtime


def _finding(runtime: ProtectionRuntime, finding_id: str, *, shared: bool = False):
    runtime.db.record_web_finding(
        finding_id=finding_id, created_at=time.time(), domain="malware.test", remote_address="192.0.2.55",
        pid=4242, process_name="browser.exe", process_path="C:/browser.exe", score=90, level="CRITICAL",
        source="signed_ioc_domain", reasons_json=json.dumps(["signed IOC"]),
        evidence_json=json.dumps({"signed_ioc": True, "event_category": "network", "dns_correlated": True}), shared_ip=shared,
        block_recommended=not shared, decision="review_shared_infrastructure" if shared else "containment_recommended",
    )


def run(*, service_live: bool = False) -> dict:
    result = {"product": "BC Sentinel", "version": APP_VERSION, "harmless_fixture": True, "passed": False}
    with tempfile.TemporaryDirectory(prefix="bcs-web-response-") as raw:
        root = Path(raw)
        runtime = _runtime(root)
        _ioc(runtime.db, "domain", "malware.test")

        runtime.dns_cache.observe(4242, "malware.test", ["192.0.2.55"])
        nonshared = runtime.dns_cache.lookup_context(4242, "192.0.2.55")
        finding_id = "BCW-" + "B" * 20
        _finding(runtime, finding_id)
        lease = runtime.create_web_containment({
            "finding_id": finding_id, "ttl_seconds": 60, "reason": "harmless acceptance", "approved": True,
        })
        rule_present = len(runtime.firewall.list_rules()) == 1
        released = runtime._release_containment_lease(lease["lease_id"], reason="acceptance_release")
        baseline_restored = runtime.firewall.list_rules() == []

        shared_runtime = _runtime(root / "shared")
        _ioc(shared_runtime.db, "domain", "malware.test")
        shared_runtime.dns_cache.observe(4242, "malware.test", ["192.0.2.55"])
        shared_runtime.dns_cache.observe(9009, "other.example.test", ["192.0.2.55"])
        shared = shared_runtime.dns_cache.lookup_context(4242, "192.0.2.55")
        shared_assessment = shared_runtime.web_protection.assess_connection(
            domain="malware.test", address="192.0.2.55", shared_ip=shared.shared_ip,
            domain_count=shared.domain_count, pid_count=shared.pid_count,
        )
        shared_block_denied = False
        shared_id = "BCW-" + "C" * 20
        _finding(shared_runtime, shared_id, shared=True)
        try:
            shared_runtime.create_web_containment({
                "finding_id": shared_id, "ttl_seconds": 60, "reason": "should deny", "approved": True,
            })
        except PermissionError:
            shared_block_denied = True

        local_ok = all([
            nonshared.domain == "malware.test",
            nonshared.shared_ip is False,
            lease.get("qualification") == "signed_domain_nonshared_ip",
            rule_present,
            released.get("removed") is True,
            baseline_restored,
            shared.shared_ip is True,
            shared.domain_count >= 2,
            shared_assessment.block_recommended is False,
            shared_assessment.decision == "review_shared_infrastructure",
            shared_block_denied,
            shared_runtime.firewall.list_rules() == [],
        ])
        result.update({
            "local_foundation_passed": local_ok,
            "nonshared": {"context": nonshared.to_dict(), "lease": lease, "rule_present": rule_present, "baseline_restored": baseline_restored},
            "shared_guard": {"context": shared.to_dict(), "assessment": shared_assessment.to_dict(), "containment_denied": shared_block_denied},
            "safety": {"auto_block": False, "mitm_https": False, "max_web_lease_seconds": 3600, "shared_ip_guard": True},
        })

    live_ok = True
    if service_live:
        client = ProtectionServiceClient(timeout=2.0)
        status = client.web_status()
        findings = client.web_findings(20)
        live_ok = bool(
            isinstance(status, dict)
            and status.get("mode") == "active_reversible"
            and status.get("dns_etw") is True
            and status.get("pid_scoped_dns") is True
            and status.get("shared_ip_guard") is True
            and status.get("mitm_https") is False
            and status.get("auto_block") is False
            and isinstance(findings, list)
        )
        result["service"] = status if isinstance(status, dict) else {"error": client.last_error or "unavailable"}
        result["service_findings_readable"] = isinstance(findings, list)
        result["service_live_passed"] = live_ok

    result["passed"] = bool(result.get("local_foundation_passed") and live_ok)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.7.2 beta.2 active Web Protection safe acceptance")
    parser.add_argument("--service-live", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(service_live=bool(args.service_live))
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
