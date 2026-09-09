from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from pathlib import Path

from sentinel.config import APP_VERSION
from sentinel.database import Database
from sentinel.protection_client import ProtectionServiceClient
from sentinel.web_protection import DNSCorrelationCache, WebProtectionEngine, extract_ip_addresses


def _insert_safe_domain_ioc(db: Database, domain: str = "malware.test") -> None:
    db.execute(
        """INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
           VALUES('domain',?,?,?,?,?)""",
        (domain, "critical", "BC Sentinel harmless web acceptance IOC simulation", time.time() + 3600, "web-acceptance-local"),
    )


def run(*, service_live: bool = False) -> dict:
    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "harmless_fixture": True,
        "service_live_requested": bool(service_live),
        "passed": False,
    }
    with tempfile.TemporaryDirectory(prefix="bcs-web-protection-") as raw:
        db = Database(Path(raw) / "web-acceptance.sqlite")
        _insert_safe_domain_ioc(db)
        engine = WebProtectionEngine(db)

        signed = engine.assess_domain("sub.malware.test").to_dict()
        heuristic = engine.assess_url("https://user:pass@xn--paypa1-l2c.a.b.c.d.example.com/login").to_dict()
        cache = DNSCorrelationCache(ttl_seconds=60)
        inserted = cache.observe(41001, "malware.test", ["192.0.2.55"])
        same_pid = cache.lookup(41001, "192.0.2.55")
        other_pid = cache.lookup(41002, "192.0.2.55")
        parsed = extract_ip_addresses("type: 1 192.0.2.55; type: 28 2001:db8::55; invalid 999.2.3.4")

        local_ok = bool(
            signed.get("signed_ioc") is True
            and signed.get("block_recommended") is True
            and signed.get("decision") == "containment_recommended"
            and int(signed.get("score") or 0) >= 85
            and int(heuristic.get("score") or 0) < 50
            and heuristic.get("block_recommended") is False
            and heuristic.get("decision") == "review"
            and inserted == 1
            and same_pid == "malware.test"
            and other_pid == ""
            and parsed == ["192.0.2.55", "2001:db8::55"]
        )
        result.update({
            "signed_domain": signed,
            "structural_phishing": heuristic,
            "dns_correlation": {
                "inserted": inserted,
                "same_pid_domain": same_pid,
                "other_pid_domain": other_pid,
                "pid_scoped": cache.status().get("pid_scoped"),
                "parsed_addresses": parsed,
            },
            "local_foundation_passed": local_ok,
            "safety": {
                "mitm_https": False,
                "auto_block_from_heuristics": False,
                "signed_domain_action": "recommend_containment_only",
            },
        })

    live_ok = True
    if service_live:
        client = ProtectionServiceClient(timeout=2.0)
        status = client.web_status()
        live_ok = bool(
            isinstance(status, dict)
            and status.get("mode") in {"observe_recommend", "active_reversible"}
            and status.get("pid_scoped_dns") is True
            and status.get("mitm_https") is False
            and status.get("auto_block") is False
        )
        # On the native Windows service acceptance path DNS ETW is a release gate.
        if os.name == "nt":
            live_ok = live_ok and status.get("dns_etw") is True
        result["service"] = status if isinstance(status, dict) else {"error": client.last_error or "unavailable"}
        result["service_live_passed"] = live_ok

    result["passed"] = bool(result.get("local_foundation_passed") and live_ok)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.7.2 Beta 1 Web Protection safe acceptance")
    parser.add_argument("--service-live", action="store_true", help="Also require installed service Web Protection status; on Windows DNS ETW must be active.")
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
