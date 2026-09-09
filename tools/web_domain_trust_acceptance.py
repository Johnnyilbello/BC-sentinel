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
from sentinel.protection_protocol import ClientContext, build_request
from sentinel.protection_service_core import ProtectionRuntime, ProtectionServiceCore
from sentinel.web_protection import DNSCorrelationCache, WebProtectionEngine, classify_browser_process

SECRET = "d" * 64
AUTH_USER = ClientContext(local=True, authenticated=True, is_admin=False, sid="S-1-5-21-webtrust", session_id=1, transport="acceptance", process_id=7201)
ADMIN = ClientContext(local=True, authenticated=True, is_admin=True, sid="S-1-5-32-544", session_id=1, transport="acceptance", process_id=7202)


def _ioc(db: Database, domain: str) -> None:
    db.execute(
        """INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
           VALUES('domain',?,?,?,?,?)""",
        (domain, "critical", "BC Sentinel harmless Beta3 domain-trust acceptance IOC", time.time() + 3600, "web-trust-acceptance"),
    )


def _runtime(root: Path) -> ProtectionRuntime:
    runtime = ProtectionRuntime.__new__(ProtectionRuntime)
    runtime.db = Database(root / "web-domain-trust.sqlite")
    runtime.web_protection = WebProtectionEngine(runtime.db)
    runtime.dns_cache = DNSCorrelationCache(ttl_seconds=120)
    runtime.firewall = FirewallManager(InMemoryFirewallBackend(), desired_state_store=runtime.db)
    runtime.events = type("E", (), {"sequence": 0, "since": lambda self, seq, limit: []})()
    return runtime


def run(*, service_live: bool = False) -> dict:
    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "harmless_fixture": True,
        "service_live_requested": bool(service_live),
        "passed": False,
    }
    with tempfile.TemporaryDirectory(prefix="bcs-web-domain-trust-") as raw:
        root = Path(raw)
        runtime = _runtime(root)
        db = runtime.db
        engine = runtime.web_protection

        domain = "xn--paypa1-l2c.a.b.c.d.example.com"
        before = engine.assess_domain(domain).to_dict()
        trust = db.add_web_domain_trust(domain, reason="harmless exact-domain acceptance trust")
        exact = engine.assess_domain(domain).to_dict()
        sub = engine.assess_domain("child." + domain).to_dict()

        _ioc(db, domain)
        overridden = engine.assess_domain(domain).to_dict()
        conflicts = db.web_domain_trust_conflicts()

        # Persistent trust changes are privileged even when harmless.
        core = ProtectionServiceCore(runtime, secret=SECRET)
        core._audit = lambda *a, **k: None
        new_domain = "portal.example.test"
        request = build_request(
            "web_domain_trust_add", SECRET, domain=new_domain, reason="acceptance", finding_id="", approved=True,
        )
        denied = core.dispatch(request, AUTH_USER)
        allowed = core.dispatch(request, ADMIN)
        removed = core.dispatch(
            build_request("web_domain_trust_remove", SECRET, domain=new_domain, approved=True), ADMIN
        )

        # Local reputation/provenance remains bounded and deterministic.
        for idx in range(3):
            db.record_web_domain_observation(
                domain="observed.example.test", score=20 + idx, status="suspicious", source="network",
                process_name="chrome.exe", process_path="C:/Chrome/chrome.exe", remote_address=f"192.0.2.{20+idx}",
            )
        reputation = runtime.web_domain_reputation("observed.example.test")
        browser = classify_browser_process("chrome.exe", "C:/Chrome/chrome.exe", "Google LLC")
        fake_browser = classify_browser_process("chrome-helper-malware.exe", "C:/Temp/chrome-helper-malware.exe", "Google LLC")

        local_ok = bool(
            int(before.get("score") or 0) > 0
            and exact.get("status") == "trusted"
            and exact.get("decision") == "allow_trusted"
            and exact.get("trusted_domain") is True
            and sub.get("trusted_domain") is False
            and overridden.get("signed_ioc") is True
            and overridden.get("status") == "malicious"
            and any(item.get("state") == "overridden_by_signed_ioc" for item in overridden.get("provenance") or [])
            and len(conflicts) == 1
            and (denied.get("error") or {}).get("code") == "admin_required"
            and allowed.get("ok") is True
            and removed.get("ok") is True
            and db.match_web_domain_trust(new_domain) is None
            and reputation.get("observations") == 3
            and reputation.get("current_assessment", {}).get("provenance") is not None
            and browser.get("is_browser") is True
            and browser.get("browser_family") == "Chrome"
            and fake_browser.get("is_browser") is False
        )
        result.update({
            "local_foundation_passed": local_ok,
            "scope": {
                "domain": domain,
                "exact_domain_trusted": bool(exact.get("trusted_domain")),
                "subdomain_inherits_trust": bool(sub.get("trusted_domain")),
                "scope": trust.get("scope"),
            },
            "precedence": {
                "order": "signed_ioc>local_domain_trust>heuristics",
                "signed_ioc_overrides_trust": bool(overridden.get("signed_ioc") and overridden.get("trusted_domain")),
                "conflict_count": len(conflicts),
            },
            "privilege": {
                "standard_user_blocked": (denied.get("error") or {}).get("code") == "admin_required",
                "admin_add_passed": bool(allowed.get("ok")),
                "admin_remove_passed": bool(removed.get("ok")),
            },
            "reputation": reputation,
            "browser_context": {"known": browser, "lookalike": fake_browser},
            "safety": {
                "wildcard_trust": False,
                "subdomain_inheritance": False,
                "signed_ioc_precedence": True,
                "mitm_https": False,
                "auto_block_from_trust": False,
            },
        })

    live_ok = True
    if service_live:
        client = ProtectionServiceClient(timeout=2.0)
        status = client.web_status()
        trust_rows = client.web_domain_trust()
        reputation_live = client.web_domain_reputation("example.test")
        live_ok = bool(
            isinstance(status, dict)
            and status.get("mode") == "active_reversible"
            and status.get("domain_trust_exact_only") is True
            and status.get("signed_ioc_overrides_trust") is True
            and status.get("mitm_https") is False
            and status.get("auto_block") is False
            and isinstance(trust_rows, list)
            and isinstance(reputation_live, dict)
        )
        result["service"] = status if isinstance(status, dict) else {"error": client.last_error or "unavailable"}
        result["service_trust_count"] = len(trust_rows) if isinstance(trust_rows, list) else -1
        result["service_reputation_readable"] = isinstance(reputation_live, dict)
        result["service_live_passed"] = live_ok

    result["passed"] = bool(result.get("local_foundation_passed") and live_ok)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.7.2 Beta 3 Domain Trust & provenance safe acceptance")
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
