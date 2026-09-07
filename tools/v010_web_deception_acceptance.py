from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path

from sentinel.config import APP_VERSION
from sentinel.database import Database
from sentinel.protection_client import ProtectionServiceClient
from sentinel.web_deception import HEURISTIC_PROFILE
from sentinel.web_protection import WebProtectionEngine
from tools.v090_release_candidate_acceptance import run as run_v090_rc1

ROOT = Path(__file__).resolve().parents[1]


def _insert_domain_ioc(db: Database, domain: str) -> None:
    db.execute(
        """INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
           VALUES('domain',?,?,?,?,?)""",
        (domain, "critical", "v0.10 harmless signed-domain fixture", time.time() + 3600, "v010-beta1-fixture"),
    )


def _local_matrix() -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-v010-beta1-") as tmp:
        db = Database(Path(tmp) / "web.sqlite")
        engine = WebProtectionEngine(db)

        safe_login = engine.assess_url("https://example.com/login")
        safe_invoice = engine.assess_url("https://example.com/invoice/123")
        nested_only = engine.assess_url("https://example.com/continue?next=https%3A%2F%2Fexample.org%2Fhome")
        mixed_script = engine.assess_url(
            "https://user:pass@раypal.example/verify-account?next=https%3A%2F%2Fexample.org%2F"
        )
        raw_ip_lure = engine.assess_url("https://192.0.2.10/login?verify=account")

        _insert_domain_ioc(db, "malware.test")
        signed = engine.assess_url("https://malware.test/login")

        db.add_web_domain_trust("trusted.example", reason="v0.10 exact-domain safe fixture")
        trusted = engine.assess_url("https://trusted.example/verify-payment")

    return {
        "safe_login": safe_login.to_dict(),
        "safe_invoice": safe_invoice.to_dict(),
        "nested_redirect_only": nested_only.to_dict(),
        "mixed_script_deception": mixed_script.to_dict(),
        "raw_ip_lure": raw_ip_lure.to_dict(),
        "signed_ioc": signed.to_dict(),
        "trusted_domain": trusted.to_dict(),
    }


def run(*, service_live: bool = False) -> dict:
    frozen = run_v090_rc1(service_live=False)
    matrix = _local_matrix()

    heuristic_cases = [
        matrix["safe_login"],
        matrix["safe_invoice"],
        matrix["nested_redirect_only"],
        matrix["mixed_script_deception"],
        matrix["raw_ip_lure"],
    ]
    all_heuristics_below_high = all(
        int(item.get("score") or 0) <= 49
        and item.get("block_recommended") is False
        and item.get("decision") != "containment_recommended"
        for item in heuristic_cases
    )
    safe_lure_words_unscored = bool(
        int(matrix["safe_login"].get("score") or 0) < 20
        and int(matrix["safe_invoice"].get("score") or 0) < 20
    )
    deception_detected = bool(
        int(matrix["mixed_script_deception"].get("score") or 0) >= 20
        and "mixed_script_hostname" in matrix["mixed_script_deception"].get("signal_codes", [])
        and "scam_lure" in matrix["mixed_script_deception"].get("risk_families", [])
    )
    signed_precedence = bool(
        matrix["signed_ioc"].get("signed_ioc") is True
        and int(matrix["signed_ioc"].get("score") or 0) >= 85
        and matrix["signed_ioc"].get("decision") == "containment_recommended"
    )
    trusted_precedence = bool(
        matrix["trusted_domain"].get("trusted_domain") is True
        and int(matrix["trusted_domain"].get("score") or 0) == 0
        and matrix["trusted_domain"].get("decision") == "allow_trusted"
    )

    local_passed = bool(
        APP_VERSION == "0.10.0-beta.1"
        and frozen.get("passed")
        and all_heuristics_below_high
        and safe_lure_words_unscored
        and deception_detected
        and signed_precedence
        and trusted_precedence
    )

    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "milestone": "v0.10.0-beta.1",
        "profile": HEURISTIC_PROFILE,
        "service_live_requested": bool(service_live),
        "frozen_v090_rc1_regression": bool(frozen.get("passed")),
        "matrix": matrix,
        "safety": {
            "heuristic_score_cap": 49,
            "all_heuristics_below_high": all_heuristics_below_high,
            "safe_lure_words_unscored": safe_lure_words_unscored,
            "signed_ioc_precedence": signed_precedence,
            "exact_trust_precedence": trusted_precedence,
            "deception_detected": deception_detected,
            "mitm_https": False,
            "heuristic_auto_block": False,
            "heuristic_destructive_action": False,
        },
        "local_passed": local_passed,
    }

    live_passed = None
    live = None
    if service_live:
        client = ProtectionServiceClient(timeout=3.0)
        status = client.web_status() or {}
        safe = client.web_assess("https://example.com/login") or {}
        risky = client.web_assess("https://user:pass@раypal.example/verify-account") or {}
        live_passed = bool(
            status.get("deception_profile") == HEURISTIC_PROFILE
            and status.get("mitm_https") is False
            and status.get("auto_block") is False
            and status.get("heuristic_can_qualify_high") is False
            and int(status.get("heuristic_score_cap") or 0) == 49
            and int(safe.get("score") or 0) < 20
            and int(risky.get("score") or 0) <= 49
            and risky.get("block_recommended") is False
            and "mixed_script_hostname" in risky.get("signal_codes", [])
        )
        live = {"status": status, "safe": safe, "risky": risky}

    result["service"] = live
    result["service_live_passed"] = live_passed
    result["passed"] = bool(local_passed and (not service_live or live_passed))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.10.0-beta.1 web deception/anti-scam acceptance")
    parser.add_argument("--service-live", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(service_live=bool(args.service_live))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
