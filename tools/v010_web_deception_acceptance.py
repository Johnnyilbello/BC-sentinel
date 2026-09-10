from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path

from sentinel.config import APP_VERSION
from sentinel.database import Database
from sentinel.protection_client import ProtectionServiceClient
from sentinel.service_update import version_key
from sentinel.web_deception import HEURISTIC_PROFILE, HEURISTIC_SCORE_CAP, assess_local_url
from sentinel.web_protection import WebProtectionEngine
from tools.v090_release_candidate_acceptance import run as run_v090_rc1

ROOT = Path(__file__).resolve().parents[1]


def _insert_domain_ioc(db: Database, domain: str) -> None:
    db.execute(
        """INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
           VALUES('domain',?,?,?,?,?)""",
        (domain, "critical", "v0.10 harmless signed-domain fixture", time.time() + 3600, "v010-beta1-fixture"),
    )


def _pure_local_matrix() -> dict[str, dict[str, object]]:
    fixtures = {
        "safe_login": assess_local_url("https://example.com/login"),
        "benign_idn": assess_local_url("https://xn--bcher-kva.example/catalog"),
        "mixed_script_deception": assess_local_url(
            "https://user:pass@раypal.example/verify-account", declared_identity="PayPal"
        ),
        "typosquat": assess_local_url(
            "https://micros0ft.example/login", declared_identity="Microsoft"
        ),
        "brand_subdomain_abuse": assess_local_url(
            "https://login.microsoft.com.evil.example/verify", declared_identity="Microsoft"
        ),
        "canonical_microsoft": assess_local_url(
            "https://login.microsoftonline.com/common/oauth2/authorize", declared_identity="Microsoft"
        ),
        "raw_ip_lure": assess_local_url("https://192.0.2.10/login?verify=account"),
        "redirect_lookalike": assess_local_url(
            "https://paypa1.example/verify-account",
            declared_identity="PayPal",
            redirect_chain=(
                "https://www.paypal.com/",
                "https://redirect.example/continue",
                "https://paypa1.example/verify-account",
            ),
        ),
    }
    return {name: value.to_dict() for name, value in fixtures.items()}


def _enterprise_false_positive_matrix() -> dict[str, dict[str, object]]:
    fixtures = (
        ("microsoft", "https://login.microsoftonline.com/common/oauth2/authorize", "Microsoft"),
        ("google", "https://accounts.google.com/signin/v2", "Google"),
        ("github", "https://github.com/login", "GitHub"),
        ("github_cdn", "https://objects.githubusercontent.com/assets/app.js", ""),
        ("jsdelivr", "https://cdn.jsdelivr.net/npm/example/index.js", ""),
        ("cloudflare", "https://static.cloudflareinsights.com/beacon.min.js", "Cloudflare"),
        ("salesforce", "https://login.salesforce.com/", "Salesforce"),
        ("atlassian", "https://id.atlassian.com/login", "Atlassian"),
    )
    return {
        name: assess_local_url(url, declared_identity=identity).to_dict()
        for name, url, identity in fixtures
    }


def _engine_precedence_matrix() -> dict[str, dict[str, object]]:
    with tempfile.TemporaryDirectory(prefix="bcs-v010-beta1-") as tmp:
        db = Database(Path(tmp) / "web.sqlite")
        engine = WebProtectionEngine(db)

        _insert_domain_ioc(db, "malware.test")
        signed = engine.assess_url("https://malware.test/login")

        db.add_web_domain_trust("trusted.example", reason="v0.10 exact-domain safe fixture")
        trusted = engine.assess_url("https://trusted.example/verify-payment")

        db.add_web_domain_trust("override.test", reason="older local trust fixture")
        _insert_domain_ioc(db, "override.test")
        override = engine.assess_url("https://override.test/login")

    return {
        "signed_ioc": signed.to_dict(),
        "trusted_domain": trusted.to_dict(),
        "signed_ioc_overrides_trust": override.to_dict(),
    }


def run(*, service_live: bool = False) -> dict:
    # This is a local regression gate only. It MUST NOT be interpreted as native
    # v0.9 freeze evidence; checkpoint 4 explicitly leaves those native gates open.
    v090_local = run_v090_rc1(service_live=False)
    pure = _pure_local_matrix()
    false_positive = _enterprise_false_positive_matrix()
    precedence = _engine_precedence_matrix()

    heuristic_cases = list(pure.values()) + list(false_positive.values())
    all_heuristics_below_high = all(
        int(item.get("score") or 0) <= HEURISTIC_SCORE_CAP
        and item.get("block_recommended") is False
        and item.get("decision") != "containment_recommended"
        for item in heuristic_cases
    )
    safe_lure_words_unscored = int(pure["safe_login"].get("score") or 0) == 0
    benign_idn_bounded = bool(
        int(pure["benign_idn"].get("score") or 0) < 20
        and pure["benign_idn"].get("block_recommended") is False
    )
    deception_detected = bool(
        int(pure["mixed_script_deception"].get("score") or 0) >= 20
        and "mixed_script_hostname" in pure["mixed_script_deception"].get("signal_codes", [])
        and "unicode_confusable_identity" in pure["mixed_script_deception"].get("signal_codes", [])
        and "scam_lure" in pure["mixed_script_deception"].get("risk_families", [])
    )
    typosquat_detected = bool(
        int(pure["typosquat"].get("score") or 0) >= 20
        and "typosquat_distance_one" in pure["typosquat"].get("signal_codes", [])
    )
    identity_separation = bool(
        pure["typosquat"].get("identity_context", {}).get("declared_identity") == "microsoft"
        and pure["typosquat"].get("identity_context", {}).get("observed_host") == "micros0ft.example"
        and pure["typosquat"].get("identity_context", {}).get("declared_matches_observed") is False
    )
    redirect_context = bool(
        "brand_redirect_to_lookalike" in pure["redirect_lookalike"].get("signal_codes", [])
        and pure["redirect_lookalike"].get("block_recommended") is False
    )
    false_positive_matrix_green = all(
        int(item.get("score") or 0) < 20
        and item.get("decision") == "observe"
        and item.get("block_recommended") is False
        for item in false_positive.values()
    )

    signed = precedence["signed_ioc"]
    trusted = precedence["trusted_domain"]
    override = precedence["signed_ioc_overrides_trust"]
    signed_precedence = bool(
        signed.get("signed_ioc") is True
        and int(signed.get("score") or 0) >= 85
        and signed.get("decision") == "containment_recommended"
    )
    trusted_precedence = bool(
        trusted.get("trusted_domain") is True
        and int(trusted.get("score") or 0) == 0
        and trusted.get("decision") == "allow_trusted"
    )
    signed_overrides_trust = bool(
        override.get("signed_ioc") is True
        and int(override.get("score") or 0) >= 85
        and override.get("decision") == "containment_recommended"
    )

    local_passed = bool(
        version_key(APP_VERSION) >= version_key("0.10.0-beta.1")
        and v090_local.get("passed")
        and all_heuristics_below_high
        and safe_lure_words_unscored
        and benign_idn_bounded
        and deception_detected
        and typosquat_detected
        and identity_separation
        and redirect_context
        and false_positive_matrix_green
        and signed_precedence
        and trusted_precedence
        and signed_overrides_trust
    )

    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "milestone": "v0.10.0-beta.1",
        "profile": HEURISTIC_PROFILE,
        "service_live_requested": bool(service_live),
        "v090_rc1_local_regression": bool(v090_local.get("passed")),
        "v090_native_freeze": False,
        "v090_native_gates_deferred": True,
        "matrix": pure,
        "false_positive_matrix": false_positive,
        "precedence": precedence,
        "safety": {
            "heuristic_score_cap": HEURISTIC_SCORE_CAP,
            "all_heuristics_below_high": all_heuristics_below_high,
            "safe_lure_words_unscored": safe_lure_words_unscored,
            "benign_idn_bounded": benign_idn_bounded,
            "deception_detected": deception_detected,
            "typosquat_detected": typosquat_detected,
            "declared_identity_separated": identity_separation,
            "redirect_context_detected": redirect_context,
            "enterprise_false_positive_matrix_green": false_positive_matrix_green,
            "signed_ioc_precedence": signed_precedence,
            "exact_trust_precedence": trusted_precedence,
            "signed_ioc_overrides_exact_trust": signed_overrides_trust,
            "mitm_https": False,
            "heuristic_auto_block": False,
            "heuristic_destructive_action": False,
            "cloud_dependency_required": False,
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
            and int(status.get("heuristic_score_cap") or 0) == HEURISTIC_SCORE_CAP
            and status.get("download_origin_never_overrides_file_verdict") is True
            and int(safe.get("score") or 0) < 20
            and int(risky.get("score") or 0) <= HEURISTIC_SCORE_CAP
            and risky.get("block_recommended") is False
            and "mixed_script_hostname" in risky.get("signal_codes", [])
        )
        live = {"status": status, "safe": safe, "risky": risky}

    result["service"] = live
    result["service_live_passed"] = live_passed
    result["passed"] = bool(local_passed and (not service_live or live_passed))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.10.0-beta.1 web reputation/phishing acceptance")
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