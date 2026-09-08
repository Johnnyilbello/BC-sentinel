from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.config import APP_VERSION
from sentinel.protection_client import ProtectionServiceClient
from sentinel.web_clone_scam import CLONE_SCAM_PROFILE, assess_page_context


def run(*, service_live: bool = False) -> dict:
    canonical = assess_page_context(
        url="https://login.microsoftonline.com/common/oauth2/authorize",
        declared_identity="Microsoft", page_title="Sign in to Microsoft",
        form_action="https://login.microsoftonline.com/login", form_fields=["email", "password"],
    )
    clone = assess_page_context(
        url="https://microsoft-login.example/verify", declared_identity="Microsoft",
        page_title="Microsoft account verification", visible_text="Sign in to verify",
        form_action="https://collector.example/post", form_fields=["email", "password", "otp"],
    )
    scam = assess_page_context(
        url="https://раypal.example/verify", declared_identity="PayPal",
        page_title="PayPal urgent verification", visible_text="Urgent payment refund. Account suspended.",
        form_action="https://capture.example/post", form_fields=["password", "card_number", "cvv"],
        payment_methods=["gift_card"],
    )
    benign_commerce = assess_page_context(
        url="https://shop.example/checkout", page_title="Checkout",
        visible_text="Complete payment today", form_action="https://shop.example/pay",
        form_fields=["card_number", "cvv"], payment_methods=["card"],
    )
    support = assess_page_context(
        url="https://192.0.2.10/support", page_title="Urgent support",
        visible_text="Technician remote access required. Enter password.", form_fields=["password"],
    )
    investment = assess_page_context(
        url="https://192.0.2.20/invest", page_title="Guaranteed return investment",
        visible_text="Double your profit with guaranteed return", payment_methods=["crypto"],
    )
    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "milestone": "v0.10.0-beta.3",
        "profile": CLONE_SCAM_PROFILE,
        "service_live_requested": bool(service_live),
        "matrix": {
            "canonical": canonical.to_dict(), "clone": clone.to_dict(), "clone_scam": scam.to_dict(),
            "benign_commerce": benign_commerce.to_dict(), "support_scam": support.to_dict(),
            "investment_scam": investment.to_dict(),
        },
        "safety": {
            "heuristic_score_cap": 49,
            "canonical_brand_green": canonical.score == 0,
            "generic_commerce_unscored": benign_commerce.score == 0,
            "clone_detected": clone.status == "suspicious" and "credential_form_on_noncanonical_brand" in clone.signal_codes,
            "cross_origin_sensitive_form_detected": "sensitive_form_cross_origin" in clone.signal_codes,
            "scam_requires_structural_anchor": True,
            "clone_and_scam_detected": scam.assessment_class == "clone_and_scam_candidate",
            "support_scam_detected": "remote_support_sensitive_request" in support.signal_codes,
            "investment_scam_detected": "investment_crypto_claim" in investment.signal_codes,
            "heuristic_auto_block": False,
            "mitm_https": False,
            "cloud_dependency_required": False,
        },
        "local_passed": False,
        "service": None,
        "service_live_passed": None,
        "passed": False,
    }
    safety = result["safety"]
    result["local_passed"] = bool(
        APP_VERSION == "0.10.0-beta.3" and all((
            safety["canonical_brand_green"], safety["generic_commerce_unscored"], safety["clone_detected"],
            safety["cross_origin_sensitive_form_detected"], safety["clone_and_scam_detected"],
            safety["support_scam_detected"], safety["investment_scam_detected"],
            clone.score <= 49, scam.score <= 49, not clone.block_recommended, not scam.block_recommended,
        ))
    )
    if service_live:
        client = ProtectionServiceClient(timeout=3.0)
        status = client.request("web_status")
        live = client.request("web_clone_scam_assess", **{
            "url": "https://microsoft-login.example/verify",
            "declared_identity": "Microsoft", "page_title": "Microsoft verify",
            "visible_text": "Sign in to verify", "form_action": "https://collector.example/post",
            "form_fields": ["password"], "payment_methods": [], "link_hosts": [], "redirect_chain": [],
        })
        result["service"] = {"status": status, "assessment": live}
        web = (status or {}).get("web") or {}
        assessment = (live or {}).get("assessment") or {}
        result["service_live_passed"] = bool(
            (status or {}).get("ok") and (live or {}).get("ok")
            and web.get("clone_scam_profile") == CLONE_SCAM_PROFILE
            and web.get("page_context_auto_block") is False
            and assessment.get("profile") == CLONE_SCAM_PROFILE
            and assessment.get("status") == "suspicious"
            and assessment.get("block_recommended") is False
        )
    result["passed"] = bool(result["local_passed"] and (not service_live or result["service_live_passed"]))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.10 Beta3 clone-site/scam acceptance")
    parser.add_argument("--service-live", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(service_live=args.service_live)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
