from __future__ import annotations

import json

from sentinel.config import APP_VERSION
from sentinel.protection_protocol import decode_request
from sentinel.protection_service_core import ProtectionRuntime
from sentinel.service_update import version_key
from sentinel.web_clone_scam import CLONE_SCAM_PROFILE, assess_page_context


def test_beta3_version_and_profile():
    assert version_key(APP_VERSION) >= version_key("0.10.0-beta.3")
    assert CLONE_SCAM_PROFILE == "v0.10.0-beta.3"


def test_canonical_microsoft_login_is_not_clone_candidate():
    result = assess_page_context(
        url="https://login.microsoftonline.com/common/oauth2/authorize",
        declared_identity="Microsoft",
        page_title="Sign in to Microsoft",
        visible_text="Sign in to continue",
        form_action="https://login.microsoftonline.com/common/login",
        form_fields=["email", "password"],
    )
    assert result.score == 0
    assert result.status == "unknown"
    assert result.assessment_class == "observe"
    assert not result.block_recommended


def test_noncanonical_brand_credential_form_is_clone_candidate():
    result = assess_page_context(
        url="https://microsoft-login.example/verify",
        declared_identity="Microsoft",
        page_title="Microsoft account verification",
        visible_text="Sign in to verify your account",
        form_action="https://collector.example/session",
        form_fields=["email", "password", "otp"],
    )
    assert result.status == "suspicious"
    assert result.assessment_class == "clone_site_candidate"
    assert "declared_brand_noncanonical" in result.signal_codes
    assert "credential_form_on_noncanonical_brand" in result.signal_codes
    assert "sensitive_form_cross_origin" in result.signal_codes
    assert result.score <= 49
    assert not result.block_recommended


def test_mixed_script_paypal_clone_and_scam_is_bounded():
    result = assess_page_context(
        url="https://раypal.example/verify-account",
        declared_identity="PayPal",
        page_title="PayPal urgent account verification",
        visible_text="Urgent: verify now to avoid suspension. Refund available after payment.",
        form_action="https://capture.example/submit",
        form_fields=["email", "password", "card_number", "cvv"],
        payment_methods=["gift_card"],
    )
    assert result.status == "suspicious"
    assert result.assessment_class == "clone_and_scam_candidate"
    assert result.score == 49
    assert "irreversible_payment_request" in result.signal_codes
    assert "urgent_payment_pressure" in result.signal_codes
    assert not result.block_recommended


def test_generic_commerce_payment_words_alone_are_unscored():
    result = assess_page_context(
        url="https://shop.example/checkout",
        page_title="Checkout",
        visible_text="Complete payment today. Limited stock.",
        form_action="https://shop.example/pay",
        form_fields=["card_number", "cvv"],
        payment_methods=["card"],
    )
    assert result.score == 0
    assert result.signal_codes == []
    assert result.decision == "observe"


def test_support_scam_requires_structural_anchor():
    benign = assess_page_context(url="https://support.example/help", page_title="Remote support", visible_text="A technician may use remote access to help you.", form_fields=["email"])
    assert benign.score == 0
    risky = assess_page_context(url="https://192.0.2.10/support", page_title="Urgent technical support", visible_text="Technician requires remote access. Enter password to continue.", form_fields=["password"])
    assert risky.status == "suspicious"
    assert "remote_support_sensitive_request" in risky.signal_codes
    assert risky.score <= 49


def test_investment_crypto_claim_with_raw_ip_is_scam_candidate():
    result = assess_page_context(url="https://192.0.2.20/invest", page_title="Guaranteed return investment", visible_text="Guaranteed return. Invest now and double your profit.", payment_methods=["crypto"])
    assert result.status == "suspicious"
    assert result.assessment_class == "scam_fraud_candidate"
    assert "investment_crypto_claim" in result.signal_codes
    assert not result.block_recommended


def test_fingerprint_is_stable_for_set_like_inputs():
    a = assess_page_context(url="https://microsoft-login.example/", declared_identity="Microsoft", page_title="Microsoft login", form_fields=["password", "otp"], payment_methods=["crypto", "gift_card"], link_hosts=["a.example", "b.example"])
    b = assess_page_context(url="https://microsoft-login.example/", declared_identity="Microsoft", page_title="Microsoft login", form_fields=["otp", "password"], payment_methods=["gift_card", "crypto"], link_hosts=["b.example", "a.example"])
    assert a.fingerprint == b.fingerprint


def test_protocol_accepts_bounded_clone_scam_payload():
    raw = json.dumps({"version":1,"request_id":"beta3-protocol","op":"web_clone_scam_assess","token":"x"*32,"payload":{"url":"https://example.com","declared_identity":"Microsoft","page_title":"Microsoft","visible_text":"verify","form_action":"https://example.com/post","form_fields":["password"],"payment_methods":[],"link_hosts":[],"redirect_chain":[]}}).encode()
    request = decode_request(raw)
    assert request.op == "web_clone_scam_assess"
    assert request.payload["form_fields"] == ["password"]


def test_runtime_exposes_beta3_assessment():
    runtime = object.__new__(ProtectionRuntime)
    result = ProtectionRuntime.web_clone_scam_assess(runtime, {"url":"https://paypa1.example/login","declared_identity":"PayPal","page_title":"PayPal login","form_fields":["password"]})
    assert result["profile"] == CLONE_SCAM_PROFILE
    assert result["score"] <= 49


def test_beta3_launchers_include_upgrade_repair_standard_user_uac_and_defer_reboot():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    normal = (root / "TEST-V010-BETA3-ALL-NORMAL.ps1").read_text(encoding="utf-8-sig").casefold()
    admin = (root / "TEST-V010-BETA3-ALL-ADMIN.ps1").read_text(encoding="utf-8-sig").casefold()
    phase = (root / "TEST-V010-BETA3-ADMIN-PHASE.ps1").read_text(encoding="utf-8-sig").casefold()
    for text in (normal, admin, phase): assert "repair" in text or "ripara" in text
    assert "-mode upgrade" in phase and "-mode repair" in phase
    assert "broker_acceptance" in normal
    assert "test-v010-beta3-standard-uac.ps1" in admin
    assert "reboot" in normal and "rinviato" in normal
    assert "reboot" in admin and "rinviato" in admin
