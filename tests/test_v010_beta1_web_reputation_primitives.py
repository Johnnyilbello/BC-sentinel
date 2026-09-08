from __future__ import annotations

from sentinel.web_deception import (
    HEURISTIC_PROFILE,
    HEURISTIC_SCORE_CAP,
    assess_local_url,
    stable_deception_fingerprint,
)


def test_v010_benign_lure_words_do_not_score_without_independent_risk():
    for url in (
        "https://example.com/login",
        "https://example.com/invoice/123",
        "https://example.com/refund/status",
        "https://example.com/wallet/help",
        "https://example.com/delivery/status",
    ):
        result = assess_local_url(url)
        assert result.score == 0
        assert result.decision == "observe"
        assert result.block_recommended is False
        assert "scam_lure" not in result.risk_families


def test_v010_benign_idn_is_reviewable_context_not_malware():
    result = assess_local_url("https://xn--bcher-kva.example/catalog")
    assert result.score == 18
    assert result.decision == "observe"
    assert result.block_recommended is False
    assert "idn_punycode" in result.signal_codes


def test_v010_mixed_script_paypal_lookalike_is_explainable_and_capped():
    result = assess_local_url("https://user:pass@раypal.example/verify-account", declared_identity="PayPal")
    assert 20 <= result.score <= HEURISTIC_SCORE_CAP
    assert result.status == "suspicious"
    assert result.decision == "review"
    assert result.block_recommended is False
    assert "mixed_script_hostname" in result.signal_codes
    assert "unicode_confusable_identity" in result.signal_codes
    assert "declared_identity_mismatch" in result.signal_codes
    assert "userinfo_before_host" in result.signal_codes
    assert "lure_with_structural_risk" in result.signal_codes
    assert "paypal" in result.identity_context["impersonation_candidates"]


def test_v010_typosquat_distance_one_requires_bounded_review_only():
    result = assess_local_url("https://micros0ft.example/login", declared_identity="Microsoft")
    assert 20 <= result.score <= HEURISTIC_SCORE_CAP
    assert "typosquat_distance_one" in result.signal_codes
    assert "declared_identity_mismatch" in result.signal_codes
    assert result.block_recommended is False
    assert result.decision == "review"


def test_v010_brand_subdomain_abuse_is_not_confused_with_canonical_subdomain():
    fake = assess_local_url("https://login.microsoft.com.evil.example/verify", declared_identity="Microsoft")
    real = assess_local_url("https://login.microsoftonline.com/verify", declared_identity="Microsoft")
    assert "brand_token_untrusted_host" in fake.signal_codes
    assert "declared_identity_mismatch" in fake.signal_codes
    assert fake.score >= 20
    assert real.score == 0
    assert real.identity_context["canonical_identity"] == "microsoft"
    assert real.identity_context["declared_matches_observed"] is True


def test_v010_declared_identity_and_observed_domain_remain_separate_evidence():
    result = assess_local_url("https://secure-login.example/verify", declared_identity="Microsoft")
    assert result.identity_context["declared_identity"] == "microsoft"
    assert result.identity_context["observed_host"] == "secure-login.example"
    assert result.identity_context["canonical_identity"] == ""
    assert result.identity_context["declared_matches_observed"] is False
    assert "declared_identity_mismatch" in result.signal_codes


def test_v010_raw_ip_and_userinfo_never_escape_heuristic_cap():
    result = assess_local_url("https://user:pass@192.0.2.10/login?verify=account")
    assert 20 <= result.score <= HEURISTIC_SCORE_CAP
    assert "raw_ip_url" in result.signal_codes
    assert "userinfo_before_host" in result.signal_codes
    assert result.block_recommended is False
    assert result.decision == "review"


def test_v010_redirect_chain_from_canonical_brand_to_lookalike_is_context_only():
    result = assess_local_url(
        "https://paypa1.example/verify-account",
        declared_identity="PayPal",
        redirect_chain=(
            "https://www.paypal.com/",
            "https://redirect.example/continue",
            "https://paypa1.example/verify-account",
        ),
    )
    assert "brand_redirect_to_lookalike" in result.signal_codes
    assert "typosquat_distance_one" in result.signal_codes
    assert result.score <= HEURISTIC_SCORE_CAP
    assert result.block_recommended is False


def test_v010_redirect_to_raw_ip_is_advisory_only():
    result = assess_local_url(
        "https://192.0.2.22/login",
        redirect_chain=("https://example.com/continue", "https://192.0.2.22/login"),
    )
    assert "redirect_to_raw_ip" in result.signal_codes
    assert result.score <= HEURISTIC_SCORE_CAP
    assert result.block_recommended is False


def test_v010_enterprise_false_positive_matrix_stays_below_review_threshold():
    fixtures = (
        ("https://login.microsoftonline.com/common/oauth2/authorize", "Microsoft"),
        ("https://accounts.google.com/signin/v2", "Google"),
        ("https://github.com/login", "GitHub"),
        ("https://objects.githubusercontent.com/assets/app.js", ""),
        ("https://cdn.jsdelivr.net/npm/example/index.js", ""),
        ("https://static.cloudflareinsights.com/beacon.min.js", "Cloudflare"),
        ("https://login.salesforce.com/", "Salesforce"),
        ("https://id.atlassian.com/login", "Atlassian"),
        ("https://microsoftware.example/docs", ""),
    )
    for url, identity in fixtures:
        result = assess_local_url(url, declared_identity=identity)
        assert result.score < 20, (url, result.to_dict())
        assert result.block_recommended is False
        assert result.decision == "observe"


def test_v010_fingerprint_is_stable_and_order_insensitive():
    left = stable_deception_fingerprint(
        "example.test", ["userinfo_before_host", "typosquat_distance_one"], declared_identity="Microsoft"
    )
    right = stable_deception_fingerprint(
        "EXAMPLE.TEST.", ["typosquat_distance_one", "userinfo_before_host", "userinfo_before_host"], declared_identity="microsoft"
    )
    assert left == right
    assert left.startswith("WDR-")
    assert len(left) == 24


def test_v010_profile_and_cap_are_frozen_for_beta1():
    assert HEURISTIC_PROFILE == "v0.10.0-beta.1"
    assert HEURISTIC_SCORE_CAP == 49
