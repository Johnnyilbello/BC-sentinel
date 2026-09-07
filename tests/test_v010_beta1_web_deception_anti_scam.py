from __future__ import annotations

from pathlib import Path
import time

from sentinel.config import APP_VERSION
from sentinel.database import Database
from sentinel.protection_service_core import ProtectionRuntime
from sentinel.web_deception import HEURISTIC_PROFILE
from sentinel.web_protection import DNSCorrelationCache, WebProtectionEngine

ROOT = Path(__file__).resolve().parents[1]


def _ioc(db: Database, domain: str) -> None:
    db.execute(
        """INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
           VALUES('domain',?,?,?,?,?)""",
        (domain, "critical", "v0.10 harmless signed IOC fixture", time.time() + 3600, "v010-unit"),
    )


def test_v010_beta1_safe_lure_words_are_not_risky_by_themselves(tmp_path):
    engine = WebProtectionEngine(Database(tmp_path / "safe.sqlite"))
    for url in (
        "https://example.com/login",
        "https://example.com/invoice/123",
        "https://example.com/refund/status",
        "https://example.com/wallet/help",
    ):
        result = engine.assess_url(url)
        assert result.score < 20
        assert result.block_recommended is False
        assert result.decision == "observe"
        assert "scam_lure" not in result.risk_families


def test_v010_beta1_mixed_script_plus_lure_is_explainable_and_bounded(tmp_path):
    engine = WebProtectionEngine(Database(tmp_path / "mixed.sqlite"))
    result = engine.assess_url("https://user:pass@раypal.example/verify-account")
    assert 20 <= result.score <= 49
    assert result.status == "suspicious"
    assert result.decision == "review"
    assert result.block_recommended is False
    assert "mixed_script_hostname" in result.signal_codes
    assert "userinfo_before_host" in result.signal_codes
    assert "lure_with_structural_risk" in result.signal_codes
    assert "identity_deception" in result.risk_families
    assert "scam_lure" in result.risk_families
    assert result.heuristic_profile == HEURISTIC_PROFILE


def test_v010_beta1_raw_ip_credential_lure_stays_heuristic_only(tmp_path):
    engine = WebProtectionEngine(Database(tmp_path / "ip.sqlite"))
    result = engine.assess_url("https://192.0.2.10/login?verify=account")
    assert 20 <= result.score <= 49
    assert "raw_ip_url" in result.signal_codes
    assert "lure_with_structural_risk" in result.signal_codes
    assert result.block_recommended is False
    assert result.decision == "review"


def test_v010_beta1_nested_redirect_context_does_not_auto_escalate(tmp_path):
    engine = WebProtectionEngine(Database(tmp_path / "redirect.sqlite"))
    result = engine.assess_url("https://example.com/continue?next=https%3A%2F%2Fexample.org%2Fhome")
    assert result.score < 20
    assert "nested_url_parameter" in result.signal_codes
    assert result.block_recommended is False
    assert result.decision == "observe"


def test_v010_beta1_signed_ioc_still_has_deterministic_precedence(tmp_path):
    db = Database(tmp_path / "ioc.sqlite")
    _ioc(db, "malware.test")
    result = WebProtectionEngine(db).assess_url("https://malware.test/login")
    assert result.signed_ioc is True
    assert result.score >= 85
    assert result.decision == "containment_recommended"
    assert result.block_recommended is True


def test_v010_beta1_exact_trust_still_precedes_local_heuristics(tmp_path):
    db = Database(tmp_path / "trust.sqlite")
    db.add_web_domain_trust("trusted.example", reason="unit safe fixture")
    result = WebProtectionEngine(db).assess_url("https://trusted.example/verify-payment")
    assert result.trusted_domain is True
    assert result.score == 0
    assert result.decision == "allow_trusted"
    assert result.block_recommended is False


def test_v010_beta1_runtime_status_declares_non_mitm_non_autoblock_policy(tmp_path):
    runtime = ProtectionRuntime.__new__(ProtectionRuntime)
    runtime.db = Database(tmp_path / "status.sqlite")
    runtime.settings = type("S", (), {"network_enabled": True, "etw_enabled": True})()
    runtime.dns_cache = DNSCorrelationCache()
    runtime.etw = type("E", (), {"status": lambda self: {"dns_tracking": True}})()
    status = runtime.web_status()
    assert status["deception_profile"] == HEURISTIC_PROFILE
    assert status["mixed_script_detection"] is True
    assert status["scam_lure_context"] is True
    assert status["lure_requires_structural_risk"] is True
    assert status["heuristic_score_cap"] == 49
    assert status["heuristic_can_qualify_high"] is False
    assert status["mitm_https"] is False
    assert status["auto_block"] is False


def test_v010_beta1_acceptance_passes_and_rc1_remains_frozen():
    from tools.v010_web_deception_acceptance import run
    result = run(service_live=False)
    assert result["passed"] is True
    assert result["frozen_v090_rc1_regression"] is True
    assert result["safety"]["all_heuristics_below_high"] is True
    assert result["safety"]["safe_lure_words_unscored"] is True
    assert result["safety"]["signed_ioc_precedence"] is True
    assert result["safety"]["exact_trust_precedence"] is True
    assert result["safety"]["mitm_https"] is False
    assert result["safety"]["heuristic_auto_block"] is False


def test_v010_beta1_version_and_release_artifacts():
    assert APP_VERSION == "0.10.0-beta.1"
    assert (ROOT / "sentinel" / "__init__.py").read_text(encoding="utf-8").strip() == '__version__ = "0.10.0-beta.1"'
    assert 'version = "0.10.0b1"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert (ROOT / "RELEASE-NOTES-v0.10.0-beta.1.md").is_file()
    assert (ROOT / "BC_SENTINEL_V0100_BETA1_WEB_DECEPTION_REPORT.md").is_file()
    assert (ROOT / "BC_Sentinel_Roadmap_v0_10_0_Beta1_Updated.md").is_file()


def test_v010_beta1_windows_acceptance_registers_foundation_and_live_gates():
    source = (ROOT / "tools" / "windows_acceptance.py").read_text(encoding="utf-8")
    assert "web-deception-v010-beta1-foundation" in source
    assert "web-deception-v010-beta1-live" in source
