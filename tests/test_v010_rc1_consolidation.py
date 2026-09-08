from __future__ import annotations

from pathlib import Path

from sentinel.config import APP_VERSION
from sentinel.web_clone_scam import CLONE_SCAM_PROFILE, assess_page_context
from sentinel.web_deception import HEURISTIC_PROFILE, HEURISTIC_SCORE_CAP
from sentinel.web_response import WEB_RESPONSE_PROFILE
from tools.v010_rc1_acceptance import RC1_PROFILE, run


def test_rc1_version_and_profiles_are_frozen():
    assert APP_VERSION == "0.10.0-rc.1"
    assert RC1_PROFILE == "v0.10.0-rc.1"
    assert HEURISTIC_PROFILE == "v0.10.0-beta.1"
    assert WEB_RESPONSE_PROFILE == "v0.10.0-beta.2"
    assert CLONE_SCAM_PROFILE == "v0.10.0-beta.3"
    assert HEURISTIC_SCORE_CAP == 49


def test_rc1_high_volume_compatibility_and_local_latency():
    result = run(service_live=False)
    assert result["compatibility"]["checked"] >= 300
    assert result["compatibility"]["failure_count"] == 0
    assert result["performance"]["local_page_assessment"]["passed"] is True
    assert result["local_passed"] is True
    assert result["passed"] is True


def test_rc1_preserves_clone_detection_without_heuristic_block():
    result = assess_page_context(
        url="https://microsoft-login.example/verify",
        declared_identity="Microsoft",
        page_title="Microsoft account verification",
        visible_text="Sign in to verify your account",
        form_action="https://collector.example/post",
        form_fields=["email", "password", "otp"],
    )
    assert result.status == "suspicious"
    assert result.score <= 49
    assert result.block_recommended is False


def test_rc1_master_launchers_include_upgrade_repair_standard_user_uac_and_defer_reboot():
    root = Path(__file__).resolve().parents[1]
    normal = (root / "TEST-V010-RC1-ALL-NORMAL.ps1").read_text(encoding="utf-8-sig").casefold()
    admin = (root / "TEST-V010-RC1-ALL-ADMIN.ps1").read_text(encoding="utf-8-sig").casefold()
    phase = (root / "TEST-V010-RC1-ADMIN-PHASE.ps1").read_text(encoding="utf-8-sig").casefold()
    assert "-mode upgrade" in phase
    assert "-mode repair" in phase
    assert "broker_acceptance" in normal
    assert "test-v010-rc1-standard-uac.ps1" in admin
    assert "v010_rc1_acceptance" in normal
    assert "v010_rc1_acceptance" in phase
    assert "reboot" in normal and "rinviato" in normal
    assert "reboot" in admin and "rinviato" in admin
