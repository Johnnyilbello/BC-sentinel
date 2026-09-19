from __future__ import annotations

from copy import deepcopy

from sentinel import beta13_consumer_readiness as b130


def test_self_check_binds_exact_beta12_final_checkpoint():
    report = b130.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v012-beta12-b129-pass"
    assert report["source_checkpoint_commit"] == "c8e51a2a3fc34c593905896d3b055f9fec252c4b"
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}


def test_readiness_inventory_is_explicit_and_deterministic():
    report = b130.self_check()
    assert report["deterministic_contract"] is True
    assert report["pillar_counts"] == {"READY": 3, "PARTIAL": 2, "BLOCKED": 5}
    assert report["release_blocker_count"] == 7


def test_public_and_paid_launch_are_correctly_blocked():
    report = b130.self_check()
    assert report["ready_for_public_launch"] is False
    assert report["ready_for_paid_launch"] is False
    assert report["ready_for_installer_work"] is True
    assert report["installer_alone_is_launch_readiness"] is False


def test_release_blockers_are_exact():
    report = b130.self_check()
    assert report["release_blockers"] == [
        "SAFE_THREAT_RESPONSE",
        "BACKGROUND_ALERTS",
        "SECURE_UPDATES",
        "INSTALLER_LIFECYCLE",
        "CODE_SIGNING",
        "LICENSING_TRIAL",
        "PRIVACY_SUPPORT",
    ]


def test_active_protection_quarantine_and_first_run_are_ready():
    pillars = {item["pillar_id"]: item for item in b130.contract()["pillars"]}
    assert pillars["ACTIVE_PROTECTION"]["status"] == "READY"
    assert pillars["USER_MEDIATED_QUARANTINE"]["status"] == "READY"
    assert pillars["FIRST_RUN_HEALTH"]["status"] == "READY"


def test_auto_response_is_not_falsely_claimed():
    pillars = {item["pillar_id"]: item for item in b130.contract()["pillars"]}
    assert pillars["SAFE_THREAT_RESPONSE"]["status"] == "BLOCKED"
    assert b130.INHERITED_BOUNDARY["automatic_quarantine"] is False
    assert b130.INHERITED_BOUNDARY["automatic_repair"] is False
    assert b130.INHERITED_BOUNDARY["terminate_process_authority"] is False


def test_update_signing_installer_and_licensing_remain_unavailable():
    pillars = {item["pillar_id"]: item for item in b130.contract()["pillars"]}
    for pillar_id in ("SECURE_UPDATES", "INSTALLER_LIFECYCLE", "CODE_SIGNING", "LICENSING_TRIAL"):
        assert pillars[pillar_id]["status"] == "BLOCKED"
    assert b130.INHERITED_BOUNDARY["installer_execution"] is False
    assert b130.INHERITED_BOUNDARY["artifact_signing"] is False
    assert b130.INHERITED_BOUNDARY["licensing_enforcement"] is False


def test_launch_policy_preserves_protection_on_license_failure():
    policy = b130.contract()["launch_policy"]
    assert policy["protection_may_be_disabled_by_license_failure"] is False
    assert policy["unsigned_public_release_allowed"] is False
    assert policy["silent_destructive_response_allowed"] is False


def test_coverage_cannot_be_promoted_by_readiness_foundation():
    broken = deepcopy(b130.contract())
    broken["source_coverage"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 8}
    report = b130.summarize(broken)
    assert report["passed"] is False
    assert "b130:contract_changed" in report["failures"]
    assert "b130:coverage_changed" in report["failures"]


def test_authority_flip_fails_closed():
    broken = deepcopy(b130.contract())
    broken["inherited_boundary"]["automatic_quarantine"] = True
    report = b130.summarize(broken)
    assert report["passed"] is False
    assert "b130:contract_changed" in report["failures"]
    assert "b130:boundary_changed" in report["failures"]


def test_blocker_cannot_be_silently_marked_ready():
    broken = deepcopy(b130.contract())
    next(item for item in broken["pillars"] if item["pillar_id"] == "CODE_SIGNING")["status"] = "READY"
    report = b130.summarize(broken)
    assert report["passed"] is False
    assert "b130:contract_changed" in report["failures"]


def test_contract_is_reproducible():
    assert b130.contract() == b130.contract()
