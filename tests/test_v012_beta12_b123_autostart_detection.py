from __future__ import annotations

from copy import deepcopy
import json

import pytest

from sentinel import beta12_autostart_detection as b123


def _control(
    control_id: str,
    *,
    target_kind: str,
    signer_state: str,
    writable: bool,
    arguments: bool,
    admin: bool = False,
    configured: bool = False,
) -> dict:
    signed = signer_state in {"SIGNED_VERIFIED", "SIGNED_UNVERIFIED"}
    seed = sum(ord(ch) for ch in control_id)
    return {
        "control_id": control_id,
        "live_observation": True,
        "windows_shortcut_created": True,
        "windows_shortcut_resolved": True,
        "shortcut_sha256": ("%064x" % (10000 + seed)),
        "shortcut_path_digest": ("%064x" % (20000 + seed)),
        "target_sha256": ("%064x" % (30000 + seed)),
        "target_path_digest": ("%064x" % (40000 + seed)),
        "target_signer_state": signer_state,
        "target_signer_subject_digest": ("f" * 64) if signed else None,
        "target_kind": target_kind,
        "target_user_writable": writable,
        "arguments_present": arguments,
        "known_admin_automation": admin,
        "user_initiated_configuration": configured,
        "startup_surface_mutated": False,
        "workspace_scope": "DISPOSABLE_TEMP_ONLY",
        "cleanup_state": "REMOVED",
    }


def _evidence() -> dict:
    return {
        "schema": b123.SCHEMA,
        "source": b123.SOURCE,
        "controls": [
            _control(
                "positive-autostart-like-shortcut",
                target_kind="SCRIPT_OR_BATCH",
                signer_state="UNSIGNED",
                writable=True,
                arguments=False,
            ),
            _control(
                "administrative-autostart-like-shortcut",
                target_kind="SCRIPT_HOST",
                signer_state="SIGNED_VERIFIED",
                writable=False,
                arguments=True,
                admin=True,
                configured=True,
            ),
            _control(
                "benign-shortcut",
                target_kind="SIGNED_APPLICATION",
                signer_state="SIGNED_VERIFIED",
                writable=False,
                arguments=False,
            ),
        ],
        "boundaries": dict(b123.BOUNDARIES),
    }


def test_self_check_binds_exact_b122_checkpoint():
    report = b123.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v012-beta12-b122-pass"
    assert report["source_checkpoint_commit"] == "dedf78ae920b87f44636a0b9bd0c9708d2ae760b"
    assert report["target_scenario_id"] == "B12-AUTOSTART-LINK-001"
    assert report["baseline_verified_scenarios"] == [
        "B7-POWERSHELL-001",
        "B7-RANSOMWARE-001",
        "B12-SCRIPT-ABUSE-001",
    ]


def test_control_outcomes_are_positive_review_benign():
    report = b123.summarize(_evidence())
    outcomes = {key: value["outcome"] for key, value in report["control_results"].items()}
    assert outcomes == {
        "positive-autostart-like-shortcut": "DETECTED",
        "administrative-autostart-like-shortcut": "REVIEW_REQUIRED",
        "benign-shortcut": "NO_MATCH",
    }
    assert report["passed"] is True


def test_b123_reaches_minimum_verified_target_without_promoting_legacy_persistence():
    report = b123.summarize(_evidence())
    assert report["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 4}
    assert report["verified_scenarios"] == [
        "B7-POWERSHELL-001",
        "B7-RANSOMWARE-001",
        "B12-SCRIPT-ABUSE-001",
        "B12-AUTOSTART-LINK-001",
    ]
    assert report["new_verified_scenario_earned"] is True
    assert report["legacy_persistence_scenario_promoted"] is False
    persistence = next(
        row for row in report["coverage_decisions"]
        if row["scenario_id"] == "B7-PERSISTENCE-001"
    )
    assert persistence["status"] == "PARTIAL"


def test_graph_and_incident_binding_passes():
    report = b123.summarize(_evidence())
    assert report["detector_to_security_graph_bound"] is True
    assert report["security_graph_to_incident_bound"] is True
    assert len(report["graph_digest"]) == 64
    assert len(report["correlation_digest"]) == 64


def test_actual_persistence_surfaces_are_never_claimed_or_mutated():
    report = b123.summarize(_evidence())
    assert report["actual_persistence_surface_mutated"] is False
    assert report["actual_persistence_execution_verified"] is False
    assert report["boundaries"]["real_startup_folder_mutated"] is False
    assert report["boundaries"]["registry_run_key_mutated"] is False
    assert report["boundaries"]["scheduled_task_mutated"] is False
    assert report["boundaries"]["service_mutated"] is False


def test_no_path_arguments_network_or_authority_expansion():
    report = b123.summarize(_evidence())
    assert report["raw_path_exported"] is False
    assert report["shortcut_arguments_exported"] is False
    assert report["authority_expanded"] is False
    assert report["network_required"] is False
    assert report["cloud_required"] is False


@pytest.mark.parametrize("field", ["raw_path", "target_path", "arguments", "username", "token"])
def test_sensitive_extra_fields_fail_closed_without_echo(field):
    data = _evidence()
    data["controls"][0][field] = "PRIVATE_B123_VALUE"
    report = b123.summarize(data)
    assert report["passed"] is False
    assert "PRIVATE_B123_VALUE" not in json.dumps(report)


def test_startup_surface_mutation_flag_fails_closed():
    data = _evidence()
    data["controls"][0]["startup_surface_mutated"] = True
    report = b123.summarize(data)
    assert report["passed"] is False
    assert any("startup_surface_mutation_forbidden" in item for item in report["failures"])


def test_cleanup_must_be_confirmed():
    data = _evidence()
    data["controls"][0]["cleanup_state"] = "PENDING"
    report = b123.summarize(data)
    assert report["passed"] is False
    assert any("cleanup_not_confirmed" in item for item in report["failures"])


def test_admin_suppressor_changes_detected_to_review():
    result = b123.detect_control(_evidence()["controls"][1])
    assert result["score"] >= 7
    assert result["suppressor"] is True
    assert result["outcome"] == "REVIEW_REQUIRED"


def test_benign_signed_application_shortcut_is_no_match():
    result = b123.detect_control(_evidence()["controls"][2])
    assert result["score"] < 7
    assert result["outcome"] == "NO_MATCH"


def test_positive_unsigned_user_writable_script_target_detects():
    result = b123.detect_control(_evidence()["controls"][0])
    assert result["score"] >= 7
    assert result["outcome"] == "DETECTED"
    assert "SCRIPT_CAPABLE_TARGET" in result["matched_signals"]
    assert "UNTRUSTED_OR_UNSIGNED_TARGET" in result["matched_signals"]
    assert "USER_WRITABLE_TARGET" in result["matched_signals"]


def test_boundary_flip_fails_closed():
    data = _evidence()
    data["boundaries"]["registry_run_key_mutated"] = True
    report = b123.summarize(data)
    assert report["passed"] is False
    assert "b123:boundary_invalid" in report["failures"]


def test_deterministic_summary():
    assert b123.summarize(_evidence()) == b123.summarize(deepcopy(_evidence()))


@pytest.mark.parametrize("bad", [None, [], "raw", 1, True, {}])
def test_malformed_top_level_fails_closed(bad):
    assert b123.summarize(bad)["passed"] is False
