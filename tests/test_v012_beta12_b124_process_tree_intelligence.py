from __future__ import annotations

from copy import deepcopy
import json

import pytest

from sentinel import beta12_process_tree_intelligence as b124


def _process(
    role: str,
    pid: int,
    parent_pid: int | None,
    kind: str,
    *,
    writable: bool,
    signer: str = "SIGNED_VERIFIED",
) -> dict:
    seed = pid + sum(ord(ch) for ch in role)
    signed = signer in {"SIGNED_VERIFIED", "SIGNED_UNVERIFIED"}
    return {
        "role": role,
        "pid": pid,
        "parent_pid": parent_pid,
        "image_sha256": ("%064x" % (100000 + seed)),
        "image_path_digest": ("%064x" % (200000 + seed)),
        "signer_state": signer,
        "signer_subject_digest": ("a" * 64) if signed else None,
        "image_kind": kind,
        "image_user_writable": writable,
    }


def _evidence() -> dict:
    root = _process("ROOT", 100, None, "SCRIPT_HOST", writable=False)
    positive = {
        "control_id": "positive-user-writable-script-shell-chain",
        "live_observation": True,
        "processes": [
            root,
            _process("INTERMEDIATE", 101, 100, "SCRIPT_HOST", writable=False),
            _process("LEAF", 102, 101, "SHELL", writable=True),
        ],
        "known_admin_automation": False,
        "user_initiated_operation": False,
        "cleanup_state": "EXITED",
    }
    administrative = {
        "control_id": "administrative-script-shell-chain",
        "live_observation": True,
        "processes": [
            _process("ROOT", 200, None, "SCRIPT_HOST", writable=False),
            _process("INTERMEDIATE", 201, 200, "SCRIPT_HOST", writable=False),
            _process("LEAF", 202, 201, "SHELL", writable=False),
        ],
        "known_admin_automation": True,
        "user_initiated_operation": True,
        "cleanup_state": "EXITED",
    }
    benign = {
        "control_id": "benign-application-child",
        "live_observation": True,
        "processes": [
            _process("ROOT", 300, None, "SCRIPT_HOST", writable=False),
            _process("LEAF", 301, 300, "SHELL", writable=False),
        ],
        "known_admin_automation": False,
        "user_initiated_operation": False,
        "cleanup_state": "EXITED",
    }
    return {
        "schema": b124.SCHEMA,
        "source": b124.SOURCE,
        "controls": [positive, administrative, benign],
        "boundaries": dict(b124.BOUNDARIES),
    }


def test_self_check_binds_exact_b123_checkpoint():
    report = b124.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v012-beta12-b123-pass"
    assert report["source_checkpoint_commit"] == "90776f9b0e3f1a9c034b79a5886b30df0db41e5c"
    assert report["target_scenario_id"] == "B12-PROCESS-TREE-001"
    assert report["baseline_verified_scenarios"] == [
        "B7-POWERSHELL-001",
        "B7-RANSOMWARE-001",
        "B12-SCRIPT-ABUSE-001",
        "B12-AUTOSTART-LINK-001",
    ]


def test_control_outcomes_are_detect_review_no_match():
    report = b124.summarize(_evidence())
    outcomes = {key: value["outcome"] for key, value in report["control_results"].items()}
    assert outcomes == {
        "positive-user-writable-script-shell-chain": "DETECTED",
        "administrative-script-shell-chain": "REVIEW_REQUIRED",
        "benign-application-child": "NO_MATCH",
    }
    assert report["passed"] is True


def test_positive_chain_has_expected_explainable_signals():
    result = b124.detect_control(_evidence()["controls"][0])
    assert result["score"] == 7
    assert result["chain_depth"] == 3
    assert result["user_writable_image_count"] == 1
    assert result["matched_signals"] == [
        "MULTI_GENERATION_PROCESS_CHAIN",
        "SCRIPT_HOST_TO_SHELL_DESCENDANT",
        "USER_WRITABLE_EXECUTABLE_IMAGE",
    ]


def test_admin_chain_is_review_due_to_suppressor():
    result = b124.detect_control(_evidence()["controls"][1])
    assert result["score"] == 5
    assert result["suppressor"] is True
    assert result["outcome"] == "REVIEW_REQUIRED"


def test_benign_two_process_chain_does_not_cross_threshold():
    result = b124.detect_control(_evidence()["controls"][2])
    assert result["chain_depth"] == 2
    assert result["score"] == 3
    assert result["outcome"] == "NO_MATCH"


def test_b124_earns_fifth_verified_scenario():
    report = b124.summarize(_evidence())
    assert report["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 5}
    assert report["verified_scenarios"] == [
        "B7-POWERSHELL-001",
        "B7-RANSOMWARE-001",
        "B12-SCRIPT-ABUSE-001",
        "B12-AUTOSTART-LINK-001",
        "B12-PROCESS-TREE-001",
    ]
    assert report["new_verified_scenario_earned"] is True


def test_graph_preserves_exact_two_spawn_edges_for_positive_chain():
    report = b124.summarize(_evidence())
    assert report["detector_to_security_graph_bound"] is True
    assert report["security_graph_to_incident_bound"] is True
    assert len(report["graph_digest"]) == 64
    assert len(report["correlation_digest"]) == 64


def test_command_line_raw_path_and_authority_are_not_exported():
    report = b124.summarize(_evidence())
    assert report["command_line_exported"] is False
    assert report["raw_path_exported"] is False
    assert report["authority_expanded"] is False
    assert report["network_required"] is False
    assert report["cloud_required"] is False


@pytest.mark.parametrize("field", ["command_line", "raw_path", "username", "token", "environment"])
def test_sensitive_extra_process_fields_fail_closed_without_echo(field):
    data = _evidence()
    data["controls"][0]["processes"][1][field] = "PRIVATE_B124_VALUE"
    report = b124.summarize(data)
    assert report["passed"] is False
    assert "PRIVATE_B124_VALUE" not in json.dumps(report)


def test_missing_parent_fails_closed():
    data = _evidence()
    data["controls"][0]["processes"][2]["parent_pid"] = 99999
    report = b124.summarize(data)
    assert report["passed"] is False
    assert any("parent_missing" in failure for failure in report["failures"])


def test_duplicate_pid_fails_closed():
    data = _evidence()
    data["controls"][0]["processes"][2]["pid"] = 101
    report = b124.summarize(data)
    assert report["passed"] is False
    assert any("duplicate_pid" in failure for failure in report["failures"])


def test_root_parent_must_remain_unknown():
    data = _evidence()
    data["controls"][0]["processes"][0]["parent_pid"] = 999
    report = b124.summarize(data)
    assert report["passed"] is False
    assert any("root_parent_must_be_unknown" in failure for failure in report["failures"])


def test_boundary_flip_fails_closed():
    data = _evidence()
    data["boundaries"]["terminate_process_authority"] = True
    report = b124.summarize(data)
    assert report["passed"] is False
    assert "b124:boundary_invalid" in report["failures"]


def test_deterministic_summary():
    assert b124.summarize(_evidence()) == b124.summarize(deepcopy(_evidence()))


@pytest.mark.parametrize("bad", [None, [], "raw", 1, True, {}])
def test_malformed_top_level_fails_closed(bad):
    assert b124.summarize(bad)["passed"] is False


def test_pathological_pid_fails_without_serialization_crash():
    data = _evidence()
    data["controls"][0]["processes"][2]["pid"] = 10**5000
    report = b124.summarize(data)
    assert report["passed"] is False
    assert any("pid_invalid" in failure for failure in report["failures"])


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("role", []),
        ("role", {}),
        ("image_kind", []),
        ("image_kind", {}),
        ("signer_state", []),
        ("signer_state", {}),
    ],
    ids=[
        "role-list",
        "role-dict",
        "kind-list",
        "kind-dict",
        "signer-list",
        "signer-dict",
    ],
)
def test_unhashable_process_enum_fields_fail_closed(field, bad):
    data = _evidence()
    data["controls"][0]["processes"][1][field] = bad
    report = b124.summarize(data)
    assert report["passed"] is False
    assert any("invalid" in failure for failure in report["failures"])


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("pid", []),
        ("pid", {}),
        ("parent_pid", []),
        ("parent_pid", {}),
    ],
    ids=["pid-list", "pid-dict", "parent-list", "parent-dict"],
)
def test_malformed_pid_fields_do_not_reach_chain_hashing(field, bad):
    data = _evidence()
    data["controls"][0]["processes"][1][field] = bad
    report = b124.summarize(data)
    assert report["passed"] is False
    assert any("pid_invalid" in failure for failure in report["failures"])
