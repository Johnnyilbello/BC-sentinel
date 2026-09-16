from copy import deepcopy
import json

import pytest

from sentinel import beta9_event_to_incident as b92


@pytest.fixture
def exercise():
    return {
        "schema": b92.SCHEMA,
        "source": b92.SOURCE,
        "exercise": {
            "live_observation": True,
            "child_process_id": 4242,
            "baseline_record_id": 100,
            "launched_at_utc": "2026-09-16T12:00:00+00:00",
            "completed_at_utc": "2026-09-16T12:00:01+00:00",
            "cleanup_state": "EXITED",
            "exit_code": 0,
        },
        "event": {
            "channel": b92.CHANNEL,
            "provider": b92.PROVIDER,
            "event_id": 400,
            "level": 4,
            "record_id": 101,
            "process_id": 4242,
            "time_created_utc": "2026-09-16T12:00:00.500000+00:00",
        },
        "boundaries": dict(b92.BOUNDARIES),
    }


def test_harmless_live_event_binds_end_to_end(exercise):
    result = b92.summarize(exercise)
    assert result["passed"]
    assert result["acceptance_detector_outcome"] == "BENIGN_EXERCISE_OBSERVED"
    assert result["live_event_bound"] is True
    assert result["event_to_acceptance_detector_bound"] is True
    assert result["detector_to_security_graph_bound"] is True
    assert result["security_graph_to_incident_bound"] is True
    assert result["incident_count"] == 1
    assert result["graph_node_count"] == 2
    assert result["graph_edge_count"] == 1
    assert result["coverage_summary"] == {"PARTIAL": 6, "GAP": 0, "VERIFIED": 0}


def test_deterministic_summary_for_same_input(exercise):
    assert b92.summarize(exercise) == b92.summarize(deepcopy(exercise))


def test_accepts_event_403(exercise):
    exercise["event"]["event_id"] = 403
    assert b92.summarize(exercise)["passed"]


def test_accepts_null_baseline(exercise):
    exercise["exercise"]["baseline_record_id"] = None
    assert b92.summarize(exercise)["passed"]


def test_accepts_null_level(exercise):
    exercise["event"]["level"] = None
    assert b92.summarize(exercise)["passed"]


@pytest.mark.parametrize("value", [None, [], "raw", 1, True, {}])
def test_malformed_top_level_fails_closed(value):
    assert not b92.summarize(value)["passed"]


@pytest.mark.parametrize("field", ["message", "properties", "xml", "username", "machine_name", "path", "command_line", "script"])
def test_forbidden_event_fields_rejected_without_echo(exercise, field):
    exercise["event"][field] = "PRIVATE_B92_VALUE"
    result = b92.summarize(exercise)
    assert not result["passed"]
    assert "PRIVATE_B92_VALUE" not in json.dumps(result)


@pytest.mark.parametrize("field", ["token", "credential", "hostname", "user", "message"])
def test_unexpected_exercise_fields_rejected_without_echo(exercise, field):
    exercise["exercise"][field] = "PRIVATE_B92_VALUE"
    result = b92.summarize(exercise)
    assert not result["passed"]
    assert "PRIVATE_B92_VALUE" not in json.dumps(result)


@pytest.mark.parametrize("field", list(b92.BOUNDARIES))
def test_boundary_changes_rejected(exercise, field):
    exercise["boundaries"][field] = not exercise["boundaries"][field]
    assert not b92.summarize(exercise)["passed"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("channel", "Application"),
        ("provider", "Other"),
        ("event_id", 4104),
        ("event_id", True),
        ("record_id", -1),
        ("record_id", True),
        ("process_id", 0),
        ("process_id", True),
        ("level", -1),
        ("level", 256),
        ("time_created_utc", "not-a-time"),
        ("time_created_utc", "2026-09-16T12:00:00"),
    ],
)
def test_invalid_event_contract_rejected(exercise, field, value):
    exercise["event"][field] = value
    assert not b92.summarize(exercise)["passed"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("live_observation", False),
        ("child_process_id", 0),
        ("child_process_id", True),
        ("baseline_record_id", -1),
        ("baseline_record_id", True),
        ("launched_at_utc", "bad"),
        ("completed_at_utc", "bad"),
        ("cleanup_state", "RUNNING"),
        ("exit_code", 1),
    ],
)
def test_invalid_exercise_contract_rejected(exercise, field, value):
    exercise["exercise"][field] = value
    assert not b92.summarize(exercise)["passed"]


def test_process_binding_must_be_exact(exercise):
    exercise["event"]["process_id"] = 4243
    result = b92.summarize(exercise)
    assert not result["passed"]
    assert "exercise:event_process_binding_mismatch" in result["failures"]


def test_record_id_must_be_newer_than_baseline(exercise):
    exercise["event"]["record_id"] = 100
    result = b92.summarize(exercise)
    assert not result["passed"]
    assert "exercise:event_not_fresh_by_record_id" in result["failures"]


def test_event_before_freshness_window_rejected(exercise):
    exercise["event"]["time_created_utc"] = "2026-09-16T11:59:50+00:00"
    result = b92.summarize(exercise)
    assert not result["passed"]
    assert "exercise:event_not_fresh_by_time" in result["failures"]


def test_event_after_freshness_window_rejected(exercise):
    exercise["event"]["time_created_utc"] = "2026-09-16T12:00:20+00:00"
    result = b92.summarize(exercise)
    assert not result["passed"]
    assert "exercise:event_not_fresh_by_time" in result["failures"]


def test_reversed_exercise_times_rejected(exercise):
    exercise["exercise"]["completed_at_utc"] = "2026-09-16T11:59:59+00:00"
    result = b92.summarize(exercise)
    assert not result["passed"]
    assert "exercise:time_window_invalid" in result["failures"]


def test_overlong_exercise_window_rejected(exercise):
    exercise["exercise"]["completed_at_utc"] = "2026-09-16T12:00:20+00:00"
    result = b92.summarize(exercise)
    assert not result["passed"]
    assert "exercise:time_window_invalid" in result["failures"]


def test_replay_flag_rejected(exercise):
    exercise["exercise"]["live_observation"] = False
    result = b92.summarize(exercise)
    assert not result["passed"]
    assert "exercise:live_observation_required" in result["failures"]


def test_wrong_schema_rejected(exercise):
    exercise["schema"] = "fixture"
    assert not b92.summarize(exercise)["passed"]


def test_wrong_source_rejected(exercise):
    exercise["source"] = "REPLAY"
    assert not b92.summarize(exercise)["passed"]


def test_top_level_extra_field_rejected_without_echo(exercise):
    exercise["secret"] = "PRIVATE_B92_VALUE"
    result = b92.summarize(exercise)
    assert not result["passed"]
    assert "PRIVATE_B92_VALUE" not in json.dumps(result)


def test_summary_never_promotes_threat_coverage(exercise):
    result = b92.summarize(exercise)
    assert result["passed"]
    assert result["threat_detector_verification_performed"] is False
    assert result["threat_classification_performed"] is False
    assert result["coverage_summary"]["VERIFIED"] == 0
    assert result["boundaries"]["remediation_authority"] is False
    assert result["boundaries"]["product_process_launch_authority"] is False
    assert result["boundaries"]["product_process_termination_authority"] is False


def test_graph_and_correlation_digests_are_sha256(exercise):
    result = b92.summarize(exercise)
    assert len(result["graph_digest"]) == 64
    assert len(result["correlation_digest"]) == 64
    assert all(ch in "0123456789abcdef" for ch in result["graph_digest"])
    assert all(ch in "0123456789abcdef" for ch in result["correlation_digest"])


def test_evidence_id_and_marker_do_not_expose_pid(exercise):
    result = b92.summarize(exercise)
    serialized = json.dumps(result)
    assert "4242" not in result["evidence_id"]
    assert "4242" not in result["exercise_marker_digest"]
    assert "child_process_id" not in serialized


def test_builder_preserves_exact_shared_evidence(exercise):
    graph, correlation, marker, evidence_id = b92._build_graph(exercise)
    assert len(graph.nodes) == 2
    assert all(node.evidence_ids == (evidence_id,) for node in graph.nodes)
    assert graph.edges[0].evidence_ids == (evidence_id,)
    assert graph.metadata["correlation_marker"] == marker
    assert len(correlation.incidents) == 1
    assert set(correlation.incidents[0].node_ids) == {node.node_id for node in graph.nodes}


def test_graph_source_is_not_mutated_by_correlation(exercise):
    graph, correlation, _, _ = b92._build_graph(exercise)
    digest = graph.digest()
    assert correlation.source_graph_digest == digest
    assert graph.digest() == digest
