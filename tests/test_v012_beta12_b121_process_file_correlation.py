from __future__ import annotations

from copy import deepcopy
import json

import pytest

from sentinel import beta12_process_file_correlation as b121


@pytest.fixture
def observation():
    return b121.sample_observation(with_parent=True)


def test_self_check_passes_and_preserves_beta12_baseline():
    report = b121.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v012-beta12-b120-pass"
    assert report["source_checkpoint_commit"] == "0015feb80c550b9c67707f24f4042a45412e7af3"
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert report["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False


def test_process_file_relation_builds_one_incident(observation):
    result = b121.summarize(observation)
    assert result["passed"]
    assert result["process_file_bound"] is True
    assert result["ancestry_evidence_present"] is True
    assert result["ancestry_bound"] is True
    assert result["graph_node_count"] == 3
    assert result["graph_edge_count"] == 2
    assert result["incident_count"] == 1


def test_unknown_ancestry_stays_unknown():
    observation = b121.sample_observation(with_parent=False)
    result = b121.summarize(observation)
    assert result["passed"]
    assert result["ancestry_evidence_present"] is False
    assert result["ancestry_bound"] is False
    assert result["unknown_ancestry_preserved"] is True
    assert result["graph_node_count"] == 2
    assert result["graph_edge_count"] == 1


@pytest.mark.parametrize("operation", ["CREATED", "MODIFIED", "ACCESSED"])
def test_supported_file_operations_are_explicit(observation, operation):
    observation["file"]["operation"] = operation
    graph, correlation = b121.build_graph(observation)
    assert any(edge.edge_type == operation for edge in graph.edges)
    assert len(correlation.incidents) == 1


def test_process_file_hashes_and_signer_state_are_preserved(observation):
    graph, _ = b121.build_graph(observation)
    process = [n for n in graph.nodes if n.node_type == "PROCESS" and n.attributes.get("pid") == 4200][0]
    file_node = graph.nodes_by_type("FILE")[0]
    assert process.attributes["image_sha256"] == "a" * 64
    assert process.attributes["signer_state"] == "SIGNED_VERIFIED"
    assert process.attributes["signer_subject_digest"] == "1" * 64
    assert file_node.attributes["sha256"] == "d" * 64
    assert file_node.attributes["target_path_digest"] == "c" * 64
    assert file_node.attributes["signer_state"] == "UNSIGNED"


def test_no_raw_path_command_line_or_username_are_collected(observation):
    result = b121.summarize(observation)
    serialized = json.dumps(result)
    assert result["raw_path_collected"] is False
    assert result["command_line_collected"] is False
    assert result["username_collected"] is False
    assert "C:\\" not in serialized
    assert "command_line" in serialized
    assert "username_collected" in serialized


@pytest.mark.parametrize("field", ["path", "command_line", "username", "message", "token"])
def test_forbidden_extra_process_fields_fail_closed_without_echo(observation, field):
    observation["process"][field] = "PRIVATE_B121_VALUE"
    result = b121.summarize(observation)
    assert not result["passed"]
    assert "PRIVATE_B121_VALUE" not in json.dumps(result)


@pytest.mark.parametrize("field", ["path", "filename", "username", "message"])
def test_forbidden_extra_file_fields_fail_closed_without_echo(observation, field):
    observation["file"][field] = "PRIVATE_B121_VALUE"
    result = b121.summarize(observation)
    assert not result["passed"]
    assert "PRIVATE_B121_VALUE" not in json.dumps(result)


def test_parent_binding_must_match_process_parent_pid(observation):
    observation["parent_process"]["pid"] = 9999
    result = b121.summarize(observation)
    assert not result["passed"]
    assert "b121:parent_binding_mismatch" in result["failures"]


def test_self_parent_is_rejected(observation):
    observation["process"]["parent_pid"] = 4200
    observation["parent_process"]["pid"] = 4200
    result = b121.summarize(observation)
    assert not result["passed"]
    assert "b121:self_parent_forbidden" in result["failures"]


@pytest.mark.parametrize("field", ["image_sha256"])
def test_invalid_process_hash_fails_closed(observation, field):
    observation["process"][field] = "bad"
    assert not b121.summarize(observation)["passed"]


@pytest.mark.parametrize("field", ["sha256", "target_path_digest"])
def test_invalid_file_hashes_fail_closed(observation, field):
    observation["file"][field] = "bad"
    assert not b121.summarize(observation)["passed"]


def test_signed_state_requires_subject_digest(observation):
    observation["file"]["signer_state"] = "SIGNED_VERIFIED"
    observation["file"]["signer_subject_digest"] = None
    result = b121.summarize(observation)
    assert not result["passed"]
    assert "b121:file_signer_invalid" in result["failures"]


def test_unsigned_state_rejects_subject_digest(observation):
    observation["file"]["signer_state"] = "UNSIGNED"
    observation["file"]["signer_subject_digest"] = "e" * 64
    result = b121.summarize(observation)
    assert not result["passed"]
    assert "b121:file_signer_invalid" in result["failures"]


def test_evidence_ids_must_be_distinct(observation):
    observation["evidence"]["file_evidence_id"] = observation["evidence"]["process_evidence_id"]
    result = b121.summarize(observation)
    assert not result["passed"]
    assert "b121:evidence_ids_not_distinct" in result["failures"]


def test_boundary_changes_fail_closed(observation):
    observation["boundaries"]["automatic_quarantine"] = True
    result = b121.summarize(observation)
    assert not result["passed"]
    assert "b121:boundary_invalid" in result["failures"]


def test_deterministic_graph_and_correlation(observation):
    first = b121.summarize(observation)
    second = b121.summarize(deepcopy(observation))
    assert first == second
    assert len(first["graph_digest"]) == 64
    assert len(first["correlation_digest"]) == 64


def test_graph_contains_explicit_explained_edges(observation):
    graph, _ = b121.build_graph(observation)
    assert {edge.edge_type for edge in graph.edges} == {"CREATED", "SPAWNED"}
    assert all(edge.reason.strip() for edge in graph.edges)
    assert all(edge.evidence_ids for edge in graph.edges)


def test_no_detection_or_coverage_promotion_occurs(observation):
    result = b121.summarize(observation)
    assert result["threat_classification_performed"] is False
    assert result["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert result["coverage_promoted"] is False
    assert result["authority_expanded"] is False
    assert result["network_required"] is False
    assert result["cloud_required"] is False


@pytest.mark.parametrize("bad", [None, [], "raw", 7, True, {}])
def test_malformed_input_fails_closed(bad):
    result = b121.summarize(bad)
    assert result["passed"] is False


def test_build_graph_rejects_invalid_observation(observation):
    observation["file"]["operation"] = "DELETED"
    with pytest.raises(ValueError, match="b121:invalid_observation"):
        b121.build_graph(observation)
