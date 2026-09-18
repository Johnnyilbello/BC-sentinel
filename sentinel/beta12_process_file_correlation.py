from __future__ import annotations

"""B12-1 Process/File Correlation 2.0.

Build a deterministic, privacy-minimal Security Graph from one bounded Windows
process/file observation. The module correlates explicit process, file, hash,
signer and optional parent-process evidence. It performs no collection, process
control, remediation, network access, coverage promotion or threat classification.
"""

import hashlib
import json
from typing import Any, Final

from sentinel import incident_correlation, security_graph

SCHEMA: Final[str] = "bc-sentinel-beta12-process-file-correlation-v1"
PROFILE: Final[str] = "v0.12.0-beta.12-b121-process-file-correlation"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v012-beta12-b120-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "0015feb80c550b9c67707f24f4042a45412e7af3"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
SOURCE_VERIFIED: Final[tuple[str, ...]] = ("B7-POWERSHELL-001", "B7-RANSOMWARE-001")

SOURCE: Final[str] = "WINDOWS_PROCESS_FILE_CORRELATION_OBSERVATION"
ALLOWED_OPERATIONS: Final[set[str]] = {"CREATED", "MODIFIED", "ACCESSED"}
ALLOWED_SIGNER_STATES: Final[set[str]] = {
    "UNKNOWN",
    "UNSIGNED",
    "SIGNED_UNVERIFIED",
    "SIGNED_VERIFIED",
}

BOUNDARIES: Final[dict[str, bool]] = {
    "local_only": True,
    "read_only": True,
    "raw_path_collected": False,
    "command_line_collected": False,
    "username_collected": False,
    "event_payload_collected": False,
    "network_required": False,
    "cloud_required": False,
    "threat_classification": False,
    "coverage_promoted": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
}

TOP_LEVEL_FIELDS: Final[set[str]] = {
    "schema",
    "source",
    "observation_id",
    "observed_at",
    "process",
    "parent_process",
    "file",
    "evidence",
    "provenance",
    "boundaries",
}
PROCESS_FIELDS: Final[set[str]] = {
    "pid",
    "parent_pid",
    "image_sha256",
    "signer_state",
    "signer_subject_digest",
}
PARENT_FIELDS: Final[set[str]] = {
    "pid",
    "image_sha256",
    "signer_state",
    "signer_subject_digest",
}
FILE_FIELDS: Final[set[str]] = {
    "operation",
    "target_path_digest",
    "sha256",
    "signer_state",
    "signer_subject_digest",
}
EVIDENCE_FIELDS: Final[set[str]] = {
    "process_evidence_id",
    "file_evidence_id",
    "relation_evidence_id",
}
PROVENANCE_FIELDS: Final[set[str]] = {"source", "source_id", "collector", "trust"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_timestamp(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and value >= 0


def _valid_pid(value: object, *, allow_none: bool = False) -> bool:
    if value is None:
        return allow_none
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value.lower())
    )


def _valid_signer(state: object, subject_digest: object) -> bool:
    if state not in ALLOWED_SIGNER_STATES:
        return False
    if state in {"SIGNED_UNVERIFIED", "SIGNED_VERIFIED"}:
        return _valid_sha256(subject_digest)
    return subject_digest is None


def _validate_process(value: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, dict) or set(value) != PROCESS_FIELDS:
        return ["b121:process_fields_invalid"]
    if not _valid_pid(value.get("pid")):
        failures.append("b121:process_pid_invalid")
    if not _valid_pid(value.get("parent_pid"), allow_none=True):
        failures.append("b121:process_parent_pid_invalid")
    if not _valid_sha256(value.get("image_sha256")):
        failures.append("b121:process_image_sha256_invalid")
    if not _valid_signer(value.get("signer_state"), value.get("signer_subject_digest")):
        failures.append("b121:process_signer_invalid")
    return failures


def _validate_parent(value: object) -> list[str]:
    if value is None:
        return []
    failures: list[str] = []
    if not isinstance(value, dict) or set(value) != PARENT_FIELDS:
        return ["b121:parent_fields_invalid"]
    if not _valid_pid(value.get("pid")):
        failures.append("b121:parent_pid_invalid")
    if not _valid_sha256(value.get("image_sha256")):
        failures.append("b121:parent_image_sha256_invalid")
    if not _valid_signer(value.get("signer_state"), value.get("signer_subject_digest")):
        failures.append("b121:parent_signer_invalid")
    return failures


def _validate_file(value: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, dict) or set(value) != FILE_FIELDS:
        return ["b121:file_fields_invalid"]
    if value.get("operation") not in ALLOWED_OPERATIONS:
        failures.append("b121:file_operation_invalid")
    if not _valid_sha256(value.get("target_path_digest")):
        failures.append("b121:target_path_digest_invalid")
    if not _valid_sha256(value.get("sha256")):
        failures.append("b121:file_sha256_invalid")
    if not _valid_signer(value.get("signer_state"), value.get("signer_subject_digest")):
        failures.append("b121:file_signer_invalid")
    return failures


def validate_observation(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b121:not_object",)

    failures: list[str] = []
    if set(data) != TOP_LEVEL_FIELDS:
        failures.append("b121:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("source") != SOURCE:
        failures.append("b121:schema_or_source_invalid")
    if not _nonempty(data.get("observation_id")):
        failures.append("b121:observation_id_invalid")
    if not _valid_timestamp(data.get("observed_at")):
        failures.append("b121:observed_at_invalid")

    failures.extend(_validate_process(data.get("process")))
    failures.extend(_validate_parent(data.get("parent_process")))
    failures.extend(_validate_file(data.get("file")))

    evidence = data.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != EVIDENCE_FIELDS:
        failures.append("b121:evidence_fields_invalid")
    else:
        values = [evidence.get(field) for field in sorted(EVIDENCE_FIELDS)]
        if not all(_nonempty(value) for value in values):
            failures.append("b121:evidence_id_invalid")
        elif len(set(values)) != len(values):
            failures.append("b121:evidence_ids_not_distinct")

    provenance = data.get("provenance")
    if not isinstance(provenance, dict) or set(provenance) != PROVENANCE_FIELDS:
        failures.append("b121:provenance_fields_invalid")
    else:
        if not all(_nonempty(provenance.get(field)) for field in ("source", "source_id", "collector")):
            failures.append("b121:provenance_value_invalid")
        if provenance.get("trust") not in security_graph.ALLOWED_PROVENANCE_TRUST:
            failures.append("b121:provenance_trust_invalid")

    boundaries = data.get("boundaries")
    if boundaries != BOUNDARIES:
        failures.append("b121:boundary_invalid")

    process = data.get("process") if isinstance(data.get("process"), dict) else {}
    parent = data.get("parent_process")
    if isinstance(parent, dict):
        if process.get("parent_pid") != parent.get("pid"):
            failures.append("b121:parent_binding_mismatch")
        if process.get("pid") == parent.get("pid"):
            failures.append("b121:self_parent_forbidden")

    return tuple(dict.fromkeys(failures))


def _provenance(data: dict[str, Any], source_id_suffix: str) -> dict[str, Any]:
    base = data["provenance"]
    return {
        "source": base["source"],
        "source_id": f"{base['source_id']}:{source_id_suffix}",
        "collector": base["collector"],
        "trust": base["trust"],
    }


def build_graph(data: object) -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult]:
    failures = validate_observation(data)
    if failures:
        raise ValueError("b121:invalid_observation:" + ",".join(failures))
    assert isinstance(data, dict)

    observed_at = float(data["observed_at"])
    process = data["process"]
    parent = data["parent_process"]
    file_info = data["file"]
    evidence = data["evidence"]

    builder = security_graph.SecurityGraphBuilder()

    process_node = builder.ingest_observation(
        {
            "node_type": "PROCESS",
            "identity": {
                "pid": process["pid"],
                "image_sha256": process["image_sha256"],
            },
            "label": "Observed process",
            "observed_at": observed_at,
            "provenance": _provenance(data, "process"),
            "evidence_ids": [evidence["process_evidence_id"]],
            "confidence": 1.0,
            "attributes": {
                "pid": process["pid"],
                "parent_pid": process["parent_pid"],
                "image_sha256": process["image_sha256"].lower(),
                "signer_state": process["signer_state"],
                "signer_subject_digest": process["signer_subject_digest"],
            },
        }
    )

    file_node = builder.ingest_observation(
        {
            "node_type": "FILE",
            "identity": {
                "target_path_digest": file_info["target_path_digest"],
                "sha256": file_info["sha256"],
            },
            "label": "Observed file artifact",
            "observed_at": observed_at,
            "provenance": _provenance(data, "file"),
            "evidence_ids": [evidence["file_evidence_id"]],
            "confidence": 1.0,
            "attributes": {
                "operation": file_info["operation"],
                "target_path_digest": file_info["target_path_digest"].lower(),
                "sha256": file_info["sha256"].lower(),
                "signer_state": file_info["signer_state"],
                "signer_subject_digest": file_info["signer_subject_digest"],
            },
        }
    )

    builder.link(
        edge_type=file_info["operation"],
        source=process_node.node_id,
        target=file_node.node_id,
        observed_at=observed_at,
        provenance=_provenance(data, "relation"),
        evidence_ids=[evidence["relation_evidence_id"]],
        confidence=1.0,
        reason=f"Explicit bounded process/file relation observed as {file_info['operation']}.",
    )

    if parent is not None:
        parent_node = builder.ingest_observation(
            {
                "node_type": "PROCESS",
                "identity": {
                    "pid": parent["pid"],
                    "image_sha256": parent["image_sha256"],
                },
                "label": "Observed parent process",
                "observed_at": observed_at,
                "provenance": _provenance(data, "parent"),
                "evidence_ids": [evidence["process_evidence_id"]],
                "confidence": 1.0,
                "attributes": {
                    "pid": parent["pid"],
                    "image_sha256": parent["image_sha256"].lower(),
                    "signer_state": parent["signer_state"],
                    "signer_subject_digest": parent["signer_subject_digest"],
                },
            }
        )
        builder.link(
            edge_type="SPAWNED",
            source=parent_node.node_id,
            target=process_node.node_id,
            observed_at=observed_at,
            provenance=_provenance(data, "parent-relation"),
            evidence_ids=[evidence["process_evidence_id"]],
            confidence=1.0,
            reason="Explicit parent-process evidence binds observed parent to child.",
        )

    observation_digest = _sha(
        {
            "observation_id": data["observation_id"],
            "observed_at": data["observed_at"],
            "process_image_sha256": process["image_sha256"],
            "file_sha256": file_info["sha256"],
            "operation": file_info["operation"],
        }
    )
    graph = builder.build(
        graph_id="b121-graph:" + observation_digest[:20],
        incident_id="b121-incident:" + observation_digest[20:40],
        created_at=observed_at,
        metadata={
            "milestone": "B12-1",
            "observation_digest": observation_digest,
            "privacy_minimal": True,
            "threat_classification": False,
            "coverage_promoted": False,
        },
    )
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)
    return graph, correlation


def summarize(data: object) -> dict[str, Any]:
    failures = validate_observation(data)
    if failures:
        return {"passed": False, "failures": list(failures)}

    assert isinstance(data, dict)
    graph, correlation = build_graph(data)
    graph_validation = security_graph.validate_graph(graph.to_dict())
    correlation_validation = incident_correlation.validate_result(correlation, graph)

    process_nodes = graph.nodes_by_type("PROCESS")
    file_nodes = graph.nodes_by_type("FILE")
    operation = data["file"]["operation"]
    relation_edges = [edge for edge in graph.edges if edge.edge_type == operation]
    ancestry_edges = [edge for edge in graph.edges if edge.edge_type == "SPAWNED"]
    parent_expected = data["parent_process"] is not None

    passed = (
        graph_validation.passed
        and correlation_validation.passed
        and len(file_nodes) == 1
        and len(relation_edges) == 1
        and len(correlation.incidents) == 1
        and len(process_nodes) == (2 if parent_expected else 1)
        and len(ancestry_edges) == (1 if parent_expected else 0)
    )

    return {
        "passed": bool(passed),
        "failures": [],
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "graph_digest": graph.digest(),
        "correlation_digest": correlation.digest(),
        "graph_node_count": len(graph.nodes),
        "graph_edge_count": len(graph.edges),
        "incident_count": len(correlation.incidents),
        "process_file_bound": len(relation_edges) == 1,
        "ancestry_evidence_present": parent_expected,
        "ancestry_bound": len(ancestry_edges) == 1 if parent_expected else False,
        "unknown_ancestry_preserved": not parent_expected,
        "process_hash_preserved": True,
        "file_hash_preserved": True,
        "signer_state_preserved": True,
        "raw_path_collected": False,
        "command_line_collected": False,
        "username_collected": False,
        "threat_classification_performed": False,
        "coverage_summary": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(SOURCE_VERIFIED),
        "coverage_promoted": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
    }


def sample_observation(*, with_parent: bool = True) -> dict[str, Any]:
    process = {
        "pid": 4200,
        "parent_pid": 4100 if with_parent else None,
        "image_sha256": "a" * 64,
        "signer_state": "SIGNED_VERIFIED",
        "signer_subject_digest": "1" * 64,
    }
    parent = (
        {
            "pid": 4100,
            "image_sha256": "b" * 64,
            "signer_state": "SIGNED_VERIFIED",
            "signer_subject_digest": "2" * 64,
        }
        if with_parent
        else None
    )
    return {
        "schema": SCHEMA,
        "source": SOURCE,
        "observation_id": "b121-self-check-observation",
        "observed_at": 1000.0,
        "process": process,
        "parent_process": parent,
        "file": {
            "operation": "CREATED",
            "target_path_digest": "c" * 64,
            "sha256": "d" * 64,
            "signer_state": "UNSIGNED",
            "signer_subject_digest": None,
        },
        "evidence": {
            "process_evidence_id": "ev-b121-process",
            "file_evidence_id": "ev-b121-file",
            "relation_evidence_id": "ev-b121-relation",
        },
        "provenance": {
            "source": "b121-controlled-fixture",
            "source_id": "b121-self-check",
            "collector": "sentinel.beta12_process_file_correlation",
            "trust": "DIRECT",
        },
        "boundaries": dict(BOUNDARIES),
    }


def self_check() -> dict[str, Any]:
    with_parent = summarize(sample_observation(with_parent=True))
    without_parent = summarize(sample_observation(with_parent=False))
    deterministic = with_parent == summarize(sample_observation(with_parent=True))
    failures: list[str] = []
    if not with_parent.get("passed"):
        failures.append("b121:parent_sample_failed")
    if not without_parent.get("passed"):
        failures.append("b121:no_parent_sample_failed")
    if not without_parent.get("unknown_ancestry_preserved"):
        failures.append("b121:unknown_ancestry_not_preserved")
    if not deterministic:
        failures.append("b121:not_deterministic")
    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(SOURCE_VERIFIED),
        "contract_digest": _sha(
            {
                "schema": SCHEMA,
                "profile": PROFILE,
                "source_checkpoint": SOURCE_CHECKPOINT,
                "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
                "allowed_operations": sorted(ALLOWED_OPERATIONS),
                "allowed_signer_states": sorted(ALLOWED_SIGNER_STATES),
                "boundaries": BOUNDARIES,
            }
        ),
        "deterministic": deterministic,
        "process_file_binding": with_parent.get("process_file_bound") is True,
        "optional_ancestry_binding": with_parent.get("ancestry_bound") is True,
        "unknown_ancestry_preserved": without_parent.get("unknown_ancestry_preserved") is True,
        "coverage_promoted": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
    }


def main() -> int:
    print(json.dumps(self_check(), indent=2, sort_keys=True))
    return 0 if self_check()["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
