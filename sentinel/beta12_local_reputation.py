from __future__ import annotations

"""B12-6 Local Reputation & Hash Intelligence.

Consumes privacy-minimal local metadata for three harmless live controls:
1) a signed file explicitly present in an ephemeral local allowlist,
2) a signed file not present in that allowlist,
3) an unsigned file not present in that allowlist.

Classification is informational only. The module never executes files, changes
trust state, contacts a reputation service, or grants remediation authority.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Final

from sentinel import incident_correlation, security_graph

SCHEMA: Final[str] = "bc-sentinel-beta12-local-reputation-v1"
PROFILE: Final[str] = "v0.12.0-beta.12-b126-local-reputation-hash-intelligence"
SOURCE: Final[str] = "WINDOWS_LOCAL_HASH_SIGNER_CONTROLS"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v012-beta12-b125-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "04dfef15f5cb5583fd49b878efc9de663e74cdcb"
TARGET_SCENARIO: Final[str] = "B12-LOCAL-REPUTATION-001"

BASELINE_VERIFIED: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
    "B12-SCRIPT-ABUSE-001",
    "B12-AUTOSTART-LINK-001",
    "B12-PROCESS-TREE-001",
    "B12-RANSOMWARE-PROCESS-001",
)

CONTROL_IDS: Final[tuple[str, ...]] = (
    "known-good-signed-allowlisted",
    "signed-unknown",
    "unsigned-unknown",
)
SIGNER_STATES: Final[set[str]] = {
    "UNKNOWN",
    "UNSIGNED",
    "SIGNED_UNVERIFIED",
    "SIGNED_VERIFIED",
}
OUTCOME_TRUSTED: Final[str] = "TRUSTED_LOCAL"
OUTCOME_UNKNOWN_SIGNED: Final[str] = "UNKNOWN_SIGNED"
OUTCOME_UNKNOWN_UNSIGNED: Final[str] = "UNKNOWN_UNSIGNED"

ALLOWLIST_FIELDS: Final[set[str]] = {
    "entry_id",
    "sha256",
    "signer_subject_digest",
    "source",
}
CONTROL_FIELDS: Final[set[str]] = {
    "control_id",
    "live_observation",
    "sha256",
    "path_digest",
    "signer_state",
    "signer_subject_digest",
    "local_allowlist_hit",
    "allowlist_entry_id",
    "file_executed",
}
BOUNDARIES: Final[dict[str, bool]] = {
    "local_only": True,
    "explicit_opt_in_required": True,
    "cloud_required": False,
    "network_io": False,
    "remote_access": False,
    "raw_path_exported": False,
    "file_content_exported": False,
    "username_collected": False,
    "file_execution": False,
    "trust_allowlist_mutation": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "privileged_system_mutation": False,
}

BASELINE_DECISIONS: Final[tuple[dict[str, str], ...]] = (
    {"scenario_id":"B7-POWERSHELL-001","status":"VERIFIED","evidence_basis":"ACCEPTED_B10_METADATA_LIFECYCLE_BURST_CONTROL","limitation":"Metadata-only lifecycle-burst verification."},
    {"scenario_id":"B7-RANSOMWARE-001","status":"VERIFIED","evidence_basis":"ACCEPTED_B9_CONTROLLED_LOCAL_RANSOMWARE_LIKE_PATH","limitation":"Controlled local scenario only; not broad ransomware-family coverage."},
    {"scenario_id":"B12-SCRIPT-ABUSE-001","status":"VERIFIED","evidence_basis":"ACCEPTED_B12_2_LIVE_WINDOWS_SCRIPT_MUTATION_PATH","limitation":"Disposable-workspace script-driven mutation burst only."},
    {"scenario_id":"B12-AUTOSTART-LINK-001","status":"VERIFIED","evidence_basis":"ACCEPTED_B12_3_LIVE_WINDOWS_SHORTCUT_PATTERN","limitation":"Disposable-workspace shortcut metadata only."},
    {"scenario_id":"B12-PROCESS-TREE-001","status":"VERIFIED","evidence_basis":"ACCEPTED_B12_4_LIVE_WINDOWS_PROCESS_TREE","limitation":"Bounded live ancestry pattern only."},
    {"scenario_id":"B12-RANSOMWARE-PROCESS-001","status":"VERIFIED","evidence_basis":"ACCEPTED_B12_5_PROCESS_ATTRIBUTION","limitation":"Process attribution around accepted harmless B9 live controls only."},
    {"scenario_id":"B7-PERSISTENCE-001","status":"PARTIAL","evidence_basis":"NO_REAL_PERSISTENCE_SURFACE_MUTATION","limitation":"Actual persistence execution remains unverified."},
    {"scenario_id":"B7-DEFENSE-EVASION-001","status":"PARTIAL","evidence_basis":"NO_ACCEPTED_SAFE_LIVE_POSITIVE_CONTROL","limitation":"No security-control impairment is performed."},
    {"scenario_id":"B7-C2-DNS-001","status":"PARTIAL","evidence_basis":"NO_ACCEPTED_NETWORK_CONTROL","limitation":"Core acceptance remains network-free."},
    {"scenario_id":"B7-CREDENTIAL-001","status":"PARTIAL","evidence_basis":"NO_ACCEPTED_SENSITIVE_ACCESS_CONTROL","limitation":"Credential access remains prohibited."},
)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value.lower())
    )


def _valid_signer(state: object, subject_digest: object) -> bool:
    if state not in SIGNER_STATES:
        return False
    if state in {"SIGNED_UNVERIFIED", "SIGNED_VERIFIED"}:
        return _valid_sha256(subject_digest)
    return subject_digest is None


def validate_evidence(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b126:not_object",)

    failures: list[str] = []
    if set(data) != {"schema", "source", "allowlist", "controls", "boundaries"}:
        failures.append("b126:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("source") != SOURCE:
        failures.append("b126:schema_or_source_invalid")
    if data.get("boundaries") != BOUNDARIES:
        failures.append("b126:boundary_invalid")

    allowlist = data.get("allowlist")
    if not isinstance(allowlist, list) or len(allowlist) != 1:
        failures.append("b126:allowlist_shape_invalid")
    else:
        entry = allowlist[0]
        if not isinstance(entry, dict) or set(entry) != ALLOWLIST_FIELDS:
            failures.append("b126:allowlist_entry_fields_invalid")
        else:
            if entry.get("entry_id") != "b126-known-good-1":
                failures.append("b126:allowlist_entry_id_invalid")
            if not _valid_sha256(entry.get("sha256")):
                failures.append("b126:allowlist_hash_invalid")
            if not _valid_sha256(entry.get("signer_subject_digest")):
                failures.append("b126:allowlist_signer_invalid")
            if entry.get("source") != "EXPLICIT_EPHEMERAL_ACCEPTANCE_ALLOWLIST":
                failures.append("b126:allowlist_source_invalid")

    controls = data.get("controls")
    if not isinstance(controls, list) or len(controls) != 3:
        return tuple(dict.fromkeys(failures + ["b126:control_count_invalid"]))

    for index, (expected_id, row) in enumerate(zip(CONTROL_IDS, controls)):
        prefix = f"b126:control[{index}]"
        if not isinstance(row, dict) or set(row) != CONTROL_FIELDS:
            failures.append(f"{prefix}:fields_invalid")
            continue
        if row.get("control_id") != expected_id:
            failures.append(f"{prefix}:identity_invalid")
        if row.get("live_observation") is not True:
            failures.append(f"{prefix}:live_observation_required")
        if not _valid_sha256(row.get("sha256")):
            failures.append(f"{prefix}:sha256_invalid")
        if not _valid_sha256(row.get("path_digest")):
            failures.append(f"{prefix}:path_digest_invalid")
        if not _valid_signer(row.get("signer_state"), row.get("signer_subject_digest")):
            failures.append(f"{prefix}:signer_invalid")
        if not isinstance(row.get("local_allowlist_hit"), bool):
            failures.append(f"{prefix}:allowlist_hit_invalid")
        if row.get("file_executed") is not False:
            failures.append(f"{prefix}:file_execution_forbidden")

    if isinstance(allowlist, list) and len(allowlist) == 1 and isinstance(allowlist[0], dict):
        entry = allowlist[0]
        if all(isinstance(row, dict) for row in controls):
            known, signed_unknown, unsigned_unknown = controls
            if known.get("local_allowlist_hit") is not True:
                failures.append("b126:known_good_hit_required")
            if known.get("allowlist_entry_id") != entry.get("entry_id"):
                failures.append("b126:known_good_entry_binding_invalid")
            if known.get("sha256") != entry.get("sha256"):
                failures.append("b126:known_good_hash_binding_invalid")
            if known.get("signer_subject_digest") != entry.get("signer_subject_digest"):
                failures.append("b126:known_good_signer_binding_invalid")
            if known.get("signer_state") != "SIGNED_VERIFIED":
                failures.append("b126:known_good_verified_signature_required")

            if signed_unknown.get("local_allowlist_hit") is not False:
                failures.append("b126:signed_unknown_must_not_hit")
            if signed_unknown.get("allowlist_entry_id") is not None:
                failures.append("b126:signed_unknown_entry_forbidden")
            if signed_unknown.get("signer_state") != "SIGNED_VERIFIED":
                failures.append("b126:signed_unknown_verified_signature_required")

            if unsigned_unknown.get("local_allowlist_hit") is not False:
                failures.append("b126:unsigned_unknown_must_not_hit")
            if unsigned_unknown.get("allowlist_entry_id") is not None:
                failures.append("b126:unsigned_unknown_entry_forbidden")
            if unsigned_unknown.get("signer_state") != "UNSIGNED":
                failures.append("b126:unsigned_unknown_unsigned_required")

    return tuple(dict.fromkeys(failures))


def classify(row: dict[str, Any], allowlist: list[dict[str, Any]]) -> dict[str, Any]:
    match = next((entry for entry in allowlist if entry["sha256"] == row["sha256"]), None)
    if (
        match is not None
        and row["signer_state"] == "SIGNED_VERIFIED"
        and row["signer_subject_digest"] == match["signer_subject_digest"]
    ):
        outcome = OUTCOME_TRUSTED
        reasons = ["LOCAL_HASH_MATCH", "VERIFIED_SIGNER_MATCH"]
    elif row["signer_state"] == "SIGNED_VERIFIED":
        outcome = OUTCOME_UNKNOWN_SIGNED
        reasons = ["VERIFIED_SIGNER", "LOCAL_HASH_NOT_ALLOWLISTED"]
    else:
        outcome = OUTCOME_UNKNOWN_UNSIGNED
        reasons = ["UNSIGNED", "LOCAL_HASH_NOT_ALLOWLISTED"]

    return {
        "outcome": outcome,
        "reasons": reasons,
        "allowlist_match": match["entry_id"] if match else None,
    }


def _build_graph(
    row: dict[str, Any],
    result: dict[str, Any],
) -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult]:
    evidence_id = "b126-reputation:" + _sha({
        "sha256": row["sha256"],
        "signer_state": row["signer_state"],
        "signer_subject_digest": row["signer_subject_digest"],
        "outcome": result["outcome"],
    })[:24]
    direct = {
        "source": "windows-local-hash-signer-observation",
        "source_id": evidence_id,
        "collector": "sentinel.beta12_local_reputation",
        "trust": "DIRECT",
    }
    derived = {
        "source": "b126-local-reputation-classifier",
        "source_id": TARGET_SCENARIO,
        "collector": "sentinel.beta12_local_reputation.classify",
        "trust": "DERIVED",
    }
    builder = security_graph.SecurityGraphBuilder()
    file_node = builder.ingest_observation({
        "node_type": "FILE",
        "identity": {"sha256": row["sha256"], "path_digest": row["path_digest"]},
        "label": "Local reputation file",
        "observed_at": 1.0,
        "provenance": direct,
        "evidence_ids": [evidence_id],
        "confidence": 1.0,
        "attributes": {
            "sha256": row["sha256"],
            "path_digest": row["path_digest"],
            "signer_state": row["signer_state"],
            "signer_subject_digest": row["signer_subject_digest"],
            "correlation_keys": [evidence_id],
        },
    })
    detection = builder.ingest_observation({
        "node_type": "DETECTION",
        "identity": {"scenario": TARGET_SCENARIO, "evidence_id": evidence_id},
        "label": "B12-6 local reputation classification",
        "observed_at": 1.0,
        "provenance": derived,
        "evidence_ids": [evidence_id],
        "confidence": 1.0,
        "attributes": {
            "outcome": result["outcome"],
            "reasons": list(result["reasons"]),
            "allowlist_match": result["allowlist_match"],
            "correlation_keys": [evidence_id],
        },
    })
    builder.link(
        edge_type="SUPPORTED_BY",
        source=detection.node_id,
        target=file_node.node_id,
        observed_at=1.0,
        provenance=derived,
        evidence_ids=[evidence_id],
        confidence=1.0,
        reason="Local reputation classification is supported by the observed file hash and signer metadata.",
    )
    graph = builder.build(
        graph_id="b126-reputation:" + _sha({"evidence": evidence_id})[:20],
        incident_id="b126-reputation:" + _sha({"scenario": TARGET_SCENARIO, "evidence": evidence_id})[:20],
        created_at=1.0,
        metadata={
            "milestone": "B12-6",
            "scenario_id": TARGET_SCENARIO,
            "local_only": True,
            "trust_allowlist_mutation": False,
        },
    )
    return graph, incident_correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)


def summarize(data: object) -> dict[str, Any]:
    failures = validate_evidence(data)
    if failures:
        return {"passed": False, "failures": list(failures)}
    assert isinstance(data, dict)

    allowlist = data["allowlist"]
    rows = {row["control_id"]: row for row in data["controls"]}
    results = {control_id: classify(row, allowlist) for control_id, row in rows.items()}

    known = results[CONTROL_IDS[0]]
    signed_unknown = results[CONTROL_IDS[1]]
    unsigned_unknown = results[CONTROL_IDS[2]]

    graph, correlation = _build_graph(rows[CONTROL_IDS[0]], known)
    binding_ok = (
        security_graph.validate_graph(graph.to_dict()).passed
        and incident_correlation.validate_result(correlation, graph).passed
        and len(graph.nodes_by_type("FILE")) == 1
        and len(graph.nodes_by_type("DETECTION")) == 1
        and len(correlation.incidents) == 1
        and any(edge.edge_type == "SUPPORTED_BY" for edge in graph.edges)
    )
    controls_ok = (
        known["outcome"] == OUTCOME_TRUSTED
        and signed_unknown["outcome"] == OUTCOME_UNKNOWN_SIGNED
        and unsigned_unknown["outcome"] == OUTCOME_UNKNOWN_UNSIGNED
        and binding_ok
    )

    decisions = [dict(item) for item in BASELINE_DECISIONS]
    decisions.append({
        "scenario_id": TARGET_SCENARIO,
        "status": "VERIFIED" if controls_ok else "PARTIAL",
        "evidence_basis": (
            "LIVE_LOCAL_HASH_SIGNER_ALLOWLIST_CLASSIFICATION"
            if controls_ok
            else "LOCAL_REPUTATION_ACCEPTANCE_INCOMPLETE"
        ),
        "limitation": "Verified only for local hash/signer/ephemeral-allowlist classification; no cloud reputation or maliciousness verdict is claimed.",
    })
    coverage = {
        key: sum(1 for item in decisions if item["status"] == key)
        for key in ("PARTIAL", "GAP", "VERIFIED")
    }

    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": bool(controls_ok),
        "failures": [] if controls_ok else ["b126:controls_or_binding_incomplete"],
        "target_scenario_id": TARGET_SCENARIO,
        "control_results": results,
        "local_reputation_to_graph_bound": bool(binding_ok),
        "security_graph_to_incident_bound": bool(binding_ok),
        "graph_digest": graph.digest(),
        "correlation_digest": correlation.digest(),
        "coverage_summary": coverage,
        "coverage_decisions": decisions,
        "verified_scenarios": [
            item["scenario_id"] for item in decisions if item["status"] == "VERIFIED"
        ],
        "new_verified_scenario_earned": bool(controls_ok),
        "maliciousness_verdict_claimed": False,
        "trust_allowlist_mutated": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
        "boundaries": dict(BOUNDARIES),
    }


def self_check() -> dict[str, Any]:
    contract = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source": SOURCE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "target_scenario": TARGET_SCENARIO,
        "baseline_verified": list(BASELINE_VERIFIED),
        "control_ids": list(CONTROL_IDS),
        "signer_states": sorted(SIGNER_STATES),
        "boundaries": dict(BOUNDARIES),
    }
    return {
        "passed": True,
        "failures": [],
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "target_scenario_id": TARGET_SCENARIO,
        "baseline_verified_scenarios": list(BASELINE_VERIFIED),
        "contract_digest": _sha(contract),
        "local_hash_required": True,
        "signer_metadata_required": True,
        "ephemeral_allowlist_required": True,
        "trust_allowlist_mutated": False,
        "maliciousness_verdict_claimed": False,
        "coverage_promoted_by_self_check": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.evidence is None:
        result = self_check()
    else:
        try:
            result = summarize(json.loads(args.evidence.read_text(encoding="utf-8-sig")))
        except (OSError, UnicodeError, ValueError):
            result = {"passed": False, "failures": ["b126:evidence_unreadable_or_invalid_json"]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
