from __future__ import annotations

"""B7-4 harmless, deterministic attack-chain acceptance harness.

The harness composes the accepted B7-1 Security Graph, B7-2 Incident
Correlation Engine and B7-3 Confidence Gate using synthetic in-memory fixtures.
It does not launch processes, write files, contact networks, mutate registry
state, or execute remediation. Timing is derived only from fixture timestamps.
"""

from dataclasses import dataclass
import argparse
import hashlib
import json
from typing import Any, Final

from sentinel import confidence_gate, incident_correlation, security_graph

SCHEMA: Final[str] = "bc-sentinel-attack-chain-acceptance-v1"
PROFILE: Final[str] = "v0.11.0-beta.7-b74-attack-chain-harness"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta7-b73-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "eef5c40edc853ff3f13cb521ce980dcaaea75fd0"

SCENARIO_ID: Final[str] = "b74-controlled-script-persistence-dns-chain"
EXPECTED_STAGE_ORDER: Final[tuple[str, ...]] = (
    "PROCESS",
    "SCRIPT",
    "PERSISTENCE",
    "DNS",
    "DETECTION",
)

HARNESS_EXECUTES_PROCESSES: Final[bool] = False
HARNESS_WRITES_FILES: Final[bool] = False
HARNESS_NETWORK_IO: Final[bool] = False
HARNESS_MUTATES_REGISTRY: Final[bool] = False
HARNESS_EXECUTES_REMEDIATION: Final[bool] = False


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(char in "0123456789abcdef" for char in value.lower())


def _valid_nonnegative_number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and float(value) >= 0.0
    )


@dataclass(frozen=True)
class GateCaseResult:
    case_id: str
    expected_outcome: str
    actual_outcome: str
    decision_digest: str
    matched_evidence_ids: tuple[str, ...]
    authority_granted: bool
    advisory_interruption_eligible: bool
    passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "expected_outcome": self.expected_outcome,
            "actual_outcome": self.actual_outcome,
            "decision_digest": self.decision_digest,
            "matched_evidence_ids": list(self.matched_evidence_ids),
            "authority_granted": self.authority_granted,
            "advisory_interruption_eligible": self.advisory_interruption_eligible,
            "passed": self.passed,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GateCaseResult":
        return cls(
            case_id=str(payload.get("case_id") or ""),
            expected_outcome=str(payload.get("expected_outcome") or ""),
            actual_outcome=str(payload.get("actual_outcome") or ""),
            decision_digest=str(payload.get("decision_digest") or ""),
            matched_evidence_ids=tuple(sorted(str(item) for item in (payload.get("matched_evidence_ids") or []))),
            authority_granted=bool(payload.get("authority_granted", False)),
            advisory_interruption_eligible=bool(payload.get("advisory_interruption_eligible", False)),
            passed=bool(payload.get("passed", False)),
        )


@dataclass(frozen=True)
class AttackChainReport:
    scenario_id: str
    source_graph_digest: str
    source_correlation_digest: str
    incident_id: str
    stage_order: tuple[str, ...]
    stage_node_ids: tuple[str, ...]
    graph_edge_ids: tuple[str, ...]
    first_observed_at: float
    detection_observed_at: float
    detection_latency: float
    correlation_link_count: int
    gate_cases: tuple[GateCaseResult, ...]
    source_graph_unchanged: bool
    source_correlation_unchanged: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "source_checkpoint": SOURCE_CHECKPOINT,
            "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
            "scenario_id": self.scenario_id,
            "source_graph_digest": self.source_graph_digest,
            "source_correlation_digest": self.source_correlation_digest,
            "incident_id": self.incident_id,
            "stage_order": list(self.stage_order),
            "stage_node_ids": list(self.stage_node_ids),
            "graph_edge_ids": list(self.graph_edge_ids),
            "first_observed_at": self.first_observed_at,
            "detection_observed_at": self.detection_observed_at,
            "detection_latency": self.detection_latency,
            "correlation_link_count": self.correlation_link_count,
            "gate_cases": [case.to_dict() for case in sorted(self.gate_cases, key=lambda item: item.case_id)],
            "source_graph_unchanged": self.source_graph_unchanged,
            "source_correlation_unchanged": self.source_correlation_unchanged,
            "read_only": True,
            "synthetic_fixture_only": True,
            "process_execution": HARNESS_EXECUTES_PROCESSES,
            "file_write": HARNESS_WRITES_FILES,
            "network_io": HARNESS_NETWORK_IO,
            "registry_mutation": HARNESS_MUTATES_REGISTRY,
            "remediation_execution": HARNESS_EXECUTES_REMEDIATION,
            "authority_granted": False,
            "execution_authority_added": False,
        }

    def stable_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.stable_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AttackChainReport":
        return cls(
            scenario_id=str(payload.get("scenario_id") or ""),
            source_graph_digest=str(payload.get("source_graph_digest") or ""),
            source_correlation_digest=str(payload.get("source_correlation_digest") or ""),
            incident_id=str(payload.get("incident_id") or ""),
            stage_order=tuple(str(item) for item in (payload.get("stage_order") or [])),
            stage_node_ids=tuple(str(item) for item in (payload.get("stage_node_ids") or [])),
            graph_edge_ids=tuple(sorted(str(item) for item in (payload.get("graph_edge_ids") or []))),
            first_observed_at=float(payload.get("first_observed_at") or 0.0),
            detection_observed_at=float(payload.get("detection_observed_at") or 0.0),
            detection_latency=float(payload.get("detection_latency") or 0.0),
            correlation_link_count=int(payload.get("correlation_link_count") or 0),
            gate_cases=tuple(GateCaseResult.from_dict(item) for item in (payload.get("gate_cases") or [])),
            source_graph_unchanged=bool(payload.get("source_graph_unchanged", False)),
            source_correlation_unchanged=bool(payload.get("source_correlation_unchanged", False)),
        )


@dataclass(frozen=True)
class HarnessValidation:
    passed: bool
    failures: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "passed": self.passed,
            "failures": list(self.failures),
            "read_only": True,
            "execution_authority_added": False,
        }


def _provenance() -> dict[str, Any]:
    return {
        "source": "b74-controlled-in-memory-fixture",
        "source_id": SCENARIO_ID,
        "collector": "sentinel.attack_chain_harness",
        "trust": "DIRECT",
    }


def build_controlled_graph() -> tuple[security_graph.SecurityGraph, tuple[str, ...]]:
    """Build a harmless five-stage chain entirely in memory."""
    provenance = _provenance()
    builder = security_graph.SecurityGraphBuilder()

    process = builder.ingest_observation({
        "node_type": "PROCESS",
        "identity": {"fixture": "launcher", "scenario": SCENARIO_ID},
        "label": "synthetic-launcher.exe",
        "observed_at": 10.0,
        "provenance": provenance,
        "evidence_ids": ["ev-b74-process"],
        "confidence": 1.0,
        "attributes": {"fixture": True, "correlation_keys": ["chain:b74"]},
    })
    script = builder.ingest_observation({
        "node_type": "SCRIPT",
        "identity": {"fixture": "script", "scenario": SCENARIO_ID},
        "label": "synthetic-controlled.ps1",
        "observed_at": 11.0,
        "provenance": provenance,
        "evidence_ids": ["ev-b74-script"],
        "confidence": 1.0,
        "attributes": {"fixture": True, "correlation_keys": ["chain:b74"]},
    })
    persistence = builder.ingest_observation({
        "node_type": "PERSISTENCE",
        "identity": {"fixture": "persistence", "scenario": SCENARIO_ID},
        "label": "synthetic-persistence-marker",
        "observed_at": 12.0,
        "provenance": provenance,
        "evidence_ids": ["ev-b74-persistence"],
        "confidence": 0.95,
        "attributes": {"fixture": True, "correlation_keys": ["chain:b74"]},
    })
    dns = builder.ingest_observation({
        "node_type": "DNS",
        "identity": {"query": "b74-fixture.invalid", "scenario": SCENARIO_ID},
        "label": "b74-fixture.invalid",
        "observed_at": 13.0,
        "provenance": provenance,
        "evidence_ids": ["ev-b74-dns"],
        "confidence": 0.90,
        "attributes": {"fixture": True, "correlation_keys": ["chain:b74"]},
    })
    detection = builder.ingest_observation({
        "node_type": "DETECTION",
        "identity": {"fixture": "detection", "scenario": SCENARIO_ID},
        "label": "Synthetic multi-signal chain detection",
        "observed_at": 14.0,
        "provenance": provenance,
        "evidence_ids": [
            "ev-b74-script",
            "ev-b74-persistence",
            "ev-b74-dns",
            "ev-b74-detection",
        ],
        "confidence": 0.93,
        "attributes": {"fixture": True, "severity": "HIGH", "correlation_keys": ["chain:b74"]},
    })

    builder.link(
        edge_type="EXECUTED",
        source=process.node_id,
        target=script.node_id,
        observed_at=11.0,
        provenance=provenance,
        evidence_ids=["ev-b74-script"],
        confidence=1.0,
        reason="Synthetic launcher-to-script fixture relation.",
    )
    builder.link(
        edge_type="PERSISTED_VIA",
        source=script.node_id,
        target=persistence.node_id,
        observed_at=12.0,
        provenance=provenance,
        evidence_ids=["ev-b74-persistence"],
        confidence=0.95,
        reason="Synthetic script-to-persistence fixture relation.",
    )
    builder.link(
        edge_type="OBSERVED_WITH",
        source=persistence.node_id,
        target=dns.node_id,
        observed_at=13.0,
        provenance=provenance,
        evidence_ids=["ev-b74-dns"],
        confidence=0.90,
        reason="Synthetic persistence and DNS evidence belong to the same controlled chain.",
    )
    builder.link(
        edge_type="TRIGGERED",
        source=dns.node_id,
        target=detection.node_id,
        observed_at=14.0,
        provenance=provenance,
        evidence_ids=["ev-b74-detection"],
        confidence=0.93,
        reason="Synthetic DNS-stage evidence contributes to the controlled detection.",
    )

    graph = builder.build(
        graph_id="graph-b74-controlled-chain",
        incident_id="uncorrelated-b74-controlled-chain",
        created_at=15.0,
        metadata={"fixture": True, "scenario_id": SCENARIO_ID, "harmless": True},
    )
    stage_node_ids = (
        process.node_id,
        script.node_id,
        persistence.node_id,
        dns.node_id,
        detection.node_id,
    )
    return graph, stage_node_ids


def _candidate(
    *,
    case_id: str,
    incident_id: str,
    evidence_strength: str,
    confidence: float | None,
    potential_damage: str,
    evidence_ids: tuple[str, ...],
) -> confidence_gate.RecommendationCandidate:
    return confidence_gate.RecommendationCandidate(
        candidate_id=case_id,
        incident_id=incident_id,
        action="QUARANTINE",
        severity="HIGH",
        evidence_strength=evidence_strength,
        confidence=confidence,
        reversibility="REVERSIBLE",
        potential_damage=potential_damage,
        evidence_ids=tuple(sorted(evidence_ids)),
        rationale="Synthetic B7-4 acceptance-gate candidate; advisory only.",
    )


def _run_gate_case(
    *,
    gate: confidence_gate.ConfidenceGate,
    candidate: confidence_gate.RecommendationCandidate,
    expected_outcome: str,
    correlation: incident_correlation.CorrelationResult,
    graph: security_graph.SecurityGraph,
) -> GateCaseResult:
    decision = gate.evaluate(candidate=candidate, correlation=correlation, graph=graph)
    eligible = decision.outcome == confidence_gate.OUTCOME_RECOMMEND and decision.authority_granted is False
    passed = (
        decision.outcome == expected_outcome
        and decision.authority_granted is False
        and confidence_gate.validate_decision(decision, correlation, graph).passed
    )
    return GateCaseResult(
        case_id=candidate.candidate_id,
        expected_outcome=expected_outcome,
        actual_outcome=decision.outcome,
        decision_digest=decision.digest(),
        matched_evidence_ids=tuple(sorted(decision.matched_evidence_ids)),
        authority_granted=decision.authority_granted,
        advisory_interruption_eligible=eligible,
        passed=passed,
    )


def run_controlled_harness() -> AttackChainReport:
    graph, stage_node_ids = build_controlled_graph()
    graph_before = graph.digest()
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=120.0).correlate(graph)
    correlation_before = correlation.digest()

    stage_set = set(stage_node_ids)
    incidents = [incident for incident in correlation.incidents if stage_set.issubset(set(incident.node_ids))]
    if len(incidents) != 1:
        raise ValueError("attack_chain_fixture_not_single_incident")
    incident = incidents[0]

    node_map = {node.node_id: node for node in graph.nodes}
    stage_order = tuple(node_map[node_id].node_type for node_id in stage_node_ids)
    first_observed_at = float(node_map[stage_node_ids[0]].observed_at)
    detection_observed_at = float(node_map[stage_node_ids[-1]].observed_at)

    gate = confidence_gate.ConfidenceGate()
    strong_evidence = ("ev-b74-script", "ev-b74-persistence", "ev-b74-dns", "ev-b74-detection")
    cases = (
        _run_gate_case(
            gate=gate,
            candidate=_candidate(
                case_id="b74-case-recommend",
                incident_id=incident.incident_id,
                evidence_strength="STRONG",
                confidence=0.93,
                potential_damage="MEDIUM",
                evidence_ids=strong_evidence,
            ),
            expected_outcome=confidence_gate.OUTCOME_RECOMMEND,
            correlation=correlation,
            graph=graph,
        ),
        _run_gate_case(
            gate=gate,
            candidate=_candidate(
                case_id="b74-case-review",
                incident_id=incident.incident_id,
                evidence_strength="STRONG",
                confidence=0.93,
                potential_damage="HIGH",
                evidence_ids=strong_evidence,
            ),
            expected_outcome=confidence_gate.OUTCOME_REVIEW,
            correlation=correlation,
            graph=graph,
        ),
        _run_gate_case(
            gate=gate,
            candidate=_candidate(
                case_id="b74-case-blocked",
                incident_id=incident.incident_id,
                evidence_strength="WEAK",
                confidence=0.40,
                potential_damage="LOW",
                evidence_ids=("ev-b74-script",),
            ),
            expected_outcome=confidence_gate.OUTCOME_BLOCKED,
            correlation=correlation,
            graph=graph,
        ),
    )

    return AttackChainReport(
        scenario_id=SCENARIO_ID,
        source_graph_digest=graph_before,
        source_correlation_digest=correlation_before,
        incident_id=incident.incident_id,
        stage_order=stage_order,
        stage_node_ids=stage_node_ids,
        graph_edge_ids=tuple(sorted(incident.graph_edge_ids)),
        first_observed_at=first_observed_at,
        detection_observed_at=detection_observed_at,
        detection_latency=detection_observed_at - first_observed_at,
        correlation_link_count=len(incident.links),
        gate_cases=cases,
        source_graph_unchanged=graph.digest() == graph_before,
        source_correlation_unchanged=correlation.digest() == correlation_before,
    )


def validate_report(report: AttackChainReport | dict[str, Any]) -> HarnessValidation:
    payload = report.to_dict() if isinstance(report, AttackChainReport) else report
    failures: list[str] = []
    if not isinstance(payload, dict):
        return HarnessValidation(False, ("attack_chain:not_object",))

    if payload.get("schema") != SCHEMA:
        failures.append("attack_chain:schema_mismatch")
    if payload.get("profile") != PROFILE:
        failures.append("attack_chain:profile_mismatch")
    if payload.get("source_checkpoint") != SOURCE_CHECKPOINT:
        failures.append("attack_chain:source_checkpoint_mismatch")
    if payload.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("attack_chain:source_checkpoint_commit_mismatch")
    if payload.get("scenario_id") != SCENARIO_ID:
        failures.append("attack_chain:scenario_id_mismatch")
    if not _valid_sha256(payload.get("source_graph_digest")):
        failures.append("attack_chain:graph_digest_invalid")
    if not _valid_sha256(payload.get("source_correlation_digest")):
        failures.append("attack_chain:correlation_digest_invalid")
    if not _nonempty_string(payload.get("incident_id")):
        failures.append("attack_chain:incident_id_invalid")

    stage_order = payload.get("stage_order")
    if stage_order != list(EXPECTED_STAGE_ORDER):
        failures.append("attack_chain:stage_order_mismatch")
    stage_node_ids = payload.get("stage_node_ids")
    if not isinstance(stage_node_ids, list) or len(stage_node_ids) != len(EXPECTED_STAGE_ORDER):
        failures.append("attack_chain:stage_node_ids_invalid")
    elif len(stage_node_ids) != len(set(stage_node_ids)) or any(not _nonempty_string(item) for item in stage_node_ids):
        failures.append("attack_chain:stage_node_ids_not_unique")

    edge_ids = payload.get("graph_edge_ids")
    if not isinstance(edge_ids, list) or len(edge_ids) != 4 or len(edge_ids) != len(set(edge_ids)):
        failures.append("attack_chain:graph_edge_count_invalid")
    if not _valid_nonnegative_number(payload.get("first_observed_at")):
        failures.append("attack_chain:first_observed_at_invalid")
    if not _valid_nonnegative_number(payload.get("detection_observed_at")):
        failures.append("attack_chain:detection_observed_at_invalid")
    if not _valid_nonnegative_number(payload.get("detection_latency")):
        failures.append("attack_chain:detection_latency_invalid")
    elif _valid_nonnegative_number(payload.get("first_observed_at")) and _valid_nonnegative_number(payload.get("detection_observed_at")):
        expected_latency = float(payload["detection_observed_at"]) - float(payload["first_observed_at"])
        if float(payload["detection_latency"]) != expected_latency:
            failures.append("attack_chain:detection_latency_not_exact")
    if not isinstance(payload.get("correlation_link_count"), int) or payload.get("correlation_link_count", 0) < 4:
        failures.append("attack_chain:correlation_link_count_invalid")

    cases = payload.get("gate_cases")
    if not isinstance(cases, list) or len(cases) != 3:
        failures.append("attack_chain:gate_cases_invalid")
        cases = []
    expected = {
        "b74-case-recommend": confidence_gate.OUTCOME_RECOMMEND,
        "b74-case-review": confidence_gate.OUTCOME_REVIEW,
        "b74-case-blocked": confidence_gate.OUTCOME_BLOCKED,
    }
    seen: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            failures.append(f"attack_chain:case[{index}]:not_object")
            continue
        case_id = str(case.get("case_id") or "")
        if case_id not in expected or case_id in seen:
            failures.append(f"attack_chain:case[{index}]:case_id_invalid")
        seen.add(case_id)
        if case.get("expected_outcome") != expected.get(case_id):
            failures.append(f"attack_chain:case[{index}]:expected_outcome_mismatch")
        if case.get("actual_outcome") != expected.get(case_id):
            failures.append(f"attack_chain:case[{index}]:actual_outcome_mismatch")
        if case.get("passed") is not True:
            failures.append(f"attack_chain:case[{index}]:not_passed")
        if case.get("authority_granted") is not False:
            failures.append(f"attack_chain:case[{index}]:authority_granted")
        if not _valid_sha256(case.get("decision_digest")):
            failures.append(f"attack_chain:case[{index}]:decision_digest_invalid")
        eligible = case.get("advisory_interruption_eligible")
        should_be_eligible = case_id == "b74-case-recommend"
        if eligible is not should_be_eligible:
            failures.append(f"attack_chain:case[{index}]:eligibility_mismatch")

    if set(expected) != seen:
        failures.append("attack_chain:gate_case_set_incomplete")
    if payload.get("source_graph_unchanged") is not True:
        failures.append("attack_chain:source_graph_changed")
    if payload.get("source_correlation_unchanged") is not True:
        failures.append("attack_chain:source_correlation_changed")
    if payload.get("read_only") is not True or payload.get("synthetic_fixture_only") is not True:
        failures.append("attack_chain:read_only_fixture_required")
    for field_name in ("process_execution", "file_write", "network_io", "registry_mutation", "remediation_execution"):
        if payload.get(field_name) is not False:
            failures.append(f"attack_chain:{field_name}_must_be_false")
    if payload.get("authority_granted") is not False:
        failures.append("attack_chain:authority_granted_must_be_false")
    if payload.get("execution_authority_added") is not False:
        failures.append("attack_chain:execution_authority_added")

    return HarnessValidation(not failures, tuple(failures))


def self_check() -> dict[str, Any]:
    first = run_controlled_harness()
    second = run_controlled_harness()
    restored = AttackChainReport.from_dict(first.to_dict())
    validation = validate_report(first)
    case_outcomes = {case.case_id: case.actual_outcome for case in first.gate_cases}
    return {
        **validation.to_dict(),
        "scenario_id": first.scenario_id,
        "report_digest": first.digest(),
        "stage_order": list(first.stage_order),
        "stage_count": len(first.stage_order),
        "graph_edge_count": len(first.graph_edge_ids),
        "correlation_link_count": first.correlation_link_count,
        "detection_latency": first.detection_latency,
        "case_outcomes": case_outcomes,
        "advisory_interruption_eligible": any(case.advisory_interruption_eligible for case in first.gate_cases),
        "stable_round_trip": restored.stable_json() == first.stable_json(),
        "deterministic_serialization": second.stable_json() == first.stable_json(),
        "source_graph_unchanged": first.source_graph_unchanged,
        "source_correlation_unchanged": first.source_correlation_unchanged,
        "synthetic_fixture_only": True,
        "process_execution": False,
        "file_write": False,
        "network_io": False,
        "registry_mutation": False,
        "remediation_execution": False,
        "authority_granted": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_restore": False,
        "general_home_execution_authorized": False,
        "delete_authorized": False,
        "repair_authorized": False,
        "terminate_process_authorized": False,
        "trust_allowlist_mutation_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B7-4 Attack-Chain Acceptance Harness")
    parser.add_argument("--self-check", action="store_true")
    parser.parse_args(argv)
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    required = (
        result.get("passed") is True
        and result.get("stage_order") == list(EXPECTED_STAGE_ORDER)
        and result.get("case_outcomes", {}).get("b74-case-recommend") == confidence_gate.OUTCOME_RECOMMEND
        and result.get("case_outcomes", {}).get("b74-case-review") == confidence_gate.OUTCOME_REVIEW
        and result.get("case_outcomes", {}).get("b74-case-blocked") == confidence_gate.OUTCOME_BLOCKED
        and result.get("stable_round_trip") is True
        and result.get("deterministic_serialization") is True
        and result.get("authority_granted") is False
        and result.get("process_execution") is False
        and result.get("file_write") is False
        and result.get("network_io") is False
        and result.get("registry_mutation") is False
        and result.get("remediation_execution") is False
    )
    return 0 if required else 4


if __name__ == "__main__":
    raise SystemExit(main())
