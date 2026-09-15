from __future__ import annotations

"""B7-5 deterministic, evidence-grounded Explainable Security.

This module converts already accepted B7-1/B7-2/B7-3 incident intelligence
into two read-only explanations: a concise user-facing explanation and an
advanced technical explanation. It never executes, authorizes, or mutates any
remediation state. Every positive claim must remain bound to source evidence.
"""

from dataclasses import dataclass, field
import argparse
import hashlib
import json
from typing import Any, Final

from sentinel import attack_chain_harness, confidence_gate, incident_correlation, security_graph

SCHEMA: Final[str] = "bc-sentinel-explainable-security-v1"
PROFILE: Final[str] = "v0.11.0-beta.7-b75-explainable-security"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta7-b74-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "d836aef24480d21e6631c1fe0dac640c7862e7ec"

ALLOWED_CLAIM_TYPES: Final[set[str]] = {
    "OBSERVATION",
    "RELATIONSHIP",
    "DECISION",
    "LIMITATION",
}
ALLOWED_CERTAINTY: Final[set[str]] = {
    "DIRECT_EVIDENCE",
    "CORRELATED_EVIDENCE",
    "ADVISORY_DECISION",
    "LIMITATION",
}


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


def _valid_confidence(value: Any) -> bool:
    return value is None or (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and 0.0 <= float(value) <= 1.0
    )


@dataclass(frozen=True)
class EvidenceBoundClaim:
    claim_id: str
    claim_type: str
    certainty: str
    text: str
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    node_ids: tuple[str, ...] = field(default_factory=tuple)
    edge_ids: tuple[str, ...] = field(default_factory=tuple)
    confidence: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "certainty": self.certainty,
            "text": self.text,
            "evidence_ids": list(self.evidence_ids),
            "node_ids": list(self.node_ids),
            "edge_ids": list(self.edge_ids),
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EvidenceBoundClaim":
        confidence = payload.get("confidence")
        return cls(
            claim_id=str(payload.get("claim_id") or ""),
            claim_type=str(payload.get("claim_type") or "").upper(),
            certainty=str(payload.get("certainty") or "").upper(),
            text=str(payload.get("text") or ""),
            evidence_ids=tuple(sorted(str(item) for item in (payload.get("evidence_ids") or []))),
            node_ids=tuple(sorted(str(item) for item in (payload.get("node_ids") or []))),
            edge_ids=tuple(sorted(str(item) for item in (payload.get("edge_ids") or []))),
            confidence=None if confidence is None else float(confidence),
        )


@dataclass(frozen=True)
class IncidentExplanation:
    explanation_id: str
    incident_id: str
    decision_id: str
    decision_outcome: str
    source_graph_digest: str
    source_correlation_digest: str
    source_decision_digest: str
    user_explanation: str
    technical_explanation: str
    claims: tuple[EvidenceBoundClaim, ...]
    uncertainty_notes: tuple[str, ...]
    authority_granted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "source_checkpoint": SOURCE_CHECKPOINT,
            "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
            "explanation_id": self.explanation_id,
            "incident_id": self.incident_id,
            "decision_id": self.decision_id,
            "decision_outcome": self.decision_outcome,
            "source_graph_digest": self.source_graph_digest,
            "source_correlation_digest": self.source_correlation_digest,
            "source_decision_digest": self.source_decision_digest,
            "user_explanation": self.user_explanation,
            "technical_explanation": self.technical_explanation,
            "claims": [claim.to_dict() for claim in sorted(self.claims, key=lambda item: item.claim_id)],
            "uncertainty_notes": list(self.uncertainty_notes),
            "authority_granted": self.authority_granted,
            "read_only": True,
            "execution_authority_added": False,
            "confidence_amplified": False,
            "unsupported_positive_claims_allowed": False,
        }

    def stable_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.stable_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "IncidentExplanation":
        return cls(
            explanation_id=str(payload.get("explanation_id") or ""),
            incident_id=str(payload.get("incident_id") or ""),
            decision_id=str(payload.get("decision_id") or ""),
            decision_outcome=str(payload.get("decision_outcome") or "").upper(),
            source_graph_digest=str(payload.get("source_graph_digest") or ""),
            source_correlation_digest=str(payload.get("source_correlation_digest") or ""),
            source_decision_digest=str(payload.get("source_decision_digest") or ""),
            user_explanation=str(payload.get("user_explanation") or ""),
            technical_explanation=str(payload.get("technical_explanation") or ""),
            claims=tuple(EvidenceBoundClaim.from_dict(item) for item in (payload.get("claims") or [])),
            uncertainty_notes=tuple(str(item) for item in (payload.get("uncertainty_notes") or [])),
            authority_granted=bool(payload.get("authority_granted", False)),
        )


@dataclass(frozen=True)
class ExplanationValidation:
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


def _incident_supported_evidence(
    incident: incident_correlation.IncidentCluster,
    graph: security_graph.SecurityGraph,
) -> set[str]:
    node_map = {node.node_id: node for node in graph.nodes}
    edge_map = {edge.edge_id: edge for edge in graph.edges}
    supported: set[str] = set()
    for node_id in incident.node_ids:
        supported.update(node_map[node_id].evidence_ids)
    for edge_id in incident.graph_edge_ids:
        supported.update(edge_map[edge_id].evidence_ids)
    for link in incident.links:
        supported.update(link.evidence_ids)
    return supported


def _incident_context(
    incident_id: str,
    correlation: incident_correlation.CorrelationResult,
) -> incident_correlation.IncidentCluster:
    incident = next((item for item in correlation.incidents if item.incident_id == incident_id), None)
    if incident is None:
        raise ValueError(f"explainable_security_incident_unknown:{incident_id}")
    return incident


class ExplainableSecurityEngine:
    """Create deterministic explanations without adding certainty or authority."""

    def generate(
        self,
        *,
        decision: confidence_gate.GateDecision,
        correlation: incident_correlation.CorrelationResult,
        graph: security_graph.SecurityGraph,
    ) -> IncidentExplanation:
        graph_before = graph.digest()
        correlation_before = correlation.digest()
        decision_before = decision.digest()

        decision_validation = confidence_gate.validate_decision(decision, correlation, graph)
        if not decision_validation.passed:
            raise ValueError(
                "explainable_security_decision_invalid:" + ",".join(decision_validation.failures)
            )
        if decision.authority_granted:
            raise ValueError("explainable_security_authority_must_be_false")

        incident = _incident_context(decision.candidate.incident_id, correlation)
        node_map = {node.node_id: node for node in graph.nodes}
        edge_map = {edge.edge_id: edge for edge in graph.edges}
        nodes = tuple(sorted((node_map[node_id] for node_id in incident.node_ids), key=lambda n: (n.observed_at, n.node_id)))
        edges = tuple(sorted((edge_map[edge_id] for edge_id in incident.graph_edge_ids), key=lambda e: (e.observed_at, e.edge_id)))

        claims: list[EvidenceBoundClaim] = []
        for node in nodes:
            material = {"kind": "node", "node_id": node.node_id, "evidence_ids": sorted(node.evidence_ids)}
            claims.append(
                EvidenceBoundClaim(
                    claim_id="claim:" + _stable_hash(material)[:24],
                    claim_type="OBSERVATION",
                    certainty="DIRECT_EVIDENCE" if str(node.provenance.get("trust") or "").upper() == "DIRECT" else "CORRELATED_EVIDENCE",
                    text=f"Observed {node.node_type}: {node.label}.",
                    evidence_ids=tuple(sorted(node.evidence_ids)),
                    node_ids=(node.node_id,),
                    confidence=node.confidence,
                )
            )

        for edge in edges:
            source = node_map[edge.source]
            target = node_map[edge.target]
            material = {"kind": "edge", "edge_id": edge.edge_id, "evidence_ids": sorted(edge.evidence_ids)}
            claims.append(
                EvidenceBoundClaim(
                    claim_id="claim:" + _stable_hash(material)[:24],
                    claim_type="RELATIONSHIP",
                    certainty="CORRELATED_EVIDENCE",
                    text=f"Correlated relation {edge.edge_type}: {source.label} -> {target.label}.",
                    evidence_ids=tuple(sorted(edge.evidence_ids)),
                    node_ids=tuple(sorted((edge.source, edge.target))),
                    edge_ids=(edge.edge_id,),
                    confidence=edge.confidence,
                )
            )

        decision_material = {
            "kind": "decision",
            "decision_id": decision.decision_id,
            "matched_evidence_ids": sorted(decision.matched_evidence_ids),
        }
        claims.append(
            EvidenceBoundClaim(
                claim_id="claim:" + _stable_hash(decision_material)[:24],
                claim_type="DECISION",
                certainty="ADVISORY_DECISION",
                text=(
                    f"Confidence Gate outcome: {decision.outcome}; advisory only and no execution authority is granted."
                ),
                evidence_ids=tuple(sorted(decision.matched_evidence_ids)),
                node_ids=tuple(sorted(incident.node_ids)),
                confidence=decision.candidate.confidence,
            )
        )

        limitation_text = (
            "This explanation is limited to the supplied graph, correlation and evidence bindings; "
            "missing evidence is not interpreted as absence of risk."
        )
        claims.append(
            EvidenceBoundClaim(
                claim_id="claim:" + _stable_hash({"kind": "limitation", "incident_id": incident.incident_id})[:24],
                claim_type="LIMITATION",
                certainty="LIMITATION",
                text=limitation_text,
            )
        )

        chain_labels = " -> ".join(node.label for node in nodes)
        user_explanation = (
            f"BC Sentinel ha correlato {len(nodes)} segnali nello stesso incidente: {chain_labels}. "
            f"La valutazione corrente è {decision.outcome}. "
            "Il risultato è consultivo e non autorizza azioni automatiche. "
            "L'analisi è limitata alle prove disponibili."
        )
        technical_explanation = (
            f"incident={incident.incident_id}; graph={graph_before}; correlation={correlation_before}; "
            f"decision={decision_before}; nodes={len(nodes)}; edges={len(edges)}; "
            f"matched_evidence={','.join(sorted(decision.matched_evidence_ids))}; "
            f"outcome={decision.outcome}; authority_granted=false."
        )
        uncertainty_notes = (
            "Confidence values are inherited from source observations or the accepted gate decision and are not increased by explanation generation.",
            "Missing evidence is not interpreted as absence of risk or as proof of safety.",
        )

        material = {
            "incident_id": incident.incident_id,
            "decision_id": decision.decision_id,
            "decision_outcome": decision.outcome,
            "source_graph_digest": graph_before,
            "source_correlation_digest": correlation_before,
            "source_decision_digest": decision_before,
            "claims": [claim.to_dict() for claim in sorted(claims, key=lambda item: item.claim_id)],
            "uncertainty_notes": uncertainty_notes,
        }
        explanation = IncidentExplanation(
            explanation_id="explanation:" + _stable_hash(material)[:24],
            incident_id=incident.incident_id,
            decision_id=decision.decision_id,
            decision_outcome=decision.outcome,
            source_graph_digest=graph_before,
            source_correlation_digest=correlation_before,
            source_decision_digest=decision_before,
            user_explanation=user_explanation,
            technical_explanation=technical_explanation,
            claims=tuple(sorted(claims, key=lambda item: item.claim_id)),
            uncertainty_notes=uncertainty_notes,
            authority_granted=False,
        )

        validation = validate_explanation(explanation, decision, correlation, graph)
        if not validation.passed:
            raise ValueError("explainable_security_output_invalid:" + ",".join(validation.failures))
        if graph.digest() != graph_before:
            raise RuntimeError("explainable_security_source_graph_mutated")
        if correlation.digest() != correlation_before:
            raise RuntimeError("explainable_security_source_correlation_mutated")
        if decision.digest() != decision_before:
            raise RuntimeError("explainable_security_source_decision_mutated")
        return explanation


def validate_explanation(
    explanation: IncidentExplanation | dict[str, Any],
    decision: confidence_gate.GateDecision,
    correlation: incident_correlation.CorrelationResult,
    graph: security_graph.SecurityGraph,
) -> ExplanationValidation:
    payload = explanation.to_dict() if isinstance(explanation, IncidentExplanation) else explanation
    failures: list[str] = []
    if not isinstance(payload, dict):
        return ExplanationValidation(False, ("explanation:not_object",))

    if payload.get("schema") != SCHEMA:
        failures.append("explanation:schema_mismatch")
    if payload.get("profile") != PROFILE:
        failures.append("explanation:profile_mismatch")
    if payload.get("source_checkpoint") != SOURCE_CHECKPOINT:
        failures.append("explanation:source_checkpoint_mismatch")
    if payload.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("explanation:source_checkpoint_commit_mismatch")
    if not _nonempty_string(payload.get("explanation_id")):
        failures.append("explanation:explanation_id_invalid")
    if payload.get("incident_id") != decision.candidate.incident_id:
        failures.append("explanation:incident_id_mismatch")
    if payload.get("decision_id") != decision.decision_id:
        failures.append("explanation:decision_id_mismatch")
    if payload.get("decision_outcome") != decision.outcome:
        failures.append("explanation:decision_outcome_mismatch")
    if payload.get("source_graph_digest") != graph.digest() or not _valid_sha256(payload.get("source_graph_digest")):
        failures.append("explanation:source_graph_digest_mismatch")
    if payload.get("source_correlation_digest") != correlation.digest() or not _valid_sha256(payload.get("source_correlation_digest")):
        failures.append("explanation:source_correlation_digest_mismatch")
    if payload.get("source_decision_digest") != decision.digest() or not _valid_sha256(payload.get("source_decision_digest")):
        failures.append("explanation:source_decision_digest_mismatch")
    if not _nonempty_string(payload.get("user_explanation")):
        failures.append("explanation:user_explanation_invalid")
    if not _nonempty_string(payload.get("technical_explanation")):
        failures.append("explanation:technical_explanation_invalid")
    if decision.outcome not in str(payload.get("user_explanation") or ""):
        failures.append("explanation:user_outcome_missing")
    if "authority_granted=false" not in str(payload.get("technical_explanation") or ""):
        failures.append("explanation:technical_authority_boundary_missing")

    if payload.get("authority_granted") is not False:
        failures.append("explanation:authority_granted_must_be_false")
    if payload.get("read_only") is not True:
        failures.append("explanation:read_only_required")
    if payload.get("execution_authority_added") is not False:
        failures.append("explanation:execution_authority_added")
    if payload.get("confidence_amplified") is not False:
        failures.append("explanation:confidence_amplification_forbidden")
    if payload.get("unsupported_positive_claims_allowed") is not False:
        failures.append("explanation:unsupported_positive_claims_forbidden")

    incident = None
    try:
        incident = _incident_context(decision.candidate.incident_id, correlation)
    except ValueError:
        failures.append("explanation:incident_unknown")

    claims = payload.get("claims")
    if not isinstance(claims, list) or not claims:
        failures.append("explanation:claims_invalid")
        claims = []

    if incident is not None:
        supported_evidence = _incident_supported_evidence(incident, graph)
        node_ids = set(incident.node_ids)
        edge_ids = set(incident.graph_edge_ids)
    else:
        supported_evidence = set()
        node_ids = set()
        edge_ids = set()

    seen_claim_ids: set[str] = set()
    decision_claims = 0
    limitation_claims = 0
    for index, item in enumerate(claims):
        prefix = f"claim[{index}]"
        if not isinstance(item, dict):
            failures.append(f"{prefix}:not_object")
            continue
        claim_id = str(item.get("claim_id") or "")
        if not claim_id or claim_id in seen_claim_ids:
            failures.append(f"{prefix}:claim_id_invalid")
        seen_claim_ids.add(claim_id)
        claim_type = str(item.get("claim_type") or "").upper()
        certainty = str(item.get("certainty") or "").upper()
        if claim_type not in ALLOWED_CLAIM_TYPES:
            failures.append(f"{prefix}:claim_type_invalid")
        if certainty not in ALLOWED_CERTAINTY:
            failures.append(f"{prefix}:certainty_invalid")
        if not _nonempty_string(item.get("text")):
            failures.append(f"{prefix}:text_invalid")
        evidence = item.get("evidence_ids")
        nodes = item.get("node_ids")
        edges = item.get("edge_ids")
        if not isinstance(evidence, list) or any(not _nonempty_string(value) for value in evidence):
            failures.append(f"{prefix}:evidence_ids_invalid")
            evidence = []
        if not isinstance(nodes, list) or any(not _nonempty_string(value) for value in nodes):
            failures.append(f"{prefix}:node_ids_invalid")
            nodes = []
        if not isinstance(edges, list) or any(not _nonempty_string(value) for value in edges):
            failures.append(f"{prefix}:edge_ids_invalid")
            edges = []
        if len(evidence) != len(set(evidence)) or len(nodes) != len(set(nodes)) or len(edges) != len(set(edges)):
            failures.append(f"{prefix}:duplicate_bindings")
        if not set(evidence).issubset(supported_evidence):
            failures.append(f"{prefix}:unsupported_evidence_binding")
        if not set(nodes).issubset(node_ids):
            failures.append(f"{prefix}:unsupported_node_binding")
        if not set(edges).issubset(edge_ids):
            failures.append(f"{prefix}:unsupported_edge_binding")
        if claim_type != "LIMITATION" and not evidence:
            failures.append(f"{prefix}:positive_claim_requires_evidence")
        if claim_type == "DECISION":
            decision_claims += 1
            if set(evidence) != set(decision.matched_evidence_ids):
                failures.append(f"{prefix}:decision_evidence_mismatch")
            if certainty != "ADVISORY_DECISION":
                failures.append(f"{prefix}:decision_certainty_invalid")
        if claim_type == "LIMITATION":
            limitation_claims += 1
            if certainty != "LIMITATION":
                failures.append(f"{prefix}:limitation_certainty_invalid")
        if not _valid_confidence(item.get("confidence")):
            failures.append(f"{prefix}:confidence_invalid")

    if decision_claims != 1:
        failures.append("explanation:decision_claim_count_invalid")
    if limitation_claims < 1:
        failures.append("explanation:limitation_claim_required")

    uncertainty_notes = payload.get("uncertainty_notes")
    if not isinstance(uncertainty_notes, list) or len(uncertainty_notes) < 2 or any(not _nonempty_string(item) for item in uncertainty_notes):
        failures.append("explanation:uncertainty_notes_invalid")

    decision_validation = confidence_gate.validate_decision(decision, correlation, graph)
    if not decision_validation.passed:
        failures.append("explanation:source_decision_invalid")

    return ExplanationValidation(not failures, tuple(failures))


def _self_check_context() -> tuple[
    security_graph.SecurityGraph,
    incident_correlation.CorrelationResult,
    confidence_gate.GateDecision,
]:
    graph, stage_node_ids = attack_chain_harness.build_controlled_graph()
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=120.0).correlate(graph)
    stage_set = set(stage_node_ids)
    incident = next(item for item in correlation.incidents if stage_set.issubset(set(item.node_ids)))
    candidate = confidence_gate.RecommendationCandidate(
        candidate_id="b75-explanation-candidate",
        incident_id=incident.incident_id,
        action="QUARANTINE",
        severity="HIGH",
        evidence_strength="STRONG",
        confidence=0.93,
        reversibility="REVERSIBLE",
        potential_damage="MEDIUM",
        evidence_ids=("ev-b74-detection", "ev-b74-dns", "ev-b74-persistence", "ev-b74-script"),
        rationale="B7-5 controlled explanation candidate; advisory only.",
    )
    decision = confidence_gate.ConfidenceGate().evaluate(
        candidate=candidate,
        correlation=correlation,
        graph=graph,
    )
    return graph, correlation, decision


def self_check() -> dict[str, Any]:
    graph, correlation, decision = _self_check_context()
    graph_before = graph.digest()
    correlation_before = correlation.digest()
    decision_before = decision.digest()
    engine = ExplainableSecurityEngine()
    first = engine.generate(decision=decision, correlation=correlation, graph=graph)
    second = engine.generate(decision=decision, correlation=correlation, graph=graph)
    restored = IncidentExplanation.from_dict(first.to_dict())
    validation = validate_explanation(first, decision, correlation, graph)
    positive_claims = [claim for claim in first.claims if claim.claim_type != "LIMITATION"]
    all_positive_claims_bound = all(bool(claim.evidence_ids) for claim in positive_claims)
    return {
        **validation.to_dict(),
        "explanation_digest": first.digest(),
        "claim_count": len(first.claims),
        "positive_claim_count": len(positive_claims),
        "all_positive_claims_evidence_bound": all_positive_claims_bound,
        "user_explanation_present": bool(first.user_explanation),
        "technical_explanation_present": bool(first.technical_explanation),
        "uncertainty_notes_present": len(first.uncertainty_notes) >= 2,
        "stable_round_trip": restored.stable_json() == first.stable_json(),
        "deterministic_serialization": second.stable_json() == first.stable_json(),
        "source_graph_unchanged": graph.digest() == graph_before,
        "source_correlation_unchanged": correlation.digest() == correlation_before,
        "source_decision_unchanged": decision.digest() == decision_before,
        "decision_outcome": first.decision_outcome,
        "authority_granted": False,
        "confidence_amplified": False,
        "unsupported_positive_claims_allowed": False,
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
    parser = argparse.ArgumentParser(description="BC Sentinel B7-5 Explainable Security")
    parser.add_argument("--self-check", action="store_true")
    parser.parse_args(argv)
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    required = (
        result.get("passed") is True
        and result.get("all_positive_claims_evidence_bound") is True
        and result.get("user_explanation_present") is True
        and result.get("technical_explanation_present") is True
        and result.get("uncertainty_notes_present") is True
        and result.get("stable_round_trip") is True
        and result.get("deterministic_serialization") is True
        and result.get("source_graph_unchanged") is True
        and result.get("source_correlation_unchanged") is True
        and result.get("source_decision_unchanged") is True
        and result.get("authority_granted") is False
        and result.get("confidence_amplified") is False
        and result.get("unsupported_positive_claims_allowed") is False
    )
    return 0 if required else 4


if __name__ == "__main__":
    raise SystemExit(main())
