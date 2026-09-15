from __future__ import annotations

"""B7-3 deterministic, fail-closed confidence gate.

The gate evaluates a recommendation against evidence already present in the
accepted B7-2 correlation result and B7-1 Security Graph. It never executes or
authorizes remediation. A RECOMMEND outcome is advisory only.
"""

from dataclasses import dataclass, field
import argparse
import hashlib
import json
from typing import Any, Final

from sentinel import incident_correlation, security_graph

SCHEMA: Final[str] = "bc-sentinel-confidence-gate-v1"
PROFILE: Final[str] = "v0.11.0-beta.7-b73-confidence-gate"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta7-b72-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "32bf6563eccc7f03c26e08afe6fcb58cf207cd8d"

OUTCOME_RECOMMEND: Final[str] = "RECOMMEND"
OUTCOME_REVIEW: Final[str] = "REVIEW_REQUIRED"
OUTCOME_BLOCKED: Final[str] = "BLOCKED_INSUFFICIENT_EVIDENCE"
ALLOWED_OUTCOMES: Final[set[str]] = {
    OUTCOME_RECOMMEND,
    OUTCOME_REVIEW,
    OUTCOME_BLOCKED,
}

ALLOWED_ACTIONS: Final[set[str]] = {
    "QUARANTINE",
    "RESTORE",
    "INVESTIGATE",
    "COLLECT_MORE_EVIDENCE",
    "NO_ACTION",
}
ALLOWED_SEVERITY: Final[set[str]] = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_EVIDENCE_STRENGTH: Final[set[str]] = {"NONE", "WEAK", "MODERATE", "STRONG"}
ALLOWED_REVERSIBILITY: Final[set[str]] = {
    "REVERSIBLE",
    "PARTIALLY_REVERSIBLE",
    "IRREVERSIBLE",
    "UNKNOWN",
}
ALLOWED_DAMAGE: Final[set[str]] = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}

CONFIDENCE_MINIMUM: Final[float] = 0.60
CONFIDENCE_RECOMMEND: Final[float] = 0.85


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_confidence(value: Any) -> bool:
    return value is None or (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and 0.0 <= float(value) <= 1.0
    )


def _normalize(value: Any) -> str:
    return str(value or "").strip().upper()


@dataclass(frozen=True)
class RecommendationCandidate:
    candidate_id: str
    incident_id: str
    action: str
    severity: str
    evidence_strength: str
    confidence: float | None
    reversibility: str
    potential_damage: str
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "incident_id": self.incident_id,
            "action": self.action,
            "severity": self.severity,
            "evidence_strength": self.evidence_strength,
            "confidence": self.confidence,
            "reversibility": self.reversibility,
            "potential_damage": self.potential_damage,
            "evidence_ids": list(self.evidence_ids),
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RecommendationCandidate":
        confidence = payload.get("confidence")
        return cls(
            candidate_id=str(payload.get("candidate_id") or ""),
            incident_id=str(payload.get("incident_id") or ""),
            action=_normalize(payload.get("action")),
            severity=_normalize(payload.get("severity")),
            evidence_strength=_normalize(payload.get("evidence_strength")),
            confidence=None if confidence is None else float(confidence),
            reversibility=_normalize(payload.get("reversibility")),
            potential_damage=_normalize(payload.get("potential_damage")),
            evidence_ids=tuple(sorted(str(item) for item in (payload.get("evidence_ids") or []))),
            rationale=str(payload.get("rationale") or ""),
        )


@dataclass(frozen=True)
class GateDecision:
    decision_id: str
    candidate: RecommendationCandidate
    outcome: str
    reasons: tuple[str, ...]
    matched_evidence_ids: tuple[str, ...]
    source_graph_digest: str
    source_correlation_digest: str
    authority_granted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "source_checkpoint": SOURCE_CHECKPOINT,
            "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
            "decision_id": self.decision_id,
            "candidate": self.candidate.to_dict(),
            "outcome": self.outcome,
            "reasons": list(self.reasons),
            "matched_evidence_ids": list(self.matched_evidence_ids),
            "source_graph_digest": self.source_graph_digest,
            "source_correlation_digest": self.source_correlation_digest,
            "authority_granted": self.authority_granted,
            "read_only": True,
            "execution_authority_added": False,
        }

    def stable_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.stable_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GateDecision":
        return cls(
            decision_id=str(payload.get("decision_id") or ""),
            candidate=RecommendationCandidate.from_dict(dict(payload.get("candidate") or {})),
            outcome=_normalize(payload.get("outcome")),
            reasons=tuple(str(item) for item in (payload.get("reasons") or [])),
            matched_evidence_ids=tuple(sorted(str(item) for item in (payload.get("matched_evidence_ids") or []))),
            source_graph_digest=str(payload.get("source_graph_digest") or ""),
            source_correlation_digest=str(payload.get("source_correlation_digest") or ""),
            authority_granted=bool(payload.get("authority_granted", False)),
        )


@dataclass(frozen=True)
class GateValidation:
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


def _candidate_failures(candidate: RecommendationCandidate) -> list[str]:
    failures: list[str] = []
    if not _nonempty_string(candidate.candidate_id):
        failures.append("candidate:candidate_id_invalid")
    if not _nonempty_string(candidate.incident_id):
        failures.append("candidate:incident_id_invalid")
    if candidate.action not in ALLOWED_ACTIONS:
        failures.append("candidate:action_invalid")
    if candidate.severity not in ALLOWED_SEVERITY:
        failures.append("candidate:severity_invalid")
    if candidate.evidence_strength not in ALLOWED_EVIDENCE_STRENGTH:
        failures.append("candidate:evidence_strength_invalid")
    if not _valid_confidence(candidate.confidence):
        failures.append("candidate:confidence_invalid")
    if candidate.reversibility not in ALLOWED_REVERSIBILITY:
        failures.append("candidate:reversibility_invalid")
    if candidate.potential_damage not in ALLOWED_DAMAGE:
        failures.append("candidate:potential_damage_invalid")
    if any(not _nonempty_string(item) for item in candidate.evidence_ids):
        failures.append("candidate:evidence_ids_invalid")
    if len(candidate.evidence_ids) != len(set(candidate.evidence_ids)):
        failures.append("candidate:evidence_ids_duplicate")
    if not _nonempty_string(candidate.rationale):
        failures.append("candidate:rationale_invalid")
    return failures


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


class ConfidenceGate:
    """Deterministic advisory gate. No returned result is execution authority."""

    def evaluate(
        self,
        *,
        candidate: RecommendationCandidate,
        correlation: incident_correlation.CorrelationResult,
        graph: security_graph.SecurityGraph,
    ) -> GateDecision:
        candidate_errors = _candidate_failures(candidate)
        if candidate_errors:
            raise ValueError("confidence_gate_candidate_invalid:" + ",".join(candidate_errors))

        correlation_validation = incident_correlation.validate_result(correlation, graph)
        if not correlation_validation.passed:
            raise ValueError(
                "confidence_gate_correlation_invalid:" + ",".join(correlation_validation.failures)
            )

        graph_digest_before = graph.digest()
        correlation_digest_before = correlation.digest()

        incidents = {incident.incident_id: incident for incident in correlation.incidents}
        incident = incidents.get(candidate.incident_id)
        if incident is None:
            raise ValueError(f"confidence_gate_incident_unknown:{candidate.incident_id}")

        supported_evidence = _incident_supported_evidence(incident, graph)
        requested_evidence = set(candidate.evidence_ids)
        matched_evidence = tuple(sorted(requested_evidence & supported_evidence))
        unsupported_evidence = tuple(sorted(requested_evidence - supported_evidence))

        reasons: list[str] = []
        outcome = OUTCOME_REVIEW

        if not candidate.evidence_ids:
            outcome = OUTCOME_BLOCKED
            reasons.append("No explicit evidence IDs were supplied for the recommendation.")
        if unsupported_evidence:
            outcome = OUTCOME_BLOCKED
            reasons.append(
                "Candidate references evidence that is not bound to the correlated incident: "
                + ", ".join(unsupported_evidence)
            )
        if candidate.evidence_strength in {"NONE", "WEAK"}:
            outcome = OUTCOME_BLOCKED
            reasons.append("Evidence strength is insufficient for an advisory recommendation.")
        if candidate.confidence is None:
            outcome = OUTCOME_BLOCKED
            reasons.append("Confidence is absent and is never inferred from missing evidence.")
        elif candidate.confidence < CONFIDENCE_MINIMUM:
            outcome = OUTCOME_BLOCKED
            reasons.append(
                f"Confidence {candidate.confidence:.2f} is below the fail-closed minimum "
                f"{CONFIDENCE_MINIMUM:.2f}."
            )

        if outcome != OUTCOME_BLOCKED:
            if candidate.potential_damage in {"HIGH", "CRITICAL", "UNKNOWN"}:
                outcome = OUTCOME_REVIEW
                reasons.append("Potential damage requires explicit human review.")
            if candidate.reversibility in {"PARTIALLY_REVERSIBLE", "IRREVERSIBLE", "UNKNOWN"}:
                outcome = OUTCOME_REVIEW
                reasons.append("Reversibility is insufficient for a direct advisory recommendation.")
            if candidate.severity == "LOW" and candidate.action in {"QUARANTINE", "RESTORE"}:
                outcome = OUTCOME_REVIEW
                reasons.append("Low-severity incidents do not justify a disruptive recommendation.")

            if (
                not reasons
                and candidate.evidence_strength == "STRONG"
                and candidate.confidence is not None
                and candidate.confidence >= CONFIDENCE_RECOMMEND
                and candidate.severity in {"HIGH", "CRITICAL"}
                and candidate.reversibility == "REVERSIBLE"
                and candidate.potential_damage in {"LOW", "MEDIUM"}
                and matched_evidence
            ):
                outcome = OUTCOME_RECOMMEND
                reasons.append(
                    "Strong incident-bound evidence meets the advisory recommendation thresholds."
                )
            elif not reasons:
                outcome = OUTCOME_REVIEW
                reasons.append(
                    "Evidence is valid but does not meet every advisory recommendation threshold."
                )

        reasons.append("This decision is advisory only and grants no execution authority.")

        material = {
            "candidate": candidate.to_dict(),
            "outcome": outcome,
            "reasons": reasons,
            "matched_evidence_ids": matched_evidence,
            "source_graph_digest": graph_digest_before,
            "source_correlation_digest": correlation_digest_before,
        }
        decision = GateDecision(
            decision_id="decision:" + _stable_hash(material)[:24],
            candidate=candidate,
            outcome=outcome,
            reasons=tuple(reasons),
            matched_evidence_ids=matched_evidence,
            source_graph_digest=graph_digest_before,
            source_correlation_digest=correlation_digest_before,
            authority_granted=False,
        )

        validation = validate_decision(decision, correlation, graph)
        if not validation.passed:
            raise ValueError("confidence_gate_decision_invalid:" + ",".join(validation.failures))
        if graph.digest() != graph_digest_before:
            raise RuntimeError("confidence_gate_source_graph_mutated")
        if correlation.digest() != correlation_digest_before:
            raise RuntimeError("confidence_gate_source_correlation_mutated")
        return decision


def validate_decision(
    decision: GateDecision | dict[str, Any],
    correlation: incident_correlation.CorrelationResult,
    graph: security_graph.SecurityGraph,
) -> GateValidation:
    payload = decision.to_dict() if isinstance(decision, GateDecision) else decision
    failures: list[str] = []
    if not isinstance(payload, dict):
        return GateValidation(False, ("confidence_gate:not_object",))

    if payload.get("schema") != SCHEMA:
        failures.append("confidence_gate:schema_mismatch")
    if payload.get("profile") != PROFILE:
        failures.append("confidence_gate:profile_mismatch")
    if payload.get("source_checkpoint") != SOURCE_CHECKPOINT:
        failures.append("confidence_gate:source_checkpoint_mismatch")
    if payload.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("confidence_gate:source_checkpoint_commit_mismatch")
    if not _nonempty_string(payload.get("decision_id")):
        failures.append("confidence_gate:decision_id_invalid")

    candidate_payload = payload.get("candidate")
    if not isinstance(candidate_payload, dict):
        failures.append("confidence_gate:candidate_not_object")
        candidate = None
    else:
        try:
            candidate = RecommendationCandidate.from_dict(candidate_payload)
        except (TypeError, ValueError):
            candidate = None
            failures.append("confidence_gate:candidate_parse_failed")
        if candidate is not None:
            failures.extend(_candidate_failures(candidate))

    outcome = _normalize(payload.get("outcome"))
    if outcome not in ALLOWED_OUTCOMES:
        failures.append("confidence_gate:outcome_invalid")

    reasons = payload.get("reasons")
    if not isinstance(reasons, list) or not reasons or any(not _nonempty_string(item) for item in reasons):
        failures.append("confidence_gate:reasons_invalid")

    matched = payload.get("matched_evidence_ids")
    if not isinstance(matched, list) or any(not _nonempty_string(item) for item in matched):
        failures.append("confidence_gate:matched_evidence_ids_invalid")

    if payload.get("source_graph_digest") != graph.digest():
        failures.append("confidence_gate:source_graph_digest_mismatch")
    if payload.get("source_correlation_digest") != correlation.digest():
        failures.append("confidence_gate:source_correlation_digest_mismatch")
    if payload.get("authority_granted") is not False:
        failures.append("confidence_gate:authority_granted_must_be_false")
    if payload.get("read_only") is not True:
        failures.append("confidence_gate:read_only_required")
    if payload.get("execution_authority_added") is not False:
        failures.append("confidence_gate:execution_authority_added")

    correlation_validation = incident_correlation.validate_result(correlation, graph)
    if not correlation_validation.passed:
        failures.append("confidence_gate:correlation_invalid")

    if candidate is not None:
        incidents = {incident.incident_id: incident for incident in correlation.incidents}
        incident = incidents.get(candidate.incident_id)
        if incident is None:
            failures.append("confidence_gate:incident_unknown")
        else:
            supported = _incident_supported_evidence(incident, graph)
            if not set(payload.get("matched_evidence_ids") or []).issubset(supported):
                failures.append("confidence_gate:matched_evidence_not_incident_bound")
            if outcome == OUTCOME_RECOMMEND:
                if candidate.evidence_strength != "STRONG":
                    failures.append("confidence_gate:recommend_requires_strong_evidence")
                if candidate.confidence is None or candidate.confidence < CONFIDENCE_RECOMMEND:
                    failures.append("confidence_gate:recommend_requires_confidence_threshold")
                if candidate.reversibility != "REVERSIBLE":
                    failures.append("confidence_gate:recommend_requires_reversible")
                if candidate.potential_damage not in {"LOW", "MEDIUM"}:
                    failures.append("confidence_gate:recommend_requires_bounded_damage")
                if not candidate.evidence_ids:
                    failures.append("confidence_gate:recommend_requires_evidence_ids")
                if not set(candidate.evidence_ids).issubset(supported):
                    failures.append("confidence_gate:recommend_requires_supported_evidence")

    return GateValidation(not failures, tuple(failures))


def _self_check_context() -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult]:
    graph = incident_correlation.demo_graph()
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=120.0).correlate(graph)
    return graph, correlation


def self_check() -> dict[str, Any]:
    graph, correlation = _self_check_context()
    target = next(incident for incident in correlation.incidents if len(incident.node_ids) == 3)

    recommend = RecommendationCandidate(
        candidate_id="candidate-b73-recommend",
        incident_id=target.incident_id,
        action="QUARANTINE",
        severity="HIGH",
        evidence_strength="STRONG",
        confidence=0.92,
        reversibility="REVERSIBLE",
        potential_damage="MEDIUM",
        evidence_ids=("ev-script", "ev-detection"),
        rationale="Controlled fixture recommendation.",
    )
    review = RecommendationCandidate(
        candidate_id="candidate-b73-review",
        incident_id=target.incident_id,
        action="QUARANTINE",
        severity="HIGH",
        evidence_strength="STRONG",
        confidence=0.95,
        reversibility="REVERSIBLE",
        potential_damage="HIGH",
        evidence_ids=("ev-script", "ev-detection"),
        rationale="Controlled high-damage fixture.",
    )
    blocked = RecommendationCandidate(
        candidate_id="candidate-b73-blocked",
        incident_id=target.incident_id,
        action="QUARANTINE",
        severity="HIGH",
        evidence_strength="NONE",
        confidence=None,
        reversibility="REVERSIBLE",
        potential_damage="LOW",
        evidence_ids=(),
        rationale="Controlled missing-evidence fixture.",
    )

    gate = ConfidenceGate()
    graph_before = graph.digest()
    correlation_before = correlation.digest()
    recommend_decision = gate.evaluate(candidate=recommend, correlation=correlation, graph=graph)
    review_decision = gate.evaluate(candidate=review, correlation=correlation, graph=graph)
    blocked_decision = gate.evaluate(candidate=blocked, correlation=correlation, graph=graph)
    restored = GateDecision.from_dict(recommend_decision.to_dict())

    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": (
            recommend_decision.outcome == OUTCOME_RECOMMEND
            and review_decision.outcome == OUTCOME_REVIEW
            and blocked_decision.outcome == OUTCOME_BLOCKED
            and validate_decision(recommend_decision, correlation, graph).passed
        ),
        "recommend_outcome": recommend_decision.outcome,
        "review_outcome": review_decision.outcome,
        "blocked_outcome": blocked_decision.outcome,
        "recommend_digest": recommend_decision.digest(),
        "stable_round_trip": restored.stable_json() == recommend_decision.stable_json(),
        "source_graph_unchanged": graph.digest() == graph_before,
        "source_correlation_unchanged": correlation.digest() == correlation_before,
        "missing_confidence_inferred": False,
        "authority_granted": False,
        "read_only": True,
        "execution_authority_added": False,
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
    parser = argparse.ArgumentParser(description="BC Sentinel B7-3 Confidence Gate")
    parser.add_argument("--self-check", action="store_true")
    parser.parse_args(argv)
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    required = (
        result.get("passed") is True
        and result.get("recommend_outcome") == OUTCOME_RECOMMEND
        and result.get("review_outcome") == OUTCOME_REVIEW
        and result.get("blocked_outcome") == OUTCOME_BLOCKED
        and result.get("authority_granted") is False
        and result.get("source_graph_unchanged") is True
        and result.get("source_correlation_unchanged") is True
        and result.get("stable_round_trip") is True
    )
    return 0 if required else 4


if __name__ == "__main__":
    raise SystemExit(main())
