from __future__ import annotations

"""B7-6 conservative coverage-expansion campaign.

The campaign evaluates the six accepted B7-0 scenario families against evidence
already produced by accepted Beta7 synthetic fixtures. It does not execute real
attacks, detectors, remediation, processes, file writes, network I/O, registry
changes, credential access, or privileged operations. Synthetic evidence can
support PARTIAL coverage only; it is never promoted to VERIFIED detector
coverage by this milestone.
"""

from dataclasses import dataclass, field
import argparse
import hashlib
import json
from typing import Any, Final

from sentinel import attack_chain_harness, coverage_ledger

SCHEMA: Final[str] = "bc-sentinel-coverage-campaign-v1"
PROFILE: Final[str] = "v0.11.0-beta.7-b76-coverage-expansion"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta7-b75-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "40f1e9985905ceccc070e8f73d09308a8406d059"

EXPECTED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-PERSISTENCE-001",
    "B7-RANSOMWARE-001",
    "B7-DEFENSE-EVASION-001",
    "B7-C2-DNS-001",
    "B7-CREDENTIAL-001",
)
PARTIAL_SCENARIOS: Final[set[str]] = {
    "B7-POWERSHELL-001",
    "B7-PERSISTENCE-001",
    "B7-C2-DNS-001",
}
GAP_SCENARIOS: Final[set[str]] = set(EXPECTED_SCENARIOS) - PARTIAL_SCENARIOS
ALLOWED_STATUS: Final[set[str]] = {"PARTIAL", "GAP", "VERIFIED"}

CAMPAIGN_EXECUTES_PROCESSES: Final[bool] = False
CAMPAIGN_WRITES_FILES: Final[bool] = False
CAMPAIGN_NETWORK_IO: Final[bool] = False
CAMPAIGN_MUTATES_REGISTRY: Final[bool] = False
CAMPAIGN_ACCESSES_CREDENTIALS: Final[bool] = False
CAMPAIGN_EXECUTES_REMEDIATION: Final[bool] = False


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())


@dataclass(frozen=True)
class CampaignScenario:
    scenario_id: str
    family: str
    coverage_status: str
    synthetic_observed: bool
    correlated: bool
    detector_verified: bool
    evidence_quality: str
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    gap_reason: str = ""
    next_engineering_step: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "family": self.family,
            "coverage_status": self.coverage_status,
            "synthetic_observed": self.synthetic_observed,
            "correlated": self.correlated,
            "detector_verified": self.detector_verified,
            "evidence_quality": self.evidence_quality,
            "evidence_refs": list(self.evidence_refs),
            "gap_reason": self.gap_reason,
            "next_engineering_step": self.next_engineering_step,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CampaignScenario":
        return cls(
            scenario_id=str(payload.get("scenario_id") or ""),
            family=str(payload.get("family") or ""),
            coverage_status=str(payload.get("coverage_status") or "").upper(),
            synthetic_observed=bool(payload.get("synthetic_observed", False)),
            correlated=bool(payload.get("correlated", False)),
            detector_verified=bool(payload.get("detector_verified", False)),
            evidence_quality=str(payload.get("evidence_quality") or "").upper(),
            evidence_refs=tuple(sorted(str(v) for v in (payload.get("evidence_refs") or []))),
            gap_reason=str(payload.get("gap_reason") or ""),
            next_engineering_step=str(payload.get("next_engineering_step") or ""),
        )


@dataclass(frozen=True)
class CampaignReport:
    campaign_id: str
    base_ledger_digest: str
    b74_report_digest: str
    scenarios: tuple[CampaignScenario, ...]

    def to_dict(self) -> dict[str, Any]:
        summary = {"PARTIAL": 0, "GAP": 0, "VERIFIED": 0}
        for item in self.scenarios:
            summary[item.coverage_status] = summary.get(item.coverage_status, 0) + 1
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "source_checkpoint": SOURCE_CHECKPOINT,
            "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
            "campaign_id": self.campaign_id,
            "base_ledger_digest": self.base_ledger_digest,
            "b74_report_digest": self.b74_report_digest,
            "scenarios": [item.to_dict() for item in sorted(self.scenarios, key=lambda x: x.scenario_id)],
            "summary": summary,
            "verified_claims_promoted": False,
            "unsupported_positive_claims_allowed": False,
            "read_only": True,
            "synthetic_fixture_only": True,
            "process_execution": CAMPAIGN_EXECUTES_PROCESSES,
            "file_write": CAMPAIGN_WRITES_FILES,
            "network_io": CAMPAIGN_NETWORK_IO,
            "registry_mutation": CAMPAIGN_MUTATES_REGISTRY,
            "credential_access": CAMPAIGN_ACCESSES_CREDENTIALS,
            "remediation_execution": CAMPAIGN_EXECUTES_REMEDIATION,
            "authority_granted": False,
            "execution_authority_added": False,
        }

    def stable_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.stable_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CampaignReport":
        return cls(
            campaign_id=str(payload.get("campaign_id") or ""),
            base_ledger_digest=str(payload.get("base_ledger_digest") or ""),
            b74_report_digest=str(payload.get("b74_report_digest") or ""),
            scenarios=tuple(CampaignScenario.from_dict(item) for item in (payload.get("scenarios") or [])),
        )


@dataclass(frozen=True)
class CampaignValidation:
    passed: bool
    failures: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "profile": PROFILE, "passed": self.passed, "failures": list(self.failures)}


def _families() -> dict[str, str]:
    return {
        "B7-POWERSHELL-001": "SCRIPT_ABUSE",
        "B7-PERSISTENCE-001": "PERSISTENCE",
        "B7-RANSOMWARE-001": "RANSOMWARE_LIKE",
        "B7-DEFENSE-EVASION-001": "DEFENSE_EVASION",
        "B7-C2-DNS-001": "SUSPICIOUS_NETWORK_DNS",
        "B7-CREDENTIAL-001": "CREDENTIAL_ACCESS_INDICATOR",
    }


def _gap_details(scenario_id: str) -> tuple[str, str]:
    details = {
        "B7-RANSOMWARE-001": (
            "No accepted ransomware-specific detector/interruption fixture exists in Beta7 yet.",
            "Add a harmless temp-directory mutation burst fixture and verify the real ransomware detector path without destructive encryption.",
        ),
        "B7-DEFENSE-EVASION-001": (
            "No accepted control-tamper detector fixture is bound to this scenario.",
            "Add a non-privileged synthetic tamper signal and validate detection/provenance without disabling any real control.",
        ),
        "B7-CREDENTIAL-001": (
            "No accepted credential-access indicator fixture exists and no credential material may be accessed.",
            "Add metadata-only credential-access indicators using fake fixtures and prove detection without secrets or credential extraction.",
        ),
    }
    return details[scenario_id]


def run_campaign() -> CampaignReport:
    ledger = coverage_ledger.load_ledger(coverage_ledger.default_ledger_path())
    ledger_validation = coverage_ledger.validate_ledger(ledger)
    if not ledger_validation.passed:
        raise ValueError("coverage_campaign_base_ledger_invalid:" + ",".join(ledger_validation.failures))
    ledger_ids = tuple(item["scenario_id"] for item in ledger["scenarios"])
    if ledger_ids != EXPECTED_SCENARIOS:
        raise ValueError("coverage_campaign_scenario_set_changed")

    b74 = attack_chain_harness.self_check()
    if b74.get("passed") is not True or b74.get("synthetic_fixture_only") is not True:
        raise ValueError("coverage_campaign_b74_evidence_invalid")
    b74_digest = str(b74.get("report_digest") or "")
    if not _sha256(b74_digest):
        raise ValueError("coverage_campaign_b74_digest_invalid")

    families = _families()
    scenarios: list[CampaignScenario] = []
    for scenario_id in EXPECTED_SCENARIOS:
        if scenario_id in PARTIAL_SCENARIOS:
            stage = {
                "B7-POWERSHELL-001": "SCRIPT",
                "B7-PERSISTENCE-001": "PERSISTENCE",
                "B7-C2-DNS-001": "DNS",
            }[scenario_id]
            scenarios.append(CampaignScenario(
                scenario_id=scenario_id,
                family=families[scenario_id],
                coverage_status="PARTIAL",
                synthetic_observed=True,
                correlated=True,
                detector_verified=False,
                evidence_quality="MEDIUM",
                evidence_refs=(f"b74-report:{b74_digest}", f"b74-stage:{stage}"),
                gap_reason="Synthetic chain evidence exists, but scenario-specific real detector coverage is not yet accepted.",
                next_engineering_step="Add a dedicated harmless scenario fixture against the real detector path before any VERIFIED claim.",
            ))
        else:
            reason, step = _gap_details(scenario_id)
            scenarios.append(CampaignScenario(
                scenario_id=scenario_id,
                family=families[scenario_id],
                coverage_status="GAP",
                synthetic_observed=False,
                correlated=False,
                detector_verified=False,
                evidence_quality="LOW",
                evidence_refs=(f"b76-gap-evaluation:{scenario_id}",),
                gap_reason=reason,
                next_engineering_step=step,
            ))

    base_digest = _stable_hash(ledger)
    material = {
        "base_ledger_digest": base_digest,
        "b74_report_digest": b74_digest,
        "scenario_ids": list(EXPECTED_SCENARIOS),
    }
    report = CampaignReport(
        campaign_id="campaign:" + _stable_hash(material)[:24],
        base_ledger_digest=base_digest,
        b74_report_digest=b74_digest,
        scenarios=tuple(scenarios),
    )
    validation = validate_report(report)
    if not validation.passed:
        raise ValueError("coverage_campaign_report_invalid:" + ",".join(validation.failures))
    return report


def validate_report(report: CampaignReport | dict[str, Any]) -> CampaignValidation:
    payload = report.to_dict() if isinstance(report, CampaignReport) else report
    failures: list[str] = []
    if not isinstance(payload, dict):
        return CampaignValidation(False, ("campaign:not_object",))
    if payload.get("schema") != SCHEMA:
        failures.append("campaign:schema_mismatch")
    if payload.get("profile") != PROFILE:
        failures.append("campaign:profile_mismatch")
    if payload.get("source_checkpoint") != SOURCE_CHECKPOINT:
        failures.append("campaign:source_checkpoint_mismatch")
    if payload.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("campaign:source_checkpoint_commit_mismatch")
    if not _nonempty(payload.get("campaign_id")):
        failures.append("campaign:id_invalid")
    if not _sha256(payload.get("base_ledger_digest")):
        failures.append("campaign:base_ledger_digest_invalid")
    if not _sha256(payload.get("b74_report_digest")):
        failures.append("campaign:b74_report_digest_invalid")

    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != len(EXPECTED_SCENARIOS):
        failures.append("campaign:scenario_count_invalid")
        scenarios = []
    seen: set[str] = set()
    for index, item in enumerate(scenarios):
        if not isinstance(item, dict):
            failures.append(f"campaign:scenario[{index}]:not_object")
            continue
        sid = str(item.get("scenario_id") or "")
        if sid not in EXPECTED_SCENARIOS or sid in seen:
            failures.append(f"campaign:scenario[{index}]:id_invalid")
        seen.add(sid)
        status = str(item.get("coverage_status") or "").upper()
        if status not in ALLOWED_STATUS:
            failures.append(f"campaign:scenario[{index}]:status_invalid")
        if status == "VERIFIED" or item.get("detector_verified") is True:
            failures.append(f"campaign:scenario[{index}]:unsupported_verified_claim")
        refs = item.get("evidence_refs")
        if not isinstance(refs, list) or not refs or any(not _nonempty(v) for v in refs):
            failures.append(f"campaign:scenario[{index}]:evidence_refs_invalid")
        if sid in PARTIAL_SCENARIOS:
            if status != "PARTIAL" or item.get("synthetic_observed") is not True or item.get("correlated") is not True:
                failures.append(f"campaign:scenario[{index}]:partial_contract_invalid")
            if not any(str(ref).startswith("b74-report:") for ref in (refs or [])):
                failures.append(f"campaign:scenario[{index}]:partial_missing_b74_evidence")
        if sid in GAP_SCENARIOS:
            if status != "GAP" or item.get("synthetic_observed") is not False or item.get("correlated") is not False:
                failures.append(f"campaign:scenario[{index}]:gap_contract_invalid")
        if not _nonempty(item.get("gap_reason")) or not _nonempty(item.get("next_engineering_step")):
            failures.append(f"campaign:scenario[{index}]:gap_or_next_step_missing")

    if seen != set(EXPECTED_SCENARIOS):
        failures.append("campaign:scenario_set_incomplete")
    if payload.get("summary") != {"PARTIAL": 3, "GAP": 3, "VERIFIED": 0}:
        failures.append("campaign:summary_mismatch")
    if payload.get("verified_claims_promoted") is not False:
        failures.append("campaign:verified_claims_promoted")
    if payload.get("unsupported_positive_claims_allowed") is not False:
        failures.append("campaign:unsupported_positive_claims_allowed")
    if payload.get("read_only") is not True or payload.get("synthetic_fixture_only") is not True:
        failures.append("campaign:read_only_fixture_required")
    for field_name in ("process_execution", "file_write", "network_io", "registry_mutation", "credential_access", "remediation_execution"):
        if payload.get(field_name) is not False:
            failures.append(f"campaign:{field_name}_must_be_false")
    if payload.get("authority_granted") is not False or payload.get("execution_authority_added") is not False:
        failures.append("campaign:authority_must_remain_false")
    return CampaignValidation(not failures, tuple(failures))


def self_check() -> dict[str, Any]:
    first = run_campaign()
    second = run_campaign()
    restored = CampaignReport.from_dict(first.to_dict())
    validation = validate_report(first)
    return {
        **validation.to_dict(),
        "campaign_digest": first.digest(),
        "base_ledger_digest": first.base_ledger_digest,
        "b74_report_digest": first.b74_report_digest,
        "scenario_count": len(first.scenarios),
        "summary": first.to_dict()["summary"],
        "explicit_gap_count": sum(1 for s in first.scenarios if s.coverage_status == "GAP"),
        "partial_count": sum(1 for s in first.scenarios if s.coverage_status == "PARTIAL"),
        "verified_count": sum(1 for s in first.scenarios if s.coverage_status == "VERIFIED"),
        "stable_round_trip": restored.stable_json() == first.stable_json(),
        "deterministic_serialization": second.stable_json() == first.stable_json(),
        "unsupported_verified_claims_allowed": False,
        "base_ledger_mutated": False,
        "synthetic_fixture_only": True,
        "process_execution": False,
        "file_write": False,
        "network_io": False,
        "registry_mutation": False,
        "credential_access": False,
        "remediation_execution": False,
        "authority_granted": False,
        "execution_authority_added": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B7-6 Coverage Expansion Campaign")
    parser.add_argument("--self-check", action="store_true")
    parser.parse_args(argv)
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    required = (
        result.get("passed") is True
        and result.get("summary") == {"PARTIAL": 3, "GAP": 3, "VERIFIED": 0}
        and result.get("stable_round_trip") is True
        and result.get("deterministic_serialization") is True
        and result.get("authority_granted") is False
    )
    return 0 if required else 4


if __name__ == "__main__":
    raise SystemExit(main())
