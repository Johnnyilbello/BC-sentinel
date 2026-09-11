from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from sentinel import rescue_console_integrated_certification as b44
from sentinel import rescue_hostile_scenarios as b51
from sentinel import rescue_integrity_certification as rr6
from sentinel import rescue_session_resume as b53
from sentinel import rescue_stress_hardening as b52

PROFILE: Final[str] = "v0.11.0-beta.5-b54"
SCHEMA: Final[str] = "bc-sentinel-beta5-recovery-decision-v1"

STATE_REPAIRABLE: Final[str] = "REPAIRABLE"
STATE_MANUAL_REVIEW: Final[str] = "MANUAL_REVIEW"
STATE_DATA_RESCUE_ONLY: Final[str] = "DATA_RESCUE_ONLY"
STATE_REIMAGE_RECOMMENDED: Final[str] = "REIMAGE_RECOMMENDED"
STATE_INDETERMINATE: Final[str] = "INDETERMINATE"
ALLOWED_STATES: Final[frozenset[str]] = frozenset({
    STATE_REPAIRABLE,
    STATE_MANUAL_REVIEW,
    STATE_DATA_RESCUE_ONLY,
    STATE_REIMAGE_RECOMMENDED,
    STATE_INDETERMINATE,
})

B42_PROFILE: Final[str] = "v0.11.0-beta.4-b42"
B43_PROFILE: Final[str] = "v0.11.0-beta.4-b43"


@dataclass(frozen=True)
class DecisionRequest:
    certification_summary: Path
    output_path: Path
    health_assessment: Path | None = None
    stress_probe: Path | None = None
    resume_decision: Path | None = None
    repair_handoff: Path | None = None
    data_rescue_summary: Path | None = None


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _valid_sha256(value: object) -> bool:
    text = str(value or "").casefold()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        st = path.stat(follow_symlinks=False)
        attrs = int(getattr(st, "st_file_attributes", 0) or 0)
        return bool(attrs & int(getattr(os, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))
    except OSError:
        return True


def _load_json(path: Path) -> tuple[Path, dict, str]:
    original = Path(path)
    if original.is_symlink():
        raise ValueError(f"B5-4 evidence symlink/reparse refused: {original}")
    resolved = original.resolve(strict=True)
    if not resolved.is_file() or _is_reparse_or_symlink(resolved):
        raise ValueError(f"B5-4 evidence must be regular non-reparse file: {resolved}")
    payload = json.loads(resolved.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"B5-4 JSON root must be object: {resolved.name}")
    return resolved, payload, _sha256_file(resolved)


def _atomic_write(path: Path, payload: dict) -> None:
    output = Path(path).resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=str(output.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temp, output)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _validate_b44(payload: dict) -> None:
    if payload.get("profile") != b44.PROFILE or payload.get("schema") != b44.SUMMARY_SCHEMA:
        raise ValueError("b44_profile_or_schema_mismatch")
    outcome = str(payload.get("outcome") or "")
    if outcome not in {rr6.OUTCOME_RECOVERED, rr6.OUTCOME_NOT_RECOVERED, rr6.OUTCOME_REFUSED}:
        raise ValueError("b44_unknown_rr6_outcome")
    expected = str(payload.get("summary_sha256") or "").casefold()
    if not _valid_sha256(expected):
        raise ValueError("b44_summary_sha256_invalid")
    core = dict(payload)
    core.pop("summary_sha256", None)
    actual = _sha256_bytes(_canonical_json(core))
    if actual != expected:
        raise ValueError(f"b44_summary_sha256_mismatch:{actual}")
    safety = payload.get("safety")
    if not isinstance(safety, dict) or safety.get("repair_execution") is not False or safety.get("automatic_destructive_action") is not False:
        raise ValueError("b44_safety_contract_invalid")
    if outcome == rr6.OUTCOME_RECOVERED and payload.get("certified_recovered") is not True:
        raise ValueError("b44_recovered_without_certification")
    if outcome != rr6.OUTCOME_RECOVERED and payload.get("certified_recovered") is not False:
        raise ValueError("b44_nonrecovered_marked_certified")


def _validate_b51(payload: dict, fingerprint: str) -> None:
    if payload.get("profile") != b51.PROFILE or payload.get("schema") != b51.SCHEMA:
        raise ValueError("b51_profile_or_schema_mismatch")
    expected = str(payload.get("assessment_sha256") or "").casefold()
    if not _valid_sha256(expected):
        raise ValueError("b51_assessment_sha256_invalid")
    core = dict(payload)
    core.pop("assessment_sha256", None)
    core.pop("created_utc", None)
    core.pop("elapsed_ms", None)
    actual = _sha256_bytes(_canonical_json(core))
    if actual != expected:
        raise ValueError(f"b51_assessment_sha256_mismatch:{actual}")
    bound = str(payload.get("target_fingerprint") or "").casefold()
    if bound and fingerprint and bound != fingerprint:
        raise ValueError("b51_target_fingerprint_mismatch")
    if str(payload.get("state") or "") not in {
        b51.STATE_HEALTHY, b51.STATE_REVIEW, b51.STATE_DAMAGED,
        b51.STATE_ACCESS_RESTRICTED, b51.STATE_IO_DEGRADED, b51.STATE_REFUSED,
    }:
        raise ValueError("b51_unknown_state")


def _validate_b52(payload: dict, fingerprint: str) -> None:
    if payload.get("profile") != b52.PROFILE or payload.get("schema") != b52.SCHEMA:
        raise ValueError("b52_profile_or_schema_mismatch")
    expected = str(payload.get("probe_sha256") or "").casefold()
    if not _valid_sha256(expected):
        raise ValueError("b52_probe_sha256_invalid")
    core = dict(payload)
    core.pop("probe_sha256", None)
    core.pop("created_utc", None)
    core.pop("performance", None)
    counters = dict(core.get("counters") or {})
    counters.pop("slow_reads", None)
    core["counters"] = counters
    records = []
    for row in core.get("records", []) if isinstance(core.get("records"), list) else []:
        if not isinstance(row, dict):
            raise ValueError("b52_record_invalid")
        stable = dict(row)
        stable.pop("elapsed_ms", None)
        stable.pop("slow_read", None)
        records.append(stable)
    core["records"] = records
    actual = _sha256_bytes(_canonical_json(core))
    if actual != expected:
        raise ValueError(f"b52_probe_sha256_mismatch:{actual}")
    if str(payload.get("target_fingerprint") or "").casefold() != fingerprint:
        raise ValueError("b52_target_fingerprint_mismatch")


def _validate_b53(payload: dict, fingerprint: str) -> None:
    if payload.get("profile") != b53.PROFILE or payload.get("schema") != b53.RESUME_SCHEMA:
        raise ValueError("b53_profile_or_schema_mismatch")
    expected = str(payload.get("decision_sha256") or "").casefold()
    if not _valid_sha256(expected):
        raise ValueError("b53_decision_sha256_invalid")
    core = dict(payload)
    core.pop("decision_sha256", None)
    core.pop("elapsed_ms", None)
    actual = _sha256_bytes(_canonical_json(core))
    if actual != expected:
        raise ValueError(f"b53_decision_sha256_mismatch:{actual}")
    expected_fp = str(payload.get("expected_target_fingerprint") or "").casefold()
    current_fp = str(payload.get("current_target_fingerprint") or "").casefold()
    if fingerprint and (expected_fp != fingerprint or current_fp != fingerprint):
        raise ValueError("b53_target_fingerprint_mismatch")


def _validate_bound_optional(payload: dict, file_sha: str, *, profile: str, fingerprint: str, expected_file_sha: str, label: str) -> None:
    if payload.get("profile") != profile:
        raise ValueError(f"{label}_profile_mismatch")
    if str(payload.get("target_fingerprint") or "").casefold() != fingerprint:
        raise ValueError(f"{label}_target_fingerprint_mismatch")
    if not _valid_sha256(expected_file_sha) or file_sha != expected_file_sha:
        raise ValueError(f"{label}_file_sha256_binding_mismatch")


def _reconfirm_required(resume: dict | None) -> bool:
    if not resume:
        return False
    return any(
        isinstance(row, dict) and str(row.get("decision") or "") == "RECONFIRM_REQUIRED"
        for row in (resume.get("actions") or [])
    )


def build_decision(request: DecisionRequest) -> dict:
    started = time.perf_counter()
    reasons: list[str] = []
    evidence_index: dict[str, dict] = {}

    cert_path, cert, cert_file_sha = _load_json(request.certification_summary)
    try:
        _validate_b44(cert)
    except Exception as exc:
        reasons.append(f"certification_untrusted:{type(exc).__name__}:{exc}")

    fingerprint = str(cert.get("target_fingerprint") or "").casefold()
    outcome = str(cert.get("outcome") or "")
    evidence_index["b44_certification"] = {"path": str(cert_path), "file_sha256": cert_file_sha, "trusted": not reasons}

    health: dict | None = None
    stress: dict | None = None
    resume: dict | None = None
    repair: dict | None = None
    rescue: dict | None = None

    optional_specs = [
        ("b51_health", request.health_assessment),
        ("b52_stress", request.stress_probe),
        ("b53_resume", request.resume_decision),
        ("b42_repair_handoff", request.repair_handoff),
        ("b43_data_rescue", request.data_rescue_summary),
    ]
    for label, supplied in optional_specs:
        if supplied is None:
            continue
        try:
            path, payload, file_sha = _load_json(supplied)
            if label == "b51_health":
                _validate_b51(payload, fingerprint)
                health = payload
            elif label == "b52_stress":
                _validate_b52(payload, fingerprint)
                stress = payload
            elif label == "b53_resume":
                _validate_b53(payload, fingerprint)
                resume = payload
            elif label == "b42_repair_handoff":
                expected = str((cert.get("evidence") or {}).get("b42_handoff_sha256") or "").casefold()
                _validate_bound_optional(payload, file_sha, profile=B42_PROFILE, fingerprint=fingerprint, expected_file_sha=expected, label="b42")
                if payload.get("operator_confirmation_required") is not True or payload.get("execution_performed") is not False:
                    raise ValueError("b42_operator_gate_contract_invalid")
                repair = payload
            elif label == "b43_data_rescue":
                expected = str((cert.get("evidence") or {}).get("b43_summary_sha256") or "").casefold()
                _validate_bound_optional(payload, file_sha, profile=B43_PROFILE, fingerprint=fingerprint, expected_file_sha=expected, label="b43")
                rescue = payload
            evidence_index[label] = {"path": str(path), "file_sha256": file_sha, "trusted": True}
        except Exception as exc:
            reasons.append(f"{label}_untrusted:{type(exc).__name__}:{exc}")
            evidence_index[label] = {"path": str(supplied), "file_sha256": "", "trusted": False}

    state = STATE_INDETERMINATE
    decision_reasons: list[str] = []
    next_action = "Resolve evidence trust before any recovery decision."

    if reasons:
        decision_reasons.append("one_or_more_evidence_items_untrusted")
    elif outcome == rr6.OUTCOME_REFUSED:
        decision_reasons.append("rr6_outcome_indeterminate_refused_preserved")
        next_action = "Resolve RR-6/session refusal; do not treat the system as recovered or repairable. Reimage remains available."
    elif resume is not None and (resume.get("trusted") is not True or str(resume.get("state") or "") != "READY"):
        decision_reasons.append("b53_session_not_trusted")
        next_action = "Restore session trust or start a fresh trusted Rescue session."
    elif outcome == rr6.OUTCOME_RECOVERED:
        health_state = str((health or {}).get("state") or "")
        stress_state = str((stress or {}).get("state") or "")
        if health_state in {b51.STATE_DAMAGED, b51.STATE_ACCESS_RESTRICTED, b51.STATE_IO_DEGRADED, b51.STATE_REFUSED}:
            state = STATE_INDETERMINATE
            decision_reasons.append(f"post_certification_health_conflict:{health_state}")
            next_action = "Re-run trusted assessment/certification because later health evidence conflicts with RECOVERED."
        elif stress_state and stress_state not in {b52.STATE_COMPLETE, b52.STATE_DEGRADED}:
            state = STATE_MANUAL_REVIEW
            decision_reasons.append(f"stress_probe_incomplete:{stress_state}")
            next_action = "Complete the bounded stress probe before field sign-off."
        else:
            state = STATE_MANUAL_REVIEW
            decision_reasons.append("rr6_certified_recovered_preserved")
            if health_state == b51.STATE_REVIEW:
                decision_reasons.append("persistence_items_still_require_operator_review")
            next_action = "No repair recommendation: perform technician sign-off and review any remaining advisory findings."
    elif outcome == rr6.OUTCOME_NOT_RECOVERED:
        if _reconfirm_required(resume):
            state = STATE_MANUAL_REVIEW
            decision_reasons.append("interrupted_mutation_stage_requires_fresh_operator_confirmation")
            next_action = "Re-establish operator confirmation before continuing any repair or data-rescue mutation."
        elif repair is not None:
            state = STATE_REPAIRABLE
            decision_reasons.append("trusted_rr4b_repair_handoff_available")
            next_action = "Review the bound RR-4B plan and obtain explicit plan-bound confirmation before repair execution."
        elif rescue is not None and bool(rescue.get("execution_requested", False)):
            state = STATE_DATA_RESCUE_ONLY
            decision_reasons.append("trusted_data_rescue_available_without_verified_repair_path")
            next_action = "Preserve rescued/contained data and avoid claiming system recovery; consider reimage after evidence export."
        else:
            state = STATE_REIMAGE_RECOMMENDED
            decision_reasons.append("rr6_not_recovered_without_trusted_repair_path")
            next_action = "Preserve evidence/data, then reimage unless a new trusted repair path is established."
    else:
        decision_reasons.append(f"unexpected_rr6_outcome:{outcome}")

    if state not in ALLOWED_STATES:
        state = STATE_INDETERMINATE
        decision_reasons.append("decision_state_fail_closed")

    core = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "target_fingerprint": fingerprint,
        "rr6_outcome": outcome,
        "rr6_certified_recovered": bool(cert.get("certified_recovered", False)),
        "state": state,
        "reasons": reasons + decision_reasons,
        "next_action": next_action,
        "evidence_index": evidence_index,
        "signals": {
            "health_state": str((health or {}).get("state") or ""),
            "stress_state": str((stress or {}).get("state") or ""),
            "resume_state": str((resume or {}).get("state") or ""),
            "resume_reconfirm_required": _reconfirm_required(resume),
            "repair_handoff_available": repair is not None,
            "data_rescue_available": rescue is not None and bool(rescue.get("execution_requested", False)),
        },
        "safety": {
            "advisory_only": True,
            "rr6_outcome_override": False,
            "automatic_repair": False,
            "automatic_data_rescue": False,
            "automatic_reimage": False,
            "automatic_destructive_action": False,
            "target_write_authority_added": False,
            "repair_execution_authority_added": False,
            "quarantine_execution_authority_added": False,
        },
    }
    decision_sha = _sha256_bytes(_canonical_json(core))
    result = {
        **core,
        "created_utc": _utc_now(),
        "decision_sha256": decision_sha,
        "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
    }
    _atomic_write(request.output_path, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta5 B5-4 advisory recovery decision engine")
    parser.add_argument("--certification-summary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--health-assessment")
    parser.add_argument("--stress-probe")
    parser.add_argument("--resume-decision")
    parser.add_argument("--repair-handoff")
    parser.add_argument("--data-rescue-summary")
    args = parser.parse_args(argv)
    try:
        result = build_decision(DecisionRequest(
            certification_summary=Path(args.certification_summary),
            output_path=Path(args.output),
            health_assessment=Path(args.health_assessment) if args.health_assessment else None,
            stress_probe=Path(args.stress_probe) if args.stress_probe else None,
            resume_decision=Path(args.resume_decision) if args.resume_decision else None,
            repair_handoff=Path(args.repair_handoff) if args.repair_handoff else None,
            data_rescue_summary=Path(args.data_rescue_summary) if args.data_rescue_summary else None,
        ))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["state"] != STATE_INDETERMINATE else 4
    except Exception as exc:
        print(json.dumps({
            "profile": PROFILE,
            "state": STATE_INDETERMINATE,
            "passed": False,
            "stage": "decision",
            "reason": f"{type(exc).__name__}:{exc}",
        }, indent=2, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
