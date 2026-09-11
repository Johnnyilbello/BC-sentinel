from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from sentinel import rescue_console as b40
from sentinel import rescue_console_guided_scan as b41
from sentinel import rescue_integrity_certification as rr6

PROFILE: Final[str] = "v0.11.0-beta.4-b44"
SUMMARY_SCHEMA: Final[str] = "bc-sentinel-beta4-integrated-certification-summary-v1"
B42_PROFILE: Final[str] = "v0.11.0-beta.4-b42"
B43_PROFILE: Final[str] = "v0.11.0-beta.4-b43"
RR5_PROFILE: Final[str] = "v0.11.0-beta.3-rr5"


@dataclass(frozen=True)
class IntegratedCertificationRequest:
    target_root: Path
    workspace: Path
    scan_path: Path
    baseline_path: Path
    provenance_path: Path
    repair_transaction_path: Path | None = None
    b42_handoff_path: Path | None = None
    b43_summary_path: Path | None = None


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temp, path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def _load_json(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"B4-4 JSON root must be object: {path.name}")
    return payload


def _outside_target(path: Path, root: Path, *, must_exist: bool = True) -> Path:
    resolved = path.resolve(strict=must_exist)
    target = root.resolve(strict=True)
    try:
        resolved.relative_to(target)
        raise ValueError("B4-4 evidence/output must be outside offline target")
    except ValueError as exc:
        if str(exc).startswith("B4-4 evidence/output"):
            raise
    return resolved


def _valid_sha256(value: object) -> bool:
    text = str(value or "").casefold()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _validate_b40_plan(workspace: Path, fingerprint: str) -> tuple[dict, str]:
    path = workspace / "session-plan.json"
    if not path.is_file():
        raise ValueError("b40_session_plan_missing")
    payload = _load_json(path)
    if payload.get("schema") != b40.PLAN_SCHEMA or payload.get("profile") != b40.PROFILE:
        raise ValueError("b40_session_plan_profile_or_schema_mismatch")
    if str(payload.get("target_fingerprint") or "").casefold() != fingerprint:
        raise ValueError("b40_session_plan_target_fingerprint_mismatch")
    safety = payload.get("safety")
    if not isinstance(safety, dict) or safety.get("target_read_only") is not True or safety.get("automatic_execution") is not False:
        raise ValueError("b40_session_plan_safety_contract_invalid")
    return payload, _sha256_file(path)


def _validate_b41_scan(root: Path, workspace: Path, scan_path: Path) -> tuple[dict, dict]:
    inventory = b41.inventory_evidence(root, workspace, scan_path)
    record = next(item for item in inventory["records"] if item["kind"] == "rr3_scan")
    if record["trust"] != b41.TRUST_TRUSTED:
        reasons = ",".join(str(item) for item in record.get("reasons", []))
        raise ValueError("b41_trusted_scan_required:" + reasons)
    payload = _load_json(Path(record["path"]))
    return record, payload


def _validate_b42_handoff(path: Path | None, root: Path, fingerprint: str, scan_sha256: str) -> dict:
    if path is None:
        return {"present": False, "path": "", "sha256": "", "plan_sha256": ""}
    resolved = _outside_target(path, root)
    payload = _load_json(resolved)
    if payload.get("profile") != B42_PROFILE:
        raise ValueError("b42_handoff_profile_mismatch")
    if str(payload.get("target_fingerprint") or "").casefold() != fingerprint:
        raise ValueError("b42_handoff_target_fingerprint_mismatch")
    if str(payload.get("trusted_scan_sha256") or "").casefold() != scan_sha256:
        raise ValueError("b42_handoff_scan_binding_mismatch")
    if payload.get("operator_confirmation_required") is not True:
        raise ValueError("b42_handoff_operator_confirmation_contract_missing")
    if payload.get("execution_performed") is not False or payload.get("automatic_execution") is not False or payload.get("automatic_repair") is not False:
        raise ValueError("b42_handoff_unsafe_execution_contract")
    plan_hash = str(payload.get("plan_sha256") or "").casefold()
    if not _valid_sha256(plan_hash):
        raise ValueError("b42_handoff_plan_sha256_invalid")
    return {"present": True, "path": str(resolved), "sha256": _sha256_file(resolved), "plan_sha256": plan_hash}


def _validate_repair_transaction(path: Path | None, root: Path, b42_info: dict) -> dict:
    if path is None:
        return {"present": False, "path": "", "sha256": "", "state": ""}
    if not b42_info.get("present"):
        raise ValueError("repair_transaction_requires_b42_handoff")
    resolved = _outside_target(path, root)
    payload = _load_json(resolved)
    if str(payload.get("profile") or "") != rr6.RR4A_PROFILE:
        raise ValueError("repair_transaction_profile_mismatch")
    if str(payload.get("plan_sha256") or "").casefold() != str(b42_info.get("plan_sha256") or "").casefold():
        raise ValueError("repair_transaction_plan_binding_mismatch")
    state = str(payload.get("state") or "")
    if state not in {"applied", "rolled_back"}:
        raise ValueError("repair_transaction_untrusted_state")
    return {"present": True, "path": str(resolved), "sha256": _sha256_file(resolved), "state": state}


def _validate_b43_summary(path: Path | None, root: Path, fingerprint: str, scan_sha256: str) -> dict:
    if path is None:
        return {"present": False, "path": "", "sha256": "", "executed": False, "manifest_sha256": ""}
    resolved = _outside_target(path, root)
    payload = _load_json(resolved)
    if payload.get("profile") != B43_PROFILE:
        raise ValueError("b43_summary_profile_mismatch")
    if str(payload.get("target_fingerprint") or "").casefold() != fingerprint:
        raise ValueError("b43_summary_target_fingerprint_mismatch")
    if str(payload.get("trusted_scan_sha256") or "").casefold() != scan_sha256:
        raise ValueError("b43_summary_scan_binding_mismatch")
    safety = payload.get("safety")
    if not isinstance(safety, dict) or safety.get("source_read_only") is not True or safety.get("repair_execution") is not False or safety.get("recovery_certification") is not False:
        raise ValueError("b43_summary_safety_contract_invalid")

    executed = bool(payload.get("execution_requested", False))
    manifest_hash = str(payload.get("manifest_sha256") or "").casefold()
    if executed:
        manifest_path_text = str(payload.get("manifest_path") or "").strip()
        if not manifest_path_text or not _valid_sha256(manifest_hash):
            raise ValueError("b43_manifest_binding_missing")
        manifest_path = _outside_target(Path(manifest_path_text), root)
        if _sha256_file(manifest_path) != manifest_hash:
            raise ValueError("b43_manifest_hash_mismatch")
        manifest = _load_json(manifest_path)
        if manifest.get("profile") != RR5_PROFILE:
            raise ValueError("b43_rr5_manifest_profile_mismatch")
        if Path(str(manifest.get("source_root") or "")).resolve(strict=True) != root.resolve(strict=True):
            raise ValueError("b43_rr5_manifest_source_mismatch")
        summary = manifest.get("summary")
        if not isinstance(summary, dict) or int(summary.get("errors", 0) or 0) != 0:
            raise ValueError("b43_rr5_manifest_contains_errors")
    elif manifest_hash:
        raise ValueError("b43_preview_unexpected_manifest_hash")

    return {"present": True, "path": str(resolved), "sha256": _sha256_file(resolved), "executed": executed, "manifest_sha256": manifest_hash}


def _write_refused_summary(
    *,
    workspace: Path,
    session_id: str,
    correlation_id: str,
    fingerprint: str,
    reason: str,
    started: float,
    audit_path: Path,
) -> dict:
    without_hash = {
        "schema": SUMMARY_SCHEMA,
        "profile": PROFILE,
        "created_utc": _utc_now(),
        "session_id": session_id,
        "correlation_id": correlation_id,
        "target_fingerprint": fingerprint,
        "outcome": rr6.OUTCOME_REFUSED,
        "certified_recovered": False,
        "rr6_invoked": False,
        "rr6_report_path": "",
        "rr6_report_sha256": "",
        "session_refusal_reasons": [reason],
        "rr6_refusal_reasons": [],
        "rr6_not_recovered_reasons": [],
        "safety": {
            "target_read_only": True,
            "repair_execution": False,
            "automatic_destructive_action": False,
            "format_or_reimage_suppressed": False,
        },
        "duration_ms": round((time.perf_counter() - started) * 1000.0, 3),
    }
    summary_hash = hashlib.sha256(_canonical_json(without_hash)).hexdigest()
    summary = {**without_hash, "summary_sha256": summary_hash}
    _atomic_json(workspace / "b44-session-summary.json", summary)
    _append_jsonl(audit_path, {
        "profile": PROFILE,
        "session_id": session_id,
        "correlation_id": correlation_id,
        "target_fingerprint": fingerprint,
        "stage": "session_validation",
        "status": "refused",
        "reason": reason,
        "elapsed_ms": summary["duration_ms"],
    })
    return summary


def run_integrated_certification(request: IntegratedCertificationRequest) -> dict:
    started = time.perf_counter()
    root = rr6.validate_offline_windows_root(request.target_root)
    workspace = b40.validate_workspace(request.workspace, root)
    fingerprint = rr6.target_fingerprint(root)
    session_id = "B44-" + fingerprint[:16].upper()
    correlation_id = hashlib.sha256((session_id + "|integrated-certification").encode("utf-8")).hexdigest()[:24]
    audit_path = workspace / "b44-audit.jsonl"

    def audit(stage: str, status: str, reason: str, **extra: object) -> None:
        _append_jsonl(audit_path, {
            "profile": PROFILE,
            "session_id": session_id,
            "correlation_id": correlation_id,
            "target_fingerprint": fingerprint,
            "stage": stage,
            "status": status,
            "reason": reason,
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
            **extra,
        })

    try:
        audit("session_validation", "start", "beta4_session_continuity_validation_started")
        b40_plan, b40_hash = _validate_b40_plan(workspace, fingerprint)
        scan_record, _scan_payload = _validate_b41_scan(root, workspace, request.scan_path)
        scan_sha256 = str(scan_record["sha256"]).casefold()
        b42_info = _validate_b42_handoff(request.b42_handoff_path, root, fingerprint, scan_sha256)
        repair_info = _validate_repair_transaction(request.repair_transaction_path, root, b42_info)
        b43_info = _validate_b43_summary(request.b43_summary_path, root, fingerprint, scan_sha256)

        for supplied in (request.baseline_path, request.provenance_path):
            _outside_target(supplied, root)
        audit(
            "session_validation",
            "ok",
            "beta4_session_continuity_validated",
            b40_plan_sha256=b40_hash,
            rr3_scan_sha256=scan_sha256,
            b42_present=b42_info["present"],
            repair_transaction_present=repair_info["present"],
            b43_present=b43_info["present"],
        )
    except Exception as exc:
        return _write_refused_summary(
            workspace=workspace,
            session_id=session_id,
            correlation_id=correlation_id,
            fingerprint=fingerprint,
            reason=f"session_evidence_untrusted:{type(exc).__name__}:{exc}",
            started=started,
            audit_path=audit_path,
        )

    audit("rr6_certification", "start", "rr6_integrated_certification_started")
    rr6_output = workspace / "rr6-final"
    report = rr6.certify_recovery(
        root,
        rr6.CertificationEvidence(
            scan_path=request.scan_path,
            baseline_path=request.baseline_path,
            provenance_path=request.provenance_path,
            repair_transaction_path=request.repair_transaction_path,
        ),
        rr6_output,
    )
    report_path = rr6_output / "rr6-certification-report.json"
    report_file_hash = _sha256_file(report_path)
    audit(
        "rr6_certification",
        "ok" if report["outcome"] == rr6.OUTCOME_RECOVERED else ("refused" if report["outcome"] == rr6.OUTCOME_REFUSED else "fail"),
        "rr6_outcome_preserved",
        outcome=report["outcome"],
        certified_recovered=bool(report["certified_recovered"]),
        rr6_report_sha256=report["report_sha256"],
    )

    without_hash = {
        "schema": SUMMARY_SCHEMA,
        "profile": PROFILE,
        "created_utc": _utc_now(),
        "session_id": session_id,
        "correlation_id": correlation_id,
        "target_fingerprint": fingerprint,
        "outcome": report["outcome"],
        "certified_recovered": bool(report["certified_recovered"]),
        "rr6_invoked": True,
        "rr6_report_path": str(report_path),
        "rr6_report_sha256": report["report_sha256"],
        "rr6_report_file_sha256": report_file_hash,
        "session_refusal_reasons": [],
        "rr6_refusal_reasons": list(report.get("refusal_reasons", [])),
        "rr6_not_recovered_reasons": list(report.get("not_recovered_reasons", [])),
        "evidence": {
            "b40_plan_sha256": b40_hash,
            "rr3_scan_sha256": scan_sha256,
            "critical_baseline_sha256": _sha256_file(request.baseline_path),
            "provenance_sha256": _sha256_file(request.provenance_path),
            "b42_handoff_sha256": b42_info["sha256"],
            "repair_transaction_sha256": repair_info["sha256"],
            "b43_summary_sha256": b43_info["sha256"],
            "b43_manifest_sha256": b43_info["manifest_sha256"],
        },
        "safety": {
            "target_read_only": True,
            "repair_execution": False,
            "automatic_destructive_action": False,
            "format_or_reimage_suppressed": False,
        },
        "duration_ms": round((time.perf_counter() - started) * 1000.0, 3),
    }
    summary_hash = hashlib.sha256(_canonical_json(without_hash)).hexdigest()
    summary = {**without_hash, "summary_sha256": summary_hash}
    _atomic_json(workspace / "b44-session-summary.json", summary)
    audit("session_complete", "ok" if summary["certified_recovered"] else "complete", "integrated_session_summary_written", outcome=summary["outcome"], summary_sha256=summary_hash)
    return summary


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="BC Sentinel Beta4 B4-4 Integrated Certification + Session Summary")
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--scan", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--provenance", required=True)
    parser.add_argument("--repair-transaction")
    parser.add_argument("--b42-handoff")
    parser.add_argument("--b43-summary")
    args = parser.parse_args(argv)

    try:
        result = run_integrated_certification(IntegratedCertificationRequest(
            target_root=Path(args.target_root),
            workspace=Path(args.workspace),
            scan_path=Path(args.scan),
            baseline_path=Path(args.baseline),
            provenance_path=Path(args.provenance),
            repair_transaction_path=Path(args.repair_transaction) if args.repair_transaction else None,
            b42_handoff_path=Path(args.b42_handoff) if args.b42_handoff else None,
            b43_summary_path=Path(args.b43_summary) if args.b43_summary else None,
        ))
        print(json.dumps({
            "passed": result["outcome"] == rr6.OUTCOME_RECOVERED,
            "profile": PROFILE,
            "session_id": result["session_id"],
            "correlation_id": result["correlation_id"],
            "outcome": result["outcome"],
            "certified_recovered": result["certified_recovered"],
            "rr6_invoked": result["rr6_invoked"],
            "summary_sha256": result["summary_sha256"],
            "session_refusal_reasons": result["session_refusal_reasons"],
            "rr6_refusal_reasons": result["rr6_refusal_reasons"],
            "rr6_not_recovered_reasons": result["rr6_not_recovered_reasons"],
        }, indent=2))
        return 0 if result["outcome"] == rr6.OUTCOME_RECOVERED else 3
    except Exception as exc:
        print(json.dumps({
            "passed": False,
            "profile": PROFILE,
            "outcome": rr6.OUTCOME_REFUSED,
            "error": f"{type(exc).__name__}: {exc}",
        }, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
