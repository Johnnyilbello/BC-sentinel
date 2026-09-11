from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

PROFILE: Final[str] = "v0.11.0-beta.3-rr6"
BASELINE_SCHEMA: Final[str] = "bc-sentinel-rr6-critical-baseline-v1"
PROVENANCE_SCHEMA: Final[str] = "bc-sentinel-rr6-provenance-v1"
REPORT_SCHEMA: Final[str] = "bc-sentinel-rr6-certification-report-v1"
RR3_PROFILE: Final[str] = "v0.11.0-beta.3-rr3"
RR4A_PROFILE: Final[str] = "v0.11.0-beta.3-rr4a"

OUTCOME_RECOVERED: Final[str] = "RECOVERED"
OUTCOME_NOT_RECOVERED: Final[str] = "NOT_RECOVERED"
OUTCOME_REFUSED: Final[str] = "INDETERMINATE_REFUSED"

MANDATORY_CRITICAL_PATHS: Final[tuple[str, ...]] = (
    "Windows/System32/ntoskrnl.exe",
    "Windows/System32/config/SYSTEM",
    "Windows/System32/config/SOFTWARE",
)
MANDATORY_HIVE_LABELS: Final[tuple[str, ...]] = ("system:SYSTEM", "system:SOFTWARE")


@dataclass(frozen=True)
class CertificationEvidence:
    scan_path: Path
    baseline_path: Path
    provenance_path: Path
    repair_transaction_path: Path | None = None


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        st = path.stat(follow_symlinks=False)
        attrs = int(getattr(st, "st_file_attributes", 0) or 0)
        reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return bool(attrs & reparse)
    except OSError:
        return True


def validate_offline_windows_root(root: Path) -> Path:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir() or _is_reparse_or_symlink(resolved):
        raise ValueError("RR6 offline target root invalid")
    for rel in MANDATORY_CRITICAL_PATHS:
        path = _resolve_target_path(resolved, rel, require_existing=True)
        if not path.is_file():
            raise ValueError(f"RR6 offline Windows marker missing: {rel}")
    return resolved


def _resolve_target_path(root: Path, relative_path: str, *, require_existing: bool = True) -> Path:
    text = str(relative_path or "").replace("\\", "/").strip("/")
    parts = text.split("/") if text else []
    if not parts or any(part in {"", ".", ".."} for part in parts) or ":" in text:
        raise ValueError("RR6 unsafe target relative path")
    candidate = root.joinpath(*parts)
    root_resolved = root.resolve(strict=True)
    parent = candidate.parent.resolve(strict=True)
    try:
        parent.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError("RR6 target path escapes offline root") from exc
    current = root_resolved
    for part in parts[:-1]:
        current = current / part
        if _is_reparse_or_symlink(current):
            raise ValueError("RR6 symlink/reparse target path refused")
    if require_existing:
        candidate = candidate.resolve(strict=True)
    if candidate.exists() and _is_reparse_or_symlink(candidate):
        raise ValueError("RR6 symlink/reparse target refused")
    return candidate


def target_fingerprint(root: Path) -> str:
    resolved = validate_offline_windows_root(root)
    components = ["BCS-RR6-TARGET-V1"]
    for rel in MANDATORY_CRITICAL_PATHS:
        path = _resolve_target_path(resolved, rel)
        components.append(rel.casefold())
        components.append(str(path.stat().st_size))
        components.append(sha256_file(path))
    return _sha256_bytes("|".join(components).encode("utf-8"))


def _load_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise ValueError(f"RR6 evidence unreadable: {path.name}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"RR6 evidence must be JSON object: {path.name}")
    return payload


def _path_outside_target(path: Path, root: Path) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
        raise ValueError("RR6 evidence/output must be outside offline target")
    except ValueError as exc:
        if str(exc).startswith("RR6 evidence/output"):
            raise
    if _is_reparse_or_symlink(resolved):
        raise ValueError("RR6 evidence symlink/reparse refused")
    return resolved


def _normalize_evidence_path(raw: str, provenance_path: Path) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = provenance_path.parent / candidate
    return candidate.resolve(strict=True)


def _verify_provenance(
    provenance: dict,
    provenance_path: Path,
    root: Path,
    fingerprint: str,
    evidence: CertificationEvidence,
) -> tuple[list[dict], list[str]]:
    reasons: list[str] = []
    checks: list[dict] = []
    if provenance.get("schema") != PROVENANCE_SCHEMA or provenance.get("approved") is not True:
        reasons.append("provenance_schema_or_approval_invalid")
    if str(provenance.get("target_fingerprint") or "").casefold() != fingerprint:
        reasons.append("provenance_target_fingerprint_mismatch")

    entries = provenance.get("evidence")
    if not isinstance(entries, list):
        reasons.append("provenance_evidence_list_missing")
        entries = []
    expected_by_kind: dict[str, dict] = {}
    for item in entries:
        if not isinstance(item, dict):
            reasons.append("provenance_entry_invalid")
            continue
        kind = str(item.get("kind") or "").strip()
        if not kind or kind in expected_by_kind:
            reasons.append("provenance_kind_missing_or_duplicate")
            continue
        expected_by_kind[kind] = item

    supplied: dict[str, Path] = {
        "rr3_scan": evidence.scan_path,
        "critical_baseline": evidence.baseline_path,
    }
    repairs_performed = bool(provenance.get("repairs_performed", False))
    if repairs_performed:
        if evidence.repair_transaction_path is None:
            reasons.append("repair_transaction_required_by_provenance")
        else:
            supplied["repair_transaction"] = evidence.repair_transaction_path
    elif evidence.repair_transaction_path is not None:
        reasons.append("unexpected_repair_transaction_when_provenance_says_none")

    for kind, path in supplied.items():
        entry = expected_by_kind.get(kind)
        if entry is None:
            reasons.append(f"provenance_missing_kind:{kind}")
            continue
        try:
            actual_path = _path_outside_target(path, root)
            declared_path = _normalize_evidence_path(str(entry.get("path") or ""), provenance_path)
            expected_hash = str(entry.get("sha256") or "").casefold()
            actual_hash = sha256_file(actual_path)
            path_match = actual_path == declared_path
            hash_match = len(expected_hash) == 64 and actual_hash == expected_hash
            checks.append({
                "kind": kind,
                "path": str(actual_path),
                "path_match": path_match,
                "expected_sha256": expected_hash,
                "actual_sha256": actual_hash,
                "hash_match": hash_match,
            })
            if not path_match:
                reasons.append(f"provenance_path_mismatch:{kind}")
            if not hash_match:
                reasons.append(f"provenance_hash_mismatch:{kind}")
        except Exception as exc:
            reasons.append(f"provenance_verification_error:{kind}:{type(exc).__name__}")
    return checks, reasons


def _check_scan(scan: dict, root: Path) -> tuple[list[dict], list[str], list[str]]:
    checks: list[dict] = []
    refused: list[str] = []
    not_recovered: list[str] = []
    if str(scan.get("profile") or "") != RR3_PROFILE:
        refused.append("rr3_profile_mismatch")
        return checks, refused, not_recovered
    summary = scan.get("summary")
    if not isinstance(summary, dict):
        refused.append("rr3_summary_missing")
        return checks, refused, not_recovered
    errors = int(summary.get("errors", 0) or 0)
    truncated = bool(summary.get("truncated_by_max_files", False))
    ioc_hits = int(summary.get("ioc_hits", 0) or 0)
    yara_hits = int(summary.get("yara_hits", 0) or 0)
    checks.append({"name": "rr3_scan_complete", "passed": errors == 0 and not truncated, "errors": errors, "truncated": truncated})
    if errors:
        refused.append("rr3_scan_contains_errors")
    if truncated:
        refused.append("rr3_scan_truncated")
    if ioc_hits > 0:
        not_recovered.append("unresolved_deterministic_ioc")
    if yara_hits > 0:
        not_recovered.append("unresolved_yara_match")

    findings = scan.get("findings")
    if not isinstance(findings, list):
        refused.append("rr3_findings_missing")
        findings = []
    unresolved = 0
    for item in findings:
        if not isinstance(item, dict):
            refused.append("rr3_finding_invalid")
            continue
        verdict = str(item.get("verdict") or "")
        if verdict in {"deterministic_ioc", "yara_match"}:
            unresolved += 1
        rel = str(item.get("relative_path") or "")
        digest = str(item.get("sha256") or "").casefold()
        if rel and digest and len(digest) == 64:
            try:
                current = _resolve_target_path(root, rel)
                if current.is_file() and sha256_file(current) != digest:
                    refused.append(f"rr3_evidence_stale:{rel}")
            except Exception:
                refused.append(f"rr3_evidence_path_unverifiable:{rel}")
    if unresolved and ioc_hits + yara_hits == 0:
        not_recovered.append("rr3_unresolved_high_confidence_finding")
    checks.append({"name": "rr3_no_high_confidence_findings", "passed": not not_recovered, "ioc_hits": ioc_hits, "yara_hits": yara_hits, "unresolved_findings": unresolved})

    hives = scan.get("registry_hives")
    if not isinstance(hives, list):
        refused.append("rr3_registry_hive_metadata_missing")
        hives = []
    by_label = {str(item.get("label")): item for item in hives if isinstance(item, dict) and item.get("label")}
    for label in MANDATORY_HIVE_LABELS:
        item = by_label.get(label)
        if item is None:
            refused.append(f"required_hive_metadata_missing:{label}")
            continue
        digest = str(item.get("sha256") or "").casefold()
        if len(digest) != 64:
            refused.append(f"required_hive_hash_missing:{label}")
            continue
        rel = "Windows/System32/config/SYSTEM" if label.endswith("SYSTEM") else "Windows/System32/config/SOFTWARE"
        actual = sha256_file(_resolve_target_path(root, rel))
        if actual != digest:
            refused.append(f"required_hive_hash_mismatch:{label}")
    checks.append({"name": "registry_hive_metadata_complete", "passed": not any(reason.startswith("required_hive_") for reason in refused)})
    return checks, refused, not_recovered


def _check_baseline(baseline: dict, root: Path, fingerprint: str) -> tuple[list[dict], list[str], list[str]]:
    checks: list[dict] = []
    refused: list[str] = []
    not_recovered: list[str] = []
    if baseline.get("schema") != BASELINE_SCHEMA:
        refused.append("critical_baseline_schema_mismatch")
        return checks, refused, not_recovered
    if str(baseline.get("target_fingerprint") or "").casefold() != fingerprint:
        refused.append("critical_baseline_target_fingerprint_mismatch")
    entries = baseline.get("entries")
    if not isinstance(entries, list):
        refused.append("critical_baseline_entries_missing")
        return checks, refused, not_recovered
    by_rel: dict[str, dict] = {}
    for item in entries:
        if not isinstance(item, dict):
            refused.append("critical_baseline_entry_invalid")
            continue
        rel = str(item.get("relative_path") or "").replace("\\", "/").strip("/")
        if not rel or rel.casefold() in by_rel:
            refused.append("critical_baseline_path_missing_or_duplicate")
            continue
        by_rel[rel.casefold()] = item
    for rel in MANDATORY_CRITICAL_PATHS:
        item = by_rel.get(rel.casefold())
        if item is None:
            refused.append(f"critical_baseline_required_path_missing:{rel}")
            continue
        expected = str(item.get("sha256") or "").casefold()
        if len(expected) != 64:
            refused.append(f"critical_baseline_hash_invalid:{rel}")
            continue
        actual = sha256_file(_resolve_target_path(root, rel))
        matched = actual == expected
        checks.append({"name": "critical_file", "relative_path": rel, "expected_sha256": expected, "actual_sha256": actual, "passed": matched})
        if not matched:
            not_recovered.append(f"critical_file_integrity_mismatch:{rel}")
    return checks, refused, not_recovered


def _check_repair_transaction(transaction: dict | None, root: Path, required: bool) -> tuple[list[dict], list[str], list[str]]:
    checks: list[dict] = []
    refused: list[str] = []
    not_recovered: list[str] = []
    if not required:
        checks.append({"name": "repair_transaction", "passed": True, "state": "not_required"})
        return checks, refused, not_recovered
    if transaction is None:
        refused.append("repair_transaction_missing")
        return checks, refused, not_recovered
    if str(transaction.get("profile") or "") != RR4A_PROFILE:
        refused.append("repair_transaction_profile_mismatch")
    state = str(transaction.get("state") or "")
    if state not in {"applied", "rolled_back"}:
        refused.append(f"repair_transaction_untrusted_state:{state or 'missing'}")
        return checks, refused, not_recovered
    operations = transaction.get("operations")
    if not isinstance(operations, list) or not operations:
        refused.append("repair_transaction_operations_missing")
        return checks, refused, not_recovered
    for item in operations:
        if not isinstance(item, dict):
            refused.append("repair_transaction_operation_invalid")
            continue
        rel = str(item.get("relative_path") or "")
        expected_key = "after_sha256" if state == "applied" else "before_sha256"
        expected = str(item.get(expected_key) or "").casefold()
        if len(expected) != 64:
            refused.append(f"repair_transaction_expected_hash_invalid:{rel}")
            continue
        try:
            actual = sha256_file(_resolve_target_path(root, rel))
        except Exception:
            refused.append(f"repair_transaction_target_unverifiable:{rel}")
            continue
        matched = actual == expected
        checks.append({"name": "repair_transaction_file", "relative_path": rel, "state": state, "expected_sha256": expected, "actual_sha256": actual, "passed": matched})
        if not matched:
            not_recovered.append(f"repair_transaction_state_mismatch:{rel}")
    return checks, refused, not_recovered


def certify_recovery(
    target_root: Path,
    evidence: CertificationEvidence,
    output_dir: Path,
) -> dict:
    started = time.perf_counter()
    root = validate_offline_windows_root(target_root)
    output = output_dir.resolve()
    try:
        output.relative_to(root)
        raise ValueError("RR6 evidence/output must be outside offline target")
    except ValueError as exc:
        if str(exc).startswith("RR6 evidence/output"):
            raise
    output.mkdir(parents=True, exist_ok=True)
    if _is_reparse_or_symlink(output):
        raise ValueError("RR6 output symlink/reparse refused")

    scan_path = _path_outside_target(evidence.scan_path, root)
    baseline_path = _path_outside_target(evidence.baseline_path, root)
    provenance_path = _path_outside_target(evidence.provenance_path, root)
    repair_path = _path_outside_target(evidence.repair_transaction_path, root) if evidence.repair_transaction_path else None

    fingerprint = target_fingerprint(root)
    session_id = "RR6-" + fingerprint[:16].upper()
    correlation_id = hashlib.sha256((session_id + "|certification").encode("utf-8")).hexdigest()[:24]
    audit_path = output / "rr6-audit.jsonl"

    def audit(stage: str, status: str, reason: str, **extra: object) -> None:
        row = {
            "profile": PROFILE,
            "session_id": session_id,
            "correlation_id": correlation_id,
            "stage": stage,
            "status": status,
            "reason": reason,
            "utc": _utc_now(),
            **extra,
        }
        with audit_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    audit("certification_start", "ok", "read_only_integrity_assessment_started", target_fingerprint=fingerprint)
    scan = _load_json(scan_path)
    baseline = _load_json(baseline_path)
    provenance = _load_json(provenance_path)
    repair = _load_json(repair_path) if repair_path else None

    checks: list[dict] = []
    refused: list[str] = []
    not_recovered: list[str] = []

    prov_checks, prov_reasons = _verify_provenance(provenance, provenance_path, root, fingerprint, CertificationEvidence(scan_path, baseline_path, provenance_path, repair_path))
    checks.extend({"family": "provenance", **item} for item in prov_checks)
    refused.extend(prov_reasons)
    repairs_performed = bool(provenance.get("repairs_performed", False))

    scan_checks, scan_refused, scan_bad = _check_scan(scan, root)
    checks.extend({"family": "scan", **item} for item in scan_checks)
    refused.extend(scan_refused)
    not_recovered.extend(scan_bad)

    baseline_checks, baseline_refused, baseline_bad = _check_baseline(baseline, root, fingerprint)
    checks.extend({"family": "critical_integrity", **item} for item in baseline_checks)
    refused.extend(baseline_refused)
    not_recovered.extend(baseline_bad)

    repair_checks, repair_refused, repair_bad = _check_repair_transaction(repair, root, repairs_performed)
    checks.extend({"family": "repair", **item} for item in repair_checks)
    refused.extend(repair_refused)
    not_recovered.extend(repair_bad)

    refused = sorted(set(refused))
    not_recovered = sorted(set(not_recovered))
    if not_recovered:
        outcome = OUTCOME_NOT_RECOVERED
        certified = False
        reason = "positive_unresolved_integrity_or_security_problem"
    elif refused:
        outcome = OUTCOME_REFUSED
        certified = False
        reason = "required_trust_evidence_missing_stale_or_unverifiable"
    else:
        outcome = OUTCOME_RECOVERED
        certified = True
        reason = "all_mandatory_independent_integrity_gates_passed"

    report_without_hash = {
        "schema": REPORT_SCHEMA,
        "profile": PROFILE,
        "session_id": session_id,
        "correlation_id": correlation_id,
        "created_utc": _utc_now(),
        "target_fingerprint": fingerprint,
        "outcome": outcome,
        "certified_recovered": certified,
        "reason": reason,
        "refusal_reasons": refused,
        "not_recovered_reasons": not_recovered,
        "checks": checks,
        "evidence": {
            "rr3_scan_sha256": sha256_file(scan_path),
            "critical_baseline_sha256": sha256_file(baseline_path),
            "provenance_sha256": sha256_file(provenance_path),
            "repair_transaction_sha256": sha256_file(repair_path) if repair_path else "",
        },
        "safety": {
            "target_read_only": True,
            "target_execution": False,
            "registry_write": False,
            "boot_write": False,
            "file_delete": False,
            "quarantine_execution": False,
            "repair_execution": False,
            "automatic_destructive_action": False,
            "format_or_reimage_suppressed": False,
        },
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "statement": "Certification is evidence-based. Reimage/format remains appropriate whenever system integrity cannot be demonstrated.",
    }
    report_hash = _sha256_bytes(_canonical_json(report_without_hash))
    report = dict(report_without_hash)
    report["report_sha256"] = report_hash
    report_path = output / "rr6-certification-report.json"
    _atomic_json(report_path, report)
    audit("certification_complete", "ok" if certified else "refused", reason, outcome=outcome, report_sha256=report_hash, refused=len(refused), not_recovered=len(not_recovered))
    return report


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="BC Sentinel RR6 offline integrity certification")
    parser.add_argument("--root", required=True)
    parser.add_argument("--scan", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--provenance", required=True)
    parser.add_argument("--repair-transaction")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        report = certify_recovery(
            Path(args.root),
            CertificationEvidence(
                scan_path=Path(args.scan),
                baseline_path=Path(args.baseline),
                provenance_path=Path(args.provenance),
                repair_transaction_path=Path(args.repair_transaction) if args.repair_transaction else None,
            ),
            Path(args.output),
        )
        print(json.dumps({
            "passed": report["outcome"] == OUTCOME_RECOVERED,
            "profile": PROFILE,
            "outcome": report["outcome"],
            "certified_recovered": report["certified_recovered"],
            "report_sha256": report["report_sha256"],
            "refusal_reasons": report["refusal_reasons"],
            "not_recovered_reasons": report["not_recovered_reasons"],
        }, indent=2))
        return 0 if report["outcome"] == OUTCOME_RECOVERED else 3
    except Exception as exc:
        print(json.dumps({"passed": False, "profile": PROFILE, "outcome": OUTCOME_REFUSED, "error": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
