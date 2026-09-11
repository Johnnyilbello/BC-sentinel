from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

from sentinel import rescue_console as b40
from sentinel import rescue_integrity_certification as rr6
from sentinel import rescue_offline_scanner as rr3

PROFILE: Final[str] = "v0.11.0-beta.4-b41"
INVENTORY_SCHEMA: Final[str] = "bc-sentinel-beta4-evidence-inventory-v1"
SUMMARY_SCHEMA: Final[str] = "bc-sentinel-beta4-guided-scan-summary-v1"
TRUST_TRUSTED: Final[str] = "TRUSTED"
TRUST_UNTRUSTED: Final[str] = "UNTRUSTED"
TRUST_MISSING: Final[str] = "MISSING"


@dataclass(frozen=True)
class GuidedScanRequest:
    target_root: Path
    workspace: Path
    existing_scan: Path | None = None
    reuse_trusted_scan: bool = False
    run_scan: bool = False
    intel_catalog: Path | None = None
    yara_rules: Path | None = None
    max_files: int = rr3.DEFAULT_MAX_FILES
    max_file_bytes: int = rr3.DEFAULT_MAX_FILE_BYTES


@dataclass(frozen=True)
class EvidenceRecord:
    kind: str
    path: str
    exists: bool
    sha256: str
    trust: str
    reasons: tuple[str, ...]
    profile: str = ""

    def to_dict(self) -> dict:
        row = asdict(self)
        row["reasons"] = list(self.reasons)
        return row


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _outside_target(path: Path, root: Path, *, must_exist: bool = False) -> Path:
    resolved = path.resolve(strict=must_exist)
    target = root.resolve(strict=True)
    try:
        resolved.relative_to(target)
        raise ValueError("B4-1 evidence/output must be outside offline target")
    except ValueError as exc:
        if str(exc).startswith("B4-1 evidence/output"):
            raise
    return resolved


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
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, dict):
        raise ValueError("evidence JSON root must be an object")
    return raw


def _normalize_declared_root(raw: object) -> Path | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        return Path(text).resolve(strict=True)
    except OSError:
        return None


def _check_rr3_scan(scan_path: Path, root: Path) -> EvidenceRecord:
    reasons: list[str] = []
    if not scan_path.exists():
        return EvidenceRecord("rr3_scan", str(scan_path), False, "", TRUST_MISSING, ("scan_not_found",))
    try:
        resolved = _outside_target(scan_path, root, must_exist=True)
    except Exception as exc:
        return EvidenceRecord("rr3_scan", str(scan_path), True, "", TRUST_UNTRUSTED, (f"unsafe_scan_path:{type(exc).__name__}",))
    if not resolved.is_file() or _is_reparse_or_symlink(resolved):
        return EvidenceRecord("rr3_scan", str(resolved), True, "", TRUST_UNTRUSTED, ("scan_not_regular_file",))

    digest = ""
    profile = ""
    try:
        digest = _sha256_file(resolved)
        payload = _load_json(resolved)
        profile = str(payload.get("profile") or "")
        if profile != rr3.PROFILE:
            reasons.append("rr3_profile_mismatch")
        if str(payload.get("mode") or "") != "offline_read_only_threat_scan":
            reasons.append("rr3_mode_mismatch")

        declared_root = _normalize_declared_root(payload.get("offline_root"))
        if declared_root is None or declared_root != root.resolve(strict=True):
            reasons.append("rr3_target_root_mismatch")

        summary = payload.get("summary")
        if not isinstance(summary, dict):
            reasons.append("rr3_summary_missing")
        else:
            if int(summary.get("errors", 0) or 0) != 0:
                reasons.append("rr3_scan_contains_errors")
            if bool(summary.get("truncated_by_max_files", False)):
                reasons.append("rr3_scan_truncated")

        safety = payload.get("safety")
        if not isinstance(safety, dict):
            reasons.append("rr3_safety_contract_missing")
        else:
            if safety.get("target_read_only") is not True:
                reasons.append("rr3_target_read_only_not_proven")
            if safety.get("automatic_action") is not False:
                reasons.append("rr3_automatic_action_contract_invalid")
            if safety.get("target_filesystem_write") is not False:
                reasons.append("rr3_target_write_contract_invalid")

        findings = payload.get("findings")
        if not isinstance(findings, list):
            reasons.append("rr3_findings_missing")
            findings = []
        for item in findings:
            if not isinstance(item, dict):
                reasons.append("rr3_finding_invalid")
                continue
            rel = str(item.get("relative_path") or "").replace("\\", "/").strip("/")
            expected = str(item.get("sha256") or "").casefold()
            status = str(item.get("status") or "")
            if status != "hashed" or not rel or len(expected) != 64:
                continue
            try:
                current = root.joinpath(*rel.split("/")).resolve(strict=True)
                current.relative_to(root.resolve(strict=True))
                if not current.is_file() or _is_reparse_or_symlink(current):
                    reasons.append(f"rr3_finding_unverifiable:{rel}")
                elif _sha256_file(current) != expected:
                    reasons.append(f"rr3_finding_stale:{rel}")
            except Exception:
                reasons.append(f"rr3_finding_unverifiable:{rel}")

        hives = payload.get("registry_hives")
        if not isinstance(hives, list):
            reasons.append("rr3_registry_hives_missing")
            hives = []
        by_label = {str(item.get("label")): item for item in hives if isinstance(item, dict) and item.get("label")}
        for label, rel in (
            ("system:SYSTEM", "Windows/System32/config/SYSTEM"),
            ("system:SOFTWARE", "Windows/System32/config/SOFTWARE"),
        ):
            item = by_label.get(label)
            if item is None:
                reasons.append(f"rr3_required_hive_missing:{label}")
                continue
            expected = str(item.get("sha256") or "").casefold()
            if len(expected) != 64:
                reasons.append(f"rr3_required_hive_hash_missing:{label}")
                continue
            actual = _sha256_file(root.joinpath(*rel.split("/")))
            if actual != expected:
                reasons.append(f"rr3_required_hive_stale:{label}")
    except Exception as exc:
        reasons.append(f"rr3_scan_unreadable:{type(exc).__name__}:{exc}")

    unique = tuple(sorted(set(reasons)))
    trust = TRUST_TRUSTED if not unique else TRUST_UNTRUSTED
    return EvidenceRecord("rr3_scan", str(resolved), True, digest, trust, unique, profile)


def inventory_evidence(target_root: Path, workspace: Path, existing_scan: Path | None = None) -> dict:
    root = rr6.validate_offline_windows_root(target_root)
    work = b40.validate_workspace(workspace, root)
    fingerprint = rr6.target_fingerprint(root)
    scan_path = existing_scan if existing_scan is not None else work / "rr3" / "rr3-offline-scan.json"
    scan_record = _check_rr3_scan(scan_path, root)

    plan_path = work / "session-plan.json"
    plan_reasons: list[str] = []
    plan_profile = ""
    plan_hash = ""
    if plan_path.exists():
        try:
            resolved_plan = _outside_target(plan_path, root, must_exist=True)
            plan_hash = _sha256_file(resolved_plan)
            plan = _load_json(resolved_plan)
            plan_profile = str(plan.get("profile") or "")
            if plan.get("schema") != b40.PLAN_SCHEMA:
                plan_reasons.append("b40_plan_schema_mismatch")
            if str(plan.get("target_fingerprint") or "").casefold() != fingerprint:
                plan_reasons.append("b40_plan_target_fingerprint_mismatch")
        except Exception as exc:
            plan_reasons.append(f"b40_plan_unreadable:{type(exc).__name__}:{exc}")
        plan_record = EvidenceRecord(
            "b40_session_plan",
            str(plan_path),
            True,
            plan_hash,
            TRUST_TRUSTED if not plan_reasons else TRUST_UNTRUSTED,
            tuple(sorted(set(plan_reasons))),
            plan_profile,
        )
    else:
        plan_record = EvidenceRecord("b40_session_plan", str(plan_path), False, "", TRUST_MISSING, ("plan_not_found",))

    records = [plan_record, scan_record]
    counts = {
        "records": len(records),
        "trusted": sum(1 for item in records if item.trust == TRUST_TRUSTED),
        "untrusted": sum(1 for item in records if item.trust == TRUST_UNTRUSTED),
        "missing": sum(1 for item in records if item.trust == TRUST_MISSING),
    }
    return {
        "schema": INVENTORY_SCHEMA,
        "profile": PROFILE,
        "created_utc": _utc_now(),
        "target_fingerprint": fingerprint,
        "target_root": str(root),
        "workspace": str(work),
        "records": [item.to_dict() for item in records],
        "counts": counts,
        "trusted_rr3_scan_available": scan_record.trust == TRUST_TRUSTED,
    }


def run_guided_scan(request: GuidedScanRequest) -> dict:
    started = time.perf_counter()
    root = rr6.validate_offline_windows_root(request.target_root)
    workspace = b40.validate_workspace(request.workspace, root)
    plan = b40.build_session_plan(b40.RescueConsoleRequest(root, workspace))
    session_id = "B41-" + plan["target_fingerprint"][:16].upper()
    correlation_id = hashlib.sha256((session_id + "|guided-scan").encode("utf-8")).hexdigest()[:24]
    audit_path = workspace / "b41-audit.jsonl"

    def audit(stage: str, status: str, reason: str, **extra: object) -> None:
        _append_jsonl(
            audit_path,
            {
                "profile": PROFILE,
                "session_id": session_id,
                "correlation_id": correlation_id,
                "target_fingerprint": plan["target_fingerprint"],
                "stage": stage,
                "status": status,
                "reason": reason,
                "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
                **extra,
            },
        )

    audit("evidence_inventory", "start", "inventory_started", workspace=str(workspace))
    inventory = inventory_evidence(root, workspace, request.existing_scan)
    inventory_path = workspace / "b41-evidence-inventory.json"
    _atomic_json(inventory_path, inventory)
    audit("evidence_inventory", "ok", "inventory_completed", **inventory["counts"])

    existing = next(item for item in inventory["records"] if item["kind"] == "rr3_scan")
    scan_source = "none"
    scan_payload: dict | None = None
    scan_path: Path | None = None

    if request.reuse_trusted_scan:
        if existing["trust"] != TRUST_TRUSTED:
            audit(
                "offline_scan",
                "refused",
                "existing_scan_not_trusted_for_reuse",
                trust=existing["trust"],
                reasons=existing["reasons"],
            )
            if not request.run_scan:
                summary = _build_summary(
                    plan,
                    session_id,
                    correlation_id,
                    inventory,
                    scan_source="none",
                    scan_payload=None,
                    scan_path=None,
                    operator_action_required="run_fresh_scan",
                    elapsed_ms=round((time.perf_counter() - started) * 1000.0, 3),
                )
                _atomic_json(workspace / "b41-guided-scan-summary.json", summary)
                return summary
        else:
            scan_path = Path(existing["path"])
            scan_payload = _load_json(scan_path)
            scan_source = "reused_trusted_existing"
            audit(
                "offline_scan",
                "ok",
                "trusted_existing_scan_reused",
                scan_path=str(scan_path),
                scan_sha256=existing["sha256"],
            )

    if scan_payload is None and request.run_scan:
        scan_dir = workspace / "rr3"
        audit(
            "offline_scan",
            "start",
            "operator_requested_fresh_rr3_scan",
            max_files=request.max_files,
            max_file_bytes=request.max_file_bytes,
            scan_output=str(scan_dir),
        )
        scan_started = time.perf_counter()
        try:
            scan_payload = rr3.scan_offline_windows(
                root,
                scan_dir,
                limits=rr3.OfflineScanLimits(request.max_files, request.max_file_bytes),
                intel_catalog=request.intel_catalog,
                yara_rules=request.yara_rules,
            )
            scan_path = scan_dir / "rr3-offline-scan.json"
            scan_source = "fresh_operator_requested"
            summary = scan_payload.get("summary", {})
            audit(
                "offline_scan",
                "ok",
                "fresh_rr3_scan_completed",
                duration_ms=round((time.perf_counter() - scan_started) * 1000.0, 3),
                enumerated=int(summary.get("enumerated", 0) or 0),
                hashed=int(summary.get("hashed", 0) or 0),
                skipped=int(summary.get("skipped", 0) or 0),
                errors=int(summary.get("errors", 0) or 0),
                ioc_hits=int(summary.get("ioc_hits", 0) or 0),
                yara_hits=int(summary.get("yara_hits", 0) or 0),
            )
        except Exception as exc:
            audit(
                "offline_scan",
                "fail",
                f"{type(exc).__name__}: {exc}",
                duration_ms=round((time.perf_counter() - scan_started) * 1000.0, 3),
                normalized_target=str(root),
                normalized_output=str(scan_dir),
            )
            raise

    operator_action_required = "none" if scan_payload is not None else "run_scan_or_supply_trusted_existing_scan"
    result = _build_summary(
        plan,
        session_id,
        correlation_id,
        inventory,
        scan_source=scan_source,
        scan_payload=scan_payload,
        scan_path=scan_path,
        operator_action_required=operator_action_required,
        elapsed_ms=round((time.perf_counter() - started) * 1000.0, 3),
    )
    _atomic_json(workspace / "b41-guided-scan-summary.json", result)
    audit(
        "guided_scan_complete",
        "ok",
        "guided_scan_session_complete",
        scan_source=scan_source,
        operator_action_required=operator_action_required,
        repair_triggered=False,
    )
    return result


def _build_summary(
    plan: dict,
    session_id: str,
    correlation_id: str,
    inventory: dict,
    *,
    scan_source: str,
    scan_payload: dict | None,
    scan_path: Path | None,
    operator_action_required: str,
    elapsed_ms: float,
) -> dict:
    scan_summary = dict(scan_payload.get("summary", {})) if isinstance(scan_payload, dict) else {}
    return {
        "schema": SUMMARY_SCHEMA,
        "profile": PROFILE,
        "created_utc": _utc_now(),
        "session_id": session_id,
        "correlation_id": correlation_id,
        "target_fingerprint": plan["target_fingerprint"],
        "inventory_counts": inventory["counts"],
        "scan": {
            "available": scan_payload is not None,
            "source": scan_source,
            "path": str(scan_path) if scan_path else "",
            "summary": scan_summary,
        },
        "operator_action_required": operator_action_required,
        "repair_triggered": False,
        "quarantine_triggered": False,
        "automatic_execution": False,
        "safety": {
            "target_read_only": True,
            "scan_read_only": True,
            "automatic_repair": False,
            "automatic_quarantine": False,
            "process_kill": False,
            "host_isolation": False,
            "registry_write": False,
            "boot_write": False,
            "file_delete": False,
        },
        "elapsed_ms": elapsed_ms,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="BC Sentinel Beta4 B4-1 Evidence Inventory + Guided RR3 Scan")
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--existing-scan")
    parser.add_argument("--reuse-trusted-scan", action="store_true")
    parser.add_argument("--run-scan", action="store_true")
    parser.add_argument("--intel-catalog")
    parser.add_argument("--yara-rules")
    parser.add_argument("--max-files", type=int, default=rr3.DEFAULT_MAX_FILES)
    parser.add_argument("--max-file-bytes", type=int, default=rr3.DEFAULT_MAX_FILE_BYTES)
    args = parser.parse_args(argv)
    try:
        result = run_guided_scan(
            GuidedScanRequest(
                target_root=Path(args.target_root),
                workspace=Path(args.workspace),
                existing_scan=Path(args.existing_scan) if args.existing_scan else None,
                reuse_trusted_scan=bool(args.reuse_trusted_scan),
                run_scan=bool(args.run_scan),
                intel_catalog=Path(args.intel_catalog) if args.intel_catalog else None,
                yara_rules=Path(args.yara_rules) if args.yara_rules else None,
                max_files=args.max_files,
                max_file_bytes=args.max_file_bytes,
            )
        )
        print(json.dumps({
            "passed": True,
            "profile": PROFILE,
            "session_id": result["session_id"],
            "correlation_id": result["correlation_id"],
            "target_fingerprint": result["target_fingerprint"],
            "scan_source": result["scan"]["source"],
            "scan_available": result["scan"]["available"],
            "operator_action_required": result["operator_action_required"],
            "repair_triggered": False,
        }, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({
            "passed": False,
            "profile": PROFILE,
            "stage": "b41_guided_scan",
            "reason": f"{type(exc).__name__}: {exc}",
        }, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
