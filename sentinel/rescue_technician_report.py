from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from sentinel import rescue_integrity_certification as rr6
from sentinel import rescue_recovery_decision as b54

PROFILE: Final[str] = "v0.11.0-beta.5-b55"
REPORT_SCHEMA: Final[str] = "bc-sentinel-beta5-technician-report-v1"
MANIFEST_SCHEMA: Final[str] = "bc-sentinel-beta5-evidence-package-manifest-v1"
INDEX_SCHEMA: Final[str] = "bc-sentinel-beta5-evidence-index-v1"

REPORT_JSON = "technician-report.json"
REPORT_MD = "technician-report.md"
EVIDENCE_INDEX_JSON = "evidence-index.json"
MANIFEST_JSON = "package-manifest.json"
EVIDENCE_DIR = "evidence"

MAX_EVIDENCE_FILES: Final[int] = 64
MAX_EVIDENCE_FILE_BYTES: Final[int] = 256 * 1024 * 1024
MAX_PACKAGE_BYTES: Final[int] = 1024 * 1024 * 1024


@dataclass(frozen=True)
class ReportRequest:
    target_root: Path
    decision_path: Path
    package_dir: Path


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


def _refuse_reparse_pre_resolution(path: Path, *, label: str, must_exist: bool) -> Path:
    original = Path(path)
    if original.is_symlink():
        raise ValueError(f"B5-5 {label} symlink/reparse refused before resolution: {original}")
    try:
        st = original.stat(follow_symlinks=False)
        attrs = int(getattr(st, "st_file_attributes", 0) or 0)
        if bool(attrs & int(getattr(os, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))):
            raise ValueError(f"B5-5 {label} symlink/reparse refused before resolution: {original}")
    except FileNotFoundError:
        if must_exist:
            raise
    except ValueError:
        raise
    except OSError as exc:
        if must_exist:
            raise ValueError(f"B5-5 {label} pre-resolution validation failed: {type(exc).__name__}:{exc}") from exc
    return original


def _load_json_file(path: Path, *, label: str) -> tuple[Path, dict, str]:
    original = _refuse_reparse_pre_resolution(Path(path), label=label, must_exist=True)
    resolved = original.resolve(strict=True)
    if not resolved.is_file() or _is_reparse_or_symlink(resolved):
        raise ValueError(f"B5-5 {label} must be regular non-reparse file: {resolved}")
    payload = json.loads(resolved.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"B5-5 {label} JSON root must be object: {resolved}")
    return resolved, payload, _sha256_file(resolved)


def _ensure_outside_target(path: Path, target_root: Path, *, label: str, must_exist: bool) -> Path:
    original = _refuse_reparse_pre_resolution(Path(path), label=label, must_exist=must_exist)
    candidate = original.resolve(strict=must_exist)
    root = Path(target_root).resolve(strict=True)
    try:
        candidate.relative_to(root)
        raise ValueError(f"B5-5 {label} must be outside target")
    except ValueError as exc:
        if str(exc).startswith(f"B5-5 {label}"):
            raise
    return candidate


def _validate_decision(payload: dict) -> None:
    if payload.get("profile") != b54.PROFILE or payload.get("schema") != b54.SCHEMA:
        raise ValueError("decision_profile_or_schema_mismatch")
    state = str(payload.get("state") or "")
    if state not in b54.ALLOWED_STATES:
        raise ValueError("decision_state_invalid")
    expected = str(payload.get("decision_sha256") or "").casefold()
    if not _valid_sha256(expected):
        raise ValueError("decision_sha256_invalid")
    core = dict(payload)
    core.pop("decision_sha256", None)
    core.pop("created_utc", None)
    core.pop("elapsed_ms", None)
    actual = _sha256_bytes(_canonical_json(core))
    if actual != expected:
        raise ValueError(f"decision_sha256_mismatch:{actual}")
    safety = payload.get("safety")
    if not isinstance(safety, dict):
        raise ValueError("decision_safety_missing")
    if safety.get("advisory_only") is not True:
        raise ValueError("decision_not_advisory_only")
    for key in (
        "rr6_outcome_override",
        "automatic_repair",
        "automatic_data_rescue",
        "automatic_reimage",
        "automatic_destructive_action",
        "target_write_authority_added",
        "repair_execution_authority_added",
        "quarantine_execution_authority_added",
    ):
        if safety.get(key) is not False:
            raise ValueError(f"decision_unsafe_flag:{key}")


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        temp.write_text(text, encoding="utf-8", newline="\n")
        os.replace(temp, path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _atomic_json(path: Path, payload: dict) -> None:
    _atomic_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _safe_label(label: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(label))
    return cleaned[:80] or "evidence"


def _copy_verified(source: Path, destination: Path, expected_sha: str) -> tuple[int, str]:
    size = source.stat().st_size
    if size > MAX_EVIDENCE_FILE_BYTES:
        raise ValueError(f"evidence_file_too_large:{source.name}:{size}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=destination.name + ".", suffix=".tmp", dir=str(destination.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        with source.open("rb") as src, temp.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        copied_sha = _sha256_file(temp)
        if copied_sha != expected_sha:
            raise ValueError(f"copied_evidence_sha256_mismatch:{source.name}:{copied_sha}")
        os.replace(temp, destination)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
    return size, expected_sha


def _collect_rescue_detail(payload: dict | None) -> dict:
    if not isinstance(payload, dict):
        return {}
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return {
        "execution_requested": bool(payload.get("execution_requested", False)),
        "manifest_sha256": str(payload.get("manifest_sha256") or ""),
        "manifest_path": str(payload.get("manifest_path") or ""),
        "records": int(summary.get("records", 0) or 0),
        "copied": int(summary.get("copied", 0) or 0),
        "contained": int(summary.get("contained", 0) or 0),
        "skipped": int(summary.get("skipped", 0) or 0),
        "errors": int(summary.get("errors", 0) or 0),
    }


def _human_report(report: dict) -> str:
    reasons = report.get("decision_reasons") or []
    risks = report.get("unresolved_risks") or []
    evidence = report.get("evidence_summary") or {}
    rescue = report.get("data_rescue") or {}
    lines = [
        "# BC Sentinel — Technician Rescue Report",
        "",
        f"- Profile: `{report['profile']}`",
        f"- Generated UTC: {report['created_utc']}",
        f"- Target fingerprint: `{report['target_fingerprint']}`",
        f"- RR-6 outcome: **{report['rr6_outcome']}**",
        f"- Certified recovered: **{str(report['rr6_certified_recovered']).lower()}**",
        f"- B5-4 advisory state: **{report['advisory_state']}**",
        "",
        "## Recommended next action",
        report["next_action"],
        "",
        "## Decision reasons",
    ]
    lines.extend([f"- {item}" for item in reasons] or ["- none"])
    lines.extend(["", "## Unresolved risks / refusals"])
    lines.extend([f"- {item}" for item in risks] or ["- none"])
    lines.extend([
        "",
        "## Evidence",
        f"- Total indexed: {evidence.get('total', 0)}",
        f"- Trusted and copied: {evidence.get('trusted_copied', 0)}",
        f"- Untrusted/not copied: {evidence.get('untrusted_not_copied', 0)}",
        "",
        "## Data rescue",
        f"- Available: {str(bool(report.get('signals', {}).get('data_rescue_available', False))).lower()}",
        f"- Execution requested: {str(bool(rescue.get('execution_requested', False))).lower()}",
        f"- Copied records: {rescue.get('copied', 0)}",
        f"- Contained records: {rescue.get('contained', 0)}",
        f"- Errors: {rescue.get('errors', 0)}",
        f"- Manifest SHA-256: `{rescue.get('manifest_sha256', '')}`",
        "",
        "## Safety",
        "- This report/package is evidence export only.",
        "- It does not execute repair, quarantine, data rescue, format, reimage, registry writes, boot writes, or target code.",
        "- RR-6 certification remains authoritative; B5-4 remains advisory.",
        "",
        f"Report SHA-256: `{report['report_sha256']}`",
        "",
    ])
    return "\n".join(lines)


def create_package(request: ReportRequest) -> dict:
    started = time.perf_counter()
    root = rr6.validate_offline_windows_root(Path(request.target_root))
    fingerprint = rr6.target_fingerprint(root)

    decision_path = _ensure_outside_target(request.decision_path, root, label="decision", must_exist=True)
    decision_path, decision, decision_file_sha = _load_json_file(decision_path, label="decision")
    _validate_decision(decision)
    if str(decision.get("target_fingerprint") or "").casefold() != fingerprint:
        raise ValueError("decision_target_fingerprint_mismatch")

    package = _ensure_outside_target(request.package_dir, root, label="package", must_exist=False)
    if package.exists():
        if not package.is_dir():
            raise ValueError("package_path_exists_not_directory")
        if any(package.iterdir()):
            raise ValueError("package_directory_must_be_empty")
    package.mkdir(parents=True, exist_ok=True)
    if _is_reparse_or_symlink(package):
        raise ValueError("package_directory_reparse_refused")

    evidence_dir = package / EVIDENCE_DIR
    evidence_dir.mkdir()
    evidence_index_in = decision.get("evidence_index")
    if not isinstance(evidence_index_in, dict):
        raise ValueError("decision_evidence_index_missing")
    if len(evidence_index_in) > MAX_EVIDENCE_FILES:
        raise ValueError("decision_evidence_index_too_large")

    rows: list[dict] = []
    total_bytes = 0
    trusted_copied = 0
    untrusted_not_copied = 0
    payload_by_label: dict[str, dict] = {}

    decision_copy = evidence_dir / "b54-decision.json"
    size, copied_sha = _copy_verified(decision_path, decision_copy, decision_file_sha)
    total_bytes += size
    rows.append({
        "label": "b54_decision", "source_path": str(decision_path),
        "package_path": f"{EVIDENCE_DIR}/{decision_copy.name}", "trusted": True,
        "copied": True, "size": size, "sha256": copied_sha, "reason": "validated_b54_decision",
    })
    trusted_copied += 1

    for ordinal, (label, info) in enumerate(sorted(evidence_index_in.items()), start=1):
        if not isinstance(info, dict):
            rows.append({
                "label": str(label), "source_path": "", "package_path": "", "trusted": False,
                "copied": False, "size": 0, "sha256": "", "reason": "invalid_evidence_index_entry",
            })
            untrusted_not_copied += 1
            continue

        trusted = info.get("trusted") is True
        source_text = str(info.get("path") or "")
        expected_sha = str(info.get("file_sha256") or "").casefold()
        if not trusted:
            rows.append({
                "label": str(label), "source_path": source_text, "package_path": "", "trusted": False,
                "copied": False, "size": 0, "sha256": expected_sha if _valid_sha256(expected_sha) else "",
                "reason": "source_marked_untrusted_by_b54",
            })
            untrusted_not_copied += 1
            continue

        if not source_text or not _valid_sha256(expected_sha):
            raise ValueError(f"trusted_evidence_binding_invalid:{label}")
        source = _ensure_outside_target(Path(source_text), root, label=f"evidence:{label}", must_exist=True)
        if source.is_symlink() or not source.is_file() or _is_reparse_or_symlink(source):
            raise ValueError(f"trusted_evidence_not_regular:{label}:{source}")
        actual_sha = _sha256_file(source)
        if actual_sha != expected_sha:
            raise ValueError(f"trusted_evidence_sha256_drift:{label}:{actual_sha}")

        destination_name = f"{ordinal:02d}-{_safe_label(str(label))}.json"
        destination = evidence_dir / destination_name
        size, copied_sha = _copy_verified(source, destination, expected_sha)
        total_bytes += size
        if total_bytes > MAX_PACKAGE_BYTES:
            raise ValueError(f"package_byte_limit_exceeded:{total_bytes}")
        rows.append({
            "label": str(label), "source_path": str(source),
            "package_path": f"{EVIDENCE_DIR}/{destination_name}", "trusted": True,
            "copied": True, "size": size, "sha256": copied_sha, "reason": "sha256_binding_verified",
        })
        trusted_copied += 1
        try:
            parsed = json.loads(source.read_text(encoding="utf-8-sig"))
            if isinstance(parsed, dict):
                payload_by_label[str(label)] = parsed
        except (OSError, UnicodeError, json.JSONDecodeError):
            pass

    unresolved = [str(item) for item in (decision.get("reasons") or [])]
    unresolved.extend(
        f"untrusted_evidence:{row['label']}:{row['reason']}" for row in rows if row["trusted"] is False
    )

    rescue_detail = _collect_rescue_detail(payload_by_label.get("b43_data_rescue"))
    report_core = {
        "schema": REPORT_SCHEMA,
        "profile": PROFILE,
        "target_fingerprint": fingerprint,
        "rr6_outcome": str(decision.get("rr6_outcome") or ""),
        "rr6_certified_recovered": bool(decision.get("rr6_certified_recovered", False)),
        "advisory_state": str(decision.get("state") or ""),
        "decision_reasons": [str(item) for item in (decision.get("reasons") or [])],
        "next_action": str(decision.get("next_action") or ""),
        "signals": dict(decision.get("signals") or {}),
        "unresolved_risks": unresolved,
        "data_rescue": rescue_detail,
        "evidence_summary": {
            "total": len(rows), "trusted_copied": trusted_copied,
            "untrusted_not_copied": untrusted_not_copied, "total_copied_bytes": total_bytes,
        },
        "safety": {
            "report_only": True, "package_outside_target": True, "target_read_only": True,
            "target_execution": False, "repair_execution": False, "quarantine_execution": False,
            "data_rescue_execution": False, "format_or_reimage_execution": False,
            "registry_write": False, "boot_write": False, "automatic_destructive_action": False,
            "new_mutation_authority_added": False,
        },
    }
    report_sha = _sha256_bytes(_canonical_json(report_core))
    report = {
        **report_core, "created_utc": _utc_now(), "report_sha256": report_sha,
        "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
    }

    index_core = {
        "schema": INDEX_SCHEMA, "profile": PROFILE, "target_fingerprint": fingerprint,
        "decision_sha256": str(decision.get("decision_sha256") or ""), "records": rows,
    }
    index_sha = _sha256_bytes(_canonical_json(index_core))
    index_payload = {**index_core, "index_sha256": index_sha}

    _atomic_json(package / REPORT_JSON, report)
    _atomic_text(package / REPORT_MD, _human_report(report))
    _atomic_json(package / EVIDENCE_INDEX_JSON, index_payload)

    package_files = []
    for file_path in sorted((p for p in package.rglob("*") if p.is_file()), key=lambda p: str(p.relative_to(package)).casefold()):
        rel = str(file_path.relative_to(package)).replace("\\", "/")
        package_files.append({"path": rel, "size": file_path.stat().st_size, "sha256": _sha256_file(file_path)})

    manifest_core = {
        "schema": MANIFEST_SCHEMA, "profile": PROFILE, "target_fingerprint": fingerprint,
        "report_sha256": report_sha, "evidence_index_sha256": index_sha,
        "decision_sha256": str(decision.get("decision_sha256") or ""),
        "files": package_files, "safety": report_core["safety"],
    }
    manifest_sha = _sha256_bytes(_canonical_json(manifest_core))
    manifest = {**manifest_core, "created_utc": _utc_now(), "manifest_sha256": manifest_sha}
    _atomic_json(package / MANIFEST_JSON, manifest)

    verification = verify_package(package)
    if not verification["passed"]:
        raise ValueError("package_self_verification_failed:" + ",".join(verification["errors"]))

    return {
        "profile": PROFILE, "package_dir": str(package), "target_fingerprint": fingerprint,
        "report_path": str(package / REPORT_JSON), "human_report_path": str(package / REPORT_MD),
        "evidence_index_path": str(package / EVIDENCE_INDEX_JSON), "manifest_path": str(package / MANIFEST_JSON),
        "report_sha256": report_sha, "evidence_index_sha256": index_sha, "manifest_sha256": manifest_sha,
        "advisory_state": report["advisory_state"], "rr6_outcome": report["rr6_outcome"],
        "evidence_records": len(rows), "trusted_copied": trusted_copied,
        "untrusted_not_copied": untrusted_not_copied, "verification_passed": True,
        "new_mutation_authority_added": False,
    }


def verify_package(package_dir: Path) -> dict:
    try:
        original = _refuse_reparse_pre_resolution(Path(package_dir), label="verify-package", must_exist=True)
        package = original.resolve(strict=True)
    except Exception as exc:
        return {"passed": False, "errors": [f"package_preflight_refused:{type(exc).__name__}:{exc}"], "checked": 0}

    errors: list[str] = []
    if not package.is_dir() or _is_reparse_or_symlink(package):
        return {"passed": False, "errors": ["package_not_real_directory"], "checked": 0}

    manifest_path = package / MANIFEST_JSON
    try:
        _refuse_reparse_pre_resolution(manifest_path, label="manifest", must_exist=True)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        if not isinstance(manifest, dict):
            raise ValueError("manifest_root_not_object")
    except Exception as exc:
        return {"passed": False, "errors": [f"manifest_unreadable:{type(exc).__name__}:{exc}"], "checked": 0}

    if manifest.get("profile") != PROFILE or manifest.get("schema") != MANIFEST_SCHEMA:
        errors.append("manifest_profile_or_schema_mismatch")
    expected_manifest_sha = str(manifest.get("manifest_sha256") or "").casefold()
    core = dict(manifest)
    core.pop("manifest_sha256", None)
    core.pop("created_utc", None)
    actual_manifest_sha = _sha256_bytes(_canonical_json(core))
    if expected_manifest_sha != actual_manifest_sha:
        errors.append("manifest_sha256_mismatch")

    records = manifest.get("files")
    if not isinstance(records, list):
        return {"passed": False, "errors": errors + ["manifest_files_not_list"], "checked": 0}

    checked = 0
    listed_paths: set[str] = set()
    for row in records:
        if not isinstance(row, dict):
            errors.append("manifest_file_record_invalid")
            continue
        rel = str(row.get("path") or "").replace("\\", "/")
        expected_sha = str(row.get("sha256") or "").casefold()
        expected_size = int(row.get("size", -1))
        if not rel or rel.startswith("/") or ".." in Path(rel).parts:
            errors.append(f"manifest_path_invalid:{rel}")
            continue
        if rel == MANIFEST_JSON:
            errors.append("manifest_must_not_self_list")
            continue
        if rel in listed_paths:
            errors.append(f"duplicate_manifest_path:{rel}")
            continue
        listed_paths.add(rel)

        candidate = package / rel
        try:
            _refuse_reparse_pre_resolution(candidate, label=f"manifest-file:{rel}", must_exist=True)
            file_path = candidate.resolve(strict=True)
        except Exception:
            errors.append(f"package_file_missing_or_reparse:{rel}")
            continue
        try:
            file_path.relative_to(package)
        except ValueError:
            errors.append(f"manifest_path_escape:{rel}")
            continue
        if not file_path.is_file() or _is_reparse_or_symlink(file_path):
            errors.append(f"package_file_missing_or_reparse:{rel}")
            continue
        checked += 1
        if file_path.stat().st_size != expected_size:
            errors.append(f"package_file_size_mismatch:{rel}")
        actual_sha = _sha256_file(file_path)
        if actual_sha != expected_sha:
            errors.append(f"package_file_sha256_mismatch:{rel}")

    actual_files: set[str] = set()
    for candidate in package.rglob("*"):
        rel = str(candidate.relative_to(package)).replace("\\", "/")
        if rel == MANIFEST_JSON:
            continue
        if candidate.is_symlink() or _is_reparse_or_symlink(candidate):
            errors.append(f"package_reparse_present:{rel}")
            continue
        if candidate.is_file():
            actual_files.add(rel)

    missing_from_manifest = sorted(actual_files - listed_paths)
    missing_from_package = sorted(listed_paths - actual_files)
    errors.extend(f"unlisted_package_file:{item}" for item in missing_from_manifest)
    errors.extend(f"listed_file_missing:{item}" for item in missing_from_package)

    return {
        "passed": not errors, "errors": errors, "checked": checked,
        "manifest_sha256": expected_manifest_sha,
        "target_fingerprint": str(manifest.get("target_fingerprint") or ""),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta5 B5-5 technician report and evidence package")
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build")
    build.add_argument("--target-root", required=True)
    build.add_argument("--decision", required=True)
    build.add_argument("--package-dir", required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--package-dir", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = create_package(ReportRequest(
                target_root=Path(args.target_root), decision_path=Path(args.decision), package_dir=Path(args.package_dir),
            ))
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        result = verify_package(Path(args.package_dir))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 4
    except Exception as exc:
        print(json.dumps({
            "profile": PROFILE, "passed": False, "stage": "technician_report_package",
            "reason": f"{type(exc).__name__}:{exc}",
        }, indent=2, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
