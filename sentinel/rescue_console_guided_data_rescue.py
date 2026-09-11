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
from sentinel import rescue_data_rescue as rr5
from sentinel import rescue_integrity_certification as rr6

PROFILE: Final[str] = "v0.11.0-beta.4-b43"
PLAN_SCHEMA: Final[str] = "bc-sentinel-beta4-guided-data-rescue-plan-v1"
SUMMARY_SCHEMA: Final[str] = "bc-sentinel-beta4-guided-data-rescue-summary-v1"


@dataclass(frozen=True)
class GuidedDataRescueRequest:
    target_root: Path
    workspace: Path
    existing_scan: Path
    destination: Path
    includes: tuple[str, ...]
    execute_rescue: bool = False
    intel_catalog: Path | None = None
    limits: rr5.RescueLimits = rr5.RescueLimits()


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _outside_target(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    target = root.resolve(strict=True)
    try:
        resolved.relative_to(target)
        raise ValueError("B4-3 destination/output must be outside offline target")
    except ValueError as exc:
        if str(exc).startswith("B4-3 destination/output"):
            raise
    try:
        target.relative_to(resolved)
        raise ValueError("B4-3 destination may not contain offline target")
    except ValueError as exc:
        if str(exc).startswith("B4-3 destination may not contain"):
            raise
    return resolved


def _trusted_scan(root: Path, workspace: Path, scan_path: Path) -> tuple[dict, dict]:
    inventory = b41.inventory_evidence(root, workspace, scan_path)
    record = next(item for item in inventory["records"] if item["kind"] == "rr3_scan")
    if record["trust"] != b41.TRUST_TRUSTED:
        raise ValueError("B4-3 requires trusted RR3 scan evidence: " + ",".join(record["reasons"]))
    payload = json.loads(Path(record["path"]).read_text(encoding="utf-8-sig"))
    return record, payload


def _build_effective_intel(workspace: Path, scan_payload: dict, extra_catalog: Path | None) -> tuple[Path | None, int]:
    entries: dict[str, dict] = {}
    if extra_catalog is not None:
        for digest, meta in rr5.load_approved_intel_catalog(extra_catalog).items():
            entries[digest] = {"value": digest, "name": str(meta.get("name") or "approved_hash_ioc"), "source": str(meta.get("source") or "operator_catalog")}
    for item in scan_payload.get("findings", []):
        if not isinstance(item, dict):
            continue
        verdict = str(item.get("verdict") or "")
        digest = str(item.get("sha256") or "").casefold()
        if verdict not in {"deterministic_ioc", "yara_match"} or len(digest) != 64:
            continue
        entries[digest] = {
            "value": digest,
            "name": str(item.get("ioc_name") or ("B43.TrustedScan." + verdict)),
            "source": "trusted_rr3_scan_b41",
        }
    if not entries:
        return None, 0
    path = workspace / "b43-effective-intel.json"
    _atomic_json(path, {"schema": rr5.INTEL_SCHEMA, "approved": True, "sha256": list(entries.values())})
    return path, len(entries)


def prepare_or_run_guided_data_rescue(request: GuidedDataRescueRequest) -> dict:
    started = time.perf_counter()
    root = rr6.validate_offline_windows_root(request.target_root)
    workspace = b40.validate_workspace(request.workspace, root)
    request.limits.validate()
    if not request.includes:
        raise ValueError("B4-3 requires at least one explicit selection")
    normalized = tuple(rr5._safe_relative_selection(value) for value in request.includes)
    destination = _outside_target(request.destination, root)
    scan_record, scan_payload = _trusted_scan(root, workspace, request.existing_scan)
    fingerprint = rr6.target_fingerprint(root)
    session_id = "B43-" + fingerprint[:16].upper()
    correlation_id = hashlib.sha256((session_id + "|guided-data-rescue").encode("utf-8")).hexdigest()[:24]
    effective_intel, high_confidence_hashes = _build_effective_intel(workspace, scan_payload, request.intel_catalog)

    stable = {
        "schema": PLAN_SCHEMA,
        "profile": PROFILE,
        "target_fingerprint": fingerprint,
        "session_id": session_id,
        "correlation_id": correlation_id,
        "trusted_scan_sha256": scan_record["sha256"],
        "destination": str(destination),
        "includes": list(normalized),
        "limits": {
            "max_files": request.limits.max_files,
            "max_total_bytes": request.limits.max_total_bytes,
            "max_file_bytes": request.limits.max_file_bytes,
            "max_depth": request.limits.max_depth,
        },
        "high_confidence_hashes_for_containment": high_confidence_hashes,
        "automatic_restore": False,
        "automatic_execution": False,
    }
    plan_hash = hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    plan = {**stable, "created_utc": _utc_now(), "plan_sha256": plan_hash}
    plan_path = workspace / "b43-data-rescue-plan.json"
    _atomic_json(plan_path, plan)

    manifest = None
    manifest_path = None
    if request.execute_rescue:
        manifest = rr5.rescue_selected_data(root, destination, list(normalized), limits=request.limits, intel_catalog=effective_intel)
        manifest_path = destination / "rr5-rescue-manifest.json"

    summary = {
        "schema": SUMMARY_SCHEMA,
        "profile": PROFILE,
        "session_id": session_id,
        "correlation_id": correlation_id,
        "target_fingerprint": fingerprint,
        "plan_sha256": plan_hash,
        "plan_path": str(plan_path),
        "trusted_scan_sha256": scan_record["sha256"],
        "explicit_selections": list(normalized),
        "destination": str(destination),
        "execution_requested": bool(request.execute_rescue),
        "operator_action_required": "none" if request.execute_rescue else "confirm_and_run_data_rescue",
        "manifest_path": str(manifest_path) if manifest_path else "",
        "manifest_sha256": _sha256_file(manifest_path) if manifest_path and manifest_path.is_file() else "",
        "rescue_summary": dict(manifest.get("summary", {})) if manifest else {},
        "safety": {
            "source_read_only": True,
            "explicit_selection_required": True,
            "blind_whole_disk_copy": False,
            "active_or_ambiguous_content_contained": True,
            "destination_outside_target": True,
            "automatic_restore": False,
            "repair_execution": False,
            "recovery_certification": False,
        },
        "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
    }
    _atomic_json(workspace / "b43-guided-data-rescue-summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="BC Sentinel Beta4 B4-3 Guided Safe Data Rescue")
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--scan", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--include", action="append", dest="includes", default=[])
    parser.add_argument("--execute-rescue", action="store_true")
    parser.add_argument("--intel-catalog")
    args = parser.parse_args(argv)
    try:
        result = prepare_or_run_guided_data_rescue(GuidedDataRescueRequest(
            Path(args.target_root), Path(args.workspace), Path(args.scan), Path(args.destination), tuple(args.includes), bool(args.execute_rescue), Path(args.intel_catalog) if args.intel_catalog else None
        ))
        print(json.dumps({"passed": True, "profile": PROFILE, "session_id": result["session_id"], "plan_sha256": result["plan_sha256"], "execution_requested": result["execution_requested"], "operator_action_required": result["operator_action_required"], "rescue_summary": result["rescue_summary"]}, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"passed": False, "profile": PROFILE, "stage": "b43_guided_data_rescue", "reason": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
