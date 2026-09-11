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

PROFILE: Final[str] = "v0.11.0-beta.5-b56"
SCENARIO_SCHEMA: Final[str] = "bc-sentinel-beta5-real-pc-scenario-v1"
SUMMARY_SCHEMA: Final[str] = "bc-sentinel-beta5-real-pc-acceptance-summary-v1"

ENV_REAL_HARDWARE: Final[str] = "REAL_HARDWARE"
ENV_CONTROLLED_FIXTURE: Final[str] = "CONTROLLED_OFFLINE_FIXTURE"
ENV_OPERATOR_SUPPLIED: Final[str] = "OPERATOR_SUPPLIED"
ALLOWED_ENVIRONMENTS: Final[frozenset[str]] = frozenset({ENV_REAL_HARDWARE, ENV_CONTROLLED_FIXTURE, ENV_OPERATOR_SUPPLIED})

STATUS_PASS: Final[str] = "PASS"
STATUS_FAIL: Final[str] = "FAIL"
STATUS_REFUSED: Final[str] = "REFUSED"
STATUS_NOT_RUN: Final[str] = "NOT_RUN"
ALLOWED_STATUSES: Final[frozenset[str]] = frozenset({STATUS_PASS, STATUS_FAIL, STATUS_REFUSED, STATUS_NOT_RUN})

SCENARIO_KNOWN_GOOD: Final[str] = "known_good_control"
SCENARIO_DAMAGED: Final[str] = "damaged_offline_windows"
SCENARIO_PERSISTENCE: Final[str] = "persistence_fixture"
SCENARIO_RESOURCE: Final[str] = "resource_constrained"
SCENARIO_LOCKED: Final[str] = "locked_encrypted_refusal"
SCENARIO_RESUME: Final[str] = "interrupted_session_resume"
SCENARIO_PROBLEMATIC: Final[str] = "problematic_pc_optional"

REQUIRED_SCENARIOS: Final[tuple[str, ...]] = (
    SCENARIO_KNOWN_GOOD,
    SCENARIO_DAMAGED,
    SCENARIO_PERSISTENCE,
    SCENARIO_RESOURCE,
    SCENARIO_LOCKED,
    SCENARIO_RESUME,
)
OPTIONAL_SCENARIOS: Final[tuple[str, ...]] = (SCENARIO_PROBLEMATIC,)
ALL_SCENARIOS: Final[frozenset[str]] = frozenset(REQUIRED_SCENARIOS + OPTIONAL_SCENARIOS)

MAX_SCENARIO_FILES: Final[int] = 64
MAX_EVIDENCE_FILE_BYTES: Final[int] = 64 * 1024 * 1024


@dataclass(frozen=True)
class AcceptanceRequest:
    scenarios_dir: Path
    output_path: Path
    require_problematic_pc: bool = False


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def _atomic_json(path: Path, payload: dict) -> None:
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


def _load_json(path: Path, *, label: str) -> tuple[Path, dict, str]:
    original = Path(path)
    if original.is_symlink() or _is_reparse_or_symlink(original):
        raise ValueError(f"{label}_symlink_or_reparse_refused:{original}")
    resolved = original.resolve(strict=True)
    if not resolved.is_file() or _is_reparse_or_symlink(resolved):
        raise ValueError(f"{label}_not_regular_file:{resolved}")
    payload = json.loads(resolved.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label}_json_root_not_object")
    return resolved, payload, _sha256_file(resolved)


def build_scenario_record(
    *,
    scenario_id: str,
    environment_type: str,
    status: str,
    host_fingerprint: str,
    target_fingerprint_before: str,
    target_fingerprint_after: str,
    evidence: list[dict],
    checks: dict,
    refusal_reasons: list[str] | None = None,
    notes: list[str] | None = None,
) -> dict:
    if scenario_id not in ALL_SCENARIOS:
        raise ValueError("unknown_scenario_id")
    if environment_type not in ALLOWED_ENVIRONMENTS:
        raise ValueError("invalid_environment_type")
    if status not in ALLOWED_STATUSES:
        raise ValueError("invalid_status")
    if not _valid_sha256(host_fingerprint):
        raise ValueError("host_fingerprint_invalid")
    for label, value in (("before", target_fingerprint_before), ("after", target_fingerprint_after)):
        if value and not _valid_sha256(value):
            raise ValueError(f"target_fingerprint_{label}_invalid")
    if len(evidence) > MAX_SCENARIO_FILES:
        raise ValueError("evidence_count_limit_exceeded")

    core = {
        "schema": SCENARIO_SCHEMA,
        "profile": PROFILE,
        "scenario_id": scenario_id,
        "environment_type": environment_type,
        "status": status,
        "host_fingerprint": host_fingerprint.casefold(),
        "target_fingerprint_before": target_fingerprint_before.casefold(),
        "target_fingerprint_after": target_fingerprint_after.casefold(),
        "target_unchanged": bool(target_fingerprint_before and target_fingerprint_before == target_fingerprint_after),
        "evidence": evidence,
        "checks": checks,
        "refusal_reasons": list(refusal_reasons or []),
        "notes": list(notes or []),
        "safety": {
            "automatic_destructive_action": False,
            "repair_execution_authority_added": False,
            "quarantine_execution_authority_added": False,
            "format_or_reimage_execution": False,
            "registry_write_authority_added": False,
            "boot_write_authority_added": False,
        },
    }
    scenario_sha = _sha256_bytes(_canonical_json(core))
    return {**core, "created_utc": _utc_now(), "scenario_sha256": scenario_sha}


def _validate_scenario_file(path: Path, *, scenarios_dir: Path) -> dict:
    resolved, payload, file_sha = _load_json(path, label="scenario")
    if payload.get("schema") != SCENARIO_SCHEMA or payload.get("profile") != PROFILE:
        raise ValueError("scenario_profile_or_schema_mismatch")
    scenario_id = str(payload.get("scenario_id") or "")
    if scenario_id not in ALL_SCENARIOS:
        raise ValueError(f"scenario_id_invalid:{scenario_id}")
    if payload.get("environment_type") not in ALLOWED_ENVIRONMENTS:
        raise ValueError(f"environment_type_invalid:{scenario_id}")
    status = str(payload.get("status") or "")
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"status_invalid:{scenario_id}")
    host_fp = str(payload.get("host_fingerprint") or "").casefold()
    if not _valid_sha256(host_fp):
        raise ValueError(f"host_fingerprint_invalid:{scenario_id}")

    expected = str(payload.get("scenario_sha256") or "").casefold()
    if not _valid_sha256(expected):
        raise ValueError(f"scenario_sha256_invalid:{scenario_id}")
    core = dict(payload)
    core.pop("scenario_sha256", None)
    core.pop("created_utc", None)
    actual = _sha256_bytes(_canonical_json(core))
    if actual != expected:
        raise ValueError(f"scenario_sha256_mismatch:{scenario_id}:{actual}")

    before = str(payload.get("target_fingerprint_before") or "").casefold()
    after = str(payload.get("target_fingerprint_after") or "").casefold()
    if before and not _valid_sha256(before):
        raise ValueError(f"target_fingerprint_before_invalid:{scenario_id}")
    if after and not _valid_sha256(after):
        raise ValueError(f"target_fingerprint_after_invalid:{scenario_id}")
    if bool(payload.get("target_unchanged")) != bool(before and before == after):
        raise ValueError(f"target_unchanged_claim_invalid:{scenario_id}")

    safety = payload.get("safety")
    if not isinstance(safety, dict):
        raise ValueError(f"safety_missing:{scenario_id}")
    forbidden_true = (
        "automatic_destructive_action",
        "repair_execution_authority_added",
        "quarantine_execution_authority_added",
        "format_or_reimage_execution",
        "registry_write_authority_added",
        "boot_write_authority_added",
    )
    if any(safety.get(key) is not False for key in forbidden_true):
        raise ValueError(f"safety_contract_invalid:{scenario_id}")

    evidence_rows = payload.get("evidence")
    if not isinstance(evidence_rows, list) or len(evidence_rows) > MAX_SCENARIO_FILES:
        raise ValueError(f"evidence_list_invalid:{scenario_id}")
    verified = 0
    for idx, row in enumerate(evidence_rows):
        if not isinstance(row, dict):
            raise ValueError(f"evidence_record_invalid:{scenario_id}:{idx}")
        raw = Path(str(row.get("path") or ""))
        if not raw.is_absolute():
            raw = scenarios_dir / raw
        if raw.is_symlink() or _is_reparse_or_symlink(raw):
            raise ValueError(f"evidence_reparse_refused:{scenario_id}:{idx}")
        evidence_path = raw.resolve(strict=True)
        if not evidence_path.is_file() or _is_reparse_or_symlink(evidence_path):
            raise ValueError(f"evidence_not_regular:{scenario_id}:{idx}")
        size = evidence_path.stat().st_size
        if size > MAX_EVIDENCE_FILE_BYTES:
            raise ValueError(f"evidence_file_too_large:{scenario_id}:{idx}:{size}")
        expected_sha = str(row.get("sha256") or "").casefold()
        if not _valid_sha256(expected_sha):
            raise ValueError(f"evidence_sha256_invalid:{scenario_id}:{idx}")
        actual_sha = _sha256_file(evidence_path)
        if actual_sha != expected_sha:
            raise ValueError(f"evidence_sha256_mismatch:{scenario_id}:{idx}:{actual_sha}")
        expected_size = int(row.get("size", -1))
        if expected_size != size:
            raise ValueError(f"evidence_size_mismatch:{scenario_id}:{idx}:{size}")
        verified += 1

    checks = payload.get("checks")
    if not isinstance(checks, dict):
        raise ValueError(f"checks_missing:{scenario_id}")
    if status == STATUS_PASS and not checks:
        raise ValueError(f"pass_without_checks:{scenario_id}")
    if status == STATUS_REFUSED and not payload.get("refusal_reasons"):
        raise ValueError(f"refused_without_reason:{scenario_id}")
    if status == STATUS_NOT_RUN and scenario_id in REQUIRED_SCENARIOS:
        raise ValueError(f"required_scenario_not_run:{scenario_id}")

    return {
        "scenario_id": scenario_id,
        "environment_type": payload["environment_type"],
        "status": status,
        "host_fingerprint": host_fp,
        "target_unchanged": bool(payload.get("target_unchanged")),
        "evidence_verified": verified,
        "scenario_sha256": expected,
        "scenario_file_sha256": file_sha,
        "scenario_path": str(resolved),
        "refusal_reasons": list(payload.get("refusal_reasons") or []),
        "notes": list(payload.get("notes") or []),
    }


def build_acceptance_summary(request: AcceptanceRequest) -> dict:
    started = time.perf_counter()
    original_dir = Path(request.scenarios_dir)
    if original_dir.is_symlink() or _is_reparse_or_symlink(original_dir):
        raise ValueError("scenarios_dir_symlink_or_reparse_refused")
    scenarios_dir = original_dir.resolve(strict=True)
    if not scenarios_dir.is_dir() or _is_reparse_or_symlink(scenarios_dir):
        raise ValueError("scenarios_dir_invalid")

    files = sorted(scenarios_dir.glob("*.json"), key=lambda p: p.name.casefold())
    if len(files) > len(ALL_SCENARIOS) + 2:
        raise ValueError("too_many_scenario_files")

    rows: dict[str, dict] = {}
    failures: list[str] = []
    for path in files:
        try:
            row = _validate_scenario_file(path, scenarios_dir=scenarios_dir)
            scenario_id = row["scenario_id"]
            if scenario_id in rows:
                failures.append(f"duplicate_scenario:{scenario_id}")
            else:
                rows[scenario_id] = row
        except Exception as exc:
            failures.append(f"scenario_untrusted:{path.name}:{type(exc).__name__}:{exc}")

    required = list(REQUIRED_SCENARIOS)
    if request.require_problematic_pc:
        required.append(SCENARIO_PROBLEMATIC)
    missing = [scenario for scenario in required if scenario not in rows]
    failures.extend(f"missing_required_scenario:{scenario}" for scenario in missing)

    if SCENARIO_KNOWN_GOOD in rows and rows[SCENARIO_KNOWN_GOOD]["environment_type"] != ENV_REAL_HARDWARE:
        failures.append("known_good_control_must_be_real_hardware")

    for scenario in required:
        row = rows.get(scenario)
        if row is None:
            continue
        if scenario == SCENARIO_LOCKED:
            if row["status"] not in {STATUS_PASS, STATUS_REFUSED}:
                failures.append("locked_scenario_must_pass_or_refuse")
        elif row["status"] != STATUS_PASS:
            failures.append(f"required_scenario_not_pass:{scenario}:{row['status']}")

    known_host = rows.get(SCENARIO_KNOWN_GOOD, {}).get("host_fingerprint", "")
    same_host_controlled = sum(
        1 for row in rows.values()
        if row["environment_type"] in {ENV_REAL_HARDWARE, ENV_CONTROLLED_FIXTURE} and row["host_fingerprint"] == known_host
    ) if known_host else 0
    if known_host and same_host_controlled < 4:
        failures.append(f"insufficient_same_host_controlled_coverage:{same_host_controlled}")

    optional_problematic = rows.get(SCENARIO_PROBLEMATIC)
    problematic_status = optional_problematic["status"] if optional_problematic else STATUS_NOT_RUN

    summary_core = {
        "schema": SUMMARY_SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "required_scenarios": required,
        "scenario_results": [rows[key] for key in sorted(rows)],
        "counts": {
            "records": len(rows),
            "required": len(required),
            "real_hardware": sum(1 for row in rows.values() if row["environment_type"] == ENV_REAL_HARDWARE),
            "controlled_fixture": sum(1 for row in rows.values() if row["environment_type"] == ENV_CONTROLLED_FIXTURE),
            "operator_supplied": sum(1 for row in rows.values() if row["environment_type"] == ENV_OPERATOR_SUPPLIED),
            "same_host_controlled": same_host_controlled,
        },
        "problematic_pc_status": problematic_status,
        "safety": {
            "acceptance_only": True,
            "automatic_destructive_action": False,
            "repair_execution_authority_added": False,
            "quarantine_execution_authority_added": False,
            "format_or_reimage_execution": False,
            "registry_write_authority_added": False,
            "boot_write_authority_added": False,
            "fixture_not_mislabeled_as_real_hardware": True,
        },
    }
    summary_sha = _sha256_bytes(_canonical_json(summary_core))
    result = {
        **summary_core,
        "created_utc": _utc_now(),
        "summary_sha256": summary_sha,
        "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
    }
    _atomic_json(request.output_path, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta5 B5-6 controlled real-PC acceptance validator")
    parser.add_argument("--scenarios-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--require-problematic-pc", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = build_acceptance_summary(AcceptanceRequest(
            scenarios_dir=Path(args.scenarios_dir),
            output_path=Path(args.output),
            require_problematic_pc=bool(args.require_problematic_pc),
        ))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 4
    except Exception as exc:
        print(json.dumps({
            "profile": PROFILE,
            "passed": False,
            "stage": "controlled_real_pc_acceptance",
            "reason": f"{type(exc).__name__}:{exc}",
        }, indent=2, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
