from __future__ import annotations

"""B10-6 Reversible Response Pilot.

Provide one deliberately narrow response action: reversible quarantine of a
single regular file inside an explicitly initialized disposable pilot workspace.
The pilot requires exact operator confirmation, binds authority to one target
hash, writes a tamper-evident local journal, and supports rollback.

This milestone does not grant broad Home execution, automatic remediation,
delete, repair, process termination, trust/allowlist mutation, privileged
mutation, rescue mutation, or execution outside the disposable workspace.
"""

import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, Final

from sentinel import beta10_safe_response_plan as safe_response

SCHEMA: Final[str] = "bc-sentinel-beta10-reversible-response-pilot-v1"
TICKET_SCHEMA: Final[str] = "bc-sentinel-beta10-reversible-response-ticket-v1"
JOURNAL_SCHEMA: Final[str] = "bc-sentinel-beta10-reversible-response-journal-v1"
PROFILE: Final[str] = "v0.11.0-beta.10-b106-reversible-response-pilot"

SOURCE_PREDECESSOR_BRANCH: Final[str] = "feature/v011-beta10-b105-rescue-continuity"
SOURCE_PREDECESSOR_COMMIT: Final[str] = "259fdbf988e442366f0deb3a07b3de248cf309ba"
CURRENT_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}

PILOT_ACTION: Final[str] = "QUARANTINE_SINGLE_FILE_REVERSIBLY"
PILOT_SCOPE: Final[str] = "DISPOSABLE_TEMP_WORKSPACE_ONLY"
WORKSPACE_PREFIX: Final[str] = "BCSentinel-b106-pilot-"
MARKER_NAME: Final[str] = ".bc-sentinel-b106-pilot.json"
QUARANTINE_DIR: Final[str] = ".quarantine"
JOURNAL_DIR: Final[str] = ".journal"
JOURNAL_NAME: Final[str] = "response-journal.jsonl"
MAX_TARGET_BYTES: Final[int] = 8 * 1024 * 1024

AUTHORIZE_QUARANTINE: Final[str] = "AUTHORIZE_B10_6_REVERSIBLE_QUARANTINE"
AUTHORIZE_ROLLBACK: Final[str] = "AUTHORIZE_B10_6_ROLLBACK"

AUTHORITY_BOUNDARY: Final[dict[str, bool]] = {
    "pilot_quarantine_authority": True,
    "pilot_rollback_authority": True,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "delete_authority": False,
    "repair_authority": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "general_home_execution": False,
    "rescue_write_authority": False,
    "outside_disposable_workspace_execution": False,
}

PRIVACY_BOUNDARY: Final[dict[str, bool]] = {
    "local_only": True,
    "personal_data_collected": False,
    "file_content_exported": False,
    "absolute_paths_exported": False,
    "remote_access": False,
    "network_required": False,
    "cloud_required": False,
}

_TICKET_CORE_KEYS: Final[tuple[str, ...]] = (
    "schema",
    "profile",
    "action",
    "scope",
    "incident_id",
    "source_plan_id",
    "source_plan_digest",
    "workspace_id",
    "target_relative_path",
    "target_sha256",
    "target_size",
    "target_binding_id",
    "operator_confirmation_required",
    "rollback_required",
    "automatic",
    "authority_expanded",
    "authority_boundary",
    "privacy",
)

_MARKER_CORE_KEYS: Final[tuple[str, ...]] = (
    "schema",
    "profile",
    "workspace_id",
    "scope",
    "authority_boundary",
    "privacy",
)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _ticket_core(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: payload.get(key) for key in _TICKET_CORE_KEYS}


def _marker_core(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: payload.get(key) for key in _MARKER_CORE_KEYS}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _temp_root() -> Path:
    return Path(tempfile.gettempdir()).resolve()


def _normalize_workspace(root: str | os.PathLike[str]) -> Path:
    path = Path(root).expanduser().resolve()
    temp_root = _temp_root()
    if not _is_relative_to(path, temp_root):
        raise ValueError("b106:workspace_must_be_under_system_temp")
    if not path.name.startswith(WORKSPACE_PREFIX):
        raise ValueError("b106:workspace_prefix_required")
    return path


def initialize_pilot_workspace(
    root: str | os.PathLike[str],
    *,
    operator_confirmed: bool,
) -> dict[str, Any]:
    if operator_confirmed is not True:
        raise PermissionError("b106:workspace_initialization_confirmation_required")
    workspace = _normalize_workspace(root)
    workspace.mkdir(parents=True, exist_ok=False)
    (workspace / QUARANTINE_DIR).mkdir()
    (workspace / JOURNAL_DIR).mkdir()

    marker: dict[str, Any] = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "workspace_id": "b106-workspace:" + uuid.uuid4().hex,
        "scope": PILOT_SCOPE,
        "authority_boundary": dict(AUTHORITY_BOUNDARY),
        "privacy": dict(PRIVACY_BOUNDARY),
    }
    marker["marker_digest"] = _digest(_marker_core(marker))
    (workspace / MARKER_NAME).write_text(
        json.dumps(marker, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return marker


def _read_marker(workspace: Path) -> dict[str, Any]:
    marker_path = workspace / MARKER_NAME
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("b106:workspace_marker_invalid") from exc
    if not isinstance(marker, dict):
        raise ValueError("b106:workspace_marker_invalid")
    if marker.get("schema") != SCHEMA or marker.get("profile") != PROFILE:
        raise ValueError("b106:workspace_marker_schema_invalid")
    if marker.get("scope") != PILOT_SCOPE:
        raise ValueError("b106:workspace_marker_scope_invalid")
    if marker.get("authority_boundary") != AUTHORITY_BOUNDARY:
        raise ValueError("b106:workspace_marker_authority_invalid")
    if marker.get("privacy") != PRIVACY_BOUNDARY:
        raise ValueError("b106:workspace_marker_privacy_invalid")
    if marker.get("marker_digest") != _digest(_marker_core(marker)):
        raise ValueError("b106:workspace_marker_digest_invalid")
    workspace_id = str(marker.get("workspace_id") or "")
    if not workspace_id.startswith("b106-workspace:"):
        raise ValueError("b106:workspace_id_invalid")
    return marker


def validate_workspace(root: str | os.PathLike[str]) -> dict[str, Any]:
    try:
        workspace = _normalize_workspace(root)
        if not workspace.is_dir() or workspace.is_symlink():
            raise ValueError("b106:workspace_not_directory")
        marker = _read_marker(workspace)
        for name in (QUARANTINE_DIR, JOURNAL_DIR):
            child = workspace / name
            if not child.is_dir() or child.is_symlink():
                raise ValueError(f"b106:workspace_child_invalid:{name}")
    except (OSError, ValueError) as exc:
        return {"passed": False, "failures": [str(exc)]}
    return {
        "passed": True,
        "failures": [],
        "workspace_id": marker["workspace_id"],
        "scope": marker["scope"],
    }


def _normalize_relative_target(relative_path: str) -> Path:
    candidate = Path(relative_path)
    if candidate.is_absolute() or not relative_path or relative_path.strip() != relative_path:
        raise ValueError("b106:target_relative_path_invalid")
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError("b106:target_relative_path_invalid")
    if candidate.parts[0] in {QUARANTINE_DIR, JOURNAL_DIR, MARKER_NAME}:
        raise ValueError("b106:target_reserved_path")
    return candidate


def _resolve_target(workspace: Path, relative_path: str) -> Path:
    relative = _normalize_relative_target(relative_path)
    target = (workspace / relative).resolve(strict=True)
    if not _is_relative_to(target, workspace):
        raise ValueError("b106:target_escapes_workspace")
    if target.is_symlink() or not target.is_file():
        raise ValueError("b106:target_must_be_regular_file")
    size = target.stat().st_size
    if size < 0 or size > MAX_TARGET_BYTES:
        raise ValueError("b106:target_size_out_of_bounds")
    return target


def _require_source_plan(plan: object) -> dict[str, Any]:
    validation = safe_response.validate_response_plan(plan)
    if not validation.get("passed"):
        failures = ",".join(validation.get("failures", []))
        raise ValueError("b106:source_plan_invalid:" + failures)
    assert isinstance(plan, dict)
    containment = [
        row
        for row in plan.get("actions", [])
        if isinstance(row, dict) and row.get("action_id") == "PREPARE_CONTAINMENT"
    ]
    if len(containment) != 1:
        raise ValueError("b106:source_containment_action_required")
    action = containment[0]
    if action.get("state") != safe_response.ACTION_BLOCKED_AUTHORITY:
        raise ValueError("b106:source_containment_state_invalid")
    if action.get("rollback_required") is not True:
        raise ValueError("b106:source_rollback_requirement_missing")
    if action.get("user_confirmation_required") is not True:
        raise ValueError("b106:source_confirmation_requirement_missing")
    if action.get("would_mutate_system_if_executed") is not True:
        raise ValueError("b106:source_mutation_intent_missing")
    return plan


def build_authorization_ticket(
    source_plan: dict[str, Any],
    workspace_root: str | os.PathLike[str],
    target_relative_path: str,
    *,
    authorization_phrase: str,
) -> dict[str, Any]:
    if authorization_phrase != AUTHORIZE_QUARANTINE:
        raise PermissionError("b106:quarantine_authorization_phrase_invalid")
    plan = _require_source_plan(source_plan)
    workspace = _normalize_workspace(workspace_root)
    workspace_validation = validate_workspace(workspace)
    if not workspace_validation["passed"]:
        raise ValueError("b106:workspace_invalid:" + ",".join(workspace_validation["failures"]))
    marker = _read_marker(workspace)
    target = _resolve_target(workspace, target_relative_path)

    target_size = target.stat().st_size
    target_sha256 = _sha256_file(target)
    relative = target.relative_to(workspace).as_posix()
    binding_material = {
        "workspace_id": marker["workspace_id"],
        "relative_path": relative,
        "sha256": target_sha256,
        "size": target_size,
    }
    ticket: dict[str, Any] = {
        "schema": TICKET_SCHEMA,
        "profile": PROFILE,
        "action": PILOT_ACTION,
        "scope": PILOT_SCOPE,
        "incident_id": plan["incident_id"],
        "source_plan_id": plan["plan_id"],
        "source_plan_digest": plan["plan_digest"],
        "workspace_id": marker["workspace_id"],
        "target_relative_path": relative,
        "target_sha256": target_sha256,
        "target_size": target_size,
        "target_binding_id": "b106-target:" + _digest(binding_material)[:24],
        "operator_confirmation_required": True,
        "rollback_required": True,
        "automatic": False,
        "authority_expanded": True,
        "authority_boundary": dict(AUTHORITY_BOUNDARY),
        "privacy": dict(PRIVACY_BOUNDARY),
    }
    ticket["ticket_digest"] = _digest(_ticket_core(ticket))
    validation = validate_authorization_ticket(ticket)
    if not validation["passed"]:
        raise RuntimeError("b106:generated_ticket_invalid:" + ",".join(validation["failures"]))
    return ticket


def validate_authorization_ticket(payload: object) -> dict[str, Any]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return {"passed": False, "failures": ["b106:ticket_not_object"]}
    if payload.get("schema") != TICKET_SCHEMA or payload.get("profile") != PROFILE:
        failures.append("b106:ticket_schema_or_profile_invalid")
    if payload.get("action") != PILOT_ACTION or payload.get("scope") != PILOT_SCOPE:
        failures.append("b106:ticket_scope_invalid")
    if payload.get("operator_confirmation_required") is not True:
        failures.append("b106:ticket_confirmation_required")
    if payload.get("rollback_required") is not True:
        failures.append("b106:ticket_rollback_required")
    if payload.get("automatic") is not False:
        failures.append("b106:ticket_automatic_forbidden")
    if payload.get("authority_expanded") is not True:
        failures.append("b106:ticket_narrow_authority_expansion_required")
    if payload.get("authority_boundary") != AUTHORITY_BOUNDARY:
        failures.append("b106:ticket_authority_boundary_invalid")
    if payload.get("privacy") != PRIVACY_BOUNDARY:
        failures.append("b106:ticket_privacy_boundary_invalid")
    if not str(payload.get("workspace_id") or "").startswith("b106-workspace:"):
        failures.append("b106:ticket_workspace_id_invalid")
    try:
        relative = _normalize_relative_target(str(payload.get("target_relative_path") or ""))
        if relative.as_posix() != payload.get("target_relative_path"):
            failures.append("b106:ticket_target_relative_path_noncanonical")
    except ValueError:
        failures.append("b106:ticket_target_relative_path_invalid")
    digest_text = str(payload.get("target_sha256") or "")
    if len(digest_text) != 64 or any(ch not in "0123456789abcdef" for ch in digest_text):
        failures.append("b106:ticket_target_digest_invalid")
    try:
        size = int(payload.get("target_size"))
        if size < 0 or size > MAX_TARGET_BYTES:
            failures.append("b106:ticket_target_size_invalid")
    except (TypeError, ValueError):
        failures.append("b106:ticket_target_size_invalid")
    if payload.get("ticket_digest") != _digest(_ticket_core(payload)):
        failures.append("b106:ticket_digest_invalid")
    binding_material = {
        "workspace_id": payload.get("workspace_id"),
        "relative_path": payload.get("target_relative_path"),
        "sha256": payload.get("target_sha256"),
        "size": payload.get("target_size"),
    }
    expected_binding = "b106-target:" + _digest(binding_material)[:24]
    if payload.get("target_binding_id") != expected_binding:
        failures.append("b106:ticket_target_binding_invalid")
    return {"passed": not failures, "failures": failures}


def _journal_path(workspace: Path) -> Path:
    return workspace / JOURNAL_DIR / JOURNAL_NAME


def _load_journal(workspace: Path) -> list[dict[str, Any]]:
    path = _journal_path(workspace)
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    previous_digest = ""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("b106:journal_read_failed") from exc
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            raise ValueError(f"b106:journal_blank_record:{index}")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"b106:journal_json_invalid:{index}") from exc
        if not isinstance(record, dict) or record.get("schema") != JOURNAL_SCHEMA:
            raise ValueError(f"b106:journal_record_invalid:{index}")
        if record.get("sequence") != index:
            raise ValueError(f"b106:journal_sequence_invalid:{index}")
        if record.get("previous_digest") != previous_digest:
            raise ValueError(f"b106:journal_chain_invalid:{index}")
        core = {k: v for k, v in record.items() if k != "record_digest"}
        expected = _digest(core)
        if record.get("record_digest") != expected:
            raise ValueError(f"b106:journal_digest_invalid:{index}")
        previous_digest = expected
        records.append(record)
    return records


def _append_journal(workspace: Path, record: dict[str, Any]) -> dict[str, Any]:
    records = _load_journal(workspace)
    payload = dict(record)
    payload["schema"] = JOURNAL_SCHEMA
    payload["sequence"] = len(records) + 1
    payload["previous_digest"] = records[-1]["record_digest"] if records else ""
    payload["record_digest"] = _digest(payload)
    line = json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n"
    path = _journal_path(workspace)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
    return payload


def _ticket_matches_workspace(ticket: dict[str, Any], workspace: Path) -> dict[str, Any]:
    validation = validate_authorization_ticket(ticket)
    if not validation["passed"]:
        raise ValueError("b106:ticket_invalid:" + ",".join(validation["failures"]))
    marker = _read_marker(workspace)
    if ticket.get("workspace_id") != marker.get("workspace_id"):
        raise ValueError("b106:ticket_workspace_mismatch")
    return marker


def execute_reversible_quarantine(
    ticket: dict[str, Any],
    workspace_root: str | os.PathLike[str],
    *,
    authorization_phrase: str,
) -> dict[str, Any]:
    if authorization_phrase != AUTHORIZE_QUARANTINE:
        raise PermissionError("b106:quarantine_authorization_phrase_invalid")
    workspace = _normalize_workspace(workspace_root)
    workspace_validation = validate_workspace(workspace)
    if not workspace_validation["passed"]:
        raise ValueError("b106:workspace_invalid:" + ",".join(workspace_validation["failures"]))
    _ticket_matches_workspace(ticket, workspace)

    target = _resolve_target(workspace, str(ticket["target_relative_path"]))
    current_size = target.stat().st_size
    current_hash = _sha256_file(target)
    if current_size != int(ticket["target_size"]) or current_hash != ticket["target_sha256"]:
        raise ValueError("b106:target_binding_changed")

    quarantine_name = f"{ticket['target_binding_id'].split(':', 1)[1]}.bin"
    quarantine_path = workspace / QUARANTINE_DIR / quarantine_name
    if quarantine_path.exists():
        raise ValueError("b106:quarantine_destination_exists")

    transaction_id = "b106-tx:" + uuid.uuid4().hex
    base_record = {
        "transaction_id": transaction_id,
        "ticket_digest": ticket["ticket_digest"],
        "target_binding_id": ticket["target_binding_id"],
        "original_relative_path": ticket["target_relative_path"],
        "quarantine_relative_path": f"{QUARANTINE_DIR}/{quarantine_name}",
        "target_sha256": ticket["target_sha256"],
        "target_size": ticket["target_size"],
    }
    _append_journal(workspace, {**base_record, "event": "QUARANTINE_PREPARED"})
    os.replace(target, quarantine_path)
    moved_hash = _sha256_file(quarantine_path)
    if moved_hash != ticket["target_sha256"]:
        raise RuntimeError("b106:quarantine_post_move_hash_mismatch")
    _append_journal(workspace, {**base_record, "event": "QUARANTINE_COMMITTED"})

    return {
        "passed": True,
        "profile": PROFILE,
        "action": PILOT_ACTION,
        "transaction_id": transaction_id,
        "target_binding_id": ticket["target_binding_id"],
        "quarantined": True,
        "rollback_available": True,
        "automatic": False,
        "pilot_response_action_observed": True,
        "source_response_stage_claimed_observed": False,
        "broad_remediation_claimed": False,
        "authority_expanded": True,
        "scope": PILOT_SCOPE,
        "coverage_summary": dict(CURRENT_COVERAGE),
    }


def _transaction_records(workspace: Path, transaction_id: str) -> list[dict[str, Any]]:
    return [row for row in _load_journal(workspace) if row.get("transaction_id") == transaction_id]


def rollback_reversible_quarantine(
    ticket: dict[str, Any],
    workspace_root: str | os.PathLike[str],
    transaction_id: str,
    *,
    authorization_phrase: str,
) -> dict[str, Any]:
    if authorization_phrase != AUTHORIZE_ROLLBACK:
        raise PermissionError("b106:rollback_authorization_phrase_invalid")
    workspace = _normalize_workspace(workspace_root)
    workspace_validation = validate_workspace(workspace)
    if not workspace_validation["passed"]:
        raise ValueError("b106:workspace_invalid:" + ",".join(workspace_validation["failures"]))
    _ticket_matches_workspace(ticket, workspace)

    records = _transaction_records(workspace, transaction_id)
    events = [str(row.get("event") or "") for row in records]
    if events != ["QUARANTINE_PREPARED", "QUARANTINE_COMMITTED"]:
        raise ValueError("b106:transaction_not_rollback_ready")
    committed = records[-1]
    if committed.get("ticket_digest") != ticket.get("ticket_digest"):
        raise ValueError("b106:transaction_ticket_mismatch")
    if committed.get("target_binding_id") != ticket.get("target_binding_id"):
        raise ValueError("b106:transaction_target_binding_mismatch")

    quarantine_path = (workspace / str(committed["quarantine_relative_path"])).resolve(strict=True)
    if not _is_relative_to(quarantine_path, (workspace / QUARANTINE_DIR).resolve()):
        raise ValueError("b106:quarantine_path_invalid")
    if quarantine_path.is_symlink() or not quarantine_path.is_file():
        raise ValueError("b106:quarantine_object_invalid")
    if _sha256_file(quarantine_path) != ticket["target_sha256"]:
        raise ValueError("b106:quarantine_content_changed")

    original_relative = _normalize_relative_target(str(committed["original_relative_path"]))
    original_path = (workspace / original_relative).resolve(strict=False)
    if not _is_relative_to(original_path, workspace):
        raise ValueError("b106:rollback_target_escapes_workspace")
    if original_path.exists():
        raise ValueError("b106:rollback_destination_occupied")
    original_path.parent.mkdir(parents=True, exist_ok=True)

    base_record = {
        "transaction_id": transaction_id,
        "ticket_digest": ticket["ticket_digest"],
        "target_binding_id": ticket["target_binding_id"],
        "original_relative_path": committed["original_relative_path"],
        "quarantine_relative_path": committed["quarantine_relative_path"],
        "target_sha256": ticket["target_sha256"],
        "target_size": ticket["target_size"],
    }
    _append_journal(workspace, {**base_record, "event": "ROLLBACK_PREPARED"})
    os.replace(quarantine_path, original_path)
    restored_hash = _sha256_file(original_path)
    if restored_hash != ticket["target_sha256"]:
        raise RuntimeError("b106:rollback_post_move_hash_mismatch")
    _append_journal(workspace, {**base_record, "event": "ROLLED_BACK"})

    return {
        "passed": True,
        "profile": PROFILE,
        "action": PILOT_ACTION,
        "transaction_id": transaction_id,
        "target_binding_id": ticket["target_binding_id"],
        "quarantined": False,
        "rolled_back": True,
        "restored_sha256": restored_hash,
        "automatic": False,
        "pilot_response_action_observed": True,
        "source_response_stage_claimed_observed": False,
        "broad_remediation_claimed": False,
        "authority_expanded": True,
        "scope": PILOT_SCOPE,
        "coverage_summary": dict(CURRENT_COVERAGE),
    }


def inspect_transaction(
    workspace_root: str | os.PathLike[str],
    transaction_id: str,
) -> dict[str, Any]:
    workspace = _normalize_workspace(workspace_root)
    validation = validate_workspace(workspace)
    if not validation["passed"]:
        return {"passed": False, "failures": validation["failures"]}
    try:
        records = _transaction_records(workspace, transaction_id)
    except ValueError as exc:
        return {"passed": False, "failures": [str(exc)]}
    events = [str(row.get("event") or "") for row in records]
    allowed = {
        (): "MISSING",
        ("QUARANTINE_PREPARED",): "PREPARED_ONLY",
        ("QUARANTINE_PREPARED", "QUARANTINE_COMMITTED"): "QUARANTINED",
        (
            "QUARANTINE_PREPARED",
            "QUARANTINE_COMMITTED",
            "ROLLBACK_PREPARED",
        ): "ROLLBACK_PREPARED_ONLY",
        (
            "QUARANTINE_PREPARED",
            "QUARANTINE_COMMITTED",
            "ROLLBACK_PREPARED",
            "ROLLED_BACK",
        ): "ROLLED_BACK",
    }
    state = allowed.get(tuple(events))
    if state is None:
        return {"passed": False, "failures": ["b106:transaction_event_sequence_invalid"], "events": events}
    return {
        "passed": True,
        "transaction_id": transaction_id,
        "state": state,
        "events": events,
        "journal_record_count": len(records),
    }


def validate_b106_contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": True,
        "source_predecessor_branch": SOURCE_PREDECESSOR_BRANCH,
        "source_predecessor_commit": SOURCE_PREDECESSOR_COMMIT,
        "action": PILOT_ACTION,
        "scope": PILOT_SCOPE,
        "explicit_operator_confirmation_required": True,
        "target_identity_binding_required": True,
        "journal_required": True,
        "rollback_required": True,
        "automatic_action": False,
        "broad_home_execution": False,
        "delete_authority": False,
        "repair_authority": False,
        "terminate_process_authority": False,
        "privileged_system_mutation": False,
        "rescue_write_authority": False,
        "outside_disposable_workspace_execution": False,
        "pilot_quarantine_authority": True,
        "pilot_rollback_authority": True,
        "authority_expanded": True,
        "broad_remediation_claimed": False,
        "coverage_summary": dict(CURRENT_COVERAGE),
        "privacy": dict(PRIVACY_BOUNDARY),
    }
