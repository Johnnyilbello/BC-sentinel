from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Final

from sentinel import rescue_integrity_certification as rr6

PROFILE: Final[str] = "v0.11.0-beta.5-b53"
JOURNAL_SCHEMA: Final[str] = "bc-sentinel-beta5-session-journal-v1"
RESUME_SCHEMA: Final[str] = "bc-sentinel-beta5-resume-decision-v1"

STATE_PLANNED: Final[str] = "PLANNED"
STATE_STARTED: Final[str] = "STARTED"
STATE_COMPLETED: Final[str] = "COMPLETED"
STATE_REFUSED: Final[str] = "REFUSED"
STATE_ROLLED_BACK: Final[str] = "ROLLED_BACK"
STATE_INTERRUPTED: Final[str] = "INTERRUPTED"
EVENT_STATES: Final[frozenset[str]] = frozenset({
    STATE_PLANNED,
    STATE_STARTED,
    STATE_COMPLETED,
    STATE_REFUSED,
    STATE_ROLLED_BACK,
    STATE_INTERRUPTED,
})

READ_ONLY_RESUMABLE_STAGES: Final[frozenset[str]] = frozenset({
    "target_validation",
    "evidence_inventory",
    "offline_scan",
    "health_assessment",
    "stress_probe",
    "integrity_certification",
})

OPERATOR_GATED_STAGES: Final[frozenset[str]] = frozenset({
    "repair_handoff",
    "repair_execute",
    "repair_rollback",
    "data_rescue",
})

ALL_STAGES: Final[frozenset[str]] = READ_ONLY_RESUMABLE_STAGES | OPERATOR_GATED_STAGES

TERMINAL_STATES: Final[frozenset[str]] = frozenset({STATE_COMPLETED, STATE_REFUSED, STATE_ROLLED_BACK})
RESUMABLE_STATES: Final[frozenset[str]] = frozenset({STATE_PLANNED, STATE_STARTED, STATE_INTERRUPTED})


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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


def _validate_real_directory_before_resolution(path: Path, *, label: str) -> Path:
    original = Path(path)
    try:
        if original.is_symlink():
            raise ValueError(f"B5-3 {label} symlink/reparse refused before resolution: {original}")
        st = original.stat(follow_symlinks=False)
        attrs = int(getattr(st, "st_file_attributes", 0) or 0)
        reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if bool(attrs & reparse):
            raise ValueError(f"B5-3 {label} symlink/reparse refused before resolution: {original}")
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"B5-3 {label} pre-resolution validation failed: {type(exc).__name__}:{exc}") from exc
    resolved = original.resolve(strict=True)
    if not resolved.is_dir() or _is_reparse_or_symlink(resolved):
        raise ValueError(f"B5-3 {label} must be a real directory: {resolved}")
    return resolved


def _validate_target(target_root: Path) -> tuple[Path, str]:
    root = _validate_real_directory_before_resolution(Path(target_root), label="target")
    rr6.validate_offline_windows_root(root)
    return root, rr6.target_fingerprint(root)


def _ensure_outside_target(path: Path, target_root: Path, *, label: str) -> Path:
    candidate = Path(path).resolve(strict=False)
    try:
        candidate.relative_to(target_root)
    except ValueError:
        return candidate
    raise ValueError(f"B5-3 {label} must be outside target: {candidate}")


def _atomic_write_json(path: Path, payload: dict) -> None:
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


def _event_core(event: dict) -> dict:
    return {
        "seq": int(event["seq"]),
        "stage": str(event["stage"]),
        "state": str(event["state"]),
        "reason": str(event.get("reason", "")),
        "evidence_path": str(event.get("evidence_path", "")),
        "evidence_sha256": str(event.get("evidence_sha256", "")),
        "previous_event_sha256": str(event.get("previous_event_sha256", "")),
        "operation_key": str(event["operation_key"]),
        "created_utc": str(event["created_utc"]),
    }


def _event_sha256(event: dict) -> str:
    return _sha256_bytes(_canonical_json(_event_core(event)))


def _journal_hash_payload(journal: dict) -> dict:
    return {
        "schema": journal["schema"],
        "profile": journal["profile"],
        "session_id": journal["session_id"],
        "correlation_id": journal["correlation_id"],
        "target_root": journal["target_root"],
        "target_fingerprint": journal["target_fingerprint"],
        "created_utc": journal["created_utc"],
        "events": journal["events"],
        "safety": journal["safety"],
    }


def _refresh_journal_sha(journal: dict) -> None:
    journal["journal_sha256"] = _sha256_bytes(_canonical_json(_journal_hash_payload(journal)))


def _load_json_object(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"B5-3 journal parse failed: {type(exc).__name__}:{exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("B5-3 journal must be a JSON object")
    return payload


def _validate_journal_integrity(journal: dict) -> list[str]:
    reasons: list[str] = []
    if journal.get("schema") != JOURNAL_SCHEMA:
        reasons.append("journal_schema_mismatch")
    if journal.get("profile") != PROFILE:
        reasons.append("journal_profile_mismatch")
    if not isinstance(journal.get("events"), list):
        reasons.append("journal_events_invalid")
        return reasons

    previous = ""
    seen_operation_keys: set[str] = set()
    for index, event in enumerate(journal["events"]):
        if not isinstance(event, dict):
            reasons.append(f"event_{index}_invalid")
            continue
        try:
            seq = int(event.get("seq", -1))
        except Exception:
            seq = -1
        if seq != index:
            reasons.append(f"event_{index}_seq_mismatch")
        if str(event.get("stage", "")) not in ALL_STAGES:
            reasons.append(f"event_{index}_stage_invalid")
        if str(event.get("state", "")) not in EVENT_STATES:
            reasons.append(f"event_{index}_state_invalid")
        if str(event.get("previous_event_sha256", "")) != previous:
            reasons.append(f"event_{index}_chain_previous_mismatch")
        expected_hash = _event_sha256(event)
        actual_hash = str(event.get("event_sha256", ""))
        if actual_hash != expected_hash:
            reasons.append(f"event_{index}_hash_mismatch")
        operation_key = str(event.get("operation_key", ""))
        if not operation_key:
            reasons.append(f"event_{index}_operation_key_missing")
        elif operation_key in seen_operation_keys:
            reasons.append(f"event_{index}_operation_key_replayed")
        else:
            seen_operation_keys.add(operation_key)
        previous = actual_hash

    expected_journal_hash = _sha256_bytes(_canonical_json(_journal_hash_payload(journal)))
    if str(journal.get("journal_sha256", "")) != expected_journal_hash:
        reasons.append("journal_sha256_mismatch")
    return reasons


def create_session(target_root: Path, workspace: Path) -> dict:
    root, fingerprint = _validate_target(Path(target_root))
    workspace_resolved = _ensure_outside_target(Path(workspace), root, label="workspace")
    workspace_resolved.mkdir(parents=True, exist_ok=True)
    if _is_reparse_or_symlink(workspace_resolved):
        raise ValueError(f"B5-3 workspace symlink/reparse refused: {workspace_resolved}")

    seed = _sha256_bytes(f"{fingerprint}|{workspace_resolved}".encode("utf-8"))
    session_id = f"B53-{seed[:16].upper()}"
    correlation_id = seed[16:40]
    journal_path = workspace_resolved / "b53-session-journal.json"
    if journal_path.exists():
        raise FileExistsError(f"B5-3 journal already exists: {journal_path}")

    journal = {
        "schema": JOURNAL_SCHEMA,
        "profile": PROFILE,
        "session_id": session_id,
        "correlation_id": correlation_id,
        "target_root": str(root),
        "target_fingerprint": fingerprint,
        "created_utc": _utc_now(),
        "events": [],
        "safety": {
            "journal_outside_target": True,
            "automatic_mutation_resume": False,
            "repair_requires_reconfirmation_after_interruption": True,
            "data_rescue_requires_reconfirmation_after_interruption": True,
            "target_write_authority_added": False,
            "repair_execution_authority_added": False,
            "quarantine_execution_authority_added": False,
        },
    }
    _refresh_journal_sha(journal)
    _atomic_write_json(journal_path, journal)
    return {**journal, "journal_path": str(journal_path)}


def append_event(
    journal_path: Path,
    *,
    stage: str,
    state: str,
    reason: str = "",
    evidence_path: Path | None = None,
) -> dict:
    path = Path(journal_path).resolve(strict=True)
    journal = _load_json_object(path)
    integrity_reasons = _validate_journal_integrity(journal)
    if integrity_reasons:
        raise ValueError("B5-3 journal integrity refused before append: " + ",".join(integrity_reasons))

    stage = str(stage)
    state = str(state)
    if stage not in ALL_STAGES:
        raise ValueError(f"B5-3 unknown stage: {stage}")
    if state not in EVENT_STATES:
        raise ValueError(f"B5-3 unknown event state: {state}")

    root, fingerprint = _validate_target(Path(journal["target_root"]))
    if fingerprint != str(journal["target_fingerprint"]):
        raise ValueError("B5-3 target fingerprint changed before append")

    evidence_text = ""
    evidence_sha = ""
    if evidence_path is not None:
        candidate = _ensure_outside_target(Path(evidence_path), root, label="evidence")
        if not candidate.is_file() or _is_reparse_or_symlink(candidate):
            raise ValueError(f"B5-3 evidence must be a regular non-reparse file: {candidate}")
        evidence_text = str(candidate)
        evidence_sha = _sha256_file(candidate)

    operation_material = {
        "session_id": journal["session_id"],
        "stage": stage,
        "state": state,
        "reason": str(reason),
        "evidence_path": evidence_text,
        "evidence_sha256": evidence_sha,
    }
    operation_key = _sha256_bytes(_canonical_json(operation_material))
    for event in journal["events"]:
        if str(event.get("operation_key", "")) == operation_key:
            raise ValueError(f"B5-3 idempotent replay refused: stage={stage} state={state} operation_key={operation_key}")

    previous = str(journal["events"][-1]["event_sha256"]) if journal["events"] else ""
    event = {
        "seq": len(journal["events"]),
        "stage": stage,
        "state": state,
        "reason": str(reason),
        "evidence_path": evidence_text,
        "evidence_sha256": evidence_sha,
        "previous_event_sha256": previous,
        "operation_key": operation_key,
        "created_utc": _utc_now(),
    }
    event["event_sha256"] = _event_sha256(event)
    journal["events"].append(event)
    _refresh_journal_sha(journal)
    _atomic_write_json(path, journal)
    return {**journal, "journal_path": str(path), "appended_event": event}


def build_resume_decision(journal_path: Path, target_root: Path) -> dict:
    started = time.perf_counter()
    path = Path(journal_path).resolve(strict=True)
    journal = _load_json_object(path)
    reasons = _validate_journal_integrity(journal)

    current_root = ""
    current_fingerprint = ""
    try:
        root, current_fingerprint = _validate_target(Path(target_root))
        current_root = str(root)
    except Exception as exc:
        reasons.append(f"target_validation_failed:{type(exc).__name__}:{exc}")
        root = None

    expected_root = str(journal.get("target_root", ""))
    expected_fingerprint = str(journal.get("target_fingerprint", ""))
    if current_root and Path(current_root) != Path(expected_root):
        reasons.append("target_root_mismatch")
    if current_fingerprint and current_fingerprint != expected_fingerprint:
        reasons.append("target_fingerprint_mismatch")

    evidence_verified = 0
    evidence_failed = 0
    for index, event in enumerate(journal.get("events", [])) if isinstance(journal.get("events"), list) else []:
        evidence_text = str(event.get("evidence_path", ""))
        evidence_sha = str(event.get("evidence_sha256", ""))
        if not evidence_text:
            continue
        candidate = Path(evidence_text)
        try:
            if root is not None:
                candidate = _ensure_outside_target(candidate, root, label="evidence")
            candidate = candidate.resolve(strict=True)
            if not candidate.is_file() or _is_reparse_or_symlink(candidate):
                raise ValueError("not_regular_non_reparse")
            actual = _sha256_file(candidate)
            if actual != evidence_sha:
                raise ValueError(f"sha256_mismatch:{actual}")
            evidence_verified += 1
        except Exception as exc:
            evidence_failed += 1
            reasons.append(f"event_{index}_evidence_untrusted:{type(exc).__name__}:{exc}")

    actions: list[dict] = []
    latest_by_stage: dict[str, dict] = {}
    for event in journal.get("events", []) if isinstance(journal.get("events"), list) else []:
        latest_by_stage[str(event.get("stage", ""))] = event

    for stage in sorted(latest_by_stage):
        event = latest_by_stage[stage]
        state = str(event.get("state", ""))
        if state in TERMINAL_STATES:
            decision = "SKIP_TERMINAL"
            automatic_resume_allowed = False
            action_reason = f"stage_terminal:{state}"
        elif stage in READ_ONLY_RESUMABLE_STAGES and state in RESUMABLE_STATES:
            decision = "RESUME_READ_ONLY_ALLOWED"
            automatic_resume_allowed = True
            action_reason = f"read_only_stage_can_resume:{state}"
        elif stage in OPERATOR_GATED_STAGES and state in RESUMABLE_STATES:
            decision = "RECONFIRM_REQUIRED"
            automatic_resume_allowed = False
            action_reason = f"operator_gated_stage_never_auto_resumes:{state}"
        else:
            decision = "MANUAL_REVIEW"
            automatic_resume_allowed = False
            action_reason = f"unclassified_transition:{state}"
        actions.append({
            "stage": stage,
            "latest_state": state,
            "decision": decision,
            "reason": action_reason,
            "automatic_resume_allowed": automatic_resume_allowed,
        })

    trusted = not reasons
    if not trusted:
        for action in actions:
            action["decision"] = "REFUSED"
            action["reason"] = "session_trust_failed"
            action["automatic_resume_allowed"] = False

    result_core = {
        "schema": RESUME_SCHEMA,
        "profile": PROFILE,
        "session_id": str(journal.get("session_id", "")),
        "correlation_id": str(journal.get("correlation_id", "")),
        "journal_path": str(path),
        "journal_sha256": str(journal.get("journal_sha256", "")),
        "expected_target_root": expected_root,
        "current_target_root": current_root,
        "expected_target_fingerprint": expected_fingerprint,
        "current_target_fingerprint": current_fingerprint,
        "trusted": trusted,
        "state": "READY" if trusted else "REFUSED",
        "reasons": reasons,
        "actions": actions,
        "evidence_verified": evidence_verified,
        "evidence_failed": evidence_failed,
        "safety": {
            "automatic_mutation_resume": False,
            "repair_auto_resume": False,
            "data_rescue_auto_resume": False,
            "operator_reconfirmation_preserved": True,
            "target_write_authority_added": False,
            "repair_execution_authority_added": False,
            "quarantine_execution_authority_added": False,
        },
    }
    result_core["decision_sha256"] = _sha256_bytes(_canonical_json(result_core))
    result_core["elapsed_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
    return result_core


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta5 B5-3 durable session resume/crash recovery")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init")
    init.add_argument("--target-root", required=True)
    init.add_argument("--workspace", required=True)

    event = sub.add_parser("event")
    event.add_argument("--journal", required=True)
    event.add_argument("--stage", required=True, choices=sorted(ALL_STAGES))
    event.add_argument("--state", required=True, choices=sorted(EVENT_STATES))
    event.add_argument("--reason", default="")
    event.add_argument("--evidence")

    resume = sub.add_parser("resume")
    resume.add_argument("--journal", required=True)
    resume.add_argument("--target-root", required=True)
    resume.add_argument("--output")

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            result = create_session(Path(args.target_root), Path(args.workspace))
        elif args.command == "event":
            result = append_event(
                Path(args.journal),
                stage=args.stage,
                state=args.state,
                reason=args.reason,
                evidence_path=Path(args.evidence) if args.evidence else None,
            )
        else:
            result = build_resume_decision(Path(args.journal), Path(args.target_root))
            if args.output:
                out = Path(args.output).resolve(strict=False)
                root, _ = _validate_target(Path(args.target_root))
                out = _ensure_outside_target(out, root, label="resume output")
                _atomic_write_json(out, result)
        print(json.dumps(result, indent=2, sort_keys=True))
        if args.command == "resume" and not result.get("trusted", False):
            return 4
        return 0
    except Exception as exc:
        print(json.dumps({
            "passed": False,
            "profile": PROFILE,
            "stage": "session_resume",
            "reason": f"{type(exc).__name__}:{exc}",
        }, indent=2, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
