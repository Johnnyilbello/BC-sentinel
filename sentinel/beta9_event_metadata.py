"""B9-1: strict contract for bounded, privacy-minimal Windows event metadata.

This module validates already-collected allowlisted metadata. It never reads Windows
logs itself and never treats metadata availability as detector evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

SCHEMA = "bc-sentinel-beta9-event-metadata-v1"
SOURCE = "WINDOWS_EVENT_METADATA_BOUNDED"
MAX_EVENTS_LIMIT = 8
TIMEOUT_SECONDS_LIMIT = 10
STATUSES = {"OK", "EMPTY", "ACCESS_DENIED", "UNSUPPORTED", "TIMEOUT", "ERROR"}
PROFILES = (
    {
        "profile_id": "system-kernel-general",
        "channel": "System",
        "provider": "Microsoft-Windows-Kernel-General",
        "event_ids": (12, 13),
    },
    {
        "profile_id": "powershell-operational",
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "provider": "Microsoft-Windows-PowerShell",
        "event_ids": (4103, 4104),
    },
    {
        "profile_id": "defender-operational",
        "channel": "Microsoft-Windows-Windows Defender/Operational",
        "provider": "Microsoft-Windows-Windows Defender",
        "event_ids": (1000, 1001, 1002, 1116, 1117),
    },
    {
        "profile_id": "sysmon-operational",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider": "Microsoft-Windows-Sysmon",
        "event_ids": (1, 3, 7, 11),
    },
    {
        "profile_id": "security-auditing",
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_ids": (4624, 4625),
    },
)
BOUNDARIES = {
    "local_only": True,
    "explicit_opt_in_required": True,
    "bounded_event_count": True,
    "bounded_query_timeout": True,
    "event_message_read": False,
    "event_payload_read": False,
    "personal_data_collected": False,
    "remote_access": False,
    "logging_configuration_mutation": False,
    "detector_classification": False,
    "remediation_authority": False,
    "verified_coverage": False,
}
EVENT_FIELDS = {"channel", "provider", "event_id", "level", "record_id", "time_created_utc"}
PROFILE_FIELDS = {
    "profile_id", "channel", "provider", "event_ids", "max_events", "timeout_seconds", "status", "events"
}


def _valid_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def validate_metadata(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("metadata:not_object",)
    errors: list[str] = []
    if set(data) != {"schema", "source", "profiles", "boundaries"}:
        errors.append("metadata:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("source") != SOURCE:
        errors.append("metadata:source_or_schema_invalid")
    boundaries = data.get("boundaries")
    if not isinstance(boundaries, dict) or set(boundaries) != set(BOUNDARIES) or any(
        boundaries.get(key) is not value for key, value in BOUNDARIES.items()
    ):
        errors.append("metadata:boundary_invalid")
    rows = data.get("profiles")
    if not isinstance(rows, list) or len(rows) != len(PROFILES):
        return tuple(errors + ["metadata:profile_count_invalid"])

    for expected, row in zip(PROFILES, rows):
        if not isinstance(row, dict) or set(row) != PROFILE_FIELDS:
            errors.append("metadata:profile_fields_invalid")
            continue
        if any(row.get(key) != expected[key] for key in ("profile_id", "channel", "provider")):
            errors.append("metadata:profile_identity_invalid")
        event_ids = row.get("event_ids")
        if not isinstance(event_ids, list) or tuple(event_ids) != expected["event_ids"] or any(
            not isinstance(event_id, int) or isinstance(event_id, bool) for event_id in event_ids
        ):
            errors.append("metadata:event_allowlist_invalid")
        max_events = row.get("max_events")
        timeout_seconds = row.get("timeout_seconds")
        if not isinstance(max_events, int) or isinstance(max_events, bool) or not 1 <= max_events <= MAX_EVENTS_LIMIT:
            errors.append("metadata:max_events_invalid")
        if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= TIMEOUT_SECONDS_LIMIT:
            errors.append("metadata:timeout_invalid")
        status = row.get("status")
        if not isinstance(status, str) or status not in STATUSES:
            errors.append("metadata:status_invalid")
            continue
        events = row.get("events")
        if not isinstance(events, list):
            errors.append("metadata:events_not_list")
            continue
        if isinstance(max_events, int) and not isinstance(max_events, bool) and len(events) > max_events:
            errors.append("metadata:event_count_exceeds_bound")
        if status == "OK" and not events:
            errors.append("metadata:ok_requires_event")
        if status != "OK" and events:
            errors.append("metadata:non_ok_must_not_carry_events")
        for event in events:
            if not isinstance(event, dict) or set(event) != EVENT_FIELDS:
                errors.append("metadata:event_fields_invalid")
                continue
            if event.get("channel") != expected["channel"] or event.get("provider") != expected["provider"]:
                errors.append("metadata:event_source_mismatch")
            event_id = event.get("event_id")
            if not isinstance(event_id, int) or isinstance(event_id, bool) or event_id not in expected["event_ids"]:
                errors.append("metadata:event_id_not_allowlisted")
            level = event.get("level")
            if level is not None and (not isinstance(level, int) or isinstance(level, bool) or not 0 <= level <= 255):
                errors.append("metadata:event_level_invalid")
            record_id = event.get("record_id")
            if record_id is not None and (
                not isinstance(record_id, int) or isinstance(record_id, bool) or record_id < 0
            ):
                errors.append("metadata:record_id_invalid")
            if not _valid_utc_timestamp(event.get("time_created_utc")):
                errors.append("metadata:timestamp_invalid")
    return tuple(errors)


def summarize(data: object) -> dict:
    failures = validate_metadata(data)
    if failures:
        # Never echo rejected input: it may contain forbidden event payload fields.
        return {"passed": False, "failures": list(failures)}
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    profiles = data["profiles"]
    readable = [row for row in profiles if row["status"] in {"OK", "EMPTY"}]
    return {
        "passed": True,
        "metadata_digest": hashlib.sha256(canonical.encode()).hexdigest(),
        "profile_statuses": [
            {"profile_id": row["profile_id"], "status": row["status"], "event_count": len(row["events"])}
            for row in profiles
        ],
        "event_readability_tested": bool(readable),
        "readable_profile_count": len(readable),
        "total_event_count": sum(len(row["events"]) for row in profiles),
        "detector_verification_performed": False,
        "threat_classification_performed": False,
        "coverage_summary": {"PARTIAL": 6, "GAP": 0, "VERIFIED": 0},
        "boundaries": dict(BOUNDARIES),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = json.loads(args.metadata.read_text(encoding="utf-8-sig"))
        result = summarize(data)
    except (OSError, UnicodeError, ValueError):
        result = {"passed": False, "failures": ["metadata:unreadable_or_invalid_json"]}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
