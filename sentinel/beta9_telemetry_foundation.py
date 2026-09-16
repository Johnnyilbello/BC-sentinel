"""B9-0: strict, privacy-minimal Windows channel inventory contract.

Availability is not event readability, detector evidence or verified coverage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SCHEMA = "bc-sentinel-beta9-channel-inventory-v1"
CHANNELS = (
    "System",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Security",
)
STATES = {"AVAILABLE", "DISABLED", "ACCESS_DENIED", "MISSING", "ERROR"}
BOUNDARIES = {
    "configuration_read_only": True,
    "event_payload_read": False,
    "personal_data_collected": False,
    "channel_configuration_mutation": False,
    "remediation_authority": False,
    "verified_coverage": False,
}


def validate_inventory(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("inventory:not_object",)
    errors = []
    if set(data) != {"schema", "source", "channels", "boundaries"}:
        errors.append("inventory:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("source") != "WINDOWS_CHANNEL_CONFIGURATION":
        errors.append("inventory:source_or_schema_invalid")
    boundaries = data.get("boundaries")
    if not isinstance(boundaries, dict) or set(boundaries) != set(BOUNDARIES) or any(
        boundaries.get(key) is not value for key, value in BOUNDARIES.items()
    ):
        errors.append("inventory:boundary_invalid")
    rows = data.get("channels")
    if not isinstance(rows, list) or len(rows) != len(CHANNELS):
        return tuple(errors + ["inventory:channel_count_invalid"])
    for expected, row in zip(CHANNELS, rows):
        if not isinstance(row, dict) or set(row) != {"channel", "state", "enabled"}:
            errors.append("inventory:channel_fields_invalid")
            continue
        if row["channel"] != expected:
            errors.append("inventory:channel_order_invalid")
        state = row["state"]
        if not isinstance(state, str) or state not in STATES:
            errors.append("inventory:state_invalid")
            continue
        enabled = True if state == "AVAILABLE" else False if state == "DISABLED" else None
        if row["enabled"] is not enabled:
            errors.append("inventory:enabled_state_inconsistent")
    return tuple(errors)


def summarize(data: object) -> dict:
    failures = validate_inventory(data)
    if failures:
        # Never serialize rejected input, which could contain sensitive fields.
        return {"passed": False, "failures": list(failures)}
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return {
        "passed": True,
        "inventory_digest": hashlib.sha256(canonical.encode()).hexdigest(),
        "available_channels": [r["channel"] for r in data["channels"] if r["state"] == "AVAILABLE"],
        "unavailable_channels": [{"channel": r["channel"], "state": r["state"]}
                                 for r in data["channels"] if r["state"] != "AVAILABLE"],
        "event_readability_tested": False,
        "detector_verification_performed": False,
        "coverage_summary": {"PARTIAL": 6, "GAP": 0, "VERIFIED": 0},
        "boundaries": dict(BOUNDARIES),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = json.loads(args.inventory.read_text(encoding="utf-8-sig"))
        result = summarize(data)
    except (OSError, UnicodeError, ValueError):
        result = {"passed": False, "failures": ["inventory:unreadable_or_invalid_json"]}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
