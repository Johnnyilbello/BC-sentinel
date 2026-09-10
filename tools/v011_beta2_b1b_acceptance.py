from __future__ import annotations

import inspect
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinel.edr import EdrIncident
from sentinel.edr_service_bridge import EdrServiceBridge
from sentinel.protection_protocol import (
    PRIVILEGED_OPERATIONS,
    READ_OPERATIONS,
    ProtocolError,
    _validate_payload,
)
from sentinel.protection_service_core import ProtectionRuntime, ProtectionServiceCore

PROFILE = "v0.11.0-beta.2"


def run_acceptance() -> dict:
    checks: dict[str, bool] = {}
    edr_reads = {
        "edr_status", "edr_timeline", "edr_incidents", "edr_incident_evidence",
        "edr_root_cause", "edr_hunt", "edr_process_tree", "edr_retention_policy",
    }
    checks["read_allowlist_complete"] = edr_reads.issubset(set(READ_OPERATIONS))
    checks["retention_is_privileged"] = "edr_update_retention" in set(PRIVILEGED_OPERATIONS)

    valid = _validate_payload("edr_timeline", {"pid": 42, "limit": 50, "since": 1.0, "until": 2.0})
    checks["bounded_payload_validates"] = valid.get("limit") == 50 and valid.get("pid") == 42
    try:
        _validate_payload("edr_timeline", {"limit": 10, "arbitrary_method": "run"})
    except ProtocolError:
        checks["unknown_field_rejected"] = True
    else:
        checks["unknown_field_rejected"] = False
    try:
        _validate_payload("edr_update_retention", {"max_events": 99})
    except ProtocolError:
        checks["retention_bounds_enforced"] = True
    else:
        checks["retention_bounds_enforced"] = False

    dispatch_source = inspect.getsource(ProtectionServiceCore.dispatch_validated)
    authorize_index = dispatch_source.find("self._authorize(request, context)")
    rate_index = dispatch_source.find("self._enforce_request_rate(request, context)")
    read_index = dispatch_source.find("dispatch_read(op, payload)")
    privileged_index = dispatch_source.find("dispatch_privileged(op, payload)")
    checks["authorization_precedes_edr_dispatch"] = (
        authorize_index >= 0 and rate_index > authorize_index and read_index > rate_index and privileged_index > rate_index
    )
    checks["no_generic_rpc_dispatch"] = all(term not in dispatch_source for term in (
        "getattr(self.runtime, op)", "eval(", "exec(", "subprocess", "pickle.loads", "shell=True"
    ))

    pending_source = inspect.getsource(ProtectionRuntime.pending_threats)
    checks["security_center_merge_present"] = "security_inbox_items" in pending_source

    with TemporaryDirectory(prefix="bc-sentinel-b1b-") as temp:
        b = EdrServiceBridge(db_path=Path(temp) / "edr.sqlite3")
        incident = EdrIncident(
            incident_id="BCEDR-0123456789ABCDEF0123",
            score=88,
            severity="HIGH",
            confidence=0.91,
            event_ids=["BCE-TEST"],
            pids=[321],
            signal_codes=["qualified_file_verdict"],
            evidence_families=["deterministic", "execution", "delivery"],
            reasons=["qualified test incident"],
            first_seen=1.0,
            last_seen=2.0,
        )
        b.store.save_incident(incident)
        items = b.security_inbox_items(limit=10)
        checks["review_only_inbox_projection"] = bool(
            len(items) == 1
            and items[0].get("source") == "edr"
            and items[0].get("review_only") is True
            and items[0].get("automatic_destructive_action") is False
        )

    return {
        "profile": PROFILE,
        "checkpoint": "B1b-acceptance",
        "passed": all(checks.values()),
        "checks": checks,
        "automatic_process_kill": False,
        "automatic_file_delete": False,
        "automatic_host_isolation": False,
    }


def main() -> int:
    result = run_acceptance()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
