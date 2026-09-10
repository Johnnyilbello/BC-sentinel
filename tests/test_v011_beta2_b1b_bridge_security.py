from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.edr import EdrIncident
from sentinel.edr_service_bridge import EdrServiceBridge


def bridge(tmp_path: Path) -> EdrServiceBridge:
    return EdrServiceBridge(db_path=tmp_path / "b1b.sqlite3")


def test_b1b_read_payload_rejects_unknown_fields(tmp_path: Path):
    b = bridge(tmp_path)
    with pytest.raises(ValueError, match="unknown EDR payload"):
        b.dispatch_read("edr_timeline", {"limit": 10, "command": "whoami"})


def test_b1b_read_payload_enforces_server_side_bounds(tmp_path: Path):
    b = bridge(tmp_path)
    with pytest.raises(ValueError, match="limit must be between"):
        b.dispatch_read("edr_timeline", {"limit": 501})
    with pytest.raises(ValueError, match="pid is invalid"):
        b.dispatch_read("edr_timeline", {"pid": -1})
    with pytest.raises(ValueError, match="since must be less"):
        b.dispatch_read("edr_timeline", {"since": 20.0, "until": 10.0})


def test_b1b_hunt_kind_and_indicator_are_strict(tmp_path: Path):
    b = bridge(tmp_path)
    with pytest.raises(ValueError, match="unsupported EDR indicator kind"):
        b.dispatch_read("edr_hunt", {"indicator": "example.test", "kind": "shell"})
    with pytest.raises(ValueError, match="indicator cannot be empty"):
        b.dispatch_read("edr_hunt", {"indicator": ""})


def test_b1b_incident_id_shape_is_strict(tmp_path: Path):
    b = bridge(tmp_path)
    with pytest.raises(ValueError, match="incident_id is invalid"):
        b.dispatch_read("edr_root_cause", {"incident_id": "not-an-incident"})


def test_b1b_retention_is_privileged_surface_and_bounded(tmp_path: Path):
    b = bridge(tmp_path)
    with pytest.raises(ValueError, match="read operation"):
        b.dispatch_read("edr_update_retention", {"max_events": 1000})
    with pytest.raises(ValueError, match="outside the allowed bounds"):
        b.dispatch_privileged("edr_update_retention", {"max_events": 99})
    with pytest.raises(ValueError, match="unknown EDR payload"):
        b.dispatch_privileged("edr_update_retention", {"max_events": 1000, "exec": "x"})


def test_b1b_security_center_projection_is_persistent_review_only(tmp_path: Path):
    b = bridge(tmp_path)
    incident = EdrIncident(
        incident_id="BCEDR-0123456789ABCDEF0123",
        score=88,
        severity="HIGH",
        confidence=0.92,
        event_ids=["BCE-TEST"],
        pids=[123],
        signal_codes=["signed_network_ioc", "script_or_lolbin_suspicious"],
        evidence_families=["deterministic", "execution", "network"],
        reasons=["qualified"],
        first_seen=1.0,
        last_seen=2.0,
    )
    b.store.save_incident(incident)
    items = b.security_inbox_items(limit=10)
    assert len(items) == 1
    item = items[0]
    assert item["source"] == "edr"
    assert item["severity"] == "HIGH"
    assert item["review_only"] is True
    assert item["automatic_destructive_action"] is False


def test_b1b_security_center_projection_excludes_non_high_and_destructive(tmp_path: Path):
    b = bridge(tmp_path)
    medium = EdrIncident(
        incident_id="BCEDR-AAAAAAAAAAAAAAAAAAAA",
        score=60,
        severity="MEDIUM",
        confidence=0.5,
        event_ids=[], pids=[], signal_codes=[], evidence_families=[], reasons=[],
        first_seen=1.0, last_seen=2.0,
    )
    destructive = EdrIncident(
        incident_id="BCEDR-BBBBBBBBBBBBBBBBBBBB",
        score=90,
        severity="HIGH",
        confidence=0.9,
        event_ids=[], pids=[], signal_codes=[], evidence_families=[], reasons=[],
        first_seen=1.0, last_seen=2.0,
        automatic_destructive_action=True,
    )
    b.store.save_incident(medium)
    b.store.save_incident(destructive)
    assert b.security_inbox_items(limit=10) == []
