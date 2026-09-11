from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_integrity_certification as rr6
from sentinel import rescue_recovery_decision as b54
from sentinel import rescue_technician_report as b55


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def make_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    target = tmp_path / "offline"
    cfg = target / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"B55 REPARSE SYSTEM")
    (cfg / "SOFTWARE").write_bytes(b"B55 REPARSE SOFTWARE")
    (target / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ B55 REPARSE KERNEL")
    fingerprint = rr6.target_fingerprint(target)

    evidence = tmp_path / "source-evidence.json"
    evidence.write_text('{"trusted":true}\n', encoding="utf-8")
    evidence_sha = hashlib.sha256(evidence.read_bytes()).hexdigest()
    core = {
        "schema": b54.SCHEMA,
        "profile": b54.PROFILE,
        "target_fingerprint": fingerprint,
        "rr6_outcome": rr6.OUTCOME_RECOVERED,
        "rr6_certified_recovered": True,
        "state": b54.STATE_MANUAL_REVIEW,
        "reasons": ["fixture"],
        "next_action": "Technician sign-off.",
        "evidence_index": {
            "b44_certification": {"path": str(evidence), "file_sha256": evidence_sha, "trusted": True},
        },
        "signals": {
            "health_state": "HEALTHY",
            "stress_state": "COMPLETE",
            "resume_state": "READY",
            "resume_reconfirm_required": False,
            "repair_handoff_available": False,
            "data_rescue_available": False,
        },
        "safety": {
            "advisory_only": True,
            "rr6_outcome_override": False,
            "automatic_repair": False,
            "automatic_data_rescue": False,
            "automatic_reimage": False,
            "automatic_destructive_action": False,
            "target_write_authority_added": False,
            "repair_execution_authority_added": False,
            "quarantine_execution_authority_added": False,
        },
    }
    decision = tmp_path / "decision.json"
    decision.write_text(json.dumps({
        **core,
        "created_utc": "2026-09-11T00:00:00Z",
        "decision_sha256": hashlib.sha256(canonical(core)).hexdigest(),
        "elapsed_ms": 1.0,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target, decision, tmp_path / "package"


def test_verify_refuses_listed_file_replaced_by_symlink(tmp_path: Path) -> None:
    target, decision, package = make_fixture(tmp_path)
    b55.create_package(b55.ReportRequest(target, decision, package))
    manifest = json.loads((package / b55.MANIFEST_JSON).read_text(encoding="utf-8"))
    rel = next(
        row["path"] for row in manifest["files"]
        if row["path"].startswith("evidence/") and row["path"] != "evidence/b54-decision.json"
    )
    listed = package / rel
    backup = tmp_path / "outside-copy.json"
    backup.write_bytes(listed.read_bytes())
    listed.unlink()
    try:
        listed.symlink_to(backup)
    except OSError:
        pytest.skip("symlink unavailable")
    result = b55.verify_package(package)
    assert result["passed"] is False
    assert any("reparse" in item for item in result["errors"])
