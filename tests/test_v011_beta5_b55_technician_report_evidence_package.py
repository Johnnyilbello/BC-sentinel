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


def write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_windows(root: Path) -> Path:
    cfg = root / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"B55 SYSTEM")
    (cfg / "SOFTWARE").write_bytes(b"B55 SOFTWARE")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ B55 KERNEL")
    return root


def tree_hashes(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file() and not p.is_symlink()
    }


def make_evidence(base: Path, label: str, payload: dict | None = None) -> Path:
    return write_json(base / f"{label}.json", payload or {"label": label, "ok": True})


def make_decision(
    path: Path,
    fingerprint: str,
    evidence: dict[str, tuple[Path, bool]],
    *,
    state: str = b54.STATE_MANUAL_REVIEW,
    rr6_outcome: str = rr6.OUTCOME_RECOVERED,
    reasons: list[str] | None = None,
    next_action: str = "Technician sign-off.",
) -> Path:
    index = {}
    for label, (evidence_path, trusted) in evidence.items():
        index[label] = {
            "path": str(evidence_path),
            "file_sha256": file_sha(evidence_path) if trusted else "",
            "trusted": trusted,
        }
    core = {
        "schema": b54.SCHEMA,
        "profile": b54.PROFILE,
        "target_fingerprint": fingerprint,
        "rr6_outcome": rr6_outcome,
        "rr6_certified_recovered": rr6_outcome == rr6.OUTCOME_RECOVERED,
        "state": state,
        "reasons": reasons or ["fixture_reason"],
        "next_action": next_action,
        "evidence_index": index,
        "signals": {
            "health_state": "HEALTHY",
            "stress_state": "COMPLETE",
            "resume_state": "READY",
            "resume_reconfirm_required": False,
            "repair_handoff_available": False,
            "data_rescue_available": "b43_data_rescue" in evidence,
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
    payload = {
        **core,
        "created_utc": "2026-09-11T00:00:00Z",
        "decision_sha256": hashlib.sha256(canonical(core)).hexdigest(),
        "elapsed_ms": 1.0,
    }
    return write_json(path, payload)


def build_fixture(tmp_path: Path, *, untrusted: bool = False, data_rescue: bool = False) -> tuple[Path, Path, Path]:
    target = make_windows(tmp_path / "offline")
    fp = rr6.target_fingerprint(target)
    evidence_dir = tmp_path / "source-evidence"
    cert = make_evidence(evidence_dir, "cert", {"kind": "cert"})
    evidence: dict[str, tuple[Path, bool]] = {"b44_certification": (cert, True)}
    if untrusted:
        bad = make_evidence(evidence_dir, "bad", {"kind": "untrusted"})
        evidence["b51_health"] = (bad, False)
    if data_rescue:
        rescue = make_evidence(evidence_dir, "rescue", {
            "execution_requested": True,
            "manifest_sha256": "a" * 64,
            "manifest_path": str(tmp_path / "rr5-manifest.json"),
            "summary": {"records": 4, "copied": 4, "contained": 2, "skipped": 0, "errors": 0},
        })
        evidence["b43_data_rescue"] = (rescue, True)
    decision = make_decision(tmp_path / "decision.json", fp, evidence)
    package = tmp_path / "package"
    return target, decision, package


def test_build_package_copies_trusted_evidence_and_verifies(tmp_path: Path) -> None:
    target, decision, package = build_fixture(tmp_path)
    result = b55.create_package(b55.ReportRequest(target, decision, package))
    assert result["verification_passed"] is True
    assert result["trusted_copied"] == 2
    assert (package / b55.REPORT_JSON).is_file()
    assert (package / b55.REPORT_MD).is_file()
    assert (package / b55.EVIDENCE_INDEX_JSON).is_file()
    assert (package / b55.MANIFEST_JSON).is_file()
    assert b55.verify_package(package)["passed"] is True


def test_target_remains_byte_identical(tmp_path: Path) -> None:
    target, decision, package = build_fixture(tmp_path)
    before = tree_hashes(target)
    b55.create_package(b55.ReportRequest(target, decision, package))
    assert tree_hashes(target) == before


def test_package_inside_target_refused(tmp_path: Path) -> None:
    target, decision, _ = build_fixture(tmp_path)
    with pytest.raises(ValueError, match="package must be outside target"):
        b55.create_package(b55.ReportRequest(target, decision, target / "report-package"))


def test_decision_inside_target_refused(tmp_path: Path) -> None:
    target = make_windows(tmp_path / "offline")
    fp = rr6.target_fingerprint(target)
    evidence = make_evidence(tmp_path / "evidence", "cert")
    decision = make_decision(target / "decision.json", fp, {"b44_certification": (evidence, True)})
    with pytest.raises(ValueError, match="decision must be outside target"):
        b55.create_package(b55.ReportRequest(target, decision, tmp_path / "package"))


def test_tampered_decision_refused(tmp_path: Path) -> None:
    target, decision, package = build_fixture(tmp_path)
    payload = json.loads(decision.read_text(encoding="utf-8"))
    payload["state"] = b54.STATE_REPAIRABLE
    write_json(decision, payload)
    with pytest.raises(ValueError, match="decision_sha256_mismatch"):
        b55.create_package(b55.ReportRequest(target, decision, package))


def test_target_fingerprint_mismatch_refused(tmp_path: Path) -> None:
    target, decision, package = build_fixture(tmp_path)
    payload = json.loads(decision.read_text(encoding="utf-8"))
    core = dict(payload)
    core.pop("decision_sha256")
    core.pop("created_utc")
    core.pop("elapsed_ms")
    core["target_fingerprint"] = "b" * 64
    payload["target_fingerprint"] = "b" * 64
    payload["decision_sha256"] = hashlib.sha256(canonical(core)).hexdigest()
    write_json(decision, payload)
    with pytest.raises(ValueError, match="decision_target_fingerprint_mismatch"):
        b55.create_package(b55.ReportRequest(target, decision, package))


def test_trusted_evidence_drift_refused(tmp_path: Path) -> None:
    target, decision, package = build_fixture(tmp_path)
    payload = json.loads(decision.read_text(encoding="utf-8"))
    source = Path(payload["evidence_index"]["b44_certification"]["path"])
    source.write_text('{"tampered":true}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="trusted_evidence_sha256_drift"):
        b55.create_package(b55.ReportRequest(target, decision, package))


def test_untrusted_evidence_is_reported_but_not_copied(tmp_path: Path) -> None:
    target, decision, package = build_fixture(tmp_path, untrusted=True)
    result = b55.create_package(b55.ReportRequest(target, decision, package))
    assert result["untrusted_not_copied"] == 1
    report = json.loads((package / b55.REPORT_JSON).read_text(encoding="utf-8"))
    assert any("untrusted_evidence:b51_health" in item for item in report["unresolved_risks"])
    index = json.loads((package / b55.EVIDENCE_INDEX_JSON).read_text(encoding="utf-8"))
    row = next(item for item in index["records"] if item["label"] == "b51_health")
    assert row["copied"] is False


def test_symlink_trusted_evidence_refused_when_supported(tmp_path: Path) -> None:
    target = make_windows(tmp_path / "offline")
    fp = rr6.target_fingerprint(target)
    real = make_evidence(tmp_path / "source", "real")
    link = tmp_path / "source" / "link.json"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlink unavailable")
    decision = make_decision(tmp_path / "decision.json", fp, {"b44_certification": (link, True)})
    with pytest.raises(ValueError, match="trusted_evidence_not_regular|evidence:b44_certification"):
        b55.create_package(b55.ReportRequest(target, decision, tmp_path / "package"))


def test_nonempty_package_refused(tmp_path: Path) -> None:
    target, decision, package = build_fixture(tmp_path)
    package.mkdir()
    (package / "existing.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="package_directory_must_be_empty"):
        b55.create_package(b55.ReportRequest(target, decision, package))


def test_verify_detects_tampered_packaged_evidence(tmp_path: Path) -> None:
    target, decision, package = build_fixture(tmp_path)
    b55.create_package(b55.ReportRequest(target, decision, package))
    copied = next((package / b55.EVIDENCE_DIR).glob("*certification*.json"))
    copied.write_text('{"tampered":true}\n', encoding="utf-8")
    verify = b55.verify_package(package)
    assert verify["passed"] is False
    assert any("sha256_mismatch" in item for item in verify["errors"])


def test_verify_detects_unlisted_extra_file(tmp_path: Path) -> None:
    target, decision, package = build_fixture(tmp_path)
    b55.create_package(b55.ReportRequest(target, decision, package))
    (package / "extra.txt").write_text("unexpected", encoding="utf-8")
    verify = b55.verify_package(package)
    assert verify["passed"] is False
    assert "unlisted_package_file:extra.txt" in verify["errors"]


def test_human_report_contains_decision_and_next_action(tmp_path: Path) -> None:
    target, decision, package = build_fixture(tmp_path)
    b55.create_package(b55.ReportRequest(target, decision, package))
    text = (package / b55.REPORT_MD).read_text(encoding="utf-8")
    assert "RR-6 outcome: **RECOVERED**" in text
    assert "B5-4 advisory state: **MANUAL_REVIEW**" in text
    assert "Technician sign-off." in text


def test_data_rescue_summary_and_safety_flags_are_preserved(tmp_path: Path) -> None:
    target, decision, package = build_fixture(tmp_path, data_rescue=True)
    result = b55.create_package(b55.ReportRequest(target, decision, package))
    report = json.loads((package / b55.REPORT_JSON).read_text(encoding="utf-8"))
    assert report["data_rescue"]["copied"] == 4
    assert report["data_rescue"]["contained"] == 2
    assert report["safety"]["report_only"] is True
    assert report["safety"]["repair_execution"] is False
    assert report["safety"]["format_or_reimage_execution"] is False
    assert result["new_mutation_authority_added"] is False
