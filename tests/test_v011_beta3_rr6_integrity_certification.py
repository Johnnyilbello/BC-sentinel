from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_integrity_certification as rr6


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _root(base: Path) -> Path:
    root = base / "offline"
    config = root / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"RR6 SYSTEM HIVE")
    (config / "SOFTWARE").write_bytes(b"RR6 SOFTWARE HIVE")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ RR6 KERNEL")
    return root


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _scan_payload(root: Path) -> dict:
    return {
        "profile": rr6.RR3_PROFILE,
        "summary": {
            "enumerated": 3,
            "hashed": 3,
            "skipped": 0,
            "errors": 0,
            "ioc_hits": 0,
            "yara_hits": 0,
            "heuristic_review_items": 0,
            "registry_hives": 2,
            "truncated_by_max_files": False,
        },
        "findings": [],
        "registry_hives": [
            {"label": "system:SYSTEM", "sha256": _sha(root / "Windows/System32/config/SYSTEM"), "status": "hashed", "write_attempted": False},
            {"label": "system:SOFTWARE", "sha256": _sha(root / "Windows/System32/config/SOFTWARE"), "status": "hashed", "write_attempted": False},
        ],
    }


def _baseline_payload(root: Path) -> dict:
    fp = rr6.target_fingerprint(root)
    return {
        "schema": rr6.BASELINE_SCHEMA,
        "target_fingerprint": fp,
        "entries": [
            {"relative_path": rel, "sha256": _sha(root / Path(rel)), "required": True}
            for rel in rr6.MANDATORY_CRITICAL_PATHS
        ],
    }


def _fixture(base: Path, *, repairs_performed: bool = False, transaction: dict | None = None):
    root = _root(base)
    evidence_dir = base / "evidence"
    scan_path = evidence_dir / "rr3-scan.json"
    baseline_path = evidence_dir / "critical-baseline.json"
    repair_path = evidence_dir / "repair-transaction.json" if transaction is not None else None
    provenance_path = evidence_dir / "provenance.json"
    _write(scan_path, _scan_payload(root))
    _write(baseline_path, _baseline_payload(root))
    if repair_path is not None:
        _write(repair_path, transaction)
    evidence = [
        {"kind": "rr3_scan", "path": scan_path.name, "sha256": _sha(scan_path)},
        {"kind": "critical_baseline", "path": baseline_path.name, "sha256": _sha(baseline_path)},
    ]
    if repair_path is not None:
        evidence.append({"kind": "repair_transaction", "path": repair_path.name, "sha256": _sha(repair_path)})
    _write(
        provenance_path,
        {
            "schema": rr6.PROVENANCE_SCHEMA,
            "approved": True,
            "target_fingerprint": rr6.target_fingerprint(root),
            "repairs_performed": repairs_performed,
            "evidence": evidence,
            "lineage": {"rr3_profile": rr6.RR3_PROFILE, "rr6_profile": rr6.PROFILE},
        },
    )
    return root, rr6.CertificationEvidence(scan_path, baseline_path, provenance_path, repair_path)


def _refresh_provenance(ev: rr6.CertificationEvidence, root: Path, *, repairs_performed: bool | None = None) -> None:
    payload = json.loads(ev.provenance_path.read_text(encoding="utf-8"))
    payload["target_fingerprint"] = rr6.target_fingerprint(root)
    if repairs_performed is not None:
        payload["repairs_performed"] = repairs_performed
    for item in payload["evidence"]:
        if item["kind"] == "rr3_scan":
            item["sha256"] = _sha(ev.scan_path)
        elif item["kind"] == "critical_baseline":
            item["sha256"] = _sha(ev.baseline_path)
        elif item["kind"] == "repair_transaction" and ev.repair_transaction_path:
            item["sha256"] = _sha(ev.repair_transaction_path)
    _write(ev.provenance_path, payload)


def test_clean_complete_evidence_certifies_recovered(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_RECOVERED
    assert report["certified_recovered"] is True
    assert not report["refusal_reasons"]
    assert not report["not_recovered_reasons"]


def test_report_hash_is_self_consistent(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    without = dict(report)
    expected = without.pop("report_sha256")
    assert rr6._sha256_bytes(rr6._canonical_json(without)) == expected


def test_target_remains_byte_identical(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    before = {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}
    rr6.certify_recovery(root, ev, tmp_path / "out")
    after = {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}
    assert before == after


def test_deterministic_ioc_means_not_recovered(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    scan = json.loads(ev.scan_path.read_text(encoding="utf-8"))
    scan["summary"]["ioc_hits"] = 1
    scan["findings"] = [{"relative_path": "Windows/System32/ntoskrnl.exe", "sha256": _sha(root / "Windows/System32/ntoskrnl.exe"), "verdict": "deterministic_ioc"}]
    _write(ev.scan_path, scan)
    _refresh_provenance(ev, root)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_NOT_RECOVERED
    assert "unresolved_deterministic_ioc" in report["not_recovered_reasons"]


def test_yara_hit_means_not_recovered(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    scan = json.loads(ev.scan_path.read_text(encoding="utf-8"))
    scan["summary"]["yara_hits"] = 1
    _write(ev.scan_path, scan)
    _refresh_provenance(ev, root)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_NOT_RECOVERED
    assert "unresolved_yara_match" in report["not_recovered_reasons"]


def test_scan_errors_are_refused_not_certified(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    scan = json.loads(ev.scan_path.read_text(encoding="utf-8"))
    scan["summary"]["errors"] = 1
    _write(ev.scan_path, scan)
    _refresh_provenance(ev, root)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_REFUSED
    assert "rr3_scan_contains_errors" in report["refusal_reasons"]


def test_truncated_scan_is_refused(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    scan = json.loads(ev.scan_path.read_text(encoding="utf-8"))
    scan["summary"]["truncated_by_max_files"] = True
    _write(ev.scan_path, scan)
    _refresh_provenance(ev, root)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_REFUSED
    assert "rr3_scan_truncated" in report["refusal_reasons"]


def test_tampered_scan_evidence_is_refused(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    scan = json.loads(ev.scan_path.read_text(encoding="utf-8"))
    scan["summary"]["enumerated"] = 99
    _write(ev.scan_path, scan)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_REFUSED
    assert "provenance_hash_mismatch:rr3_scan" in report["refusal_reasons"]


def test_missing_required_critical_baseline_path_is_refused(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    baseline = json.loads(ev.baseline_path.read_text(encoding="utf-8"))
    baseline["entries"] = baseline["entries"][1:]
    _write(ev.baseline_path, baseline)
    _refresh_provenance(ev, root)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_REFUSED
    assert any(reason.startswith("critical_baseline_required_path_missing") for reason in report["refusal_reasons"])


def test_critical_hash_mismatch_means_not_recovered(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    baseline = json.loads(ev.baseline_path.read_text(encoding="utf-8"))
    baseline["entries"][0]["sha256"] = "0" * 64
    _write(ev.baseline_path, baseline)
    _refresh_provenance(ev, root)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_NOT_RECOVERED
    assert any(reason.startswith("critical_file_integrity_mismatch") for reason in report["not_recovered_reasons"])


def test_registry_hive_hash_mismatch_is_refused(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    scan = json.loads(ev.scan_path.read_text(encoding="utf-8"))
    scan["registry_hives"][0]["sha256"] = "f" * 64
    _write(ev.scan_path, scan)
    _refresh_provenance(ev, root)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_REFUSED
    assert "required_hive_hash_mismatch:system:SYSTEM" in report["refusal_reasons"]


def test_target_changed_after_evidence_is_refused(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    (root / "Windows/System32/config/SYSTEM").write_bytes(b"changed after evidence")
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_REFUSED
    assert "provenance_target_fingerprint_mismatch" in report["refusal_reasons"]


def test_repair_transaction_applied_and_matching_can_certify(tmp_path: Path):
    root = _root(tmp_path)
    driver = root / "Windows/System32/drivers/repaired.sys"
    driver.parent.mkdir(parents=True)
    driver.write_bytes(b"repaired-state")
    tx = {
        "schema": "bc-sentinel-rr4a-transaction-v1",
        "profile": rr6.RR4A_PROFILE,
        "state": "applied",
        "operations": [{"relative_path": "Windows/System32/drivers/repaired.sys", "before_sha256": "1" * 64, "after_sha256": _sha(driver)}],
    }
    # _fixture creates its own root, so write the same repair file after it is created.
    root, ev = _fixture(tmp_path / "case", repairs_performed=True, transaction=tx)
    driver = root / "Windows/System32/drivers/repaired.sys"
    driver.parent.mkdir(parents=True, exist_ok=True)
    driver.write_bytes(b"repaired-state")
    tx["operations"][0]["after_sha256"] = _sha(driver)
    assert ev.repair_transaction_path is not None
    _write(ev.repair_transaction_path, tx)
    _refresh_provenance(ev, root, repairs_performed=True)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_RECOVERED


def test_repair_transaction_failed_state_is_refused(tmp_path: Path):
    tx = {"schema": "bc-sentinel-rr4a-transaction-v1", "profile": rr6.RR4A_PROFILE, "state": "rollback_failed", "operations": [{"relative_path": "Windows/System32/drivers/x.sys", "before_sha256": "1" * 64, "after_sha256": "2" * 64}]}
    root, ev = _fixture(tmp_path, repairs_performed=True, transaction=tx)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_REFUSED
    assert any(reason.startswith("repair_transaction_untrusted_state") for reason in report["refusal_reasons"])


def test_repair_applied_hash_mismatch_means_not_recovered(tmp_path: Path):
    root = _root(tmp_path / "seed")
    dummy = root / "Windows/System32/drivers/x.sys"
    dummy.parent.mkdir(parents=True)
    dummy.write_bytes(b"expected")
    tx = {"schema": "bc-sentinel-rr4a-transaction-v1", "profile": rr6.RR4A_PROFILE, "state": "applied", "operations": [{"relative_path": "Windows/System32/drivers/x.sys", "before_sha256": "1" * 64, "after_sha256": _sha(dummy)}]}
    root, ev = _fixture(tmp_path / "case", repairs_performed=True, transaction=tx)
    target = root / "Windows/System32/drivers/x.sys"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"different-current-state")
    _refresh_provenance(ev, root, repairs_performed=True)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["outcome"] == rr6.OUTCOME_NOT_RECOVERED
    assert any(reason.startswith("repair_transaction_state_mismatch") for reason in report["not_recovered_reasons"])


def test_evidence_inside_target_is_refused(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    inside = root / "evidence.json"
    inside.write_bytes(ev.scan_path.read_bytes())
    bad = rr6.CertificationEvidence(inside, ev.baseline_path, ev.provenance_path, ev.repair_transaction_path)
    with pytest.raises(ValueError, match="outside offline target"):
        rr6.certify_recovery(root, bad, tmp_path / "out")


def test_output_inside_target_is_refused(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    with pytest.raises(ValueError, match="outside offline target"):
        rr6.certify_recovery(root, ev, root / "rr6-output")


def test_safety_flags_never_enable_mutation(tmp_path: Path):
    root, ev = _fixture(tmp_path)
    report = rr6.certify_recovery(root, ev, tmp_path / "out")
    assert report["safety"] == {
        "target_read_only": True,
        "target_execution": False,
        "registry_write": False,
        "boot_write": False,
        "file_delete": False,
        "quarantine_execution": False,
        "repair_execution": False,
        "automatic_destructive_action": False,
        "format_or_reimage_suppressed": False,
    }
