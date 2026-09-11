from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_console as b40
from sentinel import rescue_console_integrated_certification as b44
from sentinel import rescue_integrity_certification as rr6
from sentinel import rescue_offline_scanner as rr3


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _root(base: Path) -> Path:
    root = base / "offline-target"
    config = root / "Windows/System32/config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"B44 TEST SYSTEM")
    (config / "SOFTWARE").write_bytes(b"B44 TEST SOFTWARE")
    (root / "Windows/System32/ntoskrnl.exe").write_bytes(b"MZ B44 TEST KERNEL")
    return root


def _session(base: Path) -> tuple[Path, Path, Path]:
    root = _root(base)
    workspace = base / "workspace"
    plan = b40.build_session_plan(b40.RescueConsoleRequest(root, workspace))
    b40.write_session_plan(plan, workspace / "session-plan.json", root)
    rr3.scan_offline_windows(root, workspace / "rr3")
    return root, workspace, workspace / "rr3/rr3-offline-scan.json"


def _cert_evidence(base: Path, root: Path, scan: Path) -> tuple[Path, Path]:
    evidence = base / "evidence"
    baseline = evidence / "critical-baseline.json"
    provenance = evidence / "provenance.json"
    fp = rr6.target_fingerprint(root)
    _write(baseline, {
        "schema": rr6.BASELINE_SCHEMA,
        "target_fingerprint": fp,
        "entries": [
            {"relative_path": rel, "sha256": _sha(root / rel), "required": True}
            for rel in rr6.MANDATORY_CRITICAL_PATHS
        ],
    })
    _write(provenance, {
        "schema": rr6.PROVENANCE_SCHEMA,
        "approved": True,
        "target_fingerprint": fp,
        "repairs_performed": False,
        "evidence": [
            {"kind": "rr3_scan", "path": str(scan.resolve()), "sha256": _sha(scan)},
            {"kind": "critical_baseline", "path": str(baseline.resolve()), "sha256": _sha(baseline)},
        ],
    })
    return baseline, provenance


def _refresh_provenance(provenance: Path, scan: Path, baseline: Path, root: Path) -> None:
    payload = json.loads(provenance.read_text(encoding="utf-8"))
    payload["target_fingerprint"] = rr6.target_fingerprint(root)
    for item in payload["evidence"]:
        if item["kind"] == "rr3_scan":
            item["sha256"] = _sha(scan)
        if item["kind"] == "critical_baseline":
            item["sha256"] = _sha(baseline)
    _write(provenance, payload)


def _request(base: Path) -> tuple[b44.IntegratedCertificationRequest, Path, Path, Path, Path, Path]:
    root, workspace, scan = _session(base)
    baseline, provenance = _cert_evidence(base, root, scan)
    return b44.IntegratedCertificationRequest(root, workspace, scan, baseline, provenance), root, workspace, scan, baseline, provenance


def test_clean_session_preserves_recovered(tmp_path: Path) -> None:
    req, *_ = _request(tmp_path)
    result = b44.run_integrated_certification(req)
    assert result["outcome"] == rr6.OUTCOME_RECOVERED
    assert result["certified_recovered"] is True
    assert result["rr6_invoked"] is True


def test_trusted_ioc_preserves_not_recovered(tmp_path: Path) -> None:
    req, root, _workspace, scan, baseline, provenance = _request(tmp_path)
    payload = json.loads(scan.read_text(encoding="utf-8"))
    payload["summary"]["ioc_hits"] = 1
    payload["findings"].append({
        "relative_path": "Windows/System32/ntoskrnl.exe",
        "category": "system32",
        "size": (root / "Windows/System32/ntoskrnl.exe").stat().st_size,
        "sha256": _sha(root / "Windows/System32/ntoskrnl.exe"),
        "status": "hashed",
        "verdict": "deterministic_ioc",
        "reasons": ["approved_sha256_ioc_match"],
        "ioc_name": "B44.Test.IOC",
        "yara_matches": [],
        "automatic_action": False,
    })
    _write(scan, payload)
    _refresh_provenance(provenance, scan, baseline, root)
    result = b44.run_integrated_certification(req)
    assert result["outcome"] == rr6.OUTCOME_NOT_RECOVERED
    assert result["certified_recovered"] is False
    assert "unresolved_deterministic_ioc" in result["rr6_not_recovered_reasons"]


def test_untrusted_b41_scan_refuses_before_rr6(tmp_path: Path) -> None:
    req, _root, _workspace, scan, _baseline, _provenance = _request(tmp_path)
    payload = json.loads(scan.read_text(encoding="utf-8"))
    payload["summary"]["truncated_by_max_files"] = True
    _write(scan, payload)
    result = b44.run_integrated_certification(req)
    assert result["outcome"] == rr6.OUTCOME_REFUSED
    assert result["rr6_invoked"] is False
    assert "b41_trusted_scan_required" in result["session_refusal_reasons"][0]


def test_tampered_rr6_provenance_preserves_rr6_refusal(tmp_path: Path) -> None:
    req, _root, _workspace, _scan, _baseline, provenance = _request(tmp_path)
    payload = json.loads(provenance.read_text(encoding="utf-8"))
    payload["evidence"][0]["sha256"] = "0" * 64
    _write(provenance, payload)
    result = b44.run_integrated_certification(req)
    assert result["outcome"] == rr6.OUTCOME_REFUSED
    assert result["rr6_invoked"] is True
    assert "provenance_hash_mismatch:rr3_scan" in result["rr6_refusal_reasons"]


def test_b40_target_binding_mismatch_refuses_before_rr6(tmp_path: Path) -> None:
    req, _root, workspace, _scan, _baseline, _provenance = _request(tmp_path)
    plan_path = workspace / "session-plan.json"
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["target_fingerprint"] = "0" * 64
    _write(plan_path, payload)
    result = b44.run_integrated_certification(req)
    assert result["outcome"] == rr6.OUTCOME_REFUSED
    assert result["rr6_invoked"] is False
    assert "b40_session_plan_target_fingerprint_mismatch" in result["session_refusal_reasons"][0]


def test_b42_scan_binding_mismatch_refuses(tmp_path: Path) -> None:
    req, root, workspace, scan, _baseline, _provenance = _request(tmp_path)
    handoff = workspace / "b42-repair-handoff.json"
    _write(handoff, {
        "profile": b44.B42_PROFILE,
        "target_fingerprint": rr6.target_fingerprint(root),
        "trusted_scan_sha256": "0" * 64,
        "operator_confirmation_required": True,
        "execution_performed": False,
        "automatic_execution": False,
        "automatic_repair": False,
        "plan_sha256": "1" * 64,
    })
    req = b44.IntegratedCertificationRequest(req.target_root, req.workspace, scan, req.baseline_path, req.provenance_path, b42_handoff_path=handoff)
    result = b44.run_integrated_certification(req)
    assert result["outcome"] == rr6.OUTCOME_REFUSED
    assert result["rr6_invoked"] is False
    assert "b42_handoff_scan_binding_mismatch" in result["session_refusal_reasons"][0]


def test_repair_transaction_requires_b42_handoff(tmp_path: Path) -> None:
    req, root, workspace, scan, _baseline, _provenance = _request(tmp_path)
    tx = workspace / "transaction.json"
    _write(tx, {"profile": rr6.RR4A_PROFILE, "plan_sha256": "1" * 64, "state": "applied", "operations": []})
    req = b44.IntegratedCertificationRequest(req.target_root, req.workspace, scan, req.baseline_path, req.provenance_path, repair_transaction_path=tx)
    result = b44.run_integrated_certification(req)
    assert result["outcome"] == rr6.OUTCOME_REFUSED
    assert "repair_transaction_requires_b42_handoff" in result["session_refusal_reasons"][0]


def test_b43_manifest_hash_mismatch_refuses(tmp_path: Path) -> None:
    req, root, workspace, scan, _baseline, _provenance = _request(tmp_path)
    destination = tmp_path / "rescued"
    destination.mkdir()
    manifest = destination / "rr5-rescue-manifest.json"
    _write(manifest, {
        "profile": b44.RR5_PROFILE,
        "source_root": str(root.resolve()),
        "summary": {"errors": 0},
    })
    summary = workspace / "b43-guided-data-rescue-summary.json"
    _write(summary, {
        "profile": b44.B43_PROFILE,
        "target_fingerprint": rr6.target_fingerprint(root),
        "trusted_scan_sha256": _sha(scan),
        "execution_requested": True,
        "manifest_path": str(manifest.resolve()),
        "manifest_sha256": "0" * 64,
        "safety": {"source_read_only": True, "repair_execution": False, "recovery_certification": False},
    })
    req = b44.IntegratedCertificationRequest(req.target_root, req.workspace, scan, req.baseline_path, req.provenance_path, b43_summary_path=summary)
    result = b44.run_integrated_certification(req)
    assert result["outcome"] == rr6.OUTCOME_REFUSED
    assert result["rr6_invoked"] is False
    assert "b43_manifest_hash_mismatch" in result["session_refusal_reasons"][0]


def test_valid_b43_manifest_is_bound_into_final_summary(tmp_path: Path) -> None:
    req, root, workspace, scan, _baseline, _provenance = _request(tmp_path)
    destination = tmp_path / "rescued"
    destination.mkdir()
    manifest = destination / "rr5-rescue-manifest.json"
    _write(manifest, {
        "profile": b44.RR5_PROFILE,
        "source_root": str(root.resolve()),
        "summary": {"errors": 0},
    })
    summary = workspace / "b43-guided-data-rescue-summary.json"
    _write(summary, {
        "profile": b44.B43_PROFILE,
        "target_fingerprint": rr6.target_fingerprint(root),
        "trusted_scan_sha256": _sha(scan),
        "execution_requested": True,
        "manifest_path": str(manifest.resolve()),
        "manifest_sha256": _sha(manifest),
        "safety": {"source_read_only": True, "repair_execution": False, "recovery_certification": False},
    })
    req = b44.IntegratedCertificationRequest(req.target_root, req.workspace, scan, req.baseline_path, req.provenance_path, b43_summary_path=summary)
    result = b44.run_integrated_certification(req)
    assert result["outcome"] == rr6.OUTCOME_RECOVERED
    assert result["evidence"]["b43_manifest_sha256"] == _sha(manifest)


def test_target_remains_byte_identical(tmp_path: Path) -> None:
    req, root, *_ = _request(tmp_path)
    before = {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}
    b44.run_integrated_certification(req)
    after = {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}
    assert before == after


def test_summary_hash_is_self_consistent_and_safety_remains_read_only(tmp_path: Path) -> None:
    req, _root, workspace, *_ = _request(tmp_path)
    result = b44.run_integrated_certification(req)
    payload = dict(result)
    expected = payload.pop("summary_sha256")
    actual = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    assert expected == actual
    assert (workspace / "b44-session-summary.json").is_file()
    assert result["safety"]["target_read_only"] is True
    assert result["safety"]["repair_execution"] is False
    assert result["safety"]["automatic_destructive_action"] is False
    assert result["safety"]["format_or_reimage_suppressed"] is False


def test_workspace_inside_target_is_refused(tmp_path: Path) -> None:
    root = _root(tmp_path)
    with pytest.raises(ValueError):
        b44.run_integrated_certification(b44.IntegratedCertificationRequest(
            root,
            root / "workspace",
            tmp_path / "scan.json",
            tmp_path / "baseline.json",
            tmp_path / "provenance.json",
        ))
