from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel import rescue_integrity_certification as rr6


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _root(base: Path) -> Path:
    root = base / "offline-target"
    config = root / "Windows/System32/config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"RR6 ACCEPTANCE SYSTEM")
    (config / "SOFTWARE").write_bytes(b"RR6 ACCEPTANCE SOFTWARE")
    (root / "Windows/System32/ntoskrnl.exe").write_bytes(b"MZ RR6 ACCEPTANCE KERNEL")
    return root


def _create_clean_evidence(base: Path, root: Path) -> rr6.CertificationEvidence:
    evdir = base / "evidence"
    scan = evdir / "rr3-scan.json"
    baseline = evdir / "critical-baseline.json"
    provenance = evdir / "provenance.json"
    fp = rr6.target_fingerprint(root)
    _write(scan, {
        "profile": rr6.RR3_PROFILE,
        "summary": {"enumerated": 3, "hashed": 3, "skipped": 0, "errors": 0, "ioc_hits": 0, "yara_hits": 0, "heuristic_review_items": 0, "registry_hives": 2, "truncated_by_max_files": False},
        "findings": [],
        "registry_hives": [
            {"label": "system:SYSTEM", "sha256": _sha(root / "Windows/System32/config/SYSTEM"), "status": "hashed", "write_attempted": False},
            {"label": "system:SOFTWARE", "sha256": _sha(root / "Windows/System32/config/SOFTWARE"), "status": "hashed", "write_attempted": False},
        ],
    })
    _write(baseline, {
        "schema": rr6.BASELINE_SCHEMA,
        "target_fingerprint": fp,
        "entries": [{"relative_path": rel, "sha256": _sha(root / rel), "required": True} for rel in rr6.MANDATORY_CRITICAL_PATHS],
    })
    _write(provenance, {
        "schema": rr6.PROVENANCE_SCHEMA,
        "approved": True,
        "target_fingerprint": fp,
        "repairs_performed": False,
        "evidence": [
            {"kind": "rr3_scan", "path": scan.name, "sha256": _sha(scan)},
            {"kind": "critical_baseline", "path": baseline.name, "sha256": _sha(baseline)},
        ],
        "lineage": {"rr3": rr6.RR3_PROFILE, "rr6": rr6.PROFILE},
    })
    return rr6.CertificationEvidence(scan, baseline, provenance)


def _refresh_provenance(ev: rr6.CertificationEvidence, root: Path) -> None:
    p = json.loads(ev.provenance_path.read_text(encoding="utf-8"))
    p["target_fingerprint"] = rr6.target_fingerprint(root)
    for item in p["evidence"]:
        if item["kind"] == "rr3_scan":
            item["sha256"] = _sha(ev.scan_path)
        elif item["kind"] == "critical_baseline":
            item["sha256"] = _sha(ev.baseline_path)
    _write(ev.provenance_path, p)


def run_acceptance() -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-rr6-") as temp_name:
        base = Path(temp_name)

        clean_root = _root(base / "clean")
        clean_ev = _create_clean_evidence(base / "clean", clean_root)
        before = {str(p.relative_to(clean_root)): _sha(p) for p in clean_root.rglob("*") if p.is_file()}
        clean_report = rr6.certify_recovery(clean_root, clean_ev, base / "clean-report")
        after = {str(p.relative_to(clean_root)): _sha(p) for p in clean_root.rglob("*") if p.is_file()}

        threat_root = _root(base / "threat")
        threat_ev = _create_clean_evidence(base / "threat", threat_root)
        threat_scan = json.loads(threat_ev.scan_path.read_text(encoding="utf-8"))
        threat_scan["summary"]["ioc_hits"] = 1
        threat_scan["findings"] = [{"relative_path": "Windows/System32/ntoskrnl.exe", "sha256": _sha(threat_root / "Windows/System32/ntoskrnl.exe"), "verdict": "deterministic_ioc"}]
        _write(threat_ev.scan_path, threat_scan)
        _refresh_provenance(threat_ev, threat_root)
        threat_report = rr6.certify_recovery(threat_root, threat_ev, base / "threat-report")

        incomplete_root = _root(base / "incomplete")
        incomplete_ev = _create_clean_evidence(base / "incomplete", incomplete_root)
        incomplete_scan = json.loads(incomplete_ev.scan_path.read_text(encoding="utf-8"))
        incomplete_scan["summary"]["truncated_by_max_files"] = True
        _write(incomplete_ev.scan_path, incomplete_scan)
        _refresh_provenance(incomplete_ev, incomplete_root)
        incomplete_report = rr6.certify_recovery(incomplete_root, incomplete_ev, base / "incomplete-report")

        tamper_root = _root(base / "tamper")
        tamper_ev = _create_clean_evidence(base / "tamper", tamper_root)
        tampered_scan = json.loads(tamper_ev.scan_path.read_text(encoding="utf-8"))
        tampered_scan["summary"]["enumerated"] = 999
        _write(tamper_ev.scan_path, tampered_scan)
        tamper_report = rr6.certify_recovery(tamper_root, tamper_ev, base / "tamper-report")

        checks = {
            "profile": rr6.PROFILE == "v0.11.0-beta.3-rr6",
            "clean_certified_recovered": clean_report["outcome"] == rr6.OUTCOME_RECOVERED and clean_report["certified_recovered"] is True,
            "clean_target_unchanged": before == after,
            "clean_report_hash_present": len(clean_report["report_sha256"]) == 64,
            "unresolved_ioc_not_recovered": threat_report["outcome"] == rr6.OUTCOME_NOT_RECOVERED and "unresolved_deterministic_ioc" in threat_report["not_recovered_reasons"],
            "incomplete_scan_refused": incomplete_report["outcome"] == rr6.OUTCOME_REFUSED and "rr3_scan_truncated" in incomplete_report["refusal_reasons"],
            "tampered_evidence_refused": tamper_report["outcome"] == rr6.OUTCOME_REFUSED and "provenance_hash_mismatch:rr3_scan" in tamper_report["refusal_reasons"],
            "no_target_execution": clean_report["safety"]["target_execution"] is False,
            "no_registry_write": clean_report["safety"]["registry_write"] is False,
            "no_boot_write": clean_report["safety"]["boot_write"] is False,
            "no_delete": clean_report["safety"]["file_delete"] is False,
            "no_repair_execution": clean_report["safety"]["repair_execution"] is False,
            "no_automatic_destructive_action": clean_report["safety"]["automatic_destructive_action"] is False,
            "reimage_not_suppressed": clean_report["safety"]["format_or_reimage_suppressed"] is False,
        }
        return {
            "profile": rr6.PROFILE,
            "checkpoint": "RR-6-integrity-verification-recovery-certification",
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "clean_outcome": clean_report["outcome"],
                "clean_report_sha256": clean_report["report_sha256"],
                "not_recovered_outcome": threat_report["outcome"],
                "refused_outcome": incomplete_report["outcome"],
                "tamper_outcome": tamper_report["outcome"],
            },
            "live_host_mutation_enabled": False,
            "automatic_destructive_action_enabled": False,
            "format_or_reimage_suppressed": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    result = run_acceptance()
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
