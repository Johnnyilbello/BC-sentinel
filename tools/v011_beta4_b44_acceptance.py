from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel import rescue_console as b40
from sentinel import rescue_console_integrated_certification as b44
from sentinel import rescue_integrity_certification as rr6
from sentinel import rescue_offline_scanner as rr3


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _root(base: Path, label: str) -> Path:
    root = base / "offline-target"
    config = root / "Windows/System32/config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(("B44 ACCEPTANCE SYSTEM " + label).encode())
    (config / "SOFTWARE").write_bytes(("B44 ACCEPTANCE SOFTWARE " + label).encode())
    (root / "Windows/System32/ntoskrnl.exe").write_bytes(("MZ B44 ACCEPTANCE KERNEL " + label).encode())
    return root


def _session(base: Path, label: str) -> tuple[Path, Path, Path, Path, Path]:
    root = _root(base, label)
    workspace = base / "workspace"
    plan = b40.build_session_plan(b40.RescueConsoleRequest(root, workspace))
    b40.write_session_plan(plan, workspace / "session-plan.json", root)
    rr3.scan_offline_windows(root, workspace / "rr3")
    scan = workspace / "rr3/rr3-offline-scan.json"
    evidence = base / "evidence"
    baseline = evidence / "critical-baseline.json"
    provenance = evidence / "provenance.json"
    fp = rr6.target_fingerprint(root)
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
            {"kind": "rr3_scan", "path": str(scan.resolve()), "sha256": _sha(scan)},
            {"kind": "critical_baseline", "path": str(baseline.resolve()), "sha256": _sha(baseline)},
        ],
    })
    return root, workspace, scan, baseline, provenance


def _request(base: Path, label: str) -> tuple[b44.IntegratedCertificationRequest, Path, Path, Path, Path, Path]:
    root, workspace, scan, baseline, provenance = _session(base, label)
    req = b44.IntegratedCertificationRequest(root, workspace, scan, baseline, provenance)
    return req, root, workspace, scan, baseline, provenance


def _refresh_provenance(path: Path, scan: Path, baseline: Path, root: Path) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["target_fingerprint"] = rr6.target_fingerprint(root)
    for item in payload["evidence"]:
        if item["kind"] == "rr3_scan":
            item["sha256"] = _sha(scan)
        elif item["kind"] == "critical_baseline":
            item["sha256"] = _sha(baseline)
    _write(path, payload)


def run_acceptance() -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-b44-") as temp_name:
        base = Path(temp_name)

        clean_req, clean_root, clean_workspace, clean_scan, _, _ = _request(base / "clean", "CLEAN")
        before = {str(p.relative_to(clean_root)): _sha(p) for p in clean_root.rglob("*") if p.is_file()}
        clean = b44.run_integrated_certification(clean_req)
        after = {str(p.relative_to(clean_root)): _sha(p) for p in clean_root.rglob("*") if p.is_file()}

        threat_req, threat_root, _threat_workspace, threat_scan, threat_baseline, threat_provenance = _request(base / "threat", "THREAT")
        threat_payload = json.loads(threat_scan.read_text(encoding="utf-8"))
        threat_payload["summary"]["ioc_hits"] = 1
        threat_payload["findings"].append({
            "relative_path": "Windows/System32/ntoskrnl.exe",
            "category": "system32",
            "size": (threat_root / "Windows/System32/ntoskrnl.exe").stat().st_size,
            "sha256": _sha(threat_root / "Windows/System32/ntoskrnl.exe"),
            "status": "hashed",
            "verdict": "deterministic_ioc",
            "reasons": ["approved_sha256_ioc_match"],
            "ioc_name": "B44.Acceptance.IOC",
            "yara_matches": [],
            "automatic_action": False,
        })
        _write(threat_scan, threat_payload)
        _refresh_provenance(threat_provenance, threat_scan, threat_baseline, threat_root)
        threat = b44.run_integrated_certification(threat_req)

        session_req, _session_root, session_workspace, *_ = _request(base / "session-refused", "SESSION")
        plan_path = session_workspace / "session-plan.json"
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan["target_fingerprint"] = "0" * 64
        _write(plan_path, plan)
        session_refused = b44.run_integrated_certification(session_req)

        prov_req, _prov_root, _prov_workspace, _prov_scan, _prov_baseline, prov_path = _request(base / "provenance-refused", "PROVENANCE")
        prov = json.loads(prov_path.read_text(encoding="utf-8"))
        prov["evidence"][0]["sha256"] = "f" * 64
        _write(prov_path, prov)
        rr6_refused = b44.run_integrated_certification(prov_req)

        summary_payload = dict(clean)
        summary_hash = summary_payload.pop("summary_sha256")
        summary_recomputed = hashlib.sha256(json.dumps(summary_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()

        checks = {
            "profile": b44.PROFILE == "v0.11.0-beta.4-b44",
            "clean_recovered": clean["outcome"] == rr6.OUTCOME_RECOVERED and clean["certified_recovered"] is True,
            "clean_rr6_invoked": clean["rr6_invoked"] is True,
            "trusted_ioc_not_recovered": threat["outcome"] == rr6.OUTCOME_NOT_RECOVERED and "unresolved_deterministic_ioc" in threat["rr6_not_recovered_reasons"],
            "session_binding_refused_before_rr6": session_refused["outcome"] == rr6.OUTCOME_REFUSED and session_refused["rr6_invoked"] is False,
            "rr6_provenance_refusal_preserved": rr6_refused["outcome"] == rr6.OUTCOME_REFUSED and rr6_refused["rr6_invoked"] is True,
            "target_unchanged": before == after,
            "summary_hash_self_consistent": summary_hash == summary_recomputed,
            "summary_written": (clean_workspace / "b44-session-summary.json").is_file(),
            "target_read_only": clean["safety"]["target_read_only"] is True,
            "no_repair_execution": clean["safety"]["repair_execution"] is False,
            "no_automatic_destructive_action": clean["safety"]["automatic_destructive_action"] is False,
            "reimage_not_suppressed": clean["safety"]["format_or_reimage_suppressed"] is False,
        }
        return {
            "profile": b44.PROFILE,
            "checkpoint": "B4-4-integrated-certification-session-summary",
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "clean_outcome": clean["outcome"],
                "clean_summary_sha256": clean["summary_sha256"],
                "clean_rr6_report_sha256": clean["rr6_report_sha256"],
                "not_recovered_outcome": threat["outcome"],
                "session_refused_outcome": session_refused["outcome"],
                "rr6_refused_outcome": rr6_refused["outcome"],
            },
            "new_mutation_authority_added": False,
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
