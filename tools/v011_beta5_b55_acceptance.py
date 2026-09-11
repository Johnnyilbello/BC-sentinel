from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from sentinel import rescue_integrity_certification as rr6
from sentinel import rescue_recovery_decision as b54
from sentinel import rescue_technician_report as b55

PROFILE = b55.PROFILE
CHECKPOINT = "B5-5-technician-report-evidence-package"


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
    (cfg / "SYSTEM").write_bytes(b"B55 ACCEPTANCE SYSTEM")
    (cfg / "SOFTWARE").write_bytes(b"B55 ACCEPTANCE SOFTWARE")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ B55 ACCEPTANCE KERNEL")
    (root / "Users" / "Alice" / "Documents").mkdir(parents=True)
    (root / "Users" / "Alice" / "Documents" / "notes.txt").write_text("acceptance notes", encoding="utf-8")
    return root


def tree_hashes(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file() and not p.is_symlink()
    }


def make_decision(path: Path, fingerprint: str, source_dir: Path) -> tuple[Path, dict[str, Path]]:
    cert = write_json(source_dir / "b44-certification.json", {
        "kind": "b44-certification",
        "target_fingerprint": fingerprint,
        "outcome": rr6.OUTCOME_RECOVERED,
    })
    health = write_json(source_dir / "b51-health.json", {
        "kind": "b51-health",
        "target_fingerprint": fingerprint,
        "state": "HEALTHY",
    })
    stress = write_json(source_dir / "b52-stress.json", {
        "kind": "b52-stress",
        "target_fingerprint": fingerprint,
        "state": "COMPLETE",
    })
    untrusted = write_json(source_dir / "b53-untrusted.json", {
        "kind": "b53-resume",
        "state": "REFUSED",
        "reason": "acceptance_untrusted_fixture",
    })
    rescue = write_json(source_dir / "b43-data-rescue.json", {
        "execution_requested": True,
        "manifest_sha256": "a" * 64,
        "manifest_path": str(source_dir / "rr5-manifest.json"),
        "summary": {"records": 4, "copied": 4, "contained": 2, "skipped": 0, "errors": 0},
    })

    evidence_index = {
        "b44_certification": {"path": str(cert), "file_sha256": file_sha(cert), "trusted": True},
        "b51_health": {"path": str(health), "file_sha256": file_sha(health), "trusted": True},
        "b52_stress": {"path": str(stress), "file_sha256": file_sha(stress), "trusted": True},
        "b53_resume": {"path": str(untrusted), "file_sha256": "", "trusted": False},
        "b43_data_rescue": {"path": str(rescue), "file_sha256": file_sha(rescue), "trusted": True},
    }
    core = {
        "schema": b54.SCHEMA,
        "profile": b54.PROFILE,
        "target_fingerprint": fingerprint,
        "rr6_outcome": rr6.OUTCOME_RECOVERED,
        "rr6_certified_recovered": True,
        "state": b54.STATE_MANUAL_REVIEW,
        "reasons": ["rr6_certified_recovered_preserved", "acceptance_operator_review"],
        "next_action": "Perform technician sign-off and retain the evidence package.",
        "evidence_index": evidence_index,
        "signals": {
            "health_state": "HEALTHY",
            "stress_state": "COMPLETE",
            "resume_state": "",
            "resume_reconfirm_required": False,
            "repair_handoff_available": False,
            "data_rescue_available": True,
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
    return write_json(path, payload), {
        "cert": cert,
        "health": health,
        "stress": stress,
        "untrusted": untrusted,
        "rescue": rescue,
    }


def build_live_fixture(base: Path) -> dict[str, str]:
    base.mkdir(parents=True, exist_ok=True)
    target = make_windows(base / "offline")
    fp = rr6.target_fingerprint(target)
    decision, _ = make_decision(base / "decision.json", fp, base / "source-evidence")
    return {
        "target": str(target),
        "decision": str(decision),
        "package": str(base / "package"),
    }


def run_acceptance(output: Path, fixture_dir: Path | None = None) -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-b55-") as td:
        base = Path(td)
        target = make_windows(base / "offline")
        fingerprint = rr6.target_fingerprint(target)
        source_dir = base / "source-evidence"
        decision, sources = make_decision(base / "decision.json", fingerprint, source_dir)
        before = tree_hashes(target)

        package = base / "package"
        built = b55.create_package(b55.ReportRequest(target, decision, package))
        verified = b55.verify_package(package)
        after = tree_hashes(target)

        report = json.loads((package / b55.REPORT_JSON).read_text(encoding="utf-8"))
        index = json.loads((package / b55.EVIDENCE_INDEX_JSON).read_text(encoding="utf-8"))
        manifest = json.loads((package / b55.MANIFEST_JSON).read_text(encoding="utf-8"))
        human = (package / b55.REPORT_MD).read_text(encoding="utf-8")

        tamper_package = base / "tamper-package"
        shutil.copytree(package, tamper_package)
        copied = next((tamper_package / b55.EVIDENCE_DIR).glob("*b44_certification*.json"))
        copied.write_text('{"tampered":true}\n', encoding="utf-8")
        tamper_verify = b55.verify_package(tamper_package)

        drift_target = make_windows(base / "drift-offline")
        drift_fp = rr6.target_fingerprint(drift_target)
        drift_decision, drift_sources = make_decision(base / "drift-decision.json", drift_fp, base / "drift-source")
        drift_sources["cert"].write_text('{"drift":true}\n', encoding="utf-8")
        drift_refused = False
        drift_reason = ""
        try:
            b55.create_package(b55.ReportRequest(drift_target, drift_decision, base / "drift-package"))
        except Exception as exc:
            drift_refused = True
            drift_reason = f"{type(exc).__name__}:{exc}"

        untrusted_row = next(row for row in index["records"] if row["label"] == "b53_resume")
        checks = {
            "profile": built.get("profile") == PROFILE,
            "build_self_verified": built.get("verification_passed") is True,
            "verify_passed": verified.get("passed") is True,
            "human_report_present": (package / b55.REPORT_MD).is_file(),
            "json_report_present": (package / b55.REPORT_JSON).is_file(),
            "evidence_index_present": (package / b55.EVIDENCE_INDEX_JSON).is_file(),
            "manifest_present": (package / b55.MANIFEST_JSON).is_file(),
            "report_hash_present": len(str(built.get("report_sha256", ""))) == 64,
            "index_hash_present": len(str(built.get("evidence_index_sha256", ""))) == 64,
            "manifest_hash_present": len(str(built.get("manifest_sha256", ""))) == 64,
            "rr6_outcome_preserved": report.get("rr6_outcome") == rr6.OUTCOME_RECOVERED,
            "advisory_state_preserved": report.get("advisory_state") == b54.STATE_MANUAL_REVIEW,
            "trusted_evidence_copied": int(built.get("trusted_copied", 0)) >= 5,
            "untrusted_evidence_not_copied": built.get("untrusted_not_copied") == 1 and untrusted_row.get("copied") is False,
            "untrusted_risk_preserved": any("untrusted_evidence:b53_resume" in item for item in report.get("unresolved_risks", [])),
            "data_rescue_summary_preserved": report.get("data_rescue", {}).get("copied") == 4 and report.get("data_rescue", {}).get("contained") == 2,
            "human_report_has_next_action": "Perform technician sign-off" in human,
            "manifest_schema": manifest.get("schema") == b55.MANIFEST_SCHEMA,
            "target_byte_identical": before == after,
            "tampered_package_detected": tamper_verify.get("passed") is False and any("sha256_mismatch" in item for item in tamper_verify.get("errors", [])),
            "trusted_source_drift_refused": drift_refused and "trusted_evidence_sha256_drift" in drift_reason,
            "report_only": report.get("safety", {}).get("report_only") is True,
            "no_repair_execution": report.get("safety", {}).get("repair_execution") is False,
            "no_data_rescue_execution": report.get("safety", {}).get("data_rescue_execution") is False,
            "no_reimage_execution": report.get("safety", {}).get("format_or_reimage_execution") is False,
            "no_registry_write": report.get("safety", {}).get("registry_write") is False,
            "no_boot_write": report.get("safety", {}).get("boot_write") is False,
            "no_target_execution": report.get("safety", {}).get("target_execution") is False,
            "no_automatic_destructive_action": report.get("safety", {}).get("automatic_destructive_action") is False,
        }
        live_fixture = build_live_fixture(fixture_dir) if fixture_dir is not None else {}
        payload = {
            "profile": PROFILE,
            "checkpoint": CHECKPOINT,
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "target_fingerprint": fingerprint,
                "report_sha256": built["report_sha256"],
                "evidence_index_sha256": built["evidence_index_sha256"],
                "manifest_sha256": built["manifest_sha256"],
                "evidence_records": built["evidence_records"],
                "trusted_copied": built["trusted_copied"],
                "untrusted_not_copied": built["untrusted_not_copied"],
                "advisory_state": built["advisory_state"],
                "rr6_outcome": built["rr6_outcome"],
                "tamper_errors": tamper_verify.get("errors", []),
                "drift_refusal": drift_reason,
                "live_fixture": live_fixture,
            },
            "new_mutation_authority_added": False,
            "automatic_destructive_action_enabled": False,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--fixture-dir")
    args = parser.parse_args()
    payload = run_acceptance(Path(args.output), Path(args.fixture_dir) if args.fixture_dir else None)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
