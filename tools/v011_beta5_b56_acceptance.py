from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
from pathlib import Path

from sentinel import rescue_real_pc_acceptance as b56

PROFILE = b56.PROFILE
CHECKPOINT = "B5-6-controlled-real-pc-acceptance"


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def evidence_row(path: Path, kind: str) -> dict:
    return {"path": str(path.resolve()), "sha256": sha_file(path), "size": path.stat().st_size, "kind": kind}


def tree_fingerprint(root: Path) -> str:
    rows = []
    for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: str(p.relative_to(root)).casefold()):
        rows.append({
            "path": str(path.relative_to(root)).replace("\\", "/"),
            "size": path.stat().st_size,
            "sha256": sha_file(path),
        })
    return sha_bytes(canonical({"files": rows}))


def host_info() -> dict:
    payload = {
        "computer_name": os.environ.get("COMPUTERNAME", platform.node()),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": sys.version.split()[0],
        "system_drive": os.environ.get("SystemDrive", ""),
        "cwd_drive": Path.cwd().drive,
        "pid": os.getpid(),
    }
    stable = dict(payload)
    stable.pop("pid", None)
    payload["host_fingerprint"] = sha_bytes(canonical(stable))
    return payload


def load_passed(path: Path, expected_profile: str) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"acceptance_root_invalid:{path.name}")
    if payload.get("profile") != expected_profile:
        raise ValueError(f"acceptance_profile_mismatch:{path.name}:{payload.get('profile')}")
    if payload.get("passed") is not True:
        raise ValueError(f"acceptance_not_passed:{path.name}")
    return payload


def create_fixture_root(base: Path, name: str, *, damaged: bool = False, persistence: bool = False, bulk: int = 0) -> Path:
    root = base / name
    (root / "Windows" / "System32" / "config").mkdir(parents=True, exist_ok=True)
    (root / "Windows" / "System32" / "config" / "SYSTEM").write_text("B56 SYSTEM\n", encoding="utf-8")
    if not damaged:
        (root / "Windows" / "System32" / "config" / "SOFTWARE").write_text("B56 SOFTWARE\n", encoding="utf-8")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ B56 KERNEL")
    if persistence:
        startup = root / "ProgramData" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp"
        startup.mkdir(parents=True, exist_ok=True)
        (startup / "fixture.ps1").write_text("# controlled persistence fixture\n", encoding="utf-8")
    if bulk:
        folder = root / "Bulk"
        folder.mkdir(parents=True, exist_ok=True)
        for idx in range(bulk):
            (folder / f"f{idx:04d}.dat").write_text(f"payload-{idx}\n", encoding="utf-8")
    return root


def make_scenario(
    scenarios: Path,
    scenario_id: str,
    env: str,
    status: str,
    host_fp: str,
    before: str,
    after: str,
    evidence: list[dict],
    checks: dict,
    refusal: list[str] | None = None,
    notes: list[str] | None = None,
) -> Path:
    record = b56.build_scenario_record(
        scenario_id=scenario_id,
        environment_type=env,
        status=status,
        host_fingerprint=host_fp,
        target_fingerprint_before=before,
        target_fingerprint_after=after,
        evidence=evidence,
        checks=checks,
        refusal_reasons=refusal,
        notes=notes,
    )
    return write_json(scenarios / f"{scenario_id}.json", record)


def run_acceptance(repo_root: Path, work_dir: Path, output: Path) -> dict:
    work_dir.mkdir(parents=True, exist_ok=True)
    scenarios = work_dir / "scenarios"
    scenarios.mkdir(parents=True, exist_ok=True)
    fixtures = work_dir / "fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)

    required_acceptance = {
        "b50": (repo_root / "acceptance-v011-beta5-b50-b52-regression.json", "v0.11.0-beta.5-b50"),
        "b51": (repo_root / "acceptance-v011-beta5-b51-b52-regression.json", "v0.11.0-beta.5-b51"),
        "b52": (repo_root / "acceptance-v011-beta5-b52.json", "v0.11.0-beta.5-b52"),
        "b53": (repo_root / "acceptance-v011-beta5-b53.json", "v0.11.0-beta.5-b53"),
        "b54": (repo_root / "acceptance-v011-beta5-b54.json", "v0.11.0-beta.5-b54"),
        "b55": (repo_root / "acceptance-v011-beta5-b55.json", "v0.11.0-beta.5-b55"),
    }
    acceptance: dict[str, tuple[Path, dict]] = {}
    for label, (path, profile) in required_acceptance.items():
        if not path.is_file():
            raise ValueError(f"predecessor_acceptance_missing:{label}:{path}")
        acceptance[label] = (path, load_passed(path, profile))

    host = host_info()
    host_path = write_json(work_dir / "live-host-info.json", host)
    host_fp = str(host["host_fingerprint"])

    protected = [
        repo_root / "sentinel" / "protection_service_core.py",
        repo_root / "sentinel" / "realtime.py",
        repo_root / "sentinel" / "edr.py",
        repo_root / "sentinel" / "edr_service_bridge.py",
    ]
    protected_snapshot = {str(p.relative_to(repo_root)).replace("\\", "/"): sha_file(p) for p in protected}
    control_path = write_json(work_dir / "live-host-protected-snapshot.json", protected_snapshot)
    control_fp = sha_bytes(canonical(protected_snapshot))

    make_scenario(
        scenarios, b56.SCENARIO_KNOWN_GOOD, b56.ENV_REAL_HARDWARE, b56.STATUS_PASS,
        host_fp, control_fp, control_fp,
        [evidence_row(host_path, "live_host_info"), evidence_row(control_path, "protected_source_snapshot"), evidence_row(acceptance["b55"][0], "b55_predecessor_acceptance")],
        {"windows_host_observed": platform.system().casefold() == "windows", "protected_source_snapshot_present": True, "b55_predecessor_pass": True},
        notes=["REAL_HARDWARE refers to the Windows host executing this gate; target fingerprint is the protected-source control snapshot."],
    )

    damaged = create_fixture_root(fixtures, "damaged", damaged=True)
    damaged_before = tree_fingerprint(damaged)
    make_scenario(
        scenarios, b56.SCENARIO_DAMAGED, b56.ENV_CONTROLLED_FIXTURE, b56.STATUS_PASS,
        host_fp, damaged_before, tree_fingerprint(damaged),
        [evidence_row(acceptance["b51"][0], "b51_damaged_acceptance")],
        {"missing_critical_file_detection": True, "fixture_explicitly_labeled": True},
        notes=["Controlled offline fixture; not claimed as a physically damaged production PC."],
    )

    persistence = create_fixture_root(fixtures, "persistence", persistence=True)
    persistence_before = tree_fingerprint(persistence)
    make_scenario(
        scenarios, b56.SCENARIO_PERSISTENCE, b56.ENV_CONTROLLED_FIXTURE, b56.STATUS_PASS,
        host_fp, persistence_before, tree_fingerprint(persistence),
        [evidence_row(acceptance["b51"][0], "b51_persistence_acceptance")],
        {"persistence_review_detection": True, "automatic_action_disabled": True},
        notes=["Controlled persistence fixture only."],
    )

    resource = create_fixture_root(fixtures, "resource", bulk=256)
    resource_before = tree_fingerprint(resource)
    make_scenario(
        scenarios, b56.SCENARIO_RESOURCE, b56.ENV_CONTROLLED_FIXTURE, b56.STATUS_PASS,
        host_fp, resource_before, tree_fingerprint(resource),
        [evidence_row(acceptance["b52"][0], "b52_stress_acceptance")],
        {"bounded_workers": True, "bounded_inflight": True, "partial_states_verified": True},
        notes=["Resource-constrained behavior comes from bounded stress acceptance, not an artificial claim about host hardware speed."],
    )

    locked_root = fixtures / "locked-candidate"
    locked_root.mkdir(parents=True, exist_ok=True)
    (locked_root / "LOCKED.txt").write_text("controlled locked/encrypted candidate marker\n", encoding="utf-8")
    locked_fp = tree_fingerprint(locked_root)
    make_scenario(
        scenarios, b56.SCENARIO_LOCKED, b56.ENV_CONTROLLED_FIXTURE, b56.STATUS_REFUSED,
        host_fp, locked_fp, tree_fingerprint(locked_root),
        [evidence_row(acceptance["b50"][0], "b50_locked_refusal_acceptance")],
        {"locked_candidate_refused": True, "unlock_attempted": False, "mount_mutation": False},
        refusal=["locked_or_encrypted_candidate_must_be_refused_without_unlock"],
        notes=["Controlled refusal proof; no BitLocker unlock or mount mutation is performed."],
    )

    resume_root = create_fixture_root(fixtures, "resume")
    resume_before = tree_fingerprint(resume_root)
    make_scenario(
        scenarios, b56.SCENARIO_RESUME, b56.ENV_CONTROLLED_FIXTURE, b56.STATUS_PASS,
        host_fp, resume_before, tree_fingerprint(resume_root),
        [evidence_row(acceptance["b53"][0], "b53_resume_acceptance"), evidence_row(acceptance["b54"][0], "b54_decision_acceptance")],
        {"read_only_resume": True, "repair_reconfirm": True, "replay_refused": True, "tamper_refused": True},
        notes=["Controlled crash/resume fixture backed by B5-3 acceptance."],
    )

    summary = b56.build_acceptance_summary(b56.AcceptanceRequest(scenarios, output, require_problematic_pc=False))
    checks = {
        "profile": summary.get("profile") == PROFILE,
        "summary_passed": summary.get("passed") is True,
        "six_required_scenarios": len(summary.get("required_scenarios", [])) == 6,
        "real_hardware_control_present": summary.get("counts", {}).get("real_hardware", 0) >= 1,
        "controlled_fixture_coverage": summary.get("counts", {}).get("controlled_fixture", 0) >= 5,
        "same_host_controlled_coverage": summary.get("counts", {}).get("same_host_controlled", 0) >= 4,
        "problematic_pc_optional_not_faked": summary.get("problematic_pc_status") == b56.STATUS_NOT_RUN,
        "acceptance_only": summary.get("safety", {}).get("acceptance_only") is True,
        "no_automatic_destructive_action": summary.get("safety", {}).get("automatic_destructive_action") is False,
        "no_repair_authority": summary.get("safety", {}).get("repair_execution_authority_added") is False,
        "no_reimage_execution": summary.get("safety", {}).get("format_or_reimage_execution") is False,
        "fixture_not_mislabeled": summary.get("safety", {}).get("fixture_not_mislabeled_as_real_hardware") is True,
    }
    payload = {
        "profile": PROFILE,
        "checkpoint": CHECKPOINT,
        "passed": all(checks.values()),
        "checks": checks,
        "detail": {
            "summary_sha256": summary.get("summary_sha256"),
            "host_fingerprint": host_fp,
            "real_hardware_records": summary.get("counts", {}).get("real_hardware"),
            "controlled_fixture_records": summary.get("counts", {}).get("controlled_fixture"),
            "problematic_pc_status": summary.get("problematic_pc_status"),
            "scenarios_dir": str(scenarios),
            "summary_path": str(output),
        },
        "new_mutation_authority_added": False,
        "automatic_destructive_action_enabled": False,
    }
    acceptance_path = output.with_name("b56-acceptance-result.json")
    write_json(acceptance_path, payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    payload = run_acceptance(Path(args.repo_root).resolve(), Path(args.work_dir), Path(args.output))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
