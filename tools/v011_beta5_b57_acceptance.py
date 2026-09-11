from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import tempfile
from pathlib import Path

from sentinel import rescue_technician_portable as b57

PROFILE = b57.PROFILE
CHECKPOINT = "B5-7-portable-technician-release"
EXPECTED_COMMANDS = [
    "plan", "scan", "repair-handoff", "data-rescue", "certify",
    "discover", "assess", "stress", "resume", "decide", "report",
]


def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_fingerprint(root: Path) -> str:
    rows = []
    for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: str(p.relative_to(root)).casefold()):
        rows.append((str(path.relative_to(root)).replace("\\", "/"), path.stat().st_size, sha_file(path)))
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode("utf-8")).hexdigest()


def invoke(argv: list[str]) -> tuple[int, dict]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = b57.main(argv)
    text = buffer.getvalue().strip()
    payload = json.loads(text) if text else {}
    return int(code), payload


def make_target(root: Path) -> Path:
    target = root / "offline"
    config = target / "Windows" / "System32" / "config"
    config.mkdir(parents=True, exist_ok=True)
    (config / "SYSTEM").write_text("B57 SYSTEM\n", encoding="utf-8")
    (config / "SOFTWARE").write_text("B57 SOFTWARE\n", encoding="utf-8")
    (target / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ B57 KERNEL")
    startup = target / "ProgramData" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp"
    startup.mkdir(parents=True, exist_ok=True)
    (startup / "notes.txt").write_text("passive fixture\n", encoding="utf-8")
    bulk = target / "Bulk"
    bulk.mkdir(parents=True, exist_ok=True)
    for idx in range(64):
        (bulk / f"f{idx:03d}.dat").write_text(f"payload-{idx}\n", encoding="utf-8")
    return target


def run_acceptance(output: Path, fixture_dir: Path | None = None) -> dict:
    owned_tmp: tempfile.TemporaryDirectory[str] | None = None
    if fixture_dir is None:
        owned_tmp = tempfile.TemporaryDirectory(prefix="bcs-b57-")
        root = Path(owned_tmp.name)
    else:
        root = Path(fixture_dir)
        root.mkdir(parents=True, exist_ok=True)

    try:
        target = make_target(root)
        before = tree_fingerprint(target)
        workspace = root / "workspace"
        evidence = root / "evidence"
        workspace.mkdir(parents=True, exist_ok=True)
        evidence.mkdir(parents=True, exist_ok=True)

        status_code, status = invoke(["status"])
        refused_code, refused = invoke(["repair-execute"])

        discover_out = evidence / "discover.json"
        discover_code, discover = invoke([
            "discover", str(target), "--no-windows-volumes", "--no-child-probe", "--output", str(discover_out)
        ])

        assess_out = evidence / "assessment.json"
        assess_code, assessment = invoke([
            "assess", "--target-root", str(target), "--output", str(assess_out), "--max-files", "256"
        ])

        stress_out = evidence / "stress.json"
        stress_code, stress = invoke([
            "stress", "--target-root", str(target), "--output", str(stress_out),
            "--max-files", "512", "--max-total-sample-bytes", "8388608", "--max-elapsed-sec", "10",
            "--max-depth", "64", "--sample-bytes", "64", "--max-workers", "2", "--max-inflight", "16"
        ])

        resume_code, resume_init = invoke([
            "resume", "init", "--target-root", str(target), "--workspace", str(workspace)
        ])

        after = tree_fingerprint(target)
        checks = {
            "profile": status.get("profile") == PROFILE,
            "status_passed": status_code == 0 and status.get("passed") is True,
            "command_surface_exact": status.get("commands") == EXPECTED_COMMANDS,
            "portable": status.get("portable") is True,
            "no_installer_service_driver": not any(bool(status.get(k)) for k in ("installer_required", "service_install", "driver_install")),
            "no_network_cloud": status.get("network_required") is False and status.get("cloud_required") is False,
            "repair_execute_refused": refused_code == 2 and refused.get("reason") == "unknown_command:repair-execute",
            "no_new_destructive_authority": status.get("safety", {}).get("automatic_destructive_action") is False and status.get("safety", {}).get("repair_execution_exposed_by_launcher") is False,
            "discover_passed": discover_code == 0 and discover.get("counts", {}).get("READY", 0) == 1,
            "assess_passed": assess_code == 0 and assessment.get("state") in {"HEALTHY", "REVIEW_REQUIRED", "IO_DEGRADED"},
            "stress_passed": stress_code == 0 and stress.get("state") == "COMPLETE",
            "resume_init_passed": resume_code == 0 and str(resume_init.get("profile", "")) == "v0.11.0-beta.5-b53",
            "target_byte_identical": before == after,
            "outputs_outside_target": all(p.is_file() for p in (discover_out, assess_out, stress_out)),
        }
        payload = {
            "profile": PROFILE,
            "checkpoint": CHECKPOINT,
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "target_fingerprint_before": before,
                "target_fingerprint_after": after,
                "discover_state_counts": discover.get("counts", {}),
                "assessment_state": assessment.get("state"),
                "stress_state": stress.get("state"),
                "resume_session_id": resume_init.get("session_id"),
                "commands": status.get("commands", []),
            },
            "new_mutation_authority_added": False,
            "automatic_destructive_action_enabled": False,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return payload
    finally:
        if owned_tmp is not None:
            owned_tmp.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--fixture-dir")
    args = parser.parse_args()
    payload = run_acceptance(Path(args.output), Path(args.fixture_dir) if args.fixture_dir else None)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
