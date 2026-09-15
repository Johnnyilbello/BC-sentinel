from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from sentinel import portable_gui_release as b67


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _target_snapshot(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): _sha256(path)
        for path in root.rglob("*")
        if path.is_file()
    }


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
) -> dict:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return {
            "returncode": completed.returncode,
            "timed_out": False,
            "elapsed_sec": round(time.monotonic() - started, 3),
        }
    except subprocess.TimeoutExpired:
        return {
            "returncode": None,
            "timed_out": True,
            "elapsed_sec": round(time.monotonic() - started, 3),
        }


def run_acceptance(
    *,
    artifact_dir: Path,
    output: Path,
    expected_build_commit: str = "",
) -> dict:
    source_verification = b67.verify_artifact(artifact_dir)
    source_manifest = dict(source_verification.manifest)

    with tempfile.TemporaryDirectory(prefix="BCSentinel-B67-Artifact-") as temp_raw:
        temp = Path(temp_raw)
        portable_root = temp / "portable-copy"
        shutil.copytree(artifact_dir, portable_root)
        copied_verification = b67.verify_artifact(portable_root)
        exe = portable_root / b67.ARTIFACT_EXE

        target = temp / "offline-read-only-target"
        target.mkdir(parents=True)
        (target / "Windows" / "System32" / "config").mkdir(parents=True)
        (target / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(
            b"BC Sentinel B6-7 read-only target SYSTEM fixture\n"
        )
        (target / "sample.bin").write_bytes(b"B6-7 immutable target fixture\n")
        before_target = _target_snapshot(target)

        contract_path = temp / "artifact-runtime-contract.json"
        env = dict(os.environ)
        env["QT_QPA_PLATFORM"] = "offscreen"
        env["BC_SENTINEL_REDUCED_MOTION"] = "1"
        env["BC_SENTINEL_SMART_SCAN_ROOTS"] = str(target)
        # Built GUI startup must remain safe without relying on the development
        # repo or a configured historical runtime. The Smart Scan provider is
        # allowed to fail closed/unavailable until a pinned runtime is supplied.
        for name in (
            "PYTHONPATH",
            "BC_SENTINEL_FULL_RUNTIME_ROOT",
            "BC_SENTINEL_FULL_RUNTIME_SCANNER_SHA256",
            "BC_SENTINEL_FULL_RUNTIME_PYTHON",
        ):
            env.pop(name, None)

        contract_run = _run(
            [str(exe), "--b67-contract-out", str(contract_path)],
            cwd=portable_root,
            env=env,
            timeout=45,
        )
        runtime_contract: dict = {}
        if contract_path.is_file():
            try:
                loaded = json.loads(contract_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    runtime_contract = loaded
            except Exception:
                runtime_contract = {}

        smoke_run = _run(
            [str(exe), "--offscreen-smoke"],
            cwd=portable_root,
            env=env,
            timeout=60,
        )
        after_target = _target_snapshot(target)

        runtime_release = (
            runtime_contract.get("release")
            if isinstance(runtime_contract.get("release"), dict)
            else {}
        )
        checks = {
            "source_artifact_integrity": source_verification.passed,
            "portable_copy_integrity": copied_verification.passed,
            "portable_copy_exe_hash_identical": (
                source_verification.exe_sha256 == copied_verification.exe_sha256
                and bool(source_verification.exe_sha256)
            ),
            "build_commit_matches": (
                not expected_build_commit
                or str(source_manifest.get("build_commit") or "").lower()
                == expected_build_commit.lower()
            ),
            "windowed_onedir_manifest": (
                source_manifest.get("build_mode") == "onedir"
                and source_manifest.get("windowed") is True
                and source_manifest.get("portable") is True
            ),
            "contract_process_exit_zero": (
                contract_run.get("returncode") == 0
                and contract_run.get("timed_out") is False
            ),
            "runtime_contract_written": bool(runtime_contract),
            "runtime_contract_passed": runtime_contract.get("passed") is True,
            "runtime_profile_exact": runtime_contract.get("profile") == b67.PROFILE,
            "runtime_no_general_execution": (
                runtime_release.get("general_home_execution_authorized") is False
            ),
            "runtime_explicit_operator_action": (
                runtime_release.get("explicit_operator_action_required") is True
            ),
            "runtime_no_automatic_quarantine": (
                runtime_release.get("automatic_quarantine") is False
            ),
            "runtime_no_automatic_restore": (
                runtime_release.get("automatic_restore") is False
            ),
            "runtime_no_automatic_repair": (
                runtime_release.get("automatic_repair") is False
            ),
            "runtime_no_installer_service_driver": (
                runtime_release.get("installer_required") is False
                and runtime_release.get("service_install") is False
                and runtime_release.get("driver_install") is False
            ),
            "runtime_no_network_cloud_requirement": (
                runtime_release.get("network_required") is False
                and runtime_release.get("cloud_required") is False
            ),
            "gui_offscreen_smoke_exit_zero": (
                smoke_run.get("returncode") == 0
                and smoke_run.get("timed_out") is False
            ),
            "target_byte_identical": before_target == after_target,
            "target_file_count_identical": len(before_target) == len(after_target),
            "repo_independent_working_directory": portable_root != artifact_dir,
        }
        payload = {
            "schema": "bc-sentinel-beta6-b67-artifact-acceptance-v1",
            "profile": b67.PROFILE,
            "checkpoint": "B6-7-portable-technician-gui-release",
            "passed": all(checks.values()),
            "checks": checks,
            "source_artifact": source_verification.to_dict(),
            "copied_artifact": copied_verification.to_dict(),
            "runtime_contract": runtime_contract,
            "contract_process": contract_run,
            "gui_smoke_process": smoke_run,
            "target_files": len(before_target),
            "general_home_execution_authorized": False,
            "automatic_quarantine": False,
            "automatic_restore": False,
            "automatic_repair": False,
            "installer_required": False,
            "service_install": False,
            "driver_install": False,
            "network_required": False,
            "cloud_required": False,
        }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BC Sentinel B6-7 built portable GUI artifact acceptance"
    )
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--output", default="acceptance-v011-beta6-b67-artifact.json")
    parser.add_argument("--expected-build-commit", default="")
    args = parser.parse_args()

    payload = run_acceptance(
        artifact_dir=Path(args.artifact_dir).resolve(),
        output=Path(args.output),
        expected_build_commit=str(args.expected_build_commit or "").strip(),
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
