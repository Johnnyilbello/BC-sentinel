from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from sentinel import guided_resolution_provider_loader as provider_loader
from sentinel import home_guided_resolution as guided
from sentinel import home_quarantine as b658
from sentinel import home_threat_cards as threat


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _card(path: Path) -> threat.ThreatCardModel:
    digest = _sha256(path)
    severity = "HIGH"
    finding_id = "b658-live-persistent-restore"
    card = threat.ThreatCardModel(
        finding_id=finding_id,
        title="B6-5.8 persistent restore acceptance",
        severity=severity,
        severity_label=threat.SEVERITY_LABELS[severity],
        severity_role=threat.SEVERITY_ROLES[severity],
        category="acceptance",
        reason="Controlled restart-safe Home restore acceptance",
        source_check_id="files",
        location=str(path),
        confidence=None,
        confidence_label="Non disponibile",
        recommendation="Review before action.",
        advanced_details={
            "finding": {
                "finding_id": finding_id,
                "severity": severity,
                "confidence": None,
                "path": str(path),
                "evidence": {"sha256": digest},
            }
        },
    )
    card.validate()
    return card


def _restore_worker(
    *,
    profile: Path,
    target: Path,
    finding_id: str,
    expected_sha256: str,
    output: Path,
    recovery_path: Path,
    recovery_sha256: str,
    journal_path: Path,
    journal_sha256: str,
) -> int:
    controller = b658.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    active_after_restart = controller.has_active_quarantine(finding_id)
    rows = controller.quarantine_rows()
    row_verified = bool(
        len(rows) == 1
        and rows[0].get("restore_key") == finding_id
        and rows[0].get("action") == "Ripristina file"
    )

    discovery_read_only = bool(
        recovery_path.is_file()
        and journal_path.is_file()
        and _sha256(recovery_path) == recovery_sha256
        and _sha256(journal_path) == journal_sha256
    )

    rollback = None
    if active_after_restart and row_verified and discovery_read_only:
        rollback = controller.rollback(finding_id)

    restored_sha256 = _sha256(target) if target.is_file() else ""
    payload = {
        "fresh_process": True,
        "active_after_restart": active_after_restart,
        "quarantine_page_row_after_restart": row_verified,
        "restart_discovery_read_only": discovery_read_only,
        "rollback_state": rollback.state if rollback is not None else "",
        "restored_target_exists": target.is_file(),
        "restored_sha256": restored_sha256,
        "expected_sha256": expected_sha256,
        "sha256_identical": restored_sha256 == expected_sha256,
        "rows_after_restore": len(controller.quarantine_rows()),
    }
    payload["passed"] = bool(
        payload["fresh_process"]
        and payload["active_after_restart"]
        and payload["quarantine_page_row_after_restart"]
        and payload["restart_discovery_read_only"]
        and payload["rollback_state"] == "RESTORED_VERIFIED"
        and payload["restored_target_exists"]
        and payload["sha256_identical"]
        and payload["rows_after_restore"] == 0
    )
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 4


def run_acceptance(output: Path) -> dict:
    old_localappdata = os.environ.get("LOCALAPPDATA")
    try:
        with tempfile.TemporaryDirectory(prefix="BCSentinel-B658-Acceptance-") as temp:
            root = Path(temp)
            local = root / "LocalAppData"
            profile = root / "User"
            documents = profile / "Documents"
            (profile / "Desktop").mkdir(parents=True)
            documents.mkdir(parents=True)
            (profile / "Downloads").mkdir(parents=True)
            os.environ["LOCALAPPDATA"] = str(local)

            target = documents / "persistent-home-quarantine.txt"
            target.write_text(
                "BC Sentinel B6-5.8 controlled persistent restore acceptance\n",
                encoding="utf-8",
            )
            original_hash = _sha256(target)

            controller = b658.HomeQuarantineController(
                provider_loader.load_default_provider(),
                user_profile=profile,
            )
            card = _card(target)
            resolution = guided.build_guided_resolution(card)
            availability = controller.assess(card, resolution)
            if not availability.ready:
                raise RuntimeError("b658_home_acceptance_not_ready")

            session = controller.prepare_confirmation(card, resolution)
            if not target.is_file() or _sha256(target) != original_hash:
                raise RuntimeError("b658_prepare_mutated_target")

            result = controller.confirm_and_execute(session)
            rows_before_restart = controller.quarantine_rows()
            storage = local / "BCSentinel" / "B656"
            recovery_files = list((storage / "home-restore").glob("*.json"))
            if (
                result.state != "QUARANTINED_VERIFIED"
                or target.exists()
                or len(rows_before_restart) != 1
                or len(recovery_files) != 1
            ):
                raise RuntimeError("b658_quarantine_persistence_invalid")

            # Capture persistent bytes before launching a completely fresh Python
            # process. Startup discovery in that process must not mutate them
            # before the explicit restore action.
            journal_path = storage / "journal" / "events.jsonl"
            recovery_before = recovery_files[0].read_bytes()
            journal_before = journal_path.read_bytes()
            recovery_before_sha256 = hashlib.sha256(recovery_before).hexdigest()
            journal_before_sha256 = hashlib.sha256(journal_before).hexdigest()

            worker_output = root / "restore-worker.json"
            env = os.environ.copy()
            command = [
                sys.executable,
                "-m",
                "tools.v011_beta6_b658_home_acceptance",
                "--restore-worker",
                "--user-profile",
                str(profile),
                "--target",
                str(target),
                "--finding-id",
                card.finding_id,
                "--expected-sha256",
                original_hash,
                "--worker-output",
                str(worker_output),
                "--recovery-path",
                str(recovery_files[0]),
                "--recovery-sha256",
                recovery_before_sha256,
                "--journal-path",
                str(journal_path),
                "--journal-sha256",
                journal_before_sha256,
            ]
            completed = subprocess.run(
                command,
                cwd=str(Path(__file__).resolve().parents[1]),
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError(
                    "b658_restart_worker_failed\n"
                    + completed.stdout
                    + "\n"
                    + completed.stderr
                )
            worker = json.loads(worker_output.read_text(encoding="utf-8"))

            contract = b658.validate_b658_contract()
            # The worker necessarily appends rollback events and finalizes the
            # recovery record after the explicit restore. Before that action,
            # its own checks confirmed the active row was reconstructed.
            payload = {
                "checkpoint": "B6-5.8-persistent-restore-after-restart",
                "passed": bool(
                    contract.get("passed")
                    and worker.get("passed")
                    and recovery_before
                    and journal_before
                ),
                "fresh_process_restart_verified": worker.get("fresh_process") is True,
                "persistent_active_after_restart": worker.get("active_after_restart") is True,
                "quarantine_page_row_after_restart": worker.get("quarantine_page_row_after_restart") is True,
                "persistent_restore_verified": worker.get("rollback_state") == "RESTORED_VERIFIED",
                "restored_sha256_identical": worker.get("sha256_identical") is True,
                "rows_cleared_after_restore": worker.get("rows_after_restore") == 0,
                "recovery_record_created_before_restart": len(recovery_files) == 1,
                "restart_discovery_read_only": worker.get("restart_discovery_read_only") is True,
                "general_home_execution_authorized": False,
                "automatic_quarantine": False,
                "delete_authorized": False,
                "repair_authorized": False,
                "output": str(output),
            }
    finally:
        if old_localappdata is None:
            os.environ.pop("LOCALAPPDATA", None)
        else:
            os.environ["LOCALAPPDATA"] = old_localappdata

    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="B6-5.8 persistent restore after fresh-process restart acceptance"
    )
    parser.add_argument("--confirm-persistent-restore-acceptance", action="store_true")
    parser.add_argument("--output", default="acceptance-v011-beta6-b658-home.json")
    parser.add_argument("--restore-worker", action="store_true")
    parser.add_argument("--user-profile")
    parser.add_argument("--target")
    parser.add_argument("--finding-id")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--worker-output")
    parser.add_argument("--recovery-path")
    parser.add_argument("--recovery-sha256")
    parser.add_argument("--journal-path")
    parser.add_argument("--journal-sha256")
    args = parser.parse_args()

    if args.restore_worker:
        required = (
            args.user_profile,
            args.target,
            args.finding_id,
            args.expected_sha256,
            args.worker_output,
            args.recovery_path,
            args.recovery_sha256,
            args.journal_path,
            args.journal_sha256,
        )
        if not all(required):
            raise SystemExit("B6-5.8 restore worker arguments are incomplete")
        return _restore_worker(
            profile=Path(args.user_profile),
            target=Path(args.target),
            finding_id=str(args.finding_id),
            expected_sha256=str(args.expected_sha256),
            output=Path(args.worker_output),
            recovery_path=Path(args.recovery_path),
            recovery_sha256=str(args.recovery_sha256),
            journal_path=Path(args.journal_path),
            journal_sha256=str(args.journal_sha256),
        )

    if not args.confirm_persistent_restore_acceptance:
        raise SystemExit(
            "B6-5.8 acceptance requires --confirm-persistent-restore-acceptance"
        )
    output = Path(args.output)
    payload = run_acceptance(output)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
