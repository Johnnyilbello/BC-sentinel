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
from sentinel import home_quarantine_integrity as b659
from sentinel import home_threat_cards as threat


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _storage_snapshot(storage: Path) -> dict[str, str]:
    if not storage.is_dir():
        return {}
    return {
        str(path.relative_to(storage)): _sha256(path)
        for path in storage.rglob("*")
        if path.is_file()
    }


def _card(path: Path, finding_id: str, title: str) -> threat.ThreatCardModel:
    digest = _sha256(path)
    severity = "HIGH"
    card = threat.ThreatCardModel(
        finding_id=finding_id,
        title=title,
        severity=severity,
        severity_label=threat.SEVERITY_LABELS[severity],
        severity_role=threat.SEVERITY_ROLES[severity],
        category="acceptance",
        reason="Controlled B6-5.9 quarantine integrity acceptance",
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


def _quarantine(
    controller: b659.HomeQuarantineController,
    target: Path,
    finding_id: str,
    title: str,
) -> tuple[threat.ThreatCardModel, str]:
    original_hash = _sha256(target)
    card = _card(target, finding_id, title)
    resolution = guided.build_guided_resolution(card)
    availability = controller.assess(card, resolution)
    if not availability.ready:
        raise RuntimeError(f"b659_acceptance_not_ready:{finding_id}")
    session = controller.prepare_confirmation(card, resolution)
    if not target.is_file() or _sha256(target) != original_hash:
        raise RuntimeError(f"b659_prepare_mutated_target:{finding_id}")
    result = controller.confirm_and_execute(session)
    if result.state != "QUARANTINED_VERIFIED" or target.exists():
        raise RuntimeError(f"b659_quarantine_failed:{finding_id}")
    return card, original_hash


def _worker(
    *,
    profile: Path,
    storage: Path,
    valid_target: Path,
    valid_finding_id: str,
    valid_sha256: str,
    blocked_target: Path,
    blocked_finding_id: str,
    output: Path,
) -> int:
    before = _storage_snapshot(storage)
    controller = b659.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    rows = controller.quarantine_rows()
    after_discovery = _storage_snapshot(storage)

    valid_row = next(
        (row for row in rows if row.get("restore_key") == valid_finding_id),
        None,
    )
    blocked_row = next(
        (
            row
            for row in rows
            if row.get("integrity_state") == b659.INTEGRITY_BLOCKED
            and row.get("integrity_issue_code") == "record_integrity"
        ),
        None,
    )
    valid_verified = bool(
        valid_row
        and valid_row.get("integrity_state") == b659.INTEGRITY_VERIFIED
        and valid_row.get("action") == "Ripristina file"
    )
    blocked_visible = bool(
        blocked_row
        and blocked_row.get("restore_key") == ""
        and blocked_row.get("status") == "Verifica richiesta"
        and blocked_row.get("action") == "Ripristino bloccato"
    )
    blocked_restore_refused = False
    try:
        controller.rollback(blocked_finding_id)
    except ValueError:
        blocked_restore_refused = True

    rollback = controller.rollback(valid_finding_id) if valid_verified else None
    restored_sha256 = _sha256(valid_target) if valid_target.is_file() else ""
    rows_after_restore = controller.quarantine_rows()
    blocked_after_restore = any(
        row.get("integrity_state") == b659.INTEGRITY_BLOCKED
        and row.get("integrity_issue_code") == "record_integrity"
        for row in rows_after_restore
    )

    payload = {
        "fresh_process": True,
        "verified_row_visible": valid_verified,
        "blocked_integrity_row_visible": blocked_visible,
        "blocked_row_has_restore_key": bool(blocked_row and blocked_row.get("restore_key")),
        "restart_discovery_read_only": before == after_discovery,
        "blocked_restore_refused": blocked_restore_refused,
        "valid_restore_state": rollback.state if rollback is not None else "",
        "valid_restored_sha256_identical": restored_sha256 == valid_sha256,
        "blocked_target_still_absent": not blocked_target.exists(),
        "blocked_row_persists_after_valid_restore": blocked_after_restore,
    }
    payload["passed"] = bool(
        payload["fresh_process"]
        and payload["verified_row_visible"]
        and payload["blocked_integrity_row_visible"]
        and not payload["blocked_row_has_restore_key"]
        and payload["restart_discovery_read_only"]
        and payload["blocked_restore_refused"]
        and payload["valid_restore_state"] == "RESTORED_VERIFIED"
        and payload["valid_restored_sha256_identical"]
        and payload["blocked_target_still_absent"]
        and payload["blocked_row_persists_after_valid_restore"]
    )
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 4


def run_acceptance(output: Path) -> dict:
    old_localappdata = os.environ.get("LOCALAPPDATA")
    try:
        with tempfile.TemporaryDirectory(prefix="BCSentinel-B659-Acceptance-") as temp:
            root = Path(temp)
            local = root / "LocalAppData"
            profile = root / "User"
            documents = profile / "Documents"
            (profile / "Desktop").mkdir(parents=True)
            documents.mkdir(parents=True)
            (profile / "Downloads").mkdir(parents=True)
            os.environ["LOCALAPPDATA"] = str(local)

            valid_target = documents / "verified-quarantine.txt"
            blocked_target = documents / "blocked-integrity-quarantine.txt"
            valid_target.write_text(
                "BC Sentinel B6-5.9 verified quarantine acceptance\n",
                encoding="utf-8",
            )
            blocked_target.write_text(
                "BC Sentinel B6-5.9 degraded quarantine acceptance\n",
                encoding="utf-8",
            )

            valid_id = "b659-live-valid"
            blocked_id = "b659-live-blocked"
            controller = b659.HomeQuarantineController(
                provider_loader.load_default_provider(),
                user_profile=profile,
            )
            _, valid_hash = _quarantine(
                controller,
                valid_target,
                valid_id,
                "B6-5.9 verified quarantine",
            )
            _quarantine(
                controller,
                blocked_target,
                blocked_id,
                "B6-5.9 degraded quarantine",
            )

            blocked_record = b658._record_path(blocked_id)
            payload = json.loads(blocked_record.read_text(encoding="utf-8"))
            payload["display"]["reason"] = "controlled-integrity-tamper"
            # Keep the old record_sha256 on purpose.  The new process must make
            # the degraded state visible while refusing every restore action.
            blocked_record.write_text(json.dumps(payload), encoding="utf-8")

            storage = local / "BCSentinel" / "B656"
            worker_output = root / "b659-worker.json"
            env = os.environ.copy()
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tools.v011_beta6_b659_home_acceptance",
                    "--worker",
                    "--user-profile",
                    str(profile),
                    "--storage",
                    str(storage),
                    "--valid-target",
                    str(valid_target),
                    "--valid-finding-id",
                    valid_id,
                    "--valid-sha256",
                    valid_hash,
                    "--blocked-target",
                    str(blocked_target),
                    "--blocked-finding-id",
                    blocked_id,
                    "--worker-output",
                    str(worker_output),
                ],
                cwd=str(Path(__file__).resolve().parents[1]),
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError(
                    "b659_worker_failed\n" + completed.stdout + "\n" + completed.stderr
                )
            worker = json.loads(worker_output.read_text(encoding="utf-8"))
            contract = b659.validate_b659_contract()
            final = {
                "checkpoint": "B6-5.9-quarantine-integrity-visibility",
                "passed": bool(contract.get("passed") and worker.get("passed")),
                "fresh_process_verified": worker.get("fresh_process") is True,
                "verified_row_visible": worker.get("verified_row_visible") is True,
                "blocked_integrity_row_visible": worker.get("blocked_integrity_row_visible") is True,
                "blocked_restore_refused": worker.get("blocked_restore_refused") is True,
                "restart_discovery_read_only": worker.get("restart_discovery_read_only") is True,
                "valid_restore_verified": worker.get("valid_restore_state") == "RESTORED_VERIFIED",
                "valid_sha256_identical": worker.get("valid_restored_sha256_identical") is True,
                "blocked_target_not_restored": worker.get("blocked_target_still_absent") is True,
                "general_home_execution_authorized": False,
                "automatic_cleanup": False,
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

    output.write_text(json.dumps(final, indent=2, sort_keys=True), encoding="utf-8")
    return final


def main() -> int:
    parser = argparse.ArgumentParser(
        description="B6-5.9 read-only quarantine integrity visibility acceptance"
    )
    parser.add_argument("--confirm-quarantine-integrity-acceptance", action="store_true")
    parser.add_argument("--output", default="acceptance-v011-beta6-b659-home.json")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--user-profile")
    parser.add_argument("--storage")
    parser.add_argument("--valid-target")
    parser.add_argument("--valid-finding-id")
    parser.add_argument("--valid-sha256")
    parser.add_argument("--blocked-target")
    parser.add_argument("--blocked-finding-id")
    parser.add_argument("--worker-output")
    args = parser.parse_args()

    if args.worker:
        required = (
            args.user_profile,
            args.storage,
            args.valid_target,
            args.valid_finding_id,
            args.valid_sha256,
            args.blocked_target,
            args.blocked_finding_id,
            args.worker_output,
        )
        if not all(required):
            raise SystemExit("B6-5.9 worker arguments are incomplete")
        return _worker(
            profile=Path(args.user_profile),
            storage=Path(args.storage),
            valid_target=Path(args.valid_target),
            valid_finding_id=str(args.valid_finding_id),
            valid_sha256=str(args.valid_sha256),
            blocked_target=Path(args.blocked_target),
            blocked_finding_id=str(args.blocked_finding_id),
            output=Path(args.worker_output),
        )

    if not args.confirm_quarantine_integrity_acceptance:
        raise SystemExit(
            "B6-5.9 acceptance requires --confirm-quarantine-integrity-acceptance"
        )
    output = Path(args.output)
    payload = run_acceptance(output)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
