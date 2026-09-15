from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from sentinel import guided_resolution_provider_loader as provider_loader
from sentinel import home_guided_resolution as guided
from sentinel import home_quarantine as b657
from sentinel import home_threat_cards as threat


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _card(path: Path) -> threat.ThreatCardModel:
    digest = _sha256(path)
    severity = "HIGH"
    card = threat.ThreatCardModel(
        finding_id="b657-live-acceptance",
        title="B6-5.7 Home quarantine acceptance",
        severity=severity,
        severity_label=threat.SEVERITY_LABELS[severity],
        severity_role=threat.SEVERITY_ROLES[severity],
        category="acceptance",
        reason="Controlled Home integration acceptance",
        source_check_id="files",
        location=str(path),
        confidence=None,
        confidence_label="Non disponibile",
        recommendation="Review before action.",
        advanced_details={
            "finding": {
                "finding_id": "b657-live-acceptance",
                "severity": severity,
                "confidence": None,
                "path": str(path),
                "evidence": {"sha256": digest},
            }
        },
    )
    card.validate()
    return card


def run_acceptance(output: Path) -> dict:
    old_localappdata = os.environ.get("LOCALAPPDATA")
    try:
        with tempfile.TemporaryDirectory(prefix="BCSentinel-B657-Acceptance-") as temp:
            root = Path(temp)
            local = root / "LocalAppData"
            profile = root / "User"
            documents = profile / "Documents"
            (profile / "Desktop").mkdir(parents=True)
            documents.mkdir(parents=True)
            (profile / "Downloads").mkdir(parents=True)
            os.environ["LOCALAPPDATA"] = str(local)

            target = documents / "controlled-home-quarantine.txt"
            target.write_text("BC Sentinel B6-5.7 controlled acceptance\n", encoding="utf-8")
            original_hash = _sha256(target)

            controller = b657.HomeQuarantineController(
                provider_loader.load_default_provider(),
                user_profile=profile,
            )
            card = _card(target)
            resolution = guided.build_guided_resolution(card)
            availability = controller.assess(card, resolution)
            if not availability.ready:
                raise RuntimeError("b657_home_acceptance_not_ready")

            session = controller.prepare_confirmation(card, resolution)
            if not target.is_file() or _sha256(target) != original_hash:
                raise RuntimeError("b657_prepare_mutated_target")

            result = controller.confirm_and_execute(session)
            rows_after_quarantine = controller.quarantine_rows()
            if result.state != "QUARANTINED_VERIFIED" or target.exists() or len(rows_after_quarantine) != 1:
                raise RuntimeError("b657_quarantine_state_invalid")

            rollback = controller.rollback(card.finding_id)
            restored = target.is_file() and _sha256(target) == original_hash
            rows_after_rollback = controller.quarantine_rows()
            contract = b657.validate_b657_contract()

            payload = {
                "checkpoint": "B6-5.7-home-quarantine-integration",
                "passed": bool(
                    contract.get("passed")
                    and restored
                    and rollback.state == "RESTORED_VERIFIED"
                    and not rows_after_rollback
                ),
                "explicit_home_action": True,
                "second_confirmation_required": True,
                "lazy_execution_provider": True,
                "quarantine_verified": result.state == "QUARANTINED_VERIFIED",
                "quarantine_page_rows_verified": len(rows_after_quarantine) == 1,
                "rollback_verified": rollback.state == "RESTORED_VERIFIED" and restored,
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
    parser = argparse.ArgumentParser(description="B6-5.7 controlled Home quarantine integration acceptance")
    parser.add_argument("--confirm-home-quarantine-acceptance", action="store_true")
    parser.add_argument("--output", default="acceptance-v011-beta6-b657-home.json")
    args = parser.parse_args()
    if not args.confirm_home_quarantine_acceptance:
        raise SystemExit("B6-5.7 acceptance requires --confirm-home-quarantine-acceptance")
    output = Path(args.output)
    payload = run_acceptance(output)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
