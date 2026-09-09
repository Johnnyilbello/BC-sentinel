from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile

from sentinel.config import APP_VERSION, Settings
from sentinel.database import Database
from sentinel.quarantine import QuarantineManager
from sentinel.scanner import StaticScanner
import sentinel.scanner as scanner_mod

MARKER = b"BC-SENTINEL-HARMLESS-EICAR-THREAT-DECISION-ACCEPTANCE"


def _report(scanner: StaticScanner, path: Path):
    original = scanner_mod.is_exact_eicar
    scanner_mod.is_exact_eicar = lambda data: data.rstrip(b"\r\n") == MARKER
    try:
        return scanner.scan_file(path)
    finally:
        scanner_mod.is_exact_eicar = original


def run() -> dict:
    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "passed": False,
        "harmless_fixture": True,
    }
    with tempfile.TemporaryDirectory(prefix="bcs-threat-decision-") as raw:
        root = Path(raw)
        db = Database(root / "state.sqlite")
        q = QuarantineManager(
            db,
            quarantine_dir=root / "quarantine",
            key_path=root / "quarantine.key",
            managed_roots=(root / "managed",),
        )
        settings = Settings.defaults()
        settings.reputation_enabled = False
        scanner = StaticScanner(settings, db=db)

        # 1. Detection -> quarantine with stale-decision identity protection -> restore.
        sample = root / "eicar-simulation.com"
        sample.write_bytes(MARKER)
        report = _report(scanner, sample)
        result["detection"] = {
            "score": report.assessment.score,
            "level": report.assessment.level,
            "sha256": report.sha256,
        }
        if report.assessment.score != 100 or report.assessment.level != "CRITICAL":
            result["error"] = "fixture_not_detected"
            return result
        db.add_detection(
            report.path,
            report.sha256,
            report.assessment.score,
            report.assessment.level,
            json.dumps(report.assessment.reasons, ensure_ascii=False),
            "logged",
            dedupe_minutes=0,
        )
        item_id = q.quarantine(
            sample,
            report.assessment.score,
            "Threat Decision acceptance",
            expected_sha256=report.sha256,
        )
        result["quarantine"] = {"item_id": item_id, "source_removed": not sample.exists()}
        restored = q.restore(item_id)
        result["restore"] = {
            "path": str(restored),
            "exists": restored.exists(),
            "content_verified": restored.read_bytes() == MARKER,
        }

        # 2. Permanent delete revalidates the exact detected content identity.
        delete_target = root / "delete-simulation.com"
        delete_target.write_bytes(MARKER)
        delete_report = _report(scanner, delete_target)
        q.delete_detected_file(delete_target, delete_report.sha256)
        result["delete"] = {"removed": not delete_target.exists(), "sha256": delete_report.sha256}

        # 3. Keep-once is deliberately non-persistent: no trust record is created.
        keep_target = root / "keep-once-simulation.com"
        keep_target.write_bytes(MARKER)
        keep_report = _report(scanner, keep_target)
        before_allow = len(db.list_allowlist())
        db.update_detection_action(keep_report.sha256, "allowed_once")
        after_allow = len(db.list_allowlist())
        result["keep_once"] = {
            "allowlist_unchanged": before_allow == after_allow,
            "action": db.latest_detection_action(keep_report.sha256),
        }

        # 4. Allow-hash trusts only the immutable digest. A byte change no longer matches.
        allow_target = root / "allow-hash-simulation.bin"
        allow_target.write_bytes(b"known local fixture")
        clean_report = scanner.scan_file(allow_target)
        db.add_allowlist("hash", clean_report.sha256)
        trusted = db.is_allowlisted(allow_target, clean_report.sha256)
        allow_target.write_bytes(b"changed local fixture")
        changed_report = scanner.scan_file(allow_target)
        changed_trusted = db.is_allowlisted(allow_target, changed_report.sha256)
        result["allow_hash"] = {
            "original_trusted": bool(trusted),
            "changed_content_trusted": bool(changed_trusted),
            "original_sha256": clean_report.sha256,
            "changed_sha256": changed_report.sha256,
        }

        result["passed"] = all([
            result["quarantine"]["source_removed"],
            result["restore"]["exists"],
            result["restore"]["content_verified"],
            result["delete"]["removed"],
            result["keep_once"]["allowlist_unchanged"],
            result["keep_once"]["action"] == "allowed_once",
            result["allow_hash"]["original_trusted"],
            not result["allow_hash"]["changed_content_trusted"],
        ])
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.7.1 beta.2 harmless Threat Decision acceptance")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
