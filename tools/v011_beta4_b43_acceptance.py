from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel import rescue_console_guided_data_rescue as b43
from sentinel import rescue_offline_scanner as rr3


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(output: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-b43-") as td:
        base = Path(td); root = base / "offline"; work = base / "workspace"; dest = base / "rescued"
        (root / "Windows/System32/config").mkdir(parents=True)
        (root / "Windows/System32/config/SYSTEM").write_bytes(b"SYSTEM")
        (root / "Windows/System32/config/SOFTWARE").write_bytes(b"SOFTWARE")
        (root / "Windows/System32/ntoskrnl.exe").write_bytes(b"MZ KERNEL")
        (root / "Users/Alice/Documents").mkdir(parents=True)
        (root / "Users/Alice/AppData/Local/Temp").mkdir(parents=True)
        note = root / "Users/Alice/Documents/notes.txt"; note.write_text("notes", encoding="utf-8")
        bad = root / "Users/Alice/AppData/Local/Temp/bad.exe"; bad.write_bytes(b"MZ B43 IOC")
        work.mkdir()
        intel = base / "intel.json"
        intel.write_text(json.dumps({"schema":"bc-sentinel-offline-intel-v1","approved":True,"sha256":[{"value":sha_bytes(bad.read_bytes()),"name":"B43.Acceptance.IOC"}]}), encoding="utf-8")
        rr3.scan_offline_windows(root, work / "rr3", intel_catalog=intel)
        scan = work / "rr3/rr3-offline-scan.json"
        before = {str(p.relative_to(root)): sha_bytes(p.read_bytes()) for p in root.rglob("*") if p.is_file()}

        preview = b43.prepare_or_run_guided_data_rescue(b43.GuidedDataRescueRequest(root, work, scan, dest, ("Users/Alice",), False))
        execute = b43.prepare_or_run_guided_data_rescue(b43.GuidedDataRescueRequest(root, work, scan, dest, ("Users/Alice",), True))
        after = {str(p.relative_to(root)): sha_bytes(p.read_bytes()) for p in root.rglob("*") if p.is_file()}

        checks = {
            "profile": preview["profile"] == b43.PROFILE,
            "preview_no_execution": preview["execution_requested"] is False,
            "preview_requires_operator_action": preview["operator_action_required"] == "confirm_and_run_data_rescue",
            "explicit_selection_bound": preview["explicit_selections"] == ["Users/Alice"],
            "trusted_scan_bound": len(preview["trusted_scan_sha256"]) == 64,
            "execute_requested_explicitly": execute["execution_requested"] is True,
            "passive_document_rescued": (dest / "rescued-data/Users/Alice/Documents/notes.txt").is_file(),
            "ioc_contained": (dest / "containment/Users/Alice/AppData/Local/Temp/bad.exe").is_file(),
            "ioc_absent_clean_tree": not (dest / "rescued-data/Users/Alice/AppData/Local/Temp/bad.exe").exists(),
            "manifest_hash_present": len(execute["manifest_sha256"]) == 64,
            "source_unchanged": before == after,
            "no_automatic_restore": execute["safety"]["automatic_restore"] is False,
            "no_repair_execution": execute["safety"]["repair_execution"] is False,
            "no_recovery_certification": execute["safety"]["recovery_certification"] is False,
        }
        result = {
            "profile": b43.PROFILE,
            "checkpoint": "B4-3-guided-safe-data-rescue",
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {"plan_sha256": execute["plan_sha256"], "manifest_sha256": execute["manifest_sha256"], "summary": execute["rescue_summary"]},
            "new_mutation_authority_added": False,
        }
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--output", required=True); args = parser.parse_args()
    result = run(Path(args.output)); print(json.dumps(result, indent=2, sort_keys=True)); return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
