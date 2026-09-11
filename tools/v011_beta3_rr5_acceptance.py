from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel import rescue_data_rescue as rr5


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _snapshot(root: Path) -> dict[str, str]:
    return {str(path.relative_to(root)).replace("\\", "/"): _sha(path) for path in root.rglob("*") if path.is_file()}


def run_acceptance(base: Path | None = None) -> dict:
    context = tempfile.TemporaryDirectory(prefix="bcs-rr5-") if base is None else None
    work = Path(context.name) if context is not None else base
    assert work is not None
    try:
        root = work / "offline-target"
        config = root / "Windows" / "System32" / "config"
        system32 = root / "Windows" / "System32"
        docs = root / "Users" / "Alice" / "Documents"
        downloads = root / "Users" / "Alice" / "Downloads"
        config.mkdir(parents=True)
        docs.mkdir(parents=True)
        downloads.mkdir(parents=True)
        (config / "SYSTEM").write_bytes(b"RR5 ACCEPTANCE SYSTEM")
        (system32 / "ntoskrnl.exe").write_bytes(b"MZ RR5 ACCEPTANCE KERNEL")

        normal = docs / "notes.txt"
        photo = docs / "photo.jpg"
        executable = downloads / "harmless-tool.exe"
        script = downloads / "harmless.ps1"
        macro = docs / "budget.xlsm"
        unknown = docs / "archive.custom"
        normal.write_text("RR5 harmless notes", encoding="utf-8")
        photo.write_bytes(b"RR5 harmless IOC-marked photo fixture")
        executable.write_bytes(b"MZ RR5 harmless executable fixture")
        script.write_text("Write-Output 'RR5 harmless'", encoding="utf-8")
        macro.write_bytes(b"RR5 harmless macro document fixture")
        unknown.write_bytes(b"RR5 harmless unknown extension fixture")

        intel = work / "approved-intel.json"
        intel.write_text(
            json.dumps(
                {
                    "schema": rr5.INTEL_SCHEMA,
                    "approved": True,
                    "sha256": [
                        {"value": _sha(photo), "name": "RR5.Acceptance.IOC", "source": "deterministic_acceptance"}
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        before = _snapshot(root)
        destination = work / "rescued-output"
        result = rr5.rescue_selected_data(
            root,
            destination,
            ["Users/Alice/Documents", "Users/Alice/Downloads"],
            limits=rr5.RescueLimits(max_files=64, max_total_bytes=1024 * 1024, max_file_bytes=1024 * 1024, max_depth=16),
            intel_catalog=intel,
        )
        after = _snapshot(root)

        records = {Path(item["relative_path"]).name: item for item in result["records"]}
        normal_item = records["notes.txt"]
        photo_item = records["photo.jpg"]
        executable_item = records["harmless-tool.exe"]
        script_item = records["harmless.ps1"]
        macro_item = records["budget.xlsm"]
        unknown_item = records["archive.custom"]

        copied_hashes_match = True
        for item in result["records"]:
            if item["status"] != "copied":
                copied_hashes_match = False
                break
            destination_file = destination / item["destination_relative_path"]
            source_file = root / item["relative_path"]
            if not destination_file.is_file() or _sha(destination_file) != _sha(source_file) or _sha(destination_file) != item["sha256"]:
                copied_hashes_match = False
                break

        clean_names = {path.name for path in (destination / "rescued-data").rglob("*") if path.is_file()}
        containment_names = {path.name for path in (destination / "containment").rglob("*") if path.is_file()}
        manifest = json.loads((destination / "rr5-rescue-manifest.json").read_text(encoding="utf-8"))
        audit_rows = [json.loads(line) for line in (destination / "rr5-audit.jsonl").read_text(encoding="utf-8").splitlines()]

        checks = {
            "profile": result["profile"] == rr5.PROFILE,
            "source_unchanged": before == after,
            "all_fixture_files_copied": result["summary"]["copied"] == 6 and result["summary"]["errors"] == 0,
            "passive_document_in_clean_tree": normal_item["disposition"] == "rescued-data" and "notes.txt" in clean_names,
            "approved_ioc_contained": photo_item["disposition"] == "containment" and photo_item["ioc_name"] == "RR5.Acceptance.IOC",
            "executable_contained": executable_item["disposition"] == "containment" and "harmless-tool.exe" in containment_names,
            "script_contained": script_item["disposition"] == "containment" and "harmless.ps1" in containment_names,
            "macro_document_contained": macro_item["disposition"] == "containment" and "budget.xlsm" in containment_names,
            "unknown_extension_contained": unknown_item["disposition"] == "containment" and "archive.custom" in containment_names,
            "active_content_absent_from_clean_tree": not ({"harmless-tool.exe", "harmless.ps1", "budget.xlsm", "archive.custom", "photo.jpg"} & clean_names),
            "copied_sha256_verified": copied_hashes_match,
            "manifest_written": manifest.get("profile") == rr5.PROFILE and len(manifest.get("records", [])) == 6,
            "structured_audit_written": audit_rows[0]["stage"] == "rescue_start" and audit_rows[-1]["stage"] == "rescue_complete",
            "source_read_only": manifest["safety"]["source_read_only"] is True,
            "no_source_execution": manifest["safety"]["source_file_execution"] is False and manifest["safety"]["source_shell_execution"] is False,
            "no_source_delete": manifest["safety"]["source_delete"] is False,
            "no_repair_execution": manifest["safety"]["repair_engine_execution"] is False,
            "no_recovery_certification": manifest["safety"]["recovery_certification_enabled"] is False,
        }
        return {
            "profile": rr5.PROFILE,
            "checkpoint": "RR-5-safe-data-rescue",
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "summary": result["summary"],
                "clean_files": sorted(clean_names),
                "contained_files": sorted(containment_names),
                "ioc_name": photo_item["ioc_name"],
                "session_id": result["session_id"],
            },
            "live_host_mutation_enabled": False,
            "automatic_restore_enabled": False,
            "repair_engine_execution_enabled": False,
            "recovery_certification_enabled": False,
        }
    finally:
        if context is not None:
            context.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    parser.add_argument("--base")
    args = parser.parse_args()
    result = run_acceptance(Path(args.base) if args.base else None)
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
