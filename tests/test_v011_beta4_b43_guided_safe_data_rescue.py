from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_console_guided_data_rescue as b43
from sentinel import rescue_offline_scanner as rr3


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture(tmp_path: Path):
    root = tmp_path / "offline"
    (root / "Windows/System32/config").mkdir(parents=True)
    (root / "Windows/System32/config/SYSTEM").write_bytes(b"SYSTEM")
    (root / "Windows/System32/config/SOFTWARE").write_bytes(b"SOFTWARE")
    (root / "Windows/System32/ntoskrnl.exe").write_bytes(b"MZ KERNEL")
    user = root / "Users/Alice"
    (user / "Documents").mkdir(parents=True)
    (user / "AppData/Local/Temp").mkdir(parents=True)
    (user / "Documents/notes.txt").write_text("safe notes", encoding="utf-8")
    bad = user / "AppData/Local/Temp/bad.exe"
    bad.write_bytes(b"MZ B43 IOC")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    intel = tmp_path / "intel.json"
    intel.write_text(json.dumps({"schema":"bc-sentinel-offline-intel-v1","approved":True,"sha256":[{"value":sha(bad.read_bytes()),"name":"B43.Test.IOC"}]}), encoding="utf-8")
    scan_dir = workspace / "rr3"
    rr3.scan_offline_windows(root, scan_dir, intel_catalog=intel)
    return root, workspace, scan_dir / "rr3-offline-scan.json", intel


def request(root: Path, workspace: Path, scan: Path, dest: Path, *, execute=False, includes=("Users/Alice",)):
    return b43.GuidedDataRescueRequest(root, workspace, scan, dest, tuple(includes), execute)


def test_preview_requires_no_execution(tmp_path: Path):
    root, work, scan, _ = fixture(tmp_path)
    dest = tmp_path / "rescued"
    result = b43.prepare_or_run_guided_data_rescue(request(root, work, scan, dest))
    assert result["execution_requested"] is False
    assert result["operator_action_required"] == "confirm_and_run_data_rescue"
    assert not dest.exists()
    assert result["manifest_path"] == ""


def test_explicit_selection_required(tmp_path: Path):
    root, work, scan, _ = fixture(tmp_path)
    with pytest.raises(ValueError, match="explicit selection"):
        b43.prepare_or_run_guided_data_rescue(request(root, work, scan, tmp_path / "dest", includes=()))


def test_selection_outside_users_refused(tmp_path: Path):
    root, work, scan, _ = fixture(tmp_path)
    with pytest.raises(ValueError, match="Users"):
        b43.prepare_or_run_guided_data_rescue(request(root, work, scan, tmp_path / "dest", includes=("Windows/System32",)))


def test_destination_inside_target_refused(tmp_path: Path):
    root, work, scan, _ = fixture(tmp_path)
    with pytest.raises(ValueError, match="outside offline target"):
        b43.prepare_or_run_guided_data_rescue(request(root, work, scan, root / "rescued"))


def test_untrusted_scan_refused(tmp_path: Path):
    root, work, scan, _ = fixture(tmp_path)
    payload = json.loads(scan.read_text(encoding="utf-8"))
    payload["summary"]["errors"] = 1
    scan.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="trusted RR3"):
        b43.prepare_or_run_guided_data_rescue(request(root, work, scan, tmp_path / "dest"))


def test_execute_routes_passive_and_ioc(tmp_path: Path):
    root, work, scan, _ = fixture(tmp_path)
    dest = tmp_path / "rescued"
    result = b43.prepare_or_run_guided_data_rescue(request(root, work, scan, dest, execute=True))
    assert result["rescue_summary"]["errors"] == 0
    assert (dest / "rescued-data/Users/Alice/Documents/notes.txt").is_file()
    assert (dest / "containment/Users/Alice/AppData/Local/Temp/bad.exe").is_file()
    assert not (dest / "rescued-data/Users/Alice/AppData/Local/Temp/bad.exe").exists()


def test_source_remains_unchanged(tmp_path: Path):
    root, work, scan, _ = fixture(tmp_path)
    before = {str(p.relative_to(root)): sha(p.read_bytes()) for p in root.rglob("*") if p.is_file()}
    b43.prepare_or_run_guided_data_rescue(request(root, work, scan, tmp_path / "dest", execute=True))
    after = {str(p.relative_to(root)): sha(p.read_bytes()) for p in root.rglob("*") if p.is_file()}
    assert before == after


def test_manifest_hash_and_safety_present(tmp_path: Path):
    root, work, scan, _ = fixture(tmp_path)
    result = b43.prepare_or_run_guided_data_rescue(request(root, work, scan, tmp_path / "dest", execute=True))
    assert len(result["manifest_sha256"]) == 64
    assert result["safety"]["source_read_only"] is True
    assert result["safety"]["automatic_restore"] is False
    assert result["safety"]["repair_execution"] is False
    assert result["safety"]["recovery_certification"] is False


def test_plan_binds_scan_and_selections(tmp_path: Path):
    root, work, scan, _ = fixture(tmp_path)
    result = b43.prepare_or_run_guided_data_rescue(request(root, work, scan, tmp_path / "dest"))
    plan = json.loads(Path(result["plan_path"]).read_text(encoding="utf-8"))
    assert plan["trusted_scan_sha256"] == result["trusted_scan_sha256"]
    assert plan["includes"] == ["Users/Alice"]
    assert len(plan["plan_sha256"]) == 64
    assert plan["automatic_execution"] is False
