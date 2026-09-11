from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from sentinel import rescue_data_rescue as rr5


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _offline_root(base: Path) -> Path:
    root = base / "offline"
    config = root / "Windows" / "System32" / "config"
    system32 = root / "Windows" / "System32"
    docs = root / "Users" / "Alice" / "Documents"
    downloads = root / "Users" / "Alice" / "Downloads"
    config.mkdir(parents=True)
    docs.mkdir(parents=True)
    downloads.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"RR5 SYSTEM")
    (system32 / "ntoskrnl.exe").write_bytes(b"MZ RR5 KERNEL")
    return root


def _limits(**overrides) -> rr5.RescueLimits:
    values = dict(max_files=128, max_total_bytes=16 * 1024 * 1024, max_file_bytes=1024 * 1024, max_depth=16)
    values.update(overrides)
    return rr5.RescueLimits(**values)


def _rescue(root: Path, out: Path, includes: list[str], **kwargs):
    return rr5.rescue_selected_data(root, out, includes, limits=kwargs.pop("limits", _limits()), **kwargs)


def test_limits_are_bounded():
    _limits().validate()
    with pytest.raises(ValueError):
        rr5.RescueLimits(max_files=0).validate()
    with pytest.raises(ValueError):
        rr5.RescueLimits(max_total_bytes=rr5.MAX_TOTAL_BYTES_HARD + 1).validate()
    with pytest.raises(ValueError):
        rr5.RescueLimits(max_file_bytes=rr5.MAX_FILE_BYTES_HARD + 1).validate()
    with pytest.raises(ValueError):
        rr5.RescueLimits(max_depth=rr5.MAX_DEPTH_HARD + 1).validate()


def test_offline_root_requires_windows_markers(tmp_path: Path):
    root = tmp_path / "bad"
    root.mkdir()
    with pytest.raises(ValueError, match="validated offline Windows"):
        rr5.validate_offline_windows_root(root)


def test_requires_explicit_selection(tmp_path: Path):
    root = _offline_root(tmp_path)
    with pytest.raises(ValueError, match="at least one explicit"):
        _rescue(root, tmp_path / "out", [])


def test_first_checkpoint_only_allows_users_tree(tmp_path: Path):
    root = _offline_root(tmp_path)
    with pytest.raises(ValueError, match="Users/<profile>"):
        _rescue(root, tmp_path / "out", ["Windows/System32"])


def test_path_traversal_is_refused(tmp_path: Path):
    root = _offline_root(tmp_path)
    with pytest.raises(ValueError, match="traversal"):
        _rescue(root, tmp_path / "out", ["Users/Alice/../Bob"])


def test_destination_inside_source_is_refused(tmp_path: Path):
    root = _offline_root(tmp_path)
    with pytest.raises(ValueError, match="overlap"):
        _rescue(root, root / "Users" / "Alice" / "rescued", ["Users/Alice/Documents"])


def test_passive_document_goes_to_rescued_data_and_hash_matches(tmp_path: Path):
    root = _offline_root(tmp_path)
    source = root / "Users" / "Alice" / "Documents" / "notes.txt"
    source.write_text("harmless notes", encoding="utf-8")
    result = _rescue(root, tmp_path / "out", ["Users/Alice/Documents"])
    item = next(record for record in result["records"] if record["relative_path"].endswith("notes.txt"))
    copied = tmp_path / "out" / item["destination_relative_path"]
    assert item["disposition"] == "rescued-data"
    assert item["status"] == "copied"
    assert copied.is_file()
    assert _sha(source) == _sha(copied) == item["sha256"]


def test_executable_goes_to_containment(tmp_path: Path):
    root = _offline_root(tmp_path)
    source = root / "Users" / "Alice" / "Downloads" / "tool.exe"
    source.write_bytes(b"MZ harmless executable fixture")
    result = _rescue(root, tmp_path / "out", ["Users/Alice/Downloads"])
    item = next(record for record in result["records"] if record["relative_path"].endswith("tool.exe"))
    assert item["disposition"] == "containment"
    assert item["reason"] == "active_or_risky_extension"
    assert (tmp_path / "out" / item["destination_relative_path"]).is_file()


def test_script_and_shortcut_go_to_containment(tmp_path: Path):
    root = _offline_root(tmp_path)
    downloads = root / "Users" / "Alice" / "Downloads"
    (downloads / "run.ps1").write_text("Write-Output harmless", encoding="utf-8")
    (downloads / "shortcut.lnk").write_bytes(b"harmless shortcut fixture")
    result = _rescue(root, tmp_path / "out", ["Users/Alice/Downloads"])
    by_name = {Path(item["relative_path"]).name: item for item in result["records"]}
    assert by_name["run.ps1"]["disposition"] == "containment"
    assert by_name["shortcut.lnk"]["disposition"] == "containment"


def test_unknown_extension_is_contained_not_trusted(tmp_path: Path):
    root = _offline_root(tmp_path)
    source = root / "Users" / "Alice" / "Documents" / "mystery.unknown"
    source.write_bytes(b"unknown fixture")
    result = _rescue(root, tmp_path / "out", ["Users/Alice/Documents"])
    item = next(record for record in result["records"] if record["relative_path"].endswith("mystery.unknown"))
    assert item["disposition"] == "containment"
    assert item["reason"] == "unknown_extension_review_required"


def test_approved_hash_ioc_forces_passive_file_into_containment(tmp_path: Path):
    root = _offline_root(tmp_path)
    source = root / "Users" / "Alice" / "Documents" / "photo.jpg"
    source.write_bytes(b"harmless deterministic IOC payload")
    catalog = tmp_path / "intel.json"
    catalog.write_text(
        json.dumps(
            {
                "schema": rr5.INTEL_SCHEMA,
                "approved": True,
                "sha256": [{"value": _sha(source), "name": "RR5.Test.IOC", "source": "acceptance"}],
            }
        ),
        encoding="utf-8",
    )
    result = _rescue(root, tmp_path / "out", ["Users/Alice/Documents"], intel_catalog=catalog)
    item = next(record for record in result["records"] if record["relative_path"].endswith("photo.jpg"))
    assert item["disposition"] == "containment"
    assert item["ioc_name"] == "RR5.Test.IOC"
    assert item["reason"] == "approved_sha256_ioc_match"


def test_source_tree_is_byte_identical_after_rescue(tmp_path: Path):
    root = _offline_root(tmp_path)
    docs = root / "Users" / "Alice" / "Documents"
    (docs / "a.txt").write_text("a", encoding="utf-8")
    (docs / "b.pdf").write_bytes(b"pdf fixture")
    before = {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}
    _rescue(root, tmp_path / "out", ["Users/Alice/Documents"])
    after = {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}
    assert before == after


def test_destination_must_be_empty(tmp_path: Path):
    root = _offline_root(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    (out / "existing.txt").write_text("existing", encoding="utf-8")
    with pytest.raises(ValueError, match="must be empty"):
        _rescue(root, out, ["Users/Alice/Documents"])


def test_oversized_file_is_skipped(tmp_path: Path):
    root = _offline_root(tmp_path)
    source = root / "Users" / "Alice" / "Documents" / "large.txt"
    source.write_bytes(b"x" * 128)
    result = _rescue(root, tmp_path / "out", ["Users/Alice/Documents"], limits=_limits(max_file_bytes=32))
    item = next(record for record in result["records"] if record["relative_path"].endswith("large.txt"))
    assert item["status"] == "skipped"
    assert item["reason"] == "file_too_large"
    assert result["summary"]["skipped"] == 1


def test_max_files_is_fail_closed(tmp_path: Path):
    root = _offline_root(tmp_path)
    docs = root / "Users" / "Alice" / "Documents"
    for i in range(3):
        (docs / f"{i}.txt").write_text(str(i), encoding="utf-8")
    with pytest.raises(ValueError, match="max_files"):
        _rescue(root, tmp_path / "out", ["Users/Alice/Documents"], limits=_limits(max_files=2))


def test_max_total_bytes_is_fail_closed(tmp_path: Path):
    root = _offline_root(tmp_path)
    docs = root / "Users" / "Alice" / "Documents"
    (docs / "one.txt").write_bytes(b"a" * 8)
    (docs / "two.txt").write_bytes(b"b" * 8)
    with pytest.raises(ValueError, match="max_total_bytes"):
        _rescue(root, tmp_path / "out", ["Users/Alice/Documents"], limits=_limits(max_total_bytes=10))


def test_duplicate_selection_is_deduplicated(tmp_path: Path):
    root = _offline_root(tmp_path)
    docs = root / "Users" / "Alice" / "Documents"
    (docs / "a.txt").write_text("a", encoding="utf-8")
    result = _rescue(root, tmp_path / "out", ["Users/Alice/Documents", "Users/Alice/Documents/a.txt"])
    names = [item["relative_path"] for item in result["records"] if item["relative_path"].endswith("a.txt")]
    assert len(names) == 1


def test_symlink_selection_is_refused_when_supported(tmp_path: Path):
    root = _offline_root(tmp_path)
    docs = root / "Users" / "Alice" / "Documents"
    external = tmp_path / "external"
    external.mkdir()
    link = docs / "link"
    try:
        os.symlink(external, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="symlink/reparse"):
        _rescue(root, tmp_path / "out", ["Users/Alice/Documents/link"])


def test_audit_and_manifest_include_session_and_safety(tmp_path: Path):
    root = _offline_root(tmp_path)
    source = root / "Users" / "Alice" / "Documents" / "a.txt"
    source.write_text("a", encoding="utf-8")
    out = tmp_path / "out"
    result = _rescue(root, out, ["Users/Alice/Documents"])
    manifest = json.loads((out / "rr5-rescue-manifest.json").read_text(encoding="utf-8"))
    audit = [json.loads(line) for line in (out / "rr5-audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert manifest["session_id"] == result["session_id"]
    assert manifest["correlation_id"] == result["correlation_id"]
    assert manifest["safety"]["source_read_only"] is True
    assert manifest["safety"]["source_file_execution"] is False
    assert manifest["safety"]["source_delete"] is False
    assert manifest["safety"]["recovery_certification_enabled"] is False
    assert audit[0]["stage"] == "rescue_start"
    assert audit[-1]["stage"] == "rescue_complete"
    assert all(row["session_id"] == result["session_id"] for row in audit)
