from __future__ import annotations

import hashlib
import json
import random
import struct
import subprocess
import sys
from pathlib import Path

import pefile
import pytest

from sentinel import static_pe_preflight as pecheck
from sentinel import rescue_offline_scanner as rr3
from test_v014_t2h6_pe_adversarial_matrix import _build_pe
from test_v014_t2h4_offline_pe_integration import _offline_root, _scan


OPTIONAL = 0x98
SECTION = OPTIONAL + 0xE0


def _patch(offset: int, value: int, fmt: str = "<I") -> bytes:
    data = bytearray(_build_pe())
    struct.pack_into(fmt, data, offset, value)
    return bytes(data)


def _inspect(tmp_path: Path, data: bytes):
    path = tmp_path / "synthetic.exe"
    path.write_bytes(data)
    report = pecheck.inspect_pe_metadata(path)
    assert path.read_bytes() == data
    assert report.sha256 == hashlib.sha256(data).hexdigest()
    for field in ("content_executed", "image_loaded", "imports_resolved",
                  "target_modified", "quarantine_performed", "clean_claimed"):
        assert getattr(report, field) is False
    return report


@pytest.mark.parametrize(("offset", "value", "reason"), [
    (OPTIONAL + 56, 0x1000, "section_virtual_bounds_invalid"),
    (OPTIONAL + 56, 0x2001, "size_of_image_misaligned"),
    (OPTIONAL + 60, 0x100, "headers_do_not_cover_section_table"),
    (OPTIONAL + 60, 0x201, "size_of_headers_misaligned"),
    (OPTIONAL + 36, 0x300, "alignment_invalid"),
    (OPTIONAL + 32, 0x1100, "alignment_invalid"),
    (SECTION + 12, 0x1001, "section_virtual_address_misaligned"),
    (SECTION + 20, 0x201, "section_raw_offset_misaligned"),
    (SECTION + 16, 0x1FF, "section_raw_size_misaligned"),
    (SECTION + 8, 0xFFFFFFFF, "section_virtual_bounds_invalid"),
    (OPTIONAL + 16, 0x2000, "entrypoint_outside_image"),
    (OPTIONAL + 92, 17, "data_directory_count_invalid"),
])
def test_inconsistent_geometry_is_never_accepted(tmp_path, offset, value, reason):
    report = _inspect(tmp_path, _patch(offset, value))
    assert not report.passed
    assert reason in report.reasons


@pytest.mark.parametrize(("machine", "magic"), [(0x14C, 0x20B), (0x8664, 0x10B), (0xAA64, 0x10B)])
def test_architecture_and_optional_header_must_agree(tmp_path, machine, magic):
    report = _inspect(tmp_path, _build_pe(machine=machine, optional_magic=magic))
    assert not report.passed
    assert "machine_optional_header_mismatch" in report.reasons


def test_entrypoint_in_zero_fill_is_reviewed(tmp_path):
    data = bytearray(_patch(SECTION + 8, 0x800))
    struct.pack_into("<I", data, OPTIONAL + 16, 0x1400)
    report = _inspect(tmp_path, bytes(data))
    assert "entrypoint_not_file_backed" in report.reasons
    assert not report.passed


@pytest.mark.parametrize(("offset", "value", "fmt", "reason"), [
    (0x86, 65535, "<H", "section_count_limit"),
    (0x94, 0xFFFF, "<H", "pe_header_bounds_invalid"),
    (0x94, 0, "<H", "pe_header_bounds_invalid"),
    (0x3C, 0xFFFFFFF0, "<I", "malformed_pe"),
])
def test_structural_budgets_are_checked_before_parser(tmp_path, monkeypatch, offset, value, fmt, reason):
    def forbidden_parser(*args, **kwargs):
        pytest.fail("unbounded or malformed header reached pefile")
    monkeypatch.setattr(pefile, "PE", forbidden_parser)
    report = _inspect(tmp_path, _patch(offset, value, fmt))
    assert not report.passed
    assert reason in report.reasons


@pytest.mark.parametrize("length", [0, 1, 2, 63, 64, 127, 131, 151, 247, 375, 400, 511, 512, 1023])
def test_truncated_fixture_fails_closed(tmp_path, length):
    report = _inspect(tmp_path, _build_pe()[:length])
    assert not report.passed


@pytest.mark.parametrize(("machine", "magic"), [(0x14C, 0x10B), (0x8664, 0x20B), (0xAA64, 0x20B)])
def test_supported_innocuous_controls_remain_accepted(tmp_path, machine, magic):
    report = _inspect(tmp_path, _build_pe(machine=machine, optional_magic=magic))
    assert report.passed


def test_zero_entrypoint_dll_is_not_reported_as_unbacked(tmp_path):
    data = bytearray(_build_pe(entrypoint=0))
    struct.pack_into("<H", data, 0x96, 0x2102)
    assert _inspect(tmp_path, bytes(data)).passed


def test_small_equal_alignments_remain_supported(tmp_path):
    assert _inspect(tmp_path, _build_pe(file_alignment=0x200, section_alignment=0x200)).passed


def test_path_link_is_checked_before_resolution(tmp_path, monkeypatch):
    path = tmp_path / "link.exe"
    path.write_bytes(_build_pe())
    checked = []
    def reparse(candidate):
        checked.append(candidate)
        return candidate == path
    def forbidden_resolve(*args, **kwargs):
        pytest.fail("link was resolved before rejecting it")
    monkeypatch.setattr(pecheck, "_is_reparse_or_symlink", reparse)
    monkeypatch.setattr(Path, "resolve", forbidden_resolve)
    report = pecheck.inspect_pe_metadata(path)
    assert not report.passed
    assert checked == [path]


def test_linked_parent_is_rejected_before_read(tmp_path, monkeypatch):
    folder = tmp_path / "junction"
    folder.mkdir()
    path = folder / "fixture.exe"
    path.write_bytes(_build_pe())
    monkeypatch.setattr(pecheck, "_is_reparse_or_symlink", lambda p: p == folder)
    monkeypatch.setattr(pecheck, "_bounded_read", lambda *a, **k: pytest.fail("read through linked parent"))
    assert not pecheck.inspect_pe_metadata(path).passed


def test_geometry_findings_reach_offline_scanner(tmp_path):
    root = _offline_root(tmp_path)
    path = root / "Windows" / "System32" / "geometry.exe"
    data = _patch(OPTIONAL + 56, 0x1000)
    path.write_bytes(data)
    report = _scan(root, tmp_path / "evidence")
    finding = next(row for row in report["findings"] if row["relative_path"].endswith("geometry.exe"))
    assert finding["verdict"] == "review"
    assert "section_virtual_bounds_invalid" in finding["pe_metadata_reasons"]
    assert finding["final_sha256_matches"] is True
    assert path.read_bytes() == data
    assert finding["automatic_action"] is False


def test_seeded_metadata_mutations_are_deterministic_and_non_crashing(tmp_path):
    rng = random.Random(0xBC1406)
    baseline = _build_pe()
    path = tmp_path / "mutated.exe"
    for _ in range(512):
        data = bytearray(baseline)
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        path.write_bytes(data)
        first = pecheck.inspect_pe_metadata(path)
        second = pecheck.inspect_pe_metadata(path)
        assert first == second
        assert first.sha256 == hashlib.sha256(data).hexdigest()
        assert first.passed == (first.decision == "PE_METADATA_ACCEPTED")
        assert bool(first.reasons) != first.passed
        assert not first.clean_claimed
        assert path.read_bytes() == data


def test_real_yara_and_ioc_with_benign_negative_controls(tmp_path, monkeypatch):
    root = _offline_root(tmp_path)
    folder = root / "Windows" / "System32"
    marker = b"BC_SENTINEL_H6_INNOCUOUS_MARKER_2026"
    fixtures = {
        "positive.exe": _build_pe() + marker,
        "negative32.exe": _build_pe(),
        "negative64.exe": _build_pe(machine=0x8664, optional_magic=0x20B),
        "negativearm64.exe": _build_pe(machine=0xAA64, optional_magic=0x20B),
    }
    for name, data in fixtures.items():
        (folder / name).write_bytes(data)
    rules = tmp_path / "harmless.yar"
    rules.write_text('rule BC_H6_SAFE { strings: $m = "' + marker.decode() + '" condition: $m }', encoding="utf-8")
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({
        "schema": "bc-sentinel-offline-intel-v1", "approved": True,
        "sha256": [{"value": hashlib.sha256(fixtures["positive.exe"]).hexdigest(),
                    "name": "H6.Innocuous.Marker", "source": "synthetic-regression"}],
    }), encoding="utf-8")
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("scanner attempted process execution"))
    report = _scan(root, tmp_path / "out", intel_catalog=catalog, yara_rules=rules)
    rows = {Path(row["relative_path"]).name: row for row in report["findings"]}
    assert rows["positive.exe"]["verdict"] == "deterministic_ioc"
    assert rows["positive.exe"]["yara_matches"] == ["BC_H6_SAFE"]
    for name, data in fixtures.items():
        assert (folder / name).read_bytes() == data
        assert rows[name]["final_sha256_matches"] is True
        assert rows[name]["automatic_action"] is False
        if name.startswith("negative"):
            assert rows[name]["verdict"] == "observed"
            assert rows[name]["yara_matches"] == []
    assert report["summary"]["ioc_hits"] == report["summary"]["yara_hits"] == 1
    assert report["safety"]["target_read_only"] is True
    assert all(value is False for key, value in report["safety"].items() if key != "target_read_only")


def test_yara_timeout_is_review_not_negative_detection(tmp_path, monkeypatch):
    class TimeoutRules:
        def match(self, **kwargs):
            raise TimeoutError("synthetic timeout")
    root = _offline_root(tmp_path)
    monkeypatch.setattr(rr3, "_compile_yara", lambda p: (TimeoutRules(), "available"))
    report = _scan(root, tmp_path / "out")
    assert report["findings"]
    for row in report["findings"]:
        assert row["verdict"] == "review"
        assert "__YARA_ERROR__:TimeoutError" in row["reasons"]
        assert row["yara_matches"] == []


def test_missing_pe_parser_propagates_review(tmp_path, monkeypatch):
    root = _offline_root(tmp_path)
    monkeypatch.setitem(sys.modules, "pefile", None)
    report = _scan(root, tmp_path / "out")
    assert report["findings"]
    for row in report["findings"]:
        assert row["verdict"] == "review"
        assert row["pe_metadata_decision"] == "REJECTED"
        assert row["pe_metadata_reasons"] == ["pe_parser_unavailable"]
