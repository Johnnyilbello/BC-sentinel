from __future__ import annotations

from pathlib import Path
import zipfile

import pytest

from sentinel import archive_container_preflight as preflight


def _zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("docs/readme.txt", b"static-safe")
    return path


def _eocd(raw: bytes) -> int:
    offset = raw.rfind(b"PK\x05\x06")
    assert offset >= 0
    return offset


def test_central_directory_offset_past_eocd_is_reviewed_before_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _zip(tmp_path / "offset.zip")
    raw = bytearray(path.read_bytes())
    eocd = _eocd(raw)
    raw[eocd + 16 : eocd + 20] = (eocd + 1).to_bytes(4, "little")
    path.write_bytes(raw)

    def forbidden_parser(*args, **kwargs):
        raise AssertionError("invalid central-directory geometry must not reach parser")

    monkeypatch.setattr(preflight.zipfile, "ZipFile", forbidden_parser)
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert report.decision == "REVIEW_REQUIRED"
    assert "central_directory_bounds_invalid" in report.reasons
    assert report.content_read is False


def test_central_directory_size_smaller_than_minimum_header_is_reviewed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _zip(tmp_path / "small-central.zip")
    raw = bytearray(path.read_bytes())
    eocd = _eocd(raw)
    raw[eocd + 12 : eocd + 16] = (45).to_bytes(4, "little")
    path.write_bytes(raw)

    def forbidden_parser(*args, **kwargs):
        raise AssertionError("inconsistent central-directory size must not reach parser")

    monkeypatch.setattr(preflight.zipfile, "ZipFile", forbidden_parser)
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert "central_directory_size_inconsistent" in report.reasons


def test_zero_entries_with_nonzero_directory_is_inconsistent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _zip(tmp_path / "zero-count.zip")
    raw = bytearray(path.read_bytes())
    eocd = _eocd(raw)
    raw[eocd + 8 : eocd + 10] = (0).to_bytes(2, "little")
    raw[eocd + 10 : eocd + 12] = (0).to_bytes(2, "little")
    path.write_bytes(raw)

    def forbidden_parser(*args, **kwargs):
        raise AssertionError("zero-count inconsistent directory must not reach parser")

    monkeypatch.setattr(preflight.zipfile, "ZipFile", forbidden_parser)
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert "central_directory_size_inconsistent" in report.reasons


def test_zip64_directory_offset_sentinel_is_reviewed_early(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _zip(tmp_path / "zip64-offset.zip")
    raw = bytearray(path.read_bytes())
    eocd = _eocd(raw)
    raw[eocd + 16 : eocd + 20] = (0xFFFFFFFF).to_bytes(4, "little")
    path.write_bytes(raw)

    def forbidden_parser(*args, **kwargs):
        raise AssertionError("ZIP64 offset sentinel must not reach parser")

    monkeypatch.setattr(preflight.zipfile, "ZipFile", forbidden_parser)
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert "zip64_directory_metadata" in report.reasons


def test_bounded_self_extracting_prefix_remains_metadata_compatible(tmp_path: Path):
    source = _zip(tmp_path / "source.zip")
    prefixed = tmp_path / "prefixed.zip"
    prefixed.write_bytes(b"MZ-SAFE-STATIC-STUB" * 16 + source.read_bytes())

    report = preflight.inspect_zip_metadata(prefixed)

    assert report.passed is True
    assert report.decision == "METADATA_ACCEPTED"
    assert report.entry_count == 1
    assert report.content_read is False
    assert report.extraction_performed is False
    assert report.clean_claimed is False


def test_normal_eocd_geometry_still_passes(tmp_path: Path):
    report = preflight.inspect_zip_metadata(_zip(tmp_path / "normal.zip"))
    assert report.passed is True
    assert report.reasons == ()
