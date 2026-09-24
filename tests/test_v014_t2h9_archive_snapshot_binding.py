from __future__ import annotations

import hashlib
from pathlib import Path
import zipfile

import pytest

from sentinel import archive_container_preflight as preflight


def _zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("docs/readme.txt", b"safe-static-metadata")
    return path


def test_archive_metadata_is_bound_to_stable_sha256_snapshot(tmp_path: Path):
    path = _zip(tmp_path / "stable.zip")
    expected = hashlib.sha256(path.read_bytes()).hexdigest()

    report = preflight.inspect_zip_metadata(path)

    assert report.passed is True
    assert report.decision == "METADATA_ACCEPTED"
    assert report.archive_sha256 == expected
    assert report.snapshot_stable is True
    assert report.raw_archive_hashed is True
    assert report.content_read is False
    assert report.extraction_performed is False
    assert report.clean_claimed is False


def test_archive_hash_change_during_metadata_scan_forces_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _zip(tmp_path / "changed.zip")
    real_hash = preflight._sha256_archive
    calls = 0

    def changing_hash(target: Path) -> str:
        nonlocal calls
        calls += 1
        if target == path and calls >= 2:
            return "0" * 64
        return real_hash(target)

    monkeypatch.setattr(preflight, "_sha256_archive", changing_hash)
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert report.decision == "REVIEW_REQUIRED"
    assert "archive_changed_during_metadata_scan" in report.reasons
    assert report.snapshot_stable is False
    assert report.raw_archive_hashed is True
    assert report.archive_sha256 != "0" * 64
    assert report.content_read is False
    assert report.extraction_performed is False


def test_archive_unavailable_after_metadata_scan_forces_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _zip(tmp_path / "unavailable.zip")
    real_hash = preflight._sha256_archive
    calls = 0

    def unavailable_hash(target: Path) -> str:
        nonlocal calls
        calls += 1
        if target == path and calls >= 2:
            raise OSError("synthetic TOCTOU disappearance")
        return real_hash(target)

    monkeypatch.setattr(preflight, "_sha256_archive", unavailable_hash)
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert report.decision == "REVIEW_REQUIRED"
    assert "archive_unavailable_after_metadata_scan" in report.reasons
    assert report.snapshot_stable is False
    assert report.raw_archive_hashed is True
    assert report.content_read is False


def test_early_eocd_review_still_records_initial_archive_identity(tmp_path: Path):
    path = _zip(tmp_path / "ambiguous.zip")
    with zipfile.ZipFile(path, "a") as archive:
        archive.comment = b"ambiguous-PK\x05\x06-comment"

    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert report.decision == "REVIEW_REQUIRED"
    assert "eocd_signature_in_comment" in report.reasons
    assert report.archive_sha256 == expected
    assert report.raw_archive_hashed is True
    assert report.snapshot_stable is None
    assert report.content_read is False


def test_snapshot_binding_does_not_enable_member_read_or_extraction(tmp_path: Path):
    path = _zip(tmp_path / "safety.zip")
    report = preflight.inspect_zip_metadata(path)

    assert report.raw_archive_hashed is True
    assert report.content_read is False
    assert report.extraction_performed is False
    assert report.clean_claimed is False
