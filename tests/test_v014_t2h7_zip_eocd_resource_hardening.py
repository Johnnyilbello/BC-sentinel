from __future__ import annotations

from pathlib import Path
import zipfile

import pytest

from sentinel import archive_container_preflight as preflight


def _zip(path: Path, *, comment: bytes = b"") -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("docs/readme.txt", b"safe-metadata-only")
        archive.comment = comment
    return path


def _eocd_offset(raw: bytes) -> int:
    offset = raw.rfind(b"PK\x05\x06")
    assert offset >= 0
    return offset


def test_eocd_entry_limit_is_enforced_before_zipfile_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _zip(tmp_path / "entries.zip")
    raw = bytearray(path.read_bytes())
    eocd = _eocd_offset(raw)
    count = preflight.MAX_ENTRIES + 1
    raw[eocd + 8 : eocd + 10] = count.to_bytes(2, "little")
    raw[eocd + 10 : eocd + 12] = count.to_bytes(2, "little")
    path.write_bytes(raw)

    def forbidden_parser(*args, **kwargs):
        raise AssertionError("zipfile parser must not run after EOCD entry limit")

    monkeypatch.setattr(preflight.zipfile, "ZipFile", forbidden_parser)
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert report.decision == "REVIEW_REQUIRED"
    assert report.reasons == ("entry_count_limit",)
    assert report.entry_count == count
    assert report.content_read is False
    assert report.extraction_performed is False


def test_eocd_central_directory_size_limit_is_enforced_before_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _zip(tmp_path / "central-size.zip")
    raw = bytearray(path.read_bytes())
    eocd = _eocd_offset(raw)
    size = preflight.MAX_CENTRAL_DIRECTORY_BYTES + 1
    raw[eocd + 12 : eocd + 16] = size.to_bytes(4, "little")
    path.write_bytes(raw)

    def forbidden_parser(*args, **kwargs):
        raise AssertionError("zipfile parser must not run after EOCD size limit")

    monkeypatch.setattr(preflight.zipfile, "ZipFile", forbidden_parser)
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert report.reasons == ("central_directory_size_limit",)
    assert report.content_read is False


def test_zip64_directory_sentinel_is_reviewed_without_full_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _zip(tmp_path / "zip64-sentinel.zip")
    raw = bytearray(path.read_bytes())
    eocd = _eocd_offset(raw)
    raw[eocd + 8 : eocd + 10] = (0xFFFF).to_bytes(2, "little")
    raw[eocd + 10 : eocd + 12] = (0xFFFF).to_bytes(2, "little")
    raw[eocd + 12 : eocd + 16] = (0xFFFFFFFF).to_bytes(4, "little")
    path.write_bytes(raw)

    def forbidden_parser(*args, **kwargs):
        raise AssertionError("zipfile parser must not run for ZIP64 EOCD sentinel")

    monkeypatch.setattr(preflight.zipfile, "ZipFile", forbidden_parser)
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert report.decision == "REVIEW_REQUIRED"
    assert report.reasons == ("zip64_directory_metadata",)
    assert report.content_read is False


def test_multi_disk_metadata_is_reviewed_before_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _zip(tmp_path / "multidisk.zip")
    raw = bytearray(path.read_bytes())
    eocd = _eocd_offset(raw)
    raw[eocd + 4 : eocd + 6] = (1).to_bytes(2, "little")
    raw[eocd + 6 : eocd + 8] = (1).to_bytes(2, "little")
    path.write_bytes(raw)

    def forbidden_parser(*args, **kwargs):
        raise AssertionError("zipfile parser must not run for multi-disk metadata")

    monkeypatch.setattr(preflight.zipfile, "ZipFile", forbidden_parser)
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert report.reasons == ("multi_disk_container",)


def test_eocd_signature_inside_comment_is_reviewed_before_zipfile_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    comment = b"safe-comment-prefix-PK\x05\x06-not-an-eocd"
    path = _zip(tmp_path / "comment-signature.zip", comment=comment)

    def forbidden_parser(*args, **kwargs):
        raise AssertionError("ambiguous EOCD comment must not reach zipfile parser")

    monkeypatch.setattr(preflight.zipfile, "ZipFile", forbidden_parser)
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert report.decision == "REVIEW_REQUIRED"
    assert report.reasons == ("eocd_signature_in_comment",)
    assert report.entry_count == 1
    assert report.content_read is False
    assert report.clean_claimed is False


def test_malformed_eocd_is_rejected_before_zipfile_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _zip(tmp_path / "bad-eocd.zip")
    raw = path.read_bytes()
    path.write_bytes(raw[:-10])

    def forbidden_parser(*args, **kwargs):
        raise AssertionError("zipfile parser must not run for malformed EOCD")

    monkeypatch.setattr(preflight.zipfile, "ZipFile", forbidden_parser)
    report = preflight.inspect_zip_metadata(path)

    assert report.passed is False
    assert report.decision == "REJECTED"
    assert report.reasons == ("malformed_container",)


def test_archive_symlink_is_rejected_when_platform_supports_symlink(tmp_path: Path):
    target = _zip(tmp_path / "target.zip")
    link = tmp_path / "link.zip"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable on this runner")

    report = preflight.inspect_zip_metadata(link)
    assert report.passed is False
    assert report.decision == "REJECTED"
    assert report.reasons == ("archive_symlink_or_reparse",)


def test_normal_archive_still_reaches_bounded_metadata_parser(tmp_path: Path):
    report = preflight.inspect_zip_metadata(_zip(tmp_path / "normal.zip"))
    assert report.passed is True
    assert report.decision == "METADATA_ACCEPTED"
    assert report.entry_count == 1
    assert report.content_read is False
    assert report.extraction_performed is False
    assert report.clean_claimed is False
