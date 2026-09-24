from __future__ import annotations

from pathlib import Path
import warnings
import zipfile

import pytest

from sentinel import archive_container_preflight as preflight


def _write(path: Path, names: list[str]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for index, name in enumerate(names):
            archive.writestr(name, f"metadata-only-{index}".encode())
    return path


@pytest.mark.parametrize(
    "name",
    [
        "docs/CON.txt",
        "docs/NUL",
        "docs/report.txt:alternate",
        "docs/trailing. ",
        "docs/" + ("x" * (preflight.MAX_MEMBER_COMPONENT_CHARS + 1)) + ".txt",
    ],
    ids=["con", "nul", "ads", "trailing-dot-space", "oversized-component"],
)
def test_windows_hostile_member_names_require_review(tmp_path: Path, name: str):
    report = preflight.inspect_zip_metadata(_write(tmp_path / "hostile.zip", [name]))
    assert report.passed is False
    assert "windows_member_path_hazard" in report.reasons
    assert report.content_read is False
    assert report.extraction_performed is False


def test_case_insensitive_member_collision_requires_review(tmp_path: Path):
    report = preflight.inspect_zip_metadata(
        _write(tmp_path / "collision.zip", ["Docs/Readme.txt", "docs/readme.TXT"])
    )
    assert report.passed is False
    assert "windows_member_name_collision" in report.reasons


def test_exact_duplicate_member_name_requires_review(tmp_path: Path):
    path = tmp_path / "duplicate.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("docs/readme.txt", b"one")
            archive.writestr("docs/readme.txt", b"two")
    report = preflight.inspect_zip_metadata(path)
    assert report.passed is False
    assert "duplicate_member_name" in report.reasons


def test_bidi_override_in_member_name_requires_review(tmp_path: Path):
    report = preflight.inspect_zip_metadata(
        _write(tmp_path / "unicode.zip", ["docs/invoice\u202etxt.exe"])
    )
    assert report.passed is False
    assert "unicode_path_control" in report.reasons


def test_explicit_dot_segment_is_not_silently_normalized(tmp_path: Path):
    report = preflight.inspect_zip_metadata(
        _write(tmp_path / "dot-segment.zip", ["docs/./report.txt"])
    )
    assert report.passed is False
    assert "unsafe_member_path" in report.reasons


def test_unknown_compression_method_is_rejected_from_metadata_only(tmp_path: Path):
    path = _write(tmp_path / "unknown-method.zip", ["docs/readme.txt"])
    raw = bytearray(path.read_bytes())

    local = raw.find(b"PK\x03\x04")
    central = raw.find(b"PK\x01\x02")
    assert local >= 0 and central >= 0

    # Compression method fields in local and central headers.  We alter metadata
    # only; the preflight never attempts to decompress the member.
    raw[local + 8 : local + 10] = (99).to_bytes(2, "little")
    raw[central + 10 : central + 12] = (99).to_bytes(2, "little")
    path.write_bytes(raw)

    report = preflight.inspect_zip_metadata(path)
    assert report.passed is False
    assert "unsupported_compression_method" in report.reasons
    assert report.content_read is False
    assert report.extraction_performed is False


def test_h8_archive_cases_never_claim_clean(tmp_path: Path):
    report = preflight.inspect_zip_metadata(
        _write(tmp_path / "safe.zip", ["docs/readme.txt"])
    )
    assert report.clean_claimed is False
