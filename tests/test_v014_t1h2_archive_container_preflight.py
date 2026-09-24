from __future__ import annotations

from pathlib import Path
import stat
import zipfile

from sentinel import archive_container_preflight as preflight


def _zip(path: Path, rows: list[tuple[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in rows:
            archive.writestr(name, content)
    return path


def test_benign_zip_metadata_is_accepted_without_content_read_or_extraction(tmp_path: Path):
    report = preflight.inspect_zip_metadata(_zip(tmp_path / "benign.zip", [("docs/readme.txt", b"hello")]))
    assert report.passed is True
    assert report.decision == "METADATA_ACCEPTED"
    assert report.content_read is False
    assert report.extraction_performed is False
    assert report.clean_claimed is False
    assert not list(tmp_path.glob("docs/*"))


def test_path_traversal_and_absolute_members_require_review(tmp_path: Path):
    report = preflight.inspect_zip_metadata(
        _zip(tmp_path / "paths.zip", [("../escape.txt", b"x"), ("C:/outside.txt", b"x")])
    )
    assert report.passed is False
    assert report.decision == "REVIEW_REQUIRED"
    assert "unsafe_member_path" in report.reasons
    assert not (tmp_path.parent / "escape.txt").exists()


def test_nested_container_requires_review(tmp_path: Path):
    report = preflight.inspect_zip_metadata(_zip(tmp_path / "nested.zip", [("payload/inner.zip", b"PK")]))
    assert report.reasons == ("nested_container",)


def test_high_compression_ratio_is_bounded_without_decompression(tmp_path: Path):
    report = preflight.inspect_zip_metadata(_zip(tmp_path / "ratio.zip", [("zeros.bin", b"0" * 2_000_000)]))
    assert "compression_ratio_limit" in report.reasons
    assert report.content_read is False


def test_symlink_member_requires_review(tmp_path: Path):
    path = tmp_path / "link.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, "target")
    assert "symlink_member" in preflight.inspect_zip_metadata(path).reasons


def test_malformed_and_unsupported_inputs_fail_closed(tmp_path: Path):
    malformed = tmp_path / "broken.zip"
    malformed.write_bytes(b"PK-not-a-container")
    assert preflight.inspect_zip_metadata(malformed).reasons == ("malformed_container",)
    unsupported = tmp_path / "sample.rar"
    unsupported.write_bytes(b"data")
    assert preflight.inspect_zip_metadata(unsupported).reasons == ("unsupported_or_non_file",)


def test_excessive_path_depth_requires_review(tmp_path: Path):
    name = "/".join(["d"] * (preflight.MAX_PATH_DEPTH + 1)) + "/file.txt"
    report = preflight.inspect_zip_metadata(_zip(tmp_path / "deep.zip", [(name, b"x")]))
    assert "unsafe_member_path" in report.reasons
