from __future__ import annotations

"""Read-only ZIP metadata preflight for explicitly selected local artifacts.

The preflight never extracts entries or reads member contents.  It provides a
bounded risk decision that callers can use before handing a container to a
separate scanner.  A PASS is not a malware-clean verdict.
"""

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path, PurePosixPath
import stat
import struct
import zipfile

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_ENTRY_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_COMPRESSION_RATIO = 250.0
MAX_PATH_DEPTH = 24
MAX_MEMBER_COMPONENT_CHARS = 255
MAX_CENTRAL_DIRECTORY_BYTES = 16 * 1024 * 1024
MAX_EOCD_TAIL_BYTES = 65_535 + 22
ARCHIVE_SUFFIXES = {".zip", ".jar", ".docx", ".xlsx", ".pptx"}
SUPPORTED_COMPRESSION_TYPES = {
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
    zipfile.ZIP_BZIP2,
    zipfile.ZIP_LZMA,
}
WINDOWS_RESERVED_BASENAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
BIDI_PATH_CONTROLS = {
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


@dataclass(frozen=True)
class ArchivePreflight:
    passed: bool
    decision: str
    reasons: tuple[str, ...]
    entry_count: int
    total_compressed_bytes: int
    total_uncompressed_bytes: int
    content_read: bool = False
    extraction_performed: bool = False
    clean_claimed: bool = False
    archive_sha256: str = ""
    snapshot_stable: bool | None = None
    raw_archive_hashed: bool = False

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["reasons"] = list(self.reasons)
        return result


def _unsafe_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    raw_parts = normalized.split("/")
    path = PurePosixPath(normalized)
    return (
        not normalized
        or normalized.startswith("/")
        or (len(normalized) >= 2 and normalized[1] == ":")
        or "." in raw_parts
        or ".." in raw_parts
        or len(path.parts) > MAX_PATH_DEPTH
        or "\x00" in normalized
    )


def _windows_member_hazard(name: str) -> bool:
    normalized = name.replace("\\", "/")
    for component in normalized.split("/"):
        if not component:
            continue
        if len(component) > MAX_MEMBER_COMPONENT_CHARS:
            return True
        if component != component.rstrip(" ."):
            return True
        if ":" in component:
            return True
        basename = component.rstrip(" .").split(".", 1)[0].casefold()
        if basename in WINDOWS_RESERVED_BASENAMES:
            return True
    return False


def _contains_bidi_control(name: str) -> bool:
    return any(character in BIDI_PATH_CONTROLS for character in name)


def _windows_collision_key(name: str) -> str:
    normalized = name.replace("\\", "/")
    return "/".join(
        component.rstrip(" .").casefold()
        for component in normalized.split("/")
        if component
    )


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _sha256_archive(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        st = path.stat(follow_symlinks=False)
        attrs = int(getattr(st, "st_file_attributes", 0) or 0)
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return bool(attrs & reparse_flag)
    except OSError:
        return True


def _read_eocd_metadata(path: Path) -> tuple[int, int, tuple[str, ...]]:
    try:
        size = int(path.stat().st_size)
        read_size = min(size, MAX_EOCD_TAIL_BYTES)
        with path.open("rb") as handle:
            handle.seek(size - read_size)
            tail = handle.read(read_size)
    except OSError:
        return 0, 0, ("archive_unreadable",)

    signature = b"PK\x05\x06"
    search_end = len(tail)
    position = -1
    fields: tuple[int, int, int, int, int, int, int] | None = None
    while True:
        candidate = tail.rfind(signature, 0, search_end)
        if candidate < 0:
            break
        if candidate + 22 <= len(tail):
            unpacked = struct.unpack_from("<4sHHHHIIH", tail, candidate)
            comment_length = int(unpacked[7])
            if candidate + 22 + comment_length == len(tail):
                position = candidate
                fields = (
                    int(unpacked[1]),
                    int(unpacked[2]),
                    int(unpacked[3]),
                    int(unpacked[4]),
                    int(unpacked[5]),
                    int(unpacked[6]),
                    comment_length,
                )
                break
        search_end = candidate

    if position < 0 or fields is None:
        return 0, 0, ("malformed_container",)

    disk_number, directory_disk, entries_disk, entries_total, directory_size, directory_offset, comment_length = fields
    reasons: list[str] = []
    comment = tail[position + 22 : position + 22 + comment_length]
    if signature in comment:
        reasons.append("eocd_signature_in_comment")
    if disk_number != 0 or directory_disk != 0 or entries_disk != entries_total:
        reasons.append("multi_disk_container")
    if (
        entries_total == 0xFFFF
        or entries_disk == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
    ):
        reasons.append("zip64_directory_metadata")
    else:
        if entries_total > MAX_ENTRIES:
            reasons.append("entry_count_limit")
        if directory_size > MAX_CENTRAL_DIRECTORY_BYTES:
            reasons.append("central_directory_size_limit")

        absolute_eocd_offset = size - read_size + position
        if (
            directory_offset > absolute_eocd_offset
            or directory_size > absolute_eocd_offset
            or directory_offset + directory_size > absolute_eocd_offset
        ):
            reasons.append("central_directory_bounds_invalid")

        minimum_directory_size = entries_total * 46
        if (
            (entries_total > 0 and directory_size < minimum_directory_size)
            or (entries_total == 0 and directory_size != 0)
        ):
            reasons.append("central_directory_size_inconsistent")

    return entries_total, directory_size, tuple(dict.fromkeys(reasons))


def inspect_zip_metadata(path: Path) -> ArchivePreflight:
    reasons: list[str] = []
    try:
        size = path.stat().st_size
    except OSError:
        return ArchivePreflight(False, "REJECTED", ("archive_unreadable",), 0, 0, 0)
    if not path.is_file() or path.suffix.casefold() not in ARCHIVE_SUFFIXES:
        return ArchivePreflight(False, "REJECTED", ("unsupported_or_non_file",), 0, 0, 0)
    if _is_reparse_or_symlink(path):
        return ArchivePreflight(False, "REJECTED", ("archive_symlink_or_reparse",), 0, 0, 0)
    if size > MAX_ARCHIVE_BYTES:
        return ArchivePreflight(False, "REJECTED", ("archive_size_limit",), 0, 0, 0)

    try:
        initial_sha256 = _sha256_archive(path)
    except OSError:
        return ArchivePreflight(False, "REJECTED", ("archive_unreadable",), 0, 0, 0)

    eocd_entries, _, eocd_reasons = _read_eocd_metadata(path)
    if eocd_reasons:
        decision = "REJECTED" if eocd_reasons == ("malformed_container",) else "REVIEW_REQUIRED"
        return ArchivePreflight(
            False,
            decision,
            eocd_reasons,
            eocd_entries,
            0,
            0,
            archive_sha256=initial_sha256,
            raw_archive_hashed=True,
        )

    try:
        with zipfile.ZipFile(path, mode="r", allowZip64=False) as archive:
            entries = archive.infolist()
    except (OSError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return ArchivePreflight(False, "REJECTED", ("malformed_container",), 0, 0, 0)

    if len(entries) != eocd_entries:
        reasons.append("entry_count_mismatch")
    if len(entries) > MAX_ENTRIES:
        reasons.append("entry_count_limit")
    compressed = 0
    uncompressed = 0
    seen_names: set[str] = set()
    seen_windows_keys: dict[str, str] = {}
    for info in entries[: MAX_ENTRIES + 1]:
        compressed += max(0, int(info.compress_size))
        uncompressed += max(0, int(info.file_size))
        if _unsafe_name(info.filename):
            reasons.append("unsafe_member_path")
        if _windows_member_hazard(info.filename):
            reasons.append("windows_member_path_hazard")
        if _contains_bidi_control(info.filename):
            reasons.append("unicode_path_control")
        if info.filename in seen_names:
            reasons.append("duplicate_member_name")
        else:
            seen_names.add(info.filename)
        collision_key = _windows_collision_key(info.filename)
        previous_name = seen_windows_keys.get(collision_key)
        if previous_name is not None and previous_name != info.filename:
            reasons.append("windows_member_name_collision")
        else:
            seen_windows_keys[collision_key] = info.filename
        if _is_symlink(info):
            reasons.append("symlink_member")
        if info.flag_bits & 0x1:
            reasons.append("encrypted_member")
        if info.compress_type not in SUPPORTED_COMPRESSION_TYPES:
            reasons.append("unsupported_compression_method")
        if info.file_size > MAX_ENTRY_UNCOMPRESSED_BYTES:
            reasons.append("entry_size_limit")
        ratio = info.file_size / max(1, info.compress_size)
        if ratio > MAX_COMPRESSION_RATIO:
            reasons.append("compression_ratio_limit")
        suffix = PurePosixPath(info.filename.replace("\\", "/")).suffix.casefold()
        if suffix in ARCHIVE_SUFFIXES:
            reasons.append("nested_container")
    if uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
        reasons.append("total_uncompressed_limit")

    snapshot_stable: bool | None
    try:
        final_sha256 = _sha256_archive(path)
    except OSError:
        snapshot_stable = False
        reasons.append("archive_unavailable_after_metadata_scan")
    else:
        snapshot_stable = final_sha256 == initial_sha256
        if not snapshot_stable:
            reasons.append("archive_changed_during_metadata_scan")

    unique = tuple(dict.fromkeys(reasons))
    return ArchivePreflight(
        passed=not unique,
        decision="METADATA_ACCEPTED" if not unique else "REVIEW_REQUIRED",
        reasons=unique,
        entry_count=len(entries),
        total_compressed_bytes=compressed,
        total_uncompressed_bytes=uncompressed,
        archive_sha256=initial_sha256,
        snapshot_stable=snapshot_stable,
        raw_archive_hashed=True,
    )

