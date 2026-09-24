from __future__ import annotations

"""Read-only ZIP metadata preflight for explicitly selected local artifacts.

The preflight never extracts entries or reads member contents.  It provides a
bounded risk decision that callers can use before handing a container to a
separate scanner.  A PASS is not a malware-clean verdict.
"""

from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
import stat
import zipfile

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_ENTRY_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_COMPRESSION_RATIO = 250.0
MAX_PATH_DEPTH = 24
MAX_MEMBER_COMPONENT_CHARS = 255
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


def inspect_zip_metadata(path: Path) -> ArchivePreflight:
    reasons: list[str] = []
    try:
        size = path.stat().st_size
    except OSError:
        return ArchivePreflight(False, "REJECTED", ("archive_unreadable",), 0, 0, 0)
    if not path.is_file() or path.suffix.casefold() not in ARCHIVE_SUFFIXES:
        return ArchivePreflight(False, "REJECTED", ("unsupported_or_non_file",), 0, 0, 0)
    if size > MAX_ARCHIVE_BYTES:
        return ArchivePreflight(False, "REJECTED", ("archive_size_limit",), 0, 0, 0)

    try:
        with zipfile.ZipFile(path, mode="r", allowZip64=True) as archive:
            entries = archive.infolist()
    except (OSError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return ArchivePreflight(False, "REJECTED", ("malformed_container",), 0, 0, 0)

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

    unique = tuple(dict.fromkeys(reasons))
    return ArchivePreflight(
        passed=not unique,
        decision="METADATA_ACCEPTED" if not unique else "REVIEW_REQUIRED",
        reasons=unique,
        entry_count=len(entries),
        total_compressed_bytes=compressed,
        total_uncompressed_bytes=uncompressed,
    )

