from __future__ import annotations

"""Bounded, read-only PE metadata preflight for T2 static analysis.

The preflight parses a local PE artifact from bounded in-memory bytes. It never
loads the image through the Windows loader, executes code, resolves imports,
starts a process, modifies the target, quarantines it or makes a malware-clean
claim. Findings are metadata-only reasons for review.
"""

from dataclasses import asdict, dataclass
import hashlib
import math
from pathlib import Path
import stat
from typing import Final

MAX_PE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_PE_SECTIONS: Final[int] = 32
HIGH_ENTROPY_THRESHOLD: Final[float] = 7.30
SUPPORTED_PE_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".exe", ".dll", ".sys", ".scr", ".cpl", ".drv", ".ocx"}
)

IMAGE_SCN_MEM_EXECUTE: Final[int] = 0x20000000
IMAGE_SCN_MEM_WRITE: Final[int] = 0x80000000
KNOWN_MACHINE_TYPES: Final[frozenset[int]] = frozenset({0x014C, 0x8664, 0xAA64})
KNOWN_OPTIONAL_MAGICS: Final[frozenset[int]] = frozenset({0x010B, 0x020B})


@dataclass(frozen=True)
class PEMetadataPreflight:
    passed: bool
    decision: str
    reasons: tuple[str, ...]
    file_size: int
    sha256: str
    machine: int
    section_count: int
    entrypoint_rva: int
    image_base: int
    timestamp: int
    executable_sections: tuple[str, ...]
    writable_executable_sections: tuple[str, ...]
    high_entropy_sections: tuple[str, ...]
    content_executed: bool = False
    image_loaded: bool = False
    imports_resolved: bool = False
    target_modified: bool = False
    quarantine_performed: bool = False
    clean_claimed: bool = False

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        for field_name in (
            "reasons",
            "executable_sections",
            "writable_executable_sections",
            "high_entropy_sections",
        ):
            result[field_name] = list(result[field_name])
        return result


def _rejected(reason: str, *, file_size: int = 0, sha256: str = "") -> PEMetadataPreflight:
    return PEMetadataPreflight(
        passed=False,
        decision="REJECTED",
        reasons=(reason,),
        file_size=file_size,
        sha256=sha256,
        machine=0,
        section_count=0,
        entrypoint_rva=0,
        image_base=0,
        timestamp=0,
        executable_sections=(),
        writable_executable_sections=(),
        high_entropy_sections=(),
    )


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


def _bounded_read(path: Path, *, max_bytes: int) -> bytes:
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not (1 <= max_bytes <= MAX_PE_BYTES):
        raise ValueError("PE preflight max_bytes outside bounded limit")
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("PE preflight file exceeds bounded size")
    return data


def _section_name(section: object, index: int) -> str:
    raw = getattr(section, "Name", b"")
    if isinstance(raw, bytes):
        decoded = raw.rstrip(b"\x00").decode("ascii", errors="replace")
    else:
        decoded = str(raw or "")
    name = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in decoded).strip()
    return name or f"section-{index}"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = float(len(data))
    entropy = 0.0
    for count in counts:
        if not count:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def inspect_pe_metadata(path: Path, *, max_bytes: int = MAX_PE_BYTES) -> PEMetadataPreflight:
    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or not (1 <= max_bytes <= MAX_PE_BYTES)
    ):
        return _rejected("pe_limit_invalid")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return _rejected("pe_unreadable")

    if (
        not resolved.is_file()
        or _is_reparse_or_symlink(resolved)
        or resolved.suffix.casefold() not in SUPPORTED_PE_SUFFIXES
    ):
        return _rejected("unsupported_or_non_file")

    try:
        size = int(resolved.stat().st_size)
    except OSError:
        return _rejected("pe_unreadable")
    if size < 0 or size > max_bytes or size > MAX_PE_BYTES:
        return _rejected("pe_size_limit", file_size=max(0, size))

    try:
        data = _bounded_read(resolved, max_bytes=max_bytes)
    except (OSError, ValueError):
        return _rejected("pe_size_or_read_limit", file_size=max(0, size))

    digest = hashlib.sha256(data).hexdigest()

    try:
        import pefile  # type: ignore
    except Exception:
        return _rejected("pe_parser_unavailable", file_size=len(data), sha256=digest)

    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception:
        return _rejected("malformed_pe", file_size=len(data), sha256=digest)

    reasons: list[str] = []
    executable: list[str] = []
    writable_executable: list[str] = []
    high_entropy: list[str] = []
    ranges: list[tuple[int, int, str]] = []

    try:
        machine = int(pe.FILE_HEADER.Machine)
        section_count = int(pe.FILE_HEADER.NumberOfSections)
        timestamp = int(pe.FILE_HEADER.TimeDateStamp)
        optional_magic = int(pe.OPTIONAL_HEADER.Magic)
        entrypoint = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        size_of_headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
        size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)
        file_alignment = int(pe.OPTIONAL_HEADER.FileAlignment)
        section_alignment = int(pe.OPTIONAL_HEADER.SectionAlignment)

        if machine not in KNOWN_MACHINE_TYPES:
            reasons.append("unknown_machine_type")
        if optional_magic not in KNOWN_OPTIONAL_MAGICS:
            reasons.append("unknown_optional_header_magic")
        if size_of_headers <= 0 or size_of_headers > len(data):
            reasons.append("size_of_headers_invalid")
        if size_of_image <= 0:
            reasons.append("size_of_image_invalid")
        if file_alignment <= 0 or section_alignment <= 0:
            reasons.append("alignment_invalid")
        elif section_alignment < file_alignment:
            reasons.append("section_alignment_smaller_than_file_alignment")

        sections = list(pe.sections)
        if section_count != len(sections):
            reasons.append("section_count_mismatch")
        if not (1 <= section_count <= MAX_PE_SECTIONS):
            reasons.append("section_count_limit")

        entrypoint_mapped = entrypoint == 0
        entrypoint_executable = entrypoint == 0
        virtual_ranges: list[tuple[int, int, str]] = []
        seen_section_names: set[str] = set()
        for index, section in enumerate(sections[: MAX_PE_SECTIONS + 1]):
            name = _section_name(section, index)
            raw_name = getattr(section, "Name", b"")
            if isinstance(raw_name, bytes):
                visible_raw_name = raw_name.rstrip(b"\x00")
                if any(value < 32 or value >= 127 for value in visible_raw_name):
                    reasons.append("section_name_non_printable")
            characteristics = int(getattr(section, "Characteristics", 0) or 0)
            normalized_name = name.casefold()
            if normalized_name in seen_section_names:
                reasons.append("duplicate_section_name")
            seen_section_names.add(normalized_name)
            raw_offset = int(getattr(section, "PointerToRawData", 0) or 0)
            raw_size = int(getattr(section, "SizeOfRawData", 0) or 0)
            virtual_address = int(getattr(section, "VirtualAddress", 0) or 0)
            virtual_size = int(getattr(section, "Misc_VirtualSize", 0) or 0)

            if characteristics & IMAGE_SCN_MEM_EXECUTE:
                executable.append(name)
                if characteristics & IMAGE_SCN_MEM_WRITE:
                    writable_executable.append(name)
                    reasons.append("writable_executable_section")

            if raw_offset < 0 or raw_size < 0 or raw_offset + raw_size > len(data):
                reasons.append("section_raw_bounds_invalid")
                section_bytes = b""
            else:
                section_bytes = data[raw_offset : raw_offset + raw_size]
                if raw_size:
                    ranges.append((raw_offset, raw_offset + raw_size, name))
                    if size_of_headers > 0 and raw_offset < size_of_headers:
                        reasons.append("section_raw_overlaps_headers")

            if section_bytes and _entropy(section_bytes) >= HIGH_ENTROPY_THRESHOLD:
                high_entropy.append(name)
                reasons.append("high_entropy_section")

            mapped_size = max(virtual_size, raw_size)
            if mapped_size > 0:
                virtual_ranges.append(
                    (virtual_address, virtual_address + mapped_size, name)
                )
            if (
                entrypoint
                and mapped_size > 0
                and virtual_address <= entrypoint < virtual_address + mapped_size
            ):
                entrypoint_mapped = True
                if characteristics & IMAGE_SCN_MEM_EXECUTE:
                    entrypoint_executable = True

        if not entrypoint_mapped:
            reasons.append("entrypoint_outside_sections")
        elif not entrypoint_executable:
            reasons.append("entrypoint_in_non_executable_section")

        ranges.sort()
        for previous, current in zip(ranges, ranges[1:]):
            if current[0] < previous[1]:
                reasons.append("overlapping_raw_sections")
                break

        virtual_ranges.sort()
        for previous, current in zip(virtual_ranges, virtual_ranges[1:]):
            if current[0] < previous[1]:
                reasons.append("overlapping_virtual_sections")
                break
    except (AttributeError, OverflowError, TypeError, ValueError):
        return _rejected("malformed_pe_metadata", file_size=len(data), sha256=digest)
    finally:
        try:
            pe.close()
        except Exception:
            pass

    unique = tuple(dict.fromkeys(reasons))
    return PEMetadataPreflight(
        passed=not unique,
        decision="PE_METADATA_ACCEPTED" if not unique else "REVIEW_REQUIRED",
        reasons=unique,
        file_size=len(data),
        sha256=digest,
        machine=machine,
        section_count=section_count,
        entrypoint_rva=entrypoint,
        image_base=image_base,
        timestamp=timestamp,
        executable_sections=tuple(executable),
        writable_executable_sections=tuple(writable_executable),
        high_entropy_sections=tuple(high_entropy),
    )
