"""Bounded BC file scanning shared by manual and change-triggered scans."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path
import zipfile
import zlib

from sentinel.archive_container_preflight import ARCHIVE_SUFFIXES, MAX_EOCD_TAIL_BYTES, read_zip_directory_tail
from sentinel.rescue_offline_scanner import load_approved_intel_catalog, _is_reparse_or_symlink, _validate_local_path, _compile_yara

# EICAR's harmless 68-byte standard test file, not a malware signature database.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
MAX_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_ARCHIVE_EXPANSION = 64 * 1024 * 1024


def _scan_archive(data, path, cancelled, inspect, error):
    expected, _, reasons = read_zip_directory_tail(data[-MAX_EOCD_TAIL_BYTES:], len(data))
    if reasons or expected > MAX_ARCHIVE_MEMBERS:
        error(f"Contenuto ZIP non analizzato: {path} ({', '.join(reasons) or 'limite elementi'})")
        return
    try:
        with zipfile.ZipFile(io.BytesIO(data), allowZip64=False) as archive:
            members = archive.infolist()
            if len(members) != expected or sum(member.file_size for member in members) > MAX_ARCHIVE_EXPANSION:
                error(f"Contenuto ZIP non analizzato: {path} (limite espansione o indice incoerente)")
                return
            for member in members:
                if cancelled():
                    return
                if member.is_dir():
                    continue
                location = f"{path} → {member.filename!r}"
                if (member.file_size > MAX_MEMBER_BYTES or member.flag_bits & 1 or
                        member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) or
                        member.file_size > 250 * max(1, member.compress_size)):
                    error(f"Elemento ZIP non analizzato: {location}")
                    continue
                with archive.open(member) as stream:
                    payload = stream.read(MAX_MEMBER_BYTES + 1)
                if len(payload) != member.file_size or len(payload) > MAX_MEMBER_BYTES:
                    error(f"Dimensione elemento ZIP incoerente: {location}")
                    continue
                inspect(payload, hashlib.sha256(payload).hexdigest(), location)
                if Path(member.filename).suffix.casefold() in ARCHIVE_SUFFIXES or payload.startswith(b"PK\x03\x04"):
                    error(f"Archivio annidato non aperto: {location}")
    except (OSError, ValueError, RuntimeError, EOFError, zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error) as exc:
        error(f"Contenuto ZIP non analizzato: {path} ({exc})")


@dataclass(frozen=True)
class BCScanEngine:
    catalog: dict
    rules: object | None

    @classmethod
    def load(cls, catalog_path=None, yara_path=None):
        catalog = {EICAR_SHA256: {"name": "EICAR test innocuo", "source": "EICAR"}}
        catalog.update(load_approved_intel_catalog(Path(catalog_path)) if catalog_path else {})
        rules, rule_status = _compile_yara(Path(yara_path) if yara_path else None)
        if yara_path and rules is None:
            raise ValueError("Motore YARA non disponibile: " + rule_status)
        return cls(catalog, rules)


def scan_root(root):
    root = Path(os.path.abspath(root))
    _validate_local_path(root)
    if not root.is_dir() or _is_reparse_or_symlink(root):
        raise ValueError("Scegli una cartella locale accessibile, non un collegamento.")
    return root


def _walk_files(root, error, cancelled):
    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=error):
        if cancelled():
            return
        allowed = []
        for name in dirs:
            path = Path(directory) / name
            if _is_reparse_or_symlink(path):
                error(f"Cartella saltata: {path}")
            else:
                allowed.append(name)
        dirs[:] = allowed
        yield from (Path(directory) / name for name in files)


def scan_folder(root, *, catalog_path=None, yara_path=None, cancelled=lambda: False, progress=lambda *_: None):
    root = scan_root(root)
    engine = BCScanEngine.load(catalog_path, yara_path)
    return _scan(engine, lambda error: _walk_files(root, error, cancelled), cancelled, progress)


def scan_changed(root, paths, engine, *, cancelled):
    def candidates(error):
        for value in paths:
            path = Path(os.path.abspath(value))
            if not path.is_relative_to(root) or path == root:
                error(f"Evento fuori dalla cartella: {path}")
                continue
            try:
                _validate_local_path(path)
                if not path.exists():
                    continue  # A later move or deletion can supersede the event.
            except (OSError, ValueError) as exc:
                error(f"Percorso dell’evento saltato: {path} ({exc})")
                continue
            yield path

    return _scan(engine, candidates, cancelled, lambda *_: None)


def _scan(engine, candidates, cancelled, progress):
    catalog, rules = engine.catalog, engine.rules
    result = {"files": 0, "skipped": 0, "errors": [], "findings": [], "cancelled": False}

    def error(exc):
        result["skipped"] += 1
        if len(result["errors"]) < 100:
            result["errors"].append(str(exc))

    def inspect(data, digest, path):
        if digest in catalog:
            result["findings"].append({"path": str(path), "sha256": digest, **catalog[digest]})
        if rules is None:
            return
        try:
            matches = rules.match(data=data, timeout=2)
        except Exception as exc:
            error(f"YARA non ha completato {path}: {type(exc).__name__}")
            return
        for name in sorted({match.rule for match in matches}):
            result["findings"].append({"path": str(path), "sha256": digest,
                                       "name": "Regola YARA: " + name, "source": "regola locale"})

    for p in candidates(error):
        if cancelled():
            break
        try:
            if _is_reparse_or_symlink(p) or not p.is_file() or p.stat().st_size > MAX_BYTES:
                result["skipped"] += 1
                continue
            before = p.stat()
            digest = hashlib.sha256()
            buffer = None
            read_size = 0
            is_archive = p.suffix.casefold() in ARCHIVE_SUFFIXES
            with p.open("rb") as f:
                opened = os.fstat(f.fileno())
                if not os.path.samestat(before, opened):
                    raise OSError(f"Identità del file cambiata prima della lettura: {p}")
                while True:
                    if cancelled():
                        result["cancelled"] = True
                        break
                    block = f.read(1024 * 1024)
                    if not block:
                        break
                    if read_size == 0:
                        is_archive = is_archive or block.startswith((b"PK\x03\x04", b"PK\x05\x06"))
                        if rules is not None or is_archive:
                            buffer = bytearray()
                    read_size += len(block)
                    if read_size > MAX_BYTES:
                        raise OSError(f"File oltre il limite durante la scansione: {p}")
                    digest.update(block)
                    if buffer is not None:
                        buffer.extend(block)
            if result["cancelled"]:
                break
            after = p.stat()
            if (not os.path.samestat(before, after) or read_size != before.st_size or
                    (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
                raise OSError(f"File modificato durante la scansione: {p}")
            result["files"] += 1
            data = bytes(buffer) if buffer is not None else b""
            inspect(data, digest.hexdigest(), p)
            if is_archive:
                _scan_archive(data, p, cancelled, inspect, error)
                if cancelled():
                    result["cancelled"] = True
                    break
            if result["files"] % 25 == 0:
                progress(result["files"], str(p))
        except OSError as exc:
            error(exc)
    result["cancelled"] = result["cancelled"] or cancelled()
    return result
