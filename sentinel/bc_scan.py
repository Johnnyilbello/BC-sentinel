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
from sentinel import bc_research_intel
from sentinel.bc_script_analysis import MAX_SCRIPT_BYTES, SCRIPT_SUFFIXES, inspect_script
from sentinel.rescue_offline_scanner import load_approved_intel_catalog, _is_reparse_or_symlink, _validate_local_path, _compile_yara

# EICAR's harmless 68-byte standard test file, not a malware signature database.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
MAX_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_ARCHIVE_EXPANSION = 64 * 1024 * 1024


def _scan_archive(data, path, cancelled, inspect, error, *, depth=0, budget=None):
    if budget is None:
        budget = [MAX_ARCHIVE_MEMBERS, MAX_ARCHIVE_EXPANSION]
    expected, _, reasons = read_zip_directory_tail(data[-MAX_EOCD_TAIL_BYTES:], len(data))
    if reasons or expected > budget[0]:
        error(f"Contenuto ZIP non analizzato: {path} ({', '.join(reasons) or 'limite elementi'})")
        return
    try:
        with zipfile.ZipFile(io.BytesIO(data), allowZip64=False) as archive:
            members = archive.infolist()
            expansion = sum(member.file_size for member in members)
            if len(members) != expected or expansion > budget[1]:
                error(f"Contenuto ZIP non analizzato: {path} (limite espansione o indice incoerente)")
                return
            budget[0] -= expected
            budget[1] -= expansion
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
                try:
                    with archive.open(member) as stream:
                        payload = stream.read(MAX_MEMBER_BYTES + 1)
                except (OSError, ValueError, RuntimeError, EOFError, zipfile.BadZipFile, zlib.error) as exc:
                    error(f"Elemento ZIP non analizzato: {location} ({exc})")
                    continue
                if len(payload) != member.file_size or len(payload) > MAX_MEMBER_BYTES:
                    error(f"Dimensione elemento ZIP incoerente: {location}")
                    continue
                suffix = Path(member.filename).suffix.casefold()
                inspect(payload, hashlib.sha256(payload).hexdigest(), location, suffix)
                if suffix in ARCHIVE_SUFFIXES or payload.startswith(b"PK\x03\x04"):
                    if depth == 0:
                        _scan_archive(payload, location, cancelled, inspect, error, depth=1, budget=budget)
                    else:
                        error(f"Archivio annidato non aperto: {location}")
    except (OSError, ValueError, RuntimeError, EOFError, zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error) as exc:
        error(f"Contenuto ZIP non analizzato: {path} ({exc})")


@dataclass(frozen=True)
class BCScanEngine:
    catalog: dict
    rules: object | None
    research: bc_research_intel.ResearchIntel

    @classmethod
    def load(cls, catalog_path=None, yara_path=None):
        catalog = {EICAR_SHA256: {"name": "EICAR test innocuo", "source": "EICAR"}}
        catalog.update(load_approved_intel_catalog(Path(catalog_path)) if catalog_path else {})
        rules, rule_status = _compile_yara(Path(yara_path) if yara_path else None)
        if yara_path and rules is None:
            raise ValueError("Motore YARA non disponibile: " + rule_status)
        return cls(catalog, rules, bc_research_intel.load())


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


def scan_changed(root, paths, engine, *, cancelled, wait_for_retry=None):
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

    return _scan(engine, candidates, cancelled, lambda *_: None, wait_for_retry=wait_for_retry)


def _open_file(path, wait_for_retry):
    try:
        return path.open("rb")
    except OSError as exc:
        code = getattr(exc, "winerror", None)
        transient = code in {32, 33} or (os.name == "nt" and code is None and isinstance(exc, PermissionError))
        if (not transient or
                wait_for_retry is None or wait_for_retry(0.2)):
            raise
    return path.open("rb")


def _scan(engine, candidates, cancelled, progress, *, wait_for_retry=None):
    catalog, rules = engine.catalog, engine.rules
    result = {"files": 0, "skipped": 0, "errors": [], "findings": [], "cancelled": False}

    def error(exc):
        result["skipped"] += 1
        if len(result["errors"]) < 100:
            result["errors"].append(str(exc))

    def inspect(data, digest, path, suffix, *, script_limited=False):
        signature = catalog.get(digest)
        if signature is None and digest in engine.research.hashes:
            signature = {"name": engine.research.hashes[digest], "source": bc_research_intel.SOURCE}
        if signature is not None:
            result["findings"].append({"path": str(path), "sha256": digest, **signature,
                                       "isolate_path": str(path) if isinstance(path, Path) else None})
        if data.startswith(b"MZ"):
            inspect_rules(engine.research.rules, bc_research_intel.SOURCE, data, digest, path)
        if rules is not None:
            inspect_rules(rules, "regola locale", data, digest, path)
        try:
            if script_limited:
                raise ValueError("limite analisi script: 256 KiB")
            signals = inspect_script(data, suffix)
        except ValueError as exc:
            error(f"Analisi script incompleta per {path}: {exc}")
            return
        for name in signals:
            result["findings"].append({"path": str(path), "sha256": digest,
                                       "name": name, "source": "euristica statica BC"})

    def inspect_rules(ruleset, source, data, digest, path):
        try:
            matches = ruleset.match(data=data, timeout=2)
        except Exception as exc:
            error(f"YARA non ha completato {path} ({source}): {type(exc).__name__}")
            return
        for name in sorted({match.rule for match in matches}):
            result["findings"].append({"path": str(path), "sha256": digest,
                                       "name": "Regola YARA: " + name, "source": source})

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
            suffix = p.suffix.casefold()
            script_limited = suffix in SCRIPT_SUFFIXES and before.st_size > MAX_SCRIPT_BYTES
            is_archive = suffix in ARCHIVE_SUFFIXES
            with _open_file(p, wait_for_retry) as f:
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
                        if (rules is not None or is_archive or block.startswith(b"MZ") or
                                (suffix in SCRIPT_SUFFIXES and not script_limited)):
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
            inspect(data, digest.hexdigest(), p, suffix, script_limited=script_limited)
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
