"""Bounded, on-demand BC hash scanner. This is not real-time protection."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from sentinel.rescue_offline_scanner import load_approved_intel_catalog, _is_reparse_or_symlink, _validate_local_path, _compile_yara, _yara_matches

# EICAR's harmless 68-byte standard test file, not a malware signature database.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
MAX_BYTES = 64 * 1024 * 1024


def scan_folder(root, *, catalog_path=None, yara_path=None, cancelled=lambda: False, progress=lambda *_: None):
    root = Path(root)
    _validate_local_path(root)
    if not root.is_dir() or _is_reparse_or_symlink(root):
        raise ValueError("Scegli una cartella locale accessibile, non un collegamento.")
    catalog = {EICAR_SHA256: {"name": "EICAR test innocuo", "source": "EICAR"}}
    catalog.update(load_approved_intel_catalog(Path(catalog_path)) if catalog_path else {})
    rules, rule_status = _compile_yara(Path(yara_path) if yara_path else None)
    if yara_path and rules is None:
        raise ValueError('Motore YARA non disponibile: ' + rule_status)
    result = {"files": 0, "skipped": 0, "errors": [], "findings": [], "cancelled": False}

    def error(exc):
        result["skipped"] += 1
        if len(result["errors"]) < 100:
            result["errors"].append(str(exc))

    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=error):
        if cancelled():
            result["cancelled"] = True
            break
        safe_dirs = []
        for name in dirs:
            p = Path(directory) / name
            try:
                if _is_reparse_or_symlink(p):
                    result["skipped"] += 1
                else:
                    safe_dirs.append(name)
            except OSError as exc:
                error(exc)
        dirs[:] = safe_dirs
        for name in files:
            if cancelled():
                result["cancelled"] = True
                break
            p = Path(directory) / name
            try:
                if _is_reparse_or_symlink(p) or not p.is_file() or p.stat().st_size > MAX_BYTES:
                    result["skipped"] += 1
                    continue
                before = p.stat()
                digest = hashlib.sha256()
                with p.open("rb") as f:
                    while True:
                        if cancelled():
                            result["cancelled"] = True
                            break
                        block = f.read(1024 * 1024)
                        if not block:
                            break
                        digest.update(block)
                if result["cancelled"]:
                    break
                after = p.stat()
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise OSError(f"File modificato durante la scansione: {p}")
                result["files"] += 1
                value = digest.hexdigest()
                if value in catalog:
                    result["findings"].append({"path": str(p), "sha256": value, **catalog[value]})
                if rules is not None:
                    matches = _yara_matches(rules, p, expected_sha256=value)
                    for match in matches:
                        if match.startswith('__YARA_ERROR__:'):
                            error(f'YARA non ha completato {p}: {match}')
                        else:
                            result['findings'].append({'path': str(p), 'sha256': value,
                                'name': 'Regola YARA: ' + match, 'source': 'regola locale'})
                if result["files"] % 25 == 0:
                    progress(result["files"], str(p))
            except OSError as exc:
                error(exc)
        if result["cancelled"]:
            break
    return result
