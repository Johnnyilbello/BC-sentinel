from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "sentinel" / "threat_packages.py"

HELPER = '''    @staticmethod
    def _replace_file_with_retry(source: Path, target: Path, *, attempts: int = 8) -> None:
        """Atomically publish a managed path while tolerating transient Windows locks.

        Defender, indexers and other readers can briefly open a just-written file,
        directory, or destination without FILE_SHARE_DELETE, causing os.replace() to
        fail with WinError 5/32/33. Retry only those known transient Windows
        conditions. All other errors fail immediately, and the caller remains
        responsible for path containment/reparse validation before publication.
        """
        last_error: OSError | None = None
        retryable = {5, 32, 33}
        for attempt in range(max(1, int(attempts))):
            try:
                os.replace(source, target)
                return
            except OSError as exc:
                winerror = getattr(exc, "winerror", None)
                errno_value = getattr(exc, "errno", None)
                if winerror not in retryable and errno_value not in retryable:
                    raise
                last_error = exc
                if attempt + 1 >= max(1, int(attempts)):
                    break
                time.sleep(min(0.05 * (2 ** attempt), 0.8))
        detail = f": {last_error}" if last_error is not None else ""
        raise ThreatPackageError(f"cannot atomically publish managed threat-intelligence path{detail}")

'''

INSERT_BEFORE = "    @staticmethod\n    def _remove_tree_with_retry(path: Path, *, required: bool, attempts: int = 6) -> bool:\n"
REPLACEMENTS = (
    ("        os.replace(tmp, self.state_path)", "        self._replace_file_with_retry(tmp, self.state_path)", 1),
    ("        os.replace(tmp, self.activation_journal_path)", "        self._replace_file_with_retry(tmp, self.activation_journal_path)", 1),
    ("os.replace(tmp, self.active_behavior_path)", "self._replace_file_with_retry(tmp, self.active_behavior_path)", 3),
    ("        os.replace(tmp, self.active_yara_dir)", "        self._replace_file_with_retry(tmp, self.active_yara_dir)", 1),
)


def _verify(text: str) -> None:
    if "def _replace_file_with_retry(" not in text:
        raise RuntimeError("Threat-package atomic replace helper missing after patch")
    if text.count("self._replace_file_with_retry(tmp, self.active_behavior_path)") != 3:
        raise RuntimeError("Threat-package behavior publication call count is not canonical")
    if text.count("self._replace_file_with_retry(tmp, self.state_path)") != 1:
        raise RuntimeError("Threat-package state publication call count is not canonical")
    if text.count("self._replace_file_with_retry(tmp, self.activation_journal_path)") != 1:
        raise RuntimeError("Threat-package journal publication call count is not canonical")
    if text.count("self._replace_file_with_retry(tmp, self.active_yara_dir)") != 1:
        raise RuntimeError("Threat-package YARA directory publication call count is not canonical")
    if "os.replace(tmp, self.active_yara_dir)" in text:
        raise RuntimeError("Unhardened threat-package YARA directory promotion still present")


def _upgrade_existing_helper(text: str) -> tuple[str, bool]:
    """Upgrade an already-patched FULL baseline with directory publication retry."""
    if "def _replace_file_with_retry(" not in text:
        return text, False

    old = "        os.replace(tmp, self.active_yara_dir)"
    new = "        self._replace_file_with_retry(tmp, self.active_yara_dir)"
    count = text.count(old)
    if count == 0:
        _verify(text)
        return text, False
    if count != 1:
        raise RuntimeError(
            "Unexpected threat-package source shape: expected exactly one YARA directory os.replace call, "
            f"found {count}"
        )

    updated = text.replace(old, new, 1)
    _verify(updated)
    return updated, True


def apply_compat_patch(path: Path = TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"Threat-package source missing: {path}")

    text = path.read_text(encoding="utf-8")
    if "def _replace_file_with_retry(" in text:
        updated, changed = _upgrade_existing_helper(text)
        if changed:
            path.write_text(updated, encoding="utf-8")
            persisted = path.read_text(encoding="utf-8")
            _verify(persisted)
            return {"patched": True, "already_compatible": False, "path": str(path), "upgrade": "yara_directory_retry"}
        return {"patched": False, "already_compatible": True, "path": str(path)}

    if text.count(INSERT_BEFORE) != 1:
        raise RuntimeError("Unexpected threat-package source shape: retry insertion anchor missing/ambiguous")

    for old, _new, expected in REPLACEMENTS:
        if text.count(old) != expected:
            raise RuntimeError(
                f"Unexpected threat-package source shape: expected {expected} occurrence(s) of {old!r}, "
                f"found {text.count(old)}"
            )

    updated = text.replace(INSERT_BEFORE, HELPER + INSERT_BEFORE, 1)
    for old, new, _expected in REPLACEMENTS:
        updated = updated.replace(old, new)

    _verify(updated)
    path.write_text(updated, encoding="utf-8")
    persisted = path.read_text(encoding="utf-8")
    _verify(persisted)
    return {"patched": True, "already_compatible": False, "path": str(path)}


def main() -> int:
    result = apply_compat_patch()
    if result["patched"]:
        if result.get("upgrade") == "yara_directory_retry":
            print("v0.11 threat-package Windows compatibility: atomic YARA directory replace retry installed")
        else:
            print("v0.11 threat-package Windows compatibility: atomic managed-path replace retry installed")
    else:
        print("v0.11 threat-package Windows compatibility: already canonical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
