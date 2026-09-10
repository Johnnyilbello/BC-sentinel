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
        max_attempts = max(1, int(attempts))
        for attempt in range(max_attempts):
            try:
                os.replace(source, target)
                return
            except OSError as exc:
                winerror = getattr(exc, "winerror", None)
                errno_value = getattr(exc, "errno", None)
                if winerror not in retryable and errno_value not in retryable:
                    raise
                last_error = exc
                if attempt + 1 >= max_attempts:
                    break
                time.sleep(min(0.05 * (2 ** attempt), 0.8))
        detail = f": {last_error}" if last_error is not None else ""
        raise ThreatPackageError(f"cannot atomically publish managed threat-intelligence path{detail}")

'''

INSERT_BEFORE = "    @staticmethod\n    def _remove_tree_with_retry(path: Path, *, required: bool, attempts: int = 6) -> bool:\n"
HELPER_START = "    @staticmethod\n    def _replace_file_with_retry(source: Path, target: Path, *, attempts: int = 8) -> None:\n"
REPLACEMENTS = (
    ("        os.replace(tmp, self.state_path)", "        self._replace_file_with_retry(tmp, self.state_path)", 1),
    ("        os.replace(tmp, self.activation_journal_path)", "        self._replace_file_with_retry(tmp, self.activation_journal_path)", 1),
    ("os.replace(tmp, self.active_behavior_path)", "self._replace_file_with_retry(tmp, self.active_behavior_path)", 3),
    ("        os.replace(tmp, self.active_yara_dir)", "        self._replace_file_with_retry(tmp, self.active_yara_dir)", 1),
)


def _verify(text: str) -> None:
    if text.count(HELPER_START) != 1:
        raise RuntimeError("Threat-package atomic replace helper missing/ambiguous after patch")
    start = text.index(HELPER_START)
    end = text.find(INSERT_BEFORE, start)
    if end < 0:
        raise RuntimeError("Threat-package retry helper end anchor missing after patch")
    if text[start:end] != HELPER:
        raise RuntimeError("Threat-package atomic replace helper body is not canonical")
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


def _canonicalize_existing_helper(text: str) -> tuple[str, bool]:
    """Replace any legacy helper body with the single canonical bounded-retry helper."""
    count = text.count(HELPER_START)
    if count == 0:
        return text, False
    if count != 1:
        raise RuntimeError(f"Unexpected threat-package source shape: found {count} retry helpers")
    start = text.index(HELPER_START)
    end = text.find(INSERT_BEFORE, start)
    if end < 0:
        raise RuntimeError("Unexpected threat-package source shape: retry helper end anchor missing")
    current = text[start:end]
    if current == HELPER:
        return text, False
    return text[:start] + HELPER + text[end:], True


def _upgrade_existing_helper(text: str) -> tuple[str, bool, list[str]]:
    """Upgrade an already-patched FULL baseline to the exact canonical helper/call shape."""
    updated, helper_changed = _canonicalize_existing_helper(text)
    changes: list[str] = []
    if helper_changed:
        changes.append("retry_helper_canonicalized")

    old = "        os.replace(tmp, self.active_yara_dir)"
    new = "        self._replace_file_with_retry(tmp, self.active_yara_dir)"
    count = updated.count(old)
    if count == 1:
        updated = updated.replace(old, new, 1)
        changes.append("yara_directory_retry")
    elif count > 1:
        raise RuntimeError(
            "Unexpected threat-package source shape: expected at most one YARA directory os.replace call, "
            f"found {count}"
        )

    _verify(updated)
    return updated, bool(changes), changes


def apply_compat_patch(path: Path = TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"Threat-package source missing: {path}")

    text = path.read_text(encoding="utf-8")
    if HELPER_START in text:
        updated, changed, changes = _upgrade_existing_helper(text)
        if changed:
            path.write_text(updated, encoding="utf-8")
            persisted = path.read_text(encoding="utf-8")
            _verify(persisted)
            return {
                "patched": True,
                "already_compatible": False,
                "path": str(path),
                "upgrades": changes,
            }
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
    return {"patched": True, "already_compatible": False, "path": str(path), "upgrades": ["full_managed_path_retry"]}


def main() -> int:
    result = apply_compat_patch()
    if result["patched"]:
        upgrades = ", ".join(result.get("upgrades") or [])
        print("v0.11 threat-package Windows compatibility: canonical atomic managed-path retry installed" + (f" ({upgrades})" if upgrades else ""))
    else:
        print("v0.11 threat-package Windows compatibility: already canonical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
