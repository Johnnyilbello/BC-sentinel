from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

TARGET_RELATIVE = Path("sentinel") / "protection_service_core.py"
MARKER = "bc-sentinel-v011-beta2-settings-ownership-v1"

_IMPORT_OLD = "from .config import APP_ROOT, DATA_DIR, EXE_DIR, PROGRAM_DATA_DIR, Settings"
_IMPORT_NEW = "from .config import APP_ROOT, DATA_DIR, EXE_DIR, PROGRAM_DATA_DIR, Settings, ensure_service_profile_roots"

_DESERIALIZE_OLD = '''    settings.monitored_dirs = [str(x) for x in settings.monitored_dirs if str(x)]
    settings.ransomware_dirs = [str(x) for x in settings.ransomware_dirs if str(x)]
    return settings
'''
_DESERIALIZE_NEW = '''    settings.monitored_dirs = [str(x) for x in settings.monitored_dirs if str(x)]
    settings.ransomware_dirs = [str(x) for x in settings.ransomware_dirs if str(x)]
    settings = ensure_service_profile_roots(settings)
    return settings
'''

_START_OLD = '''                try:
                    self.settings = self.config_store.load()
                except Exception as exc:
'''
_START_NEW = '''                try:
                    loaded_settings = ensure_service_profile_roots(self.config_store.load())
                    for key in CONFIG_FIELDS:
                        setattr(self.settings, key, getattr(loaded_settings, key))
                except Exception as exc:
'''

_RESUME_OLD = '''            # Resume using persisted settings.
            self._protection_enabled = True
            self.settings = self.config_store.load()
            realtime_running = bool(self.realtime.start()) if self.settings.realtime_enabled else False
'''
_RESUME_NEW = '''            # Resume using persisted settings.
            self._protection_enabled = True
            loaded_settings = ensure_service_profile_roots(self.config_store.load())
            for key in CONFIG_FIELDS:
                setattr(self.settings, key, getattr(loaded_settings, key))
            realtime_running = bool(self.realtime.start()) if self.settings.realtime_enabled else False
'''


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def apply(root: Path) -> dict[str, str | bool]:
    target = (root / TARGET_RELATIVE).resolve()
    if not target.is_file():
        raise RuntimeError(f"FULL-only target missing: {target}")

    before = target.read_text(encoding="utf-8")
    before_sha = _sha(before)

    canonical = (
        _IMPORT_NEW in before
        and _DESERIALIZE_NEW in before
        and _START_NEW in before
        and _RESUME_NEW in before
    )
    if canonical:
        return {
            "changed": False,
            "status": "already_canonical",
            "before_sha256": before_sha,
            "after_sha256": before_sha,
            "target": str(target),
        }

    checks = {
        "import": before.count(_IMPORT_OLD),
        "deserialize": before.count(_DESERIALIZE_OLD),
        "start_reload": before.count(_START_OLD),
        "resume_reload": before.count(_RESUME_OLD),
    }
    unexpected = {name: count for name, count in checks.items() if count != 1}
    if unexpected:
        raise RuntimeError(
            "Unexpected protection_service_core.py source shape; refusing partial patch: "
            + ", ".join(f"{name}={count}" for name, count in unexpected.items())
        )

    after = before
    after = after.replace(_IMPORT_OLD, _IMPORT_NEW, 1)
    after = after.replace(_DESERIALIZE_OLD, _DESERIALIZE_NEW, 1)
    after = after.replace(_START_OLD, _START_NEW, 1)
    after = after.replace(_RESUME_OLD, _RESUME_NEW, 1)

    if MARKER not in after:
        anchor = "class ProtectionConfigStore:"
        if after.count(anchor) != 1:
            raise RuntimeError("ProtectionConfigStore anchor missing/ambiguous; refusing patch")
        after = after.replace(anchor, f"# {MARKER}\n{anchor}", 1)

    compile(after, str(target), "exec")
    target.write_text(after, encoding="utf-8", newline="\n")
    after_sha = _sha(after)
    return {
        "changed": True,
        "status": "patched",
        "before_sha256": before_sha,
        "after_sha256": after_sha,
        "target": str(target),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Patch B2 persisted service settings ownership/root migration")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    result = apply(Path(args.root).resolve())
    print(
        "v0.11 Beta2 B2 service settings compatibility: "
        f"{result['status']} | {result['before_sha256']} -> {result['after_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
