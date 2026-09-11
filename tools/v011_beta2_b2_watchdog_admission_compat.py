from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
from time import sleep
from typing import Any

from tools.v011_beta2_b2_file_observation_compat import (
    MARKER as OBSERVATION_MARKER,
    apply as apply_observation,
)

PROFILE = "v0.11.0-beta.2"
CORE_REL = Path("sentinel") / "protection_service_core.py"
CORE_BACKUP_REL = Path("sentinel") / "protection_service_core.py.pre-v011-beta2-b2-watchdog-admission.bak"
ADMISSION_MARKER = "bc-sentinel-v011-beta2-watchdog-edr-admission-v2"
DEDUP_SECONDS = 2.0
BUCKET_CAPACITY = 8.0
BUCKET_REFILL_PER_SECOND = 2.0

_OLD_METHOD = f'''    # {OBSERVATION_MARKER}: service file-observation bridge\n    def _on_realtime_file_observed(self, path: str):\n        value = str(path or "")\n        if not value:\n            return\n        self._on_event(SecurityEvent(\n            category="filesystem",\n            action="observed",\n            source="watchdog",\n            score=0,\n            path=value,\n            data={{"realtime": True, "watchdog_observed": True}},\n        ))\n\n'''

_NEW_METHOD = f'''    # {OBSERVATION_MARKER}: service file-observation bridge\n    # {ADMISSION_MARKER}: bounded per-directory EDR admission for benign watchdog telemetry\n    def _on_realtime_file_observed(self, path: str):\n        value = str(path or "")\n        if not value:\n            return\n        try:\n            os_path = __import__("os").path\n            if not os_path.isfile(value):\n                return\n            normalized = os_path.normcase(os_path.abspath(value))\n            parent = os_path.dirname(normalized) or normalized\n            now = float(__import__("time").monotonic())\n        except Exception:\n            return\n\n        lock = getattr(self, "_watchdog_edr_admission_lock", None)\n        if lock is None:\n            try:\n                lock = __import__("threading").Lock()\n                self._watchdog_edr_admission_lock = lock\n            except Exception:\n                return\n\n        suppressed_count = 0\n        with lock:\n            recent = getattr(self, "_watchdog_edr_recent", None)\n            if not isinstance(recent, dict):\n                recent = {{}}\n                self._watchdog_edr_recent = recent\n            previous = recent.get(normalized)\n            if previous is not None and (now - float(previous)) < {DEDUP_SECONDS!r}:\n                return\n\n            buckets = getattr(self, "_watchdog_edr_buckets", None)\n            if not isinstance(buckets, dict):\n                buckets = {{}}\n                self._watchdog_edr_buckets = buckets\n            suppressed = getattr(self, "_watchdog_edr_suppressed", None)\n            if not isinstance(suppressed, dict):\n                suppressed = {{}}\n                self._watchdog_edr_suppressed = suppressed\n\n            state = buckets.get(parent)\n            if isinstance(state, tuple) and len(state) == 2:\n                tokens = float(state[0])\n                last_seen = float(state[1])\n            else:\n                tokens = {BUCKET_CAPACITY!r}\n                last_seen = now\n            tokens = min(\n                {BUCKET_CAPACITY!r},\n                tokens + max(0.0, now - last_seen) * {BUCKET_REFILL_PER_SECOND!r},\n            )\n            if tokens < 1.0:\n                buckets[parent] = (tokens, now)\n                suppressed[parent] = int(suppressed.get(parent, 0)) + 1\n                return\n\n            buckets[parent] = (tokens - 1.0, now)\n            recent[normalized] = now\n            suppressed_count = int(suppressed.pop(parent, 0))\n\n            if len(recent) > 1024:\n                stale_paths = [\n                    key for key, seen in recent.items()\n                    if (now - float(seen)) >= {DEDUP_SECONDS!r}\n                ]\n                for key in stale_paths:\n                    recent.pop(key, None)\n                if len(recent) > 2048:\n                    recent.clear()\n                    recent[normalized] = now\n\n            if len(buckets) > 256:\n                stale_parents = [\n                    key for key, bucket in buckets.items()\n                    if isinstance(bucket, tuple)\n                    and len(bucket) == 2\n                    and (now - float(bucket[1])) > 60.0\n                ]\n                for key in stale_parents:\n                    buckets.pop(key, None)\n                    suppressed.pop(key, None)\n                if len(buckets) > 512:\n                    buckets.clear()\n                    suppressed.clear()\n                    buckets[parent] = ({BUCKET_CAPACITY - 1.0!r}, now)\n\n        self._on_event(SecurityEvent(\n            category="filesystem",\n            action="observed",\n            source="watchdog",\n            score=0,\n            path=value,\n            data={{\n                "realtime": True,\n                "watchdog_observed": True,\n                "admission": "per_directory_token_bucket",\n                "suppressed_same_directory": suppressed_count,\n            }},\n        ))\n\n'''


def _atomic_replace(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".v011-beta2-b2-watchdog-admission.tmp")
    tmp.write_text(text, encoding="utf-8")
    last: BaseException | None = None
    for attempt in range(8):
        try:
            os.replace(tmp, path)
            return
        except OSError as exc:
            last = exc
            if attempt + 1 < 8:
                sleep(min(0.05 * (2**attempt), 0.8))
    try:
        tmp.unlink(missing_ok=True)
    except Exception:
        pass
    raise RuntimeError(f"atomic promotion failed for {path}: {last}")


def transform_core_text(text: str) -> str:
    if ADMISSION_MARKER in text:
        return text
    if text.count(OBSERVATION_MARKER) != 1:
        raise RuntimeError("watchdog observation v1 marker missing or ambiguous")
    if text.count(_OLD_METHOD) != 1:
        raise RuntimeError("watchdog observation v1 method shape changed; refusing admission patch")
    updated = text.replace(_OLD_METHOD, _NEW_METHOD, 1)
    ast.parse(updated)
    if updated.count(ADMISSION_MARKER) != 1:
        raise RuntimeError("watchdog admission marker count invalid")
    return updated


def _verify_core(text: str) -> dict[str, bool]:
    return {
        "observation_marker_once": text.count(OBSERVATION_MARKER) == 1,
        "admission_marker_once": text.count(ADMISSION_MARKER) == 1,
        "observation_method_once": text.count("def _on_realtime_file_observed") == 1,
        "existing_file_guard_once": text.count("if not os_path.isfile(value)") == 1,
        "per_directory_key_once": text.count("parent = os_path.dirname(normalized) or normalized") == 1,
        "dedup_window_once": text.count(f"< {DEDUP_SECONDS!r}") == 1,
        "bucket_capacity_present": text.count(str(BUCKET_CAPACITY)) >= 1,
        "bucket_refill_present": text.count(str(BUCKET_REFILL_PER_SECOND)) >= 1,
        "suppressed_summary_once": text.count('"suppressed_same_directory": suppressed_count') == 1,
        "filesystem_category_once": text.count('category="filesystem"') == 1,
        "watchdog_source_once": text.count('source="watchdog"') == 1,
    }


def apply(root: Path) -> dict[str, Any]:
    root = root.resolve()
    base = apply_observation(root)
    core = root / CORE_REL
    if not core.is_file():
        raise RuntimeError("FULL protection_service_core.py missing after observation patch")

    before = core.read_text(encoding="utf-8")
    canonical = ADMISSION_MARKER in before
    if canonical:
        after = before
    else:
        after = transform_core_text(before)
        backup = root / CORE_BACKUP_REL
        if backup.exists() and backup.read_text(encoding="utf-8") != before:
            raise RuntimeError("existing watchdog admission backup does not match accepted observation-v1 source")
        if not backup.exists():
            backup.write_text(before, encoding="utf-8")
        _atomic_replace(core, after)

    checks = _verify_core(after)
    if not all(checks.values()):
        raise RuntimeError(f"post-patch watchdog admission verification failed: {checks}")

    return {
        "profile": PROFILE,
        "checkpoint": "B2-watchdog-edr-admission",
        "passed": True,
        "changed": not canonical,
        "status": "patched" if not canonical else "already_canonical",
        "observation_status": str(base.get("status") or ""),
        "checks": checks,
        "policy": {
            "scope": "per_directory",
            "dedup_seconds": DEDUP_SECONDS,
            "bucket_capacity": BUCKET_CAPACITY,
            "refill_per_second": BUCKET_REFILL_PER_SECOND,
            "cross_directory_isolation": True,
            "automatic_destructive_action": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Bound stabilized watchdog filesystem telemetry before service-owned EDR ingestion")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    result = apply(Path(args.root))
    print(
        "v0.11 Beta2 B2 watchdog EDR admission: "
        f"{result['status']} | scope=per_directory | burst={BUCKET_CAPACITY:g} | refill={BUCKET_REFILL_PER_SECOND:g}/s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
