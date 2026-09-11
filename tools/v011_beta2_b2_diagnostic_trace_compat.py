from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
from time import sleep
from typing import Any, Callable

PROFILE = "v0.11.0-beta.2-marker-trace-v1"
MARKER = "bc-sentinel-v011-beta2-marker-trace-v1"
TARGETS = (
    Path("sentinel") / "watchdog_coalescing.py",
    Path("sentinel") / "realtime.py",
    Path("sentinel") / "protection_service_core.py",
    Path("sentinel") / "edr_adapter.py",
    Path("sentinel") / "edr_service_bridge.py",
)
TRACE_IMPORT = "from .b2_diagnostic_trace import trace_marker\n"
BRIDGE_TRACE_IMPORT = "from .b2_diagnostic_trace import trace_marker, trace_metadata, trace_snapshot\n"


def _atomic_replace(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".v011-beta2-marker-trace.tmp")
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


def _with_import(text: str, import_line: str) -> str:
    if import_line in text:
        return text
    anchor = "from __future__ import annotations\n"
    if text.count(anchor) != 1:
        raise RuntimeError("future-import anchor missing or ambiguous")
    return text.replace(anchor, anchor + "\n" + import_line, 1)


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def transform_watchdog(text: str) -> str:
    if MARKER in text:
        return text
    updated = _with_import(text, TRACE_IMPORT)
    old = '''    def dispatch(self, event):
        self.received += 1
        event_type = str(getattr(event, "event_type", "") or "").lower()
        is_directory = bool(getattr(event, "is_directory", False))
'''
    new = f'''    # {MARKER}: marker-aware filesystem dispatch trace
    def dispatch(self, event):
        self.received += 1
        event_type = str(getattr(event, "event_type", "") or "").lower()
        is_directory = bool(getattr(event, "is_directory", False))
        src_path = str(getattr(event, "src_path", "") or "")
        dest_path = str(getattr(event, "dest_path", "") or "")
        trace_marker(
            "WATCHDOG_EVENT_RECEIVED",
            path=src_path or dest_path,
            event_type=event_type,
            is_directory=is_directory,
            src_path=src_path,
            dest_path=dest_path,
            received=self.received,
        )
'''
    updated = _replace_once(updated, old, new, "watchdog dispatch")
    updated = _replace_once(
        updated,
        '''        if is_directory and event_type == "modified":
            self.directory_modified_dropped += 1
            return None
''',
        '''        if is_directory and event_type == "modified":
            self.directory_modified_dropped += 1
            trace_marker("WATCHDOG_EVENT_FILTERED", path=src_path or dest_path, reason="directory_modified_noise")
            return None
''',
        "watchdog directory filter",
    )
    updated = _replace_once(
        updated,
        '''                if fallback is None:
                    return None
                return self._forward(fallback)
''',
        '''                if fallback is None:
                    trace_marker(
                        "WATCHDOG_MODIFIED_PENDING",
                        path=src_path or dest_path,
                        deadline=deadline,
                        coalesced=bool(already_pending),
                        pending=len(self._pending_modified),
                    )
                    return None
                trace_marker("WATCHDOG_QUEUE_FALLBACK", path=src_path or dest_path, reason="modified_queue_bound_or_closed")
                return self._forward(fallback)
''',
        "watchdog modified queue",
    )
    updated = _replace_once(
        updated,
        '''            else:
                self._immediate.append(event)
                self._cv.notify()
''',
        '''            else:
                self._immediate.append(event)
                trace_marker(
                    "WATCHDOG_EVENT_QUEUED",
                    path=src_path or dest_path,
                    queue="immediate",
                    queue_depth=len(self._immediate),
                )
                self._cv.notify()
''',
        "watchdog immediate queue",
    )
    updated = _replace_once(
        updated,
        '''        if fallback is not None:
            return self._forward(fallback)
        return None
''',
        '''        if fallback is not None:
            trace_marker("WATCHDOG_QUEUE_FALLBACK", path=src_path or dest_path, reason="immediate_queue_bound_or_closed")
            return self._forward(fallback)
        return None
''',
        "watchdog immediate fallback",
    )
    updated = _replace_once(
        updated,
        '''    def _forward(self, event):
        bucket, detail = self._diagnostic_identity(event)
        cpu_started = thread_time()
        try:
            result = self._inner.dispatch(event)
            self.forwarded += 1
            return result
        finally:
            self._record_forward_diagnostic(bucket, detail, thread_time() - cpu_started)
''',
        '''    def _forward(self, event):
        bucket, detail = self._diagnostic_identity(event)
        path = str(getattr(event, "src_path", "") or getattr(event, "dest_path", "") or "")
        event_type = str(getattr(event, "event_type", "") or "").lower()
        trace_marker("WATCHDOG_FORWARD_BEGIN", path=path, event_type=event_type, bucket=bucket, detail=detail)
        cpu_started = thread_time()
        try:
            result = self._inner.dispatch(event)
            self.forwarded += 1
            trace_marker("WATCHDOG_FORWARD_END", path=path, event_type=event_type, forwarded=self.forwarded)
            return result
        except Exception as exc:
            trace_marker("WATCHDOG_FORWARD_ERROR", path=path, event_type=event_type, error=f"{type(exc).__name__}: {exc}")
            raise
        finally:
            self._record_forward_diagnostic(bucket, detail, thread_time() - cpu_started)
''',
        "watchdog forward",
    )
    ast.parse(updated)
    return updated


def transform_realtime(text: str) -> str:
    if MARKER in text:
        return text
    updated = _with_import(text, TRACE_IMPORT)
    old = '''        if self.event_callback is not None:
            try:
                self.event_callback(str(path))
            except Exception:
                pass
'''
    new = f'''        # {MARKER}: trace stabilized marker immediately around observation callback
        if self.event_callback is not None:
            try:
                trace_marker("FILE_STABLE_CALLBACK_ENTER", path=str(path), exists=bool(path.exists()))
                self.event_callback(str(path))
                trace_marker("FILE_STABLE_CALLBACK_RETURN", path=str(path))
            except Exception as exc:
                trace_marker("FILE_STABLE_CALLBACK_ERROR", path=str(path), error=f"{{type(exc).__name__}}: {{exc}}")
                pass
'''
    updated = _replace_once(updated, old, new, "realtime stabilized callback")
    ast.parse(updated)
    return updated


def _function_span(text: str, class_name: str, method_name: str) -> tuple[int, int]:
    tree = ast.parse(text)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == method_name:
                    lines = text.splitlines(keepends=True)
                    start = int(child.lineno) - 1
                    end = int(child.end_lineno or child.lineno)
                    return sum(len(line) for line in lines[:start]), sum(len(line) for line in lines[:end])
    raise RuntimeError(f"{class_name}.{method_name} not found")


def _replace_method(text: str, class_name: str, method_name: str, new_method: str) -> str:
    start, end = _function_span(text, class_name, method_name)
    return text[:start] + new_method + text[end:]


def transform_core(text: str) -> str:
    if MARKER in text:
        return text
    if "bc-sentinel-v011-beta2-watchdog-edr-admission-v2" not in text:
        raise RuntimeError("watchdog admission v2 marker missing from protection core")
    updated = _with_import(text, TRACE_IMPORT)
    method = f'''    def _on_realtime_file_observed(self, path: str):
        # {MARKER}: end-to-end marker trace for watchdog -> EDR admission
        value = str(path or "")
        trace_marker("OBSERVATION_CALLBACK_ENTER", path=value)
        if not value:
            return
        try:
            os_path = __import__("os").path
            if not os_path.isfile(value):
                trace_marker("ADMISSION_DROP", path=value, reason="not_existing_file", exists=False)
                return
            normalized = os_path.normcase(os_path.abspath(value))
            parent = os_path.dirname(normalized) or normalized
            now = float(__import__("time").monotonic())
        except Exception as exc:
            trace_marker("ADMISSION_DROP", path=value, reason="path_normalization_error", error=f"{{type(exc).__name__}}: {{exc}}")
            return

        lock = getattr(self, "_watchdog_edr_admission_lock", None)
        if lock is None:
            try:
                lock = __import__("threading").Lock()
                self._watchdog_edr_admission_lock = lock
            except Exception as exc:
                trace_marker("ADMISSION_DROP", path=value, reason="lock_init_error", error=f"{{type(exc).__name__}}: {{exc}}")
                return

        suppressed_count = 0
        tokens_after = 0.0
        with lock:
            recent = getattr(self, "_watchdog_edr_recent", None)
            if not isinstance(recent, dict):
                recent = {{}}
                self._watchdog_edr_recent = recent
            previous = recent.get(normalized)
            if previous is not None and (now - float(previous)) < 2.0:
                trace_marker("ADMISSION_DROP", path=value, reason="dedup_window", age_seconds=now - float(previous))
                return

            buckets = getattr(self, "_watchdog_edr_buckets", None)
            if not isinstance(buckets, dict):
                buckets = {{}}
                self._watchdog_edr_buckets = buckets
            suppressed = getattr(self, "_watchdog_edr_suppressed", None)
            if not isinstance(suppressed, dict):
                suppressed = {{}}
                self._watchdog_edr_suppressed = suppressed

            state = buckets.get(parent)
            if isinstance(state, tuple) and len(state) == 2:
                tokens = float(state[0])
                last_seen = float(state[1])
            else:
                tokens = 8.0
                last_seen = now
            tokens = min(8.0, tokens + max(0.0, now - last_seen) * 2.0)
            if tokens < 1.0:
                buckets[parent] = (tokens, now)
                suppressed[parent] = int(suppressed.get(parent, 0)) + 1
                trace_marker("ADMISSION_DROP", path=value, reason="per_directory_rate_limit", parent=parent, tokens=tokens)
                return

            tokens_after = tokens - 1.0
            buckets[parent] = (tokens_after, now)
            recent[normalized] = now
            suppressed_count = int(suppressed.pop(parent, 0))

            if len(recent) > 1024:
                stale_paths = [key for key, seen in recent.items() if (now - float(seen)) >= 2.0]
                for key in stale_paths:
                    recent.pop(key, None)
                if len(recent) > 2048:
                    recent.clear()
                    recent[normalized] = now

            if len(buckets) > 256:
                stale_parents = [
                    key for key, bucket in buckets.items()
                    if isinstance(bucket, tuple) and len(bucket) == 2 and (now - float(bucket[1])) > 60.0
                ]
                for key in stale_parents:
                    buckets.pop(key, None)
                    suppressed.pop(key, None)
                if len(buckets) > 512:
                    buckets.clear()
                    suppressed.clear()
                    buckets[parent] = (7.0, now)

        trace_marker(
            "ADMISSION_ACCEPT",
            path=value,
            normalized=normalized,
            parent=parent,
            tokens_after=tokens_after,
            suppressed_same_directory=suppressed_count,
        )
        event = SecurityEvent(
            category="filesystem",
            action="observed",
            source="watchdog",
            score=0,
            path=value,
            data={{
                "realtime": True,
                "watchdog_observed": True,
                "admission": "per_directory_token_bucket",
                "suppressed_same_directory": suppressed_count,
            }},
        )
        trace_marker("SECURITY_EVENT_CREATED", path=value, category="filesystem", source="watchdog", action="observed")
        self._on_event(event)
        trace_marker("SECURITY_EVENT_PIPELINE_RETURN", path=value)

'''
    updated = _replace_method(updated, "ProtectionRuntime", "_on_realtime_file_observed", method)
    ast.parse(updated)
    return updated


def transform_adapter(text: str) -> str:
    if MARKER in text:
        return text
    updated = _with_import(text, TRACE_IMPORT)
    old = '''    def ingest_security_event(self, event: Any) -> dict:
        return self.pipeline.ingest(telemetry_from_security_event(event))
'''
    new = f'''    def ingest_security_event(self, event: Any) -> dict:
        # {MARKER}: adapter conversion trace for diagnostic filesystem markers
        telemetry = telemetry_from_security_event(event)
        trace_marker(
            "EDR_ADAPTER_CONVERTED",
            path=telemetry.path,
            category=telemetry.category,
            source=telemetry.source,
            pid=telemetry.pid,
            ts=telemetry.ts,
        )
        result = self.pipeline.ingest(telemetry)
        trace_marker(
            "EDR_PIPELINE_RETURN",
            path=telemetry.path,
            category=telemetry.category,
            stored=bool(result.get("stored")),
            disposition=str(result.get("disposition") or ""),
            event_id=str(result.get("event_id") or ""),
        )
        return result
'''
    updated = _replace_once(updated, old, new, "edr adapter ingest")
    ast.parse(updated)
    return updated


def transform_bridge(text: str) -> str:
    if MARKER in text:
        return text
    updated = _with_import(text, BRIDGE_TRACE_IMPORT)

    start, end = _function_span(updated, "EdrServiceBridge", "ingest_security_event")
    segment = updated[start:end]
    segment = _replace_once(
        segment,
        '''            result = self.adapter.ingest_security_event(event)
''',
        f'''            event_path = str(getattr(event, "path", "") or (getattr(event, "data", {{}}) or {{}}).get("path") or "")
            trace_marker(
                "EDR_BRIDGE_INGEST_ENTER",
                path=event_path,
                category=str(getattr(event, "category", "") or ""),
                source=str(getattr(event, "source", "") or ""),
            )
            result = self.adapter.ingest_security_event(event)
            trace_marker(
                "EDR_BRIDGE_INGEST_RESULT",
                path=event_path,
                stored=bool(result.get("stored")),
                disposition=str(result.get("disposition") or ""),
                event_id=str(result.get("event_id") or ""),
            )
''',
        "edr bridge ingest result",
    )
    segment = segment.replace(
        '''        except Exception as exc:
            with self._lock:
                self._ingest_errors += 1
''',
        '''        except Exception as exc:
            event_path = str(getattr(event, "path", "") or (getattr(event, "data", {}) or {}).get("path") or "")
            trace_marker("EDR_BRIDGE_INGEST_ERROR", path=event_path, error=f"{type(exc).__name__}: {exc}")
            with self._lock:
                self._ingest_errors += 1
''',
        1,
    )
    updated = updated[:start] + segment + updated[end:]

    start, end = _function_span(updated, "EdrServiceBridge", "dispatch_read")
    segment = updated[start:end]
    old_hunt = '''        if op == "edr_hunt":
            return self.hunting.hunt(
                str(data.get("indicator") or ""), kind=str(data.get("kind") or "auto"),
                since=data.get("since"), until=data.get("until"),
                limit=data.get("limit", 100), cursor=data.get("cursor"),
            )
'''
    new_hunt = '''        if op == "edr_hunt":
            indicator = str(data.get("indicator") or "")
            kind = str(data.get("kind") or "auto")
            trace_marker("EDR_HUNT_QUERY", path=indicator, kind=kind, since=data.get("since"), until=data.get("until"))
            result = self.hunting.hunt(
                indicator, kind=kind,
                since=data.get("since"), until=data.get("until"),
                limit=data.get("limit", 100), cursor=data.get("cursor"),
            )
            items = result.get("items") if isinstance(result, dict) else None
            trace_marker(
                "EDR_HUNT_RESULT",
                path=indicator,
                kind=kind,
                match_count=len(items) if isinstance(items, list) else -1,
                event_ids=[str(item.get("event_id") or "") for item in items[:10] if isinstance(item, dict)] if isinstance(items, list) else [],
            )
            return result
'''
    segment = _replace_once(segment, old_hunt, new_hunt, "edr hunt")
    updated = updated[:start] + segment + updated[end:]

    start, end = _function_span(updated, "EdrServiceBridge", "status")
    segment = updated[start:end]
    segment = _replace_once(
        segment,
        '''        return base
''',
        f'''        base["diagnostic_marker_trace"] = trace_snapshot(128)
        base["diagnostic_marker_trace_meta"] = trace_metadata()
        base["diagnostic_marker_trace_profile"] = "{MARKER}"
        return base
''',
        "edr status trace",
    )
    updated = updated[:start] + segment + updated[end:]
    ast.parse(updated)
    return updated


TRANSFORMS: dict[str, Callable[[str], str]] = {
    "watchdog_coalescing.py": transform_watchdog,
    "realtime.py": transform_realtime,
    "protection_service_core.py": transform_core,
    "edr_adapter.py": transform_adapter,
    "edr_service_bridge.py": transform_bridge,
}


def apply(root: Path) -> dict[str, Any]:
    root = root.resolve()
    trace_module = root / "sentinel" / "b2_diagnostic_trace.py"
    if not trace_module.is_file():
        raise RuntimeError("sentinel/b2_diagnostic_trace.py missing")

    results: dict[str, Any] = {}
    for rel in TARGETS:
        path = root / rel
        if not path.is_file():
            raise RuntimeError(f"required source missing: {rel}")
        before = path.read_text(encoding="utf-8")
        transform = TRANSFORMS[path.name]
        after = transform(before)
        ast.parse(after)
        changed = after != before
        backup = path.with_name(path.name + ".pre-v011-beta2-marker-trace.bak")
        if changed:
            if backup.exists() and backup.read_text(encoding="utf-8") != before:
                raise RuntimeError(f"existing marker-trace backup mismatch: {backup.name}")
            if not backup.exists():
                backup.write_text(before, encoding="utf-8")
            _atomic_replace(path, after)
        if MARKER not in after:
            raise RuntimeError(f"marker-trace instrumentation missing after patch: {rel}")
        results[str(rel)] = {"changed": changed, "marker_count": after.count(MARKER)}

    return {
        "profile": PROFILE,
        "checkpoint": "B2-marker-trace-instrumentation",
        "passed": True,
        "marker_only": True,
        "destructive_action": False,
        "targets": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Instrument the B2 watchdog-to-EDR path with marker-only structured diagnostics")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    result = apply(Path(args.root))
    changed = sum(1 for item in result["targets"].values() if item["changed"])
    print(
        "v0.11 Beta2 B2 marker trace instrumentation: PASS | "
        f"changed={changed}/{len(result['targets'])} | marker_only=true"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
