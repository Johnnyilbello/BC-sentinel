from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
from time import sleep
from typing import Any

PROFILE = "v0.11.0-beta.2"
TARGET_RELATIVE = Path("sentinel") / "protection_service_core.py"
EXPECTED_PREPATCH_SHA256 = "29bc05622b61c0723a81a25fc658570f06b9ff96ad0460f9e6fab4e10af5f4d7"
MARKER = "bc-sentinel-v011-beta2-service-runtime-v1"
IMPORT_LINE = "from .edr_service_bridge import EdrServiceBridge\n"
LEGACY_STATUS_NAME = "_v011_beta2_legacy_status"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse(text: str, path: Path) -> ast.Module:
    return ast.parse(text, filename=str(path))


def _class(tree: ast.Module, name: str) -> ast.ClassDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise RuntimeError(f"{name} not found; refusing service runtime patch")


def _method(cls: ast.ClassDef, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in cls.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise RuntimeError(f"{cls.name}.{name} not found; refusing service runtime patch")


def _method_names(cls: ast.ClassDef) -> set[str]:
    return {
        node.name for node in cls.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _insert_after_line(lines: list[str], line_no: int, block: str) -> None:
    lines[line_no:line_no] = block.splitlines(keepends=True)


def _atomic_replace(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".v011-beta2-b1a.tmp")
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
    raise RuntimeError(f"atomic ProtectionRuntime source promotion failed: {last}")


def verify_runtime_patch(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    tree = _parse(text, path)
    runtime = _class(tree, "ProtectionRuntime")
    names = _method_names(runtime)
    checks = {
        "marker_once": text.count(MARKER) == 3,
        "bridge_import_once": text.count("from .edr_service_bridge import EdrServiceBridge") == 1,
        "legacy_status_present": LEGACY_STATUS_NAME in names,
        "status_wrapper_present": "status" in names,
        "bridge_constructed": "self.edr_bridge = EdrServiceBridge(" in text,
        "event_ingestion": "_edr_bridge.ingest_security_event(event)" in text,
        "status_exposes_edr": 'payload["edr"] = self.edr_bridge.status()' in text,
        "no_auto_response_in_patch": all(term not in text for term in (
            "self.edr_bridge.automatic_process_kill",
            "self.edr_bridge.automatic_file_delete",
            "self.edr_bridge.automatic_host_isolation",
        )),
    }
    return {
        "profile": PROFILE,
        "checkpoint": "B1a-service-runtime",
        "passed": all(checks.values()),
        "checks": checks,
        "path": str(path),
        "source_sha256": _sha256(text),
    }


def apply_runtime_patch(
    path: Path,
    *,
    expected_sha256: str | None = EXPECTED_PREPATCH_SHA256,
) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"FULL-only protection_service_core.py missing: {path}")

    original = path.read_text(encoding="utf-8")
    if MARKER in original:
        result = verify_runtime_patch(path)
        if not result["passed"]:
            raise RuntimeError("existing Beta2 runtime marker is incomplete; refusing repair-by-guess")
        result.update({"patched": False, "already_compatible": True})
        return result

    original_sha = _sha256(original)
    if expected_sha256 is not None and original_sha != expected_sha256:
        raise RuntimeError(
            "ProtectionRuntime source changed since B0 preflight; refusing mutation. "
            f"expected {expected_sha256}, got {original_sha}"
        )

    tree = _parse(original, path)
    runtime = _class(tree, "ProtectionRuntime")
    init = _method(runtime, "__init__")
    on_event = _method(runtime, "_on_event")
    status = _method(runtime, "status")
    if LEGACY_STATUS_NAME in _method_names(runtime):
        raise RuntimeError("unexpected legacy-status method already exists without Beta2 marker")
    if status.decorator_list:
        raise RuntimeError("ProtectionRuntime.status has decorators; refusing automatic wrapper patch")

    lines = original.splitlines(keepends=True)

    # Apply edits from bottom to top so original AST line numbers remain valid.
    status_wrapper = (
        f"\n    # {MARKER}: status\n"
        "    def status(self):\n"
        f"        payload = self.{LEGACY_STATUS_NAME}()\n"
        "        if isinstance(payload, dict):\n"
        "            payload = dict(payload)\n"
        "            payload[\"edr\"] = self.edr_bridge.status()\n"
        "        return payload\n"
    )
    _insert_after_line(lines, int(status.end_lineno or status.lineno), status_wrapper)

    status_index = status.lineno - 1
    if "def status(" not in lines[status_index]:
        raise RuntimeError("ProtectionRuntime.status definition line shape changed; refusing patch")
    lines[status_index] = lines[status_index].replace(
        "def status(", f"def {LEGACY_STATUS_NAME}(", 1
    )

    event_insert_line = on_event.body[0].lineno - 1
    if (
        isinstance(on_event.body[0], ast.Expr)
        and isinstance(on_event.body[0].value, ast.Constant)
        and isinstance(on_event.body[0].value.value, str)
    ):
        event_insert_line = int(on_event.body[0].end_lineno or on_event.body[0].lineno)
    event_block = (
        f"        # {MARKER}: ingest\n"
        "        _edr_bridge = getattr(self, \"edr_bridge\", None)\n"
        "        if _edr_bridge is not None:\n"
        "            _edr_bridge.ingest_security_event(event)\n"
    )
    _insert_after_line(lines, event_insert_line, event_block)

    init_block = (
        f"        # {MARKER}: ownership\n"
        "        _edr_settings = getattr(self, \"settings\", None)\n"
        "        self.edr_bridge = EdrServiceBridge(\n"
        "            retention_days=int(getattr(_edr_settings, \"edr_retention_days\", 7)),\n"
        "            max_events=int(getattr(_edr_settings, \"edr_max_events\", 100000)),\n"
        "            correlation_window_seconds=int(getattr(_edr_settings, \"edr_correlation_window_seconds\", 90)),\n"
        "            inbox_callback=None,\n"
        "        )\n"
    )
    _insert_after_line(lines, int(init.end_lineno or init.lineno), init_block)

    # Insert one isolated import after the top-level import section.
    import_end = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_end = max(import_end, int(node.end_lineno or node.lineno))
    if import_end <= 0:
        raise RuntimeError("top-level import section not found; refusing patch")
    _insert_after_line(lines, import_end, IMPORT_LINE)

    updated = "".join(lines)
    _parse(updated, path)

    # Verify the generated text before the atomic promotion.
    if updated.count(MARKER) != 3:
        raise RuntimeError("generated runtime patch marker count is invalid")
    if updated.count("from .edr_service_bridge import EdrServiceBridge") != 1:
        raise RuntimeError("generated EDR bridge import is missing or duplicated")
    if "self.edr_bridge = EdrServiceBridge(" not in updated:
        raise RuntimeError("generated service-owned EDR bridge construction is missing")
    if "_edr_bridge.ingest_security_event(event)" not in updated:
        raise RuntimeError("generated SecurityEvent -> EDR ingestion hook is missing")

    backup = path.with_name(path.name + ".pre-v011-beta2-b1a.bak")
    if not backup.exists():
        backup.write_text(original, encoding="utf-8")
    _atomic_replace(path, updated)

    result = verify_runtime_patch(path)
    if not result["passed"]:
        raise RuntimeError("post-write ProtectionRuntime verification failed")
    result.update({
        "patched": True,
        "already_compatible": False,
        "prepatch_sha256": original_sha,
        "backup": str(backup),
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11 Beta2 B1a service runtime integration patch")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--output", default="integration-v011-beta2-b1a-runtime.json")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    target = root / TARGET_RELATIVE
    try:
        result = verify_runtime_patch(target) if args.verify_only else apply_runtime_patch(target)
    except Exception as exc:
        result = {
            "profile": PROFILE,
            "checkpoint": "B1a-service-runtime",
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
            "target": str(target),
        }

    output = Path(args.output)
    if not output.is_absolute():
        output = root / output
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
