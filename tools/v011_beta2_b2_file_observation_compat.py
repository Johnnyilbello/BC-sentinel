from __future__ import annotations

import argparse
import ast
import hashlib
import os
from pathlib import Path
from time import sleep
from typing import Any

PROFILE = "v0.11.0-beta.2"
REALTIME_REL = Path("sentinel") / "realtime.py"
CORE_REL = Path("sentinel") / "protection_service_core.py"
REALTIME_PRE_SHA256 = "33f860934ccacbefada01632e2358108b64fc854f7cb2c411bf072be782afbe9"
CORE_PRE_SHA256 = "55302443fd488c4f6da28010f25a23c9e37e930943109ae4984f9719ba4187ed"
REALTIME_BACKUP_REL = Path("sentinel") / "realtime.py.pre-v011-beta2-b2-file-observation.bak"
CORE_BACKUP_REL = Path("sentinel") / "protection_service_core.py.pre-v011-beta2-b2-file-observation.bak"
MARKER = "bc-sentinel-v011-beta2-watchdog-file-observation-v1"

_RT_PARAM_OLD = "        ransomware_callback=None,\n        correlator=None,\n"
_RT_PARAM_NEW = "        ransomware_callback=None,\n        event_callback=None,\n        correlator=None,\n"
_RT_ASSIGN_OLD = "        self.ransomware_callback = ransomware_callback\n        self.correlator = correlator\n"
_RT_ASSIGN_NEW = "        self.ransomware_callback = ransomware_callback\n        self.event_callback = event_callback\n        self.correlator = correlator\n"
_CORE_CALL_OLD = "            ransomware_callback=self._on_ransomware_detection,\n            correlator=self.correlator,\n"
_CORE_CALL_NEW = "            ransomware_callback=self._on_ransomware_detection,\n            event_callback=self._on_realtime_file_observed,\n            correlator=self.correlator,\n"
_CORE_METHOD_ANCHOR = "    def _on_realtime_detection(self, report):\n"
_CORE_METHOD = f'''    # {MARKER}: service file-observation bridge\n    def _on_realtime_file_observed(self, path: str):\n        value = str(path or "")\n        if not value:\n            return\n        self._on_event(SecurityEvent(\n            category="filesystem",\n            action="observed",\n            source="watchdog",\n            score=0,\n            path=value,\n            data={{"realtime": True, "watchdog_observed": True}},\n        ))\n\n'''


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _atomic_replace(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".v011-beta2-b2-file-observation.tmp")
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


def _class(tree: ast.Module, name: str) -> ast.ClassDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise RuntimeError(f"{name} not found")


def _method(cls: ast.ClassDef, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in cls.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise RuntimeError(f"{cls.name}.{name} not found")


def _scanner_call(method: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.Call:
    calls: list[ast.Call] = []
    for node in ast.walk(method):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        owner = node.func.value
        if (
            isinstance(owner, ast.Attribute)
            and isinstance(owner.value, ast.Name)
            and owner.value.id == "self"
            and owner.attr == "scanner"
        ):
            calls.append(node)
    if len(calls) != 1:
        raise RuntimeError(f"expected exactly one scanner call in RealtimeMonitor._scan_when_stable, found {len(calls)}")
    return calls[0]


def transform_realtime_text(text: str) -> str:
    if MARKER in text:
        return text
    if text.count(_RT_PARAM_OLD) != 1 or text.count(_RT_ASSIGN_OLD) != 1:
        raise RuntimeError("unexpected realtime constructor shape; refusing patch")

    tree = ast.parse(text)
    realtime_cls = _class(tree, "RealtimeMonitor")
    stable = _method(realtime_cls, "_scan_when_stable")
    args = [arg.arg for arg in stable.args.args]
    if len(args) < 2:
        raise RuntimeError("_scan_when_stable path argument missing")
    path_arg = args[1]
    call = _scanner_call(stable)

    lines = text.splitlines(keepends=True)
    call_index = int(call.lineno) - 1
    if not (0 <= call_index < len(lines)):
        raise RuntimeError("scanner call line is outside realtime source")
    raw = lines[call_index]
    indent = raw[: len(raw) - len(raw.lstrip(" \t"))]
    if len(indent.replace("\t", "    ")) < 8:
        raise RuntimeError("scanner call indentation is unexpectedly shallow")
    callback_block = (
        f"{indent}# {MARKER}: emit only after file stabilization, before static scan\n"
        f"{indent}if self.event_callback is not None:\n"
        f"{indent}    try:\n"
        f"{indent}        self.event_callback(str({path_arg}))\n"
        f"{indent}    except Exception:\n"
        f"{indent}        pass\n"
    )
    lines[call_index:call_index] = callback_block.splitlines(keepends=True)
    updated = "".join(lines)
    updated = updated.replace(_RT_PARAM_OLD, _RT_PARAM_NEW, 1)
    updated = updated.replace(_RT_ASSIGN_OLD, _RT_ASSIGN_NEW, 1)
    ast.parse(updated)
    if updated.count(MARKER) != 1:
        raise RuntimeError("realtime observation marker count invalid")
    return updated


def transform_core_text(text: str) -> str:
    if MARKER in text:
        return text
    if text.count(_CORE_CALL_OLD) != 1:
        raise RuntimeError("unexpected RealtimeMonitor construction shape; refusing core patch")
    if text.count(_CORE_METHOD_ANCHOR) != 1:
        raise RuntimeError("_on_realtime_detection anchor missing/ambiguous")
    updated = text.replace(_CORE_CALL_OLD, _CORE_CALL_NEW, 1)
    updated = updated.replace(_CORE_METHOD_ANCHOR, _CORE_METHOD + _CORE_METHOD_ANCHOR, 1)
    ast.parse(updated)
    if updated.count(MARKER) != 1:
        raise RuntimeError("core observation marker count invalid")
    return updated


def _verify_realtime(text: str) -> dict[str, bool]:
    return {
        "marker_once": text.count(MARKER) == 1,
        "event_callback_parameter_once": text.count("        event_callback=None,") == 1,
        "event_callback_assignment_once": text.count("        self.event_callback = event_callback") == 1,
        "stabilized_emit_once": text.count("self.event_callback(str(") == 1,
    }


def _verify_core(text: str) -> dict[str, bool]:
    return {
        "marker_once": text.count(MARKER) == 1,
        "realtime_callback_wired_once": text.count("event_callback=self._on_realtime_file_observed") == 1,
        "observation_method_once": text.count("def _on_realtime_file_observed") == 1,
        "filesystem_category_once": text.count('category="filesystem"') == 1,
        "watchdog_source_once": text.count('source="watchdog"') == 1,
        "routes_through_on_event_once": text.count("self._on_event(SecurityEvent(") >= 1,
    }


def apply(root: Path) -> dict[str, Any]:
    root = root.resolve()
    realtime = root / REALTIME_REL
    core = root / CORE_REL
    if not realtime.is_file() or not core.is_file():
        raise RuntimeError("FULL realtime/core source missing")

    rt_before = realtime.read_text(encoding="utf-8")
    core_before = core.read_text(encoding="utf-8")
    rt_canonical = MARKER in rt_before
    core_canonical = MARKER in core_before
    if rt_canonical != core_canonical:
        raise RuntimeError("partial file-observation patch detected; refusing repair-by-guess")

    if not rt_canonical:
        if _sha(rt_before) != REALTIME_PRE_SHA256:
            raise RuntimeError(f"realtime.py prepatch hash mismatch: {_sha(rt_before)}")
        if _sha(core_before) != CORE_PRE_SHA256:
            raise RuntimeError(f"protection_service_core.py prepatch hash mismatch: {_sha(core_before)}")
        rt_after = transform_realtime_text(rt_before)
        core_after = transform_core_text(core_before)
        ast.parse(rt_after)
        ast.parse(core_after)

        rt_backup = root / REALTIME_BACKUP_REL
        core_backup = root / CORE_BACKUP_REL
        if rt_backup.exists() and rt_backup.read_text(encoding="utf-8") != rt_before:
            raise RuntimeError("existing realtime observation backup does not match accepted prepatch source")
        if core_backup.exists() and core_backup.read_text(encoding="utf-8") != core_before:
            raise RuntimeError("existing core observation backup does not match accepted prepatch source")
        if not rt_backup.exists():
            rt_backup.write_text(rt_before, encoding="utf-8")
        if not core_backup.exists():
            core_backup.write_text(core_before, encoding="utf-8")
        _atomic_replace(realtime, rt_after)
        _atomic_replace(core, core_after)
    else:
        rt_after = rt_before
        core_after = core_before

    rt_checks = _verify_realtime(rt_after)
    core_checks = _verify_core(core_after)
    if not all(rt_checks.values()) or not all(core_checks.values()):
        raise RuntimeError(f"post-patch verification failed: realtime={rt_checks}, core={core_checks}")

    return {
        "profile": PROFILE,
        "checkpoint": "B2-watchdog-file-observation",
        "passed": True,
        "changed": not rt_canonical,
        "status": "patched" if not rt_canonical else "already_canonical",
        "realtime_sha256": _sha(rt_after),
        "core_sha256": _sha(core_after),
        "realtime_checks": rt_checks,
        "core_checks": core_checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Patch stabilized watchdog file observation into service-owned EDR")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    result = apply(Path(args.root))
    print(
        "v0.11 Beta2 B2 file observation compatibility: "
        f"{result['status']} | realtime={result['realtime_sha256']} | core={result['core_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
