from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
from time import sleep
from typing import Any

PROFILE = "v0.11.0-beta.2-nonexec-observation-v6"
MARKER = "bc-sentinel-v011-beta2-nonexec-observation-v6"
REALTIME_REL = Path("sentinel") / "realtime.py"
BACKUP_REL = Path("sentinel") / "realtime.py.pre-v011-beta2-nonexec-observation-v6.bak"
OBSERVATION_MARKER = "bc-sentinel-v011-beta2-watchdog-file-observation-v1"


def _atomic_replace(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".v011-beta2-nonexec-observation.tmp")
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
    raise RuntimeError(f"class {name} not found")


def _method(cls: ast.ClassDef, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in cls.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise RuntimeError(f"{cls.name}.{name} not found")


def _path_arg(method: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = [arg.arg for arg in method.args.args]
    if len(args) < 2:
        raise RuntimeError(f"{method.name} path argument missing")
    return args[1]


def _is_exec_filter(node: ast.If) -> bool:
    test = node.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], ast.NotIn):
        return False
    right = test.comparators[0]
    if not isinstance(right, ast.Name) or right.id != "POTENTIALLY_EXECUTABLE":
        return False
    left = ast.unparse(test.left).replace(" ", "")
    return ".suffix.lower()" in left or ".suffix.casefold()" in left


def _find_exec_filter(queue: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.If:
    matches: list[ast.If] = []
    for node in ast.walk(queue):
        if isinstance(node, ast.If) and _is_exec_filter(node):
            matches.append(node)
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one non-executable early-return filter in _queue_scan, found {len(matches)}")
    node = matches[0]
    if not any(isinstance(child, ast.Return) for child in ast.walk(node)):
        raise RuntimeError("non-executable filter does not contain a return")
    return node


def _event_callback_calls(method: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    calls: list[ast.Call] = []
    for node in ast.walk(method):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        owner = node.func.value
        if isinstance(owner, ast.Name) and owner.id == "self" and node.func.attr == "event_callback":
            calls.append(node)
    return calls


def _scanner_calls(method: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
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
    return calls


def _indent_at(lines: list[str], line_no: int) -> str:
    raw = lines[line_no - 1]
    return raw[: len(raw) - len(raw.lstrip(" \t"))]


def transform_realtime(text: str) -> str:
    if MARKER in text:
        return text
    if OBSERVATION_MARKER not in text:
        raise RuntimeError("required stabilized B2 observation bridge is missing")

    tree = ast.parse(text)
    cls = _class(tree, "RealtimeMonitor")
    queue = _method(cls, "_queue_scan")
    stable = _method(cls, "_scan_when_stable")
    path_arg = _path_arg(queue)
    exec_filter = _find_exec_filter(queue)

    callback_calls = _event_callback_calls(stable)
    scanner_calls = _scanner_calls(stable)
    if len(callback_calls) != 1:
        raise RuntimeError(f"expected exactly one stabilized event_callback call, found {len(callback_calls)}")
    if len(scanner_calls) != 1:
        raise RuntimeError(f"expected exactly one static scanner call, found {len(scanner_calls)}")
    if int(callback_calls[0].lineno) >= int(scanner_calls[0].lineno):
        raise RuntimeError("observation callback must remain before static scanner")

    start = int(exec_filter.lineno)
    end = int(exec_filter.end_lineno or exec_filter.lineno)
    lines = text.splitlines(keepends=True)
    indent = _indent_at(lines, start)
    condition = ast.unparse(exec_filter.test)

    replacement = (
        f"{indent}# {MARKER}: benign filesystem observation is independent from static-scan eligibility\n"
        f"{indent}{'if ' + condition + ':'}\n"
        f"{indent}    if self.event_callback is not None:\n"
        f"{indent}        try:\n"
        f"{indent}            self.event_callback(str({path_arg}))\n"
        f"{indent}        except Exception:\n"
        f"{indent}            pass\n"
        f"{indent}    return\n"
    )
    lines[start - 1:end] = replacement.splitlines(keepends=True)
    result = "".join(lines)
    ast.parse(result)

    result_tree = ast.parse(result)
    result_cls = _class(result_tree, "RealtimeMonitor")
    result_queue = _method(result_cls, "_queue_scan")
    result_stable = _method(result_cls, "_scan_when_stable")
    filters = [node for node in ast.walk(result_queue) if isinstance(node, ast.If) and _is_exec_filter(node)]
    queue_callbacks = _event_callback_calls(result_queue)
    stable_callbacks = _event_callback_calls(result_stable)
    scanners = _scanner_calls(result_stable)
    checks = {
        "marker_once": result.count(MARKER) == 1,
        "exec_filter_preserved_once": len(filters) == 1,
        "nonexec_queue_callback_once": len(queue_callbacks) == 1,
        "stabilized_exec_callback_once": len(stable_callbacks) == 1,
        "static_scanner_once": len(scanners) == 1,
    }
    if not all(checks.values()):
        raise RuntimeError(f"post-transform verification failed: {checks}")
    return result


def apply(root: Path) -> dict[str, Any]:
    root = root.resolve()
    realtime = root / REALTIME_REL
    if not realtime.is_file():
        raise RuntimeError("FULL sentinel/realtime.py missing")

    before = realtime.read_text(encoding="utf-8")
    canonical = MARKER in before
    after = before if canonical else transform_realtime(before)
    ast.parse(after)

    backup = root / BACKUP_REL
    if not canonical:
        if backup.exists() and backup.read_text(encoding="utf-8") != before:
            raise RuntimeError("existing V6 realtime backup does not match current accepted pre-fix source")
        if not backup.exists():
            backup.write_text(before, encoding="utf-8")
        _atomic_replace(realtime, after)

    return {
        "profile": PROFILE,
        "checkpoint": "B2-nonexec-filesystem-observation",
        "passed": True,
        "changed": not canonical,
        "status": "patched" if not canonical else "already_canonical",
        "marker": MARKER,
        "non_executable_static_scan": False,
        "automatic_destructive_action": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Route non-executable watchdog events to benign EDR observation without widening static scan scope")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    result = apply(Path(args.root))
    print(
        "v0.11 Beta2 B2 non-executable observation V6: PASS | "
        f"status={result['status']} | static_scan_scope_unchanged=true"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
