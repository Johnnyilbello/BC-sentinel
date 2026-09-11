from __future__ import annotations

import argparse
import ast
from pathlib import Path

from tools import v011_beta2_b2_diagnostic_trace_compat as base

PROFILE = "v0.11.0-beta.2-marker-trace-v2"


def _realtime_callback_call(text: str) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.Call]:
    tree = ast.parse(text)
    realtime_cls = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "RealtimeMonitor":
            realtime_cls = node
            break
    if realtime_cls is None:
        raise RuntimeError("RealtimeMonitor not found")

    stable = None
    for node in realtime_cls.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_scan_when_stable":
            stable = node
            break
    if stable is None:
        raise RuntimeError("RealtimeMonitor._scan_when_stable not found")

    calls: list[ast.Call] = []
    for node in ast.walk(stable):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "event_callback"
            and isinstance(func.value, ast.Name)
            and func.value.id == "self"
        ):
            calls.append(node)
    if len(calls) != 1:
        raise RuntimeError(f"expected exactly one self.event_callback call in _scan_when_stable, found {len(calls)}")
    return stable, calls[0]


def transform_realtime(text: str) -> str:
    if base.MARKER in text:
        return text

    updated = base._with_import(text, base.TRACE_IMPORT)
    stable, call = _realtime_callback_call(updated)

    args = [arg.arg for arg in stable.args.args]
    if len(args) < 2:
        raise RuntimeError("_scan_when_stable path argument missing")
    path_arg = args[1]

    lines = updated.splitlines(keepends=True)
    line_index = int(call.lineno) - 1
    end_line_index = int(call.end_lineno or call.lineno) - 1
    if not (0 <= line_index <= end_line_index < len(lines)):
        raise RuntimeError("event_callback source span outside realtime.py")

    original = "".join(lines[line_index : end_line_index + 1])
    first_line = lines[line_index]
    indent = first_line[: len(first_line) - len(first_line.lstrip(" \t"))]
    if len(indent.replace("\t", "    ")) < 8:
        raise RuntimeError("event_callback indentation unexpectedly shallow")

    wrapped = (
        f"{indent}# {base.MARKER}: AST-located stabilized marker trace\n"
        f"{indent}trace_marker(\"FILE_STABLE_CALLBACK_ENTER\", path=str({path_arg}), exists=bool({path_arg}.exists()))\n"
        f"{indent}try:\n"
        + "".join(f"{indent}    {line[len(indent):]}" if line.startswith(indent) else f"{indent}    {line}" for line in original.splitlines(keepends=True))
        + f"{indent}except Exception as exc:\n"
        f"{indent}    trace_marker(\"FILE_STABLE_CALLBACK_ERROR\", path=str({path_arg}), error=f\"{{type(exc).__name__}}: {{exc}}\")\n"
        f"{indent}    raise\n"
        f"{indent}else:\n"
        f"{indent}    trace_marker(\"FILE_STABLE_CALLBACK_RETURN\", path=str({path_arg}))\n"
    )

    lines[line_index : end_line_index + 1] = wrapped.splitlines(keepends=True)
    result = "".join(lines)
    ast.parse(result)
    if result.count(base.MARKER) != 1:
        raise RuntimeError("realtime marker-trace marker count invalid")
    _realtime_callback_call(result)
    return result


def apply(root: Path):
    base.TRANSFORMS["realtime.py"] = transform_realtime
    return base.apply(root)


def main() -> int:
    parser = argparse.ArgumentParser(description="AST-resilient B2 marker trace instrumentation")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    result = apply(Path(args.root))
    changed = sum(1 for item in result["targets"].values() if item["changed"])
    print(
        "v0.11 Beta2 B2 marker trace instrumentation v2: PASS | "
        f"changed={changed}/{len(result['targets'])} | marker_only=true | realtime_anchor=AST"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
