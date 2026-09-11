from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
from time import sleep
from typing import Any

PROFILE = "v0.11.0-beta.2-queue-scan-trace-v4"
MARKER = "bc-sentinel-v011-beta2-queue-scan-trace-v4"
REALTIME_REL = Path("sentinel") / "realtime.py"
BACKUP_REL = Path("sentinel") / "realtime.py.pre-v011-beta2-queue-scan-trace-v4.bak"
TRACE_IMPORT = "from .b2_diagnostic_trace import trace_marker\n"


def _atomic_replace(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".v011-beta2-queue-trace.tmp")
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


def _with_import(text: str) -> str:
    if TRACE_IMPORT in text:
        return text
    anchor = "from __future__ import annotations\n"
    if text.count(anchor) != 1:
        raise RuntimeError("future import anchor missing or ambiguous")
    return text.replace(anchor, anchor + "\n" + TRACE_IMPORT, 1)


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


def _returns(method: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Return]:
    out: list[ast.Return] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is method:
                for item in node.body:
                    self.visit(item)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            if node is method:
                for item in node.body:
                    self.visit(item)

        def visit_Return(self, node: ast.Return) -> None:
            out.append(node)

    Visitor().visit(method)
    return sorted(out, key=lambda node: int(node.lineno))


def _indent_at(lines: list[str], line_no: int) -> str:
    raw = lines[line_no - 1]
    return raw[: len(raw) - len(raw.lstrip(" \t"))]


def _source_context(lines: list[str], line_no: int, before: int = 3) -> str:
    start = max(0, int(line_no) - before - 1)
    end = min(len(lines), int(line_no))
    parts = [line.strip() for line in lines[start:end] if line.strip()]
    return " | ".join(parts)[-900:]


def _path_arg(method: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = [arg.arg for arg in method.args.args]
    if len(args) < 2:
        raise RuntimeError(f"{method.name} path argument missing")
    return args[1]


def _thread_start_expr(method: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.Expr:
    candidates: list[ast.Expr] = []
    for node in ast.walk(method):
        if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "start":
            continue
        source = ast.dump(call, include_attributes=False)
        if "Thread" in source and "_scan_when_stable" in source:
            candidates.append(node)
    if len(candidates) != 1:
        raise RuntimeError(f"expected one BCS realtime scan thread start, found {len(candidates)}")
    return candidates[0]


def transform_realtime(text: str) -> str:
    if MARKER in text:
        return text
    updated = _with_import(text)
    tree = ast.parse(updated)
    cls = _class(tree, "RealtimeMonitor")
    queue = _method(cls, "_queue_scan")
    stable = _method(cls, "_scan_when_stable")
    queue_path = _path_arg(queue)
    stable_path = _path_arg(stable)
    thread_expr = _thread_start_expr(queue)
    lines = updated.splitlines(keepends=True)

    insertions: list[tuple[int, str]] = []

    queue_first = int(queue.body[0].lineno)
    queue_indent = _indent_at(lines, queue_first)
    insertions.append((
        queue_first - 1,
        f'{queue_indent}# {MARKER}: marker-only queue/stabilization diagnostics\n'
        f'{queue_indent}trace_marker("QUEUE_SCAN_ENTER", path=str({queue_path}), '
        f'exists=bool(__import__("os").path.exists(str({queue_path}))), '
        f'is_file=bool(__import__("os").path.isfile(str({queue_path}))), '
        f'debounce_size=len(getattr(self, "_debounce", {{}})), '
        f'recent_hashes_size=len(getattr(self, "_recent_hashes", {{}})))\n'
    ))

    for ret in _returns(queue):
        line_no = int(ret.lineno)
        indent = _indent_at(lines, line_no)
        context = repr(_source_context(lines, line_no))
        insertions.append((
            line_no - 1,
            f'{indent}trace_marker("QUEUE_SCAN_RETURN", path=str({queue_path}), '
            f'source_line={line_no}, source_context={context}, '
            f'exists=bool(__import__("os").path.exists(str({queue_path}))), '
            f'is_file=bool(__import__("os").path.isfile(str({queue_path}))), '
            f'debounce_value=str(getattr(self, "_debounce", {{}}).get(str({queue_path}), "")))\n'
        ))

    thread_start = int(thread_expr.lineno)
    thread_end = int(thread_expr.end_lineno or thread_expr.lineno)
    thread_indent = _indent_at(lines, thread_start)
    insertions.append((
        thread_start - 1,
        f'{thread_indent}trace_marker("QUEUE_SCAN_THREAD_START_REQUEST", path=str({queue_path}), source_line={thread_start})\n'
    ))
    insertions.append((
        thread_end,
        f'{thread_indent}trace_marker("QUEUE_SCAN_THREAD_STARTED", path=str({queue_path}), source_line={thread_end})\n'
    ))

    stable_first = int(stable.body[0].lineno)
    stable_indent = _indent_at(lines, stable_first)
    insertions.append((
        stable_first - 1,
        f'{stable_indent}trace_marker("STABLE_ENTER", path=str({stable_path}), '
        f'exists=bool(__import__("os").path.exists(str({stable_path}))), '
        f'is_file=bool(__import__("os").path.isfile(str({stable_path}))))\n'
    ))
    for ret in _returns(stable):
        line_no = int(ret.lineno)
        indent = _indent_at(lines, line_no)
        context = repr(_source_context(lines, line_no))
        insertions.append((
            line_no - 1,
            f'{indent}trace_marker("STABLE_RETURN", path=str({stable_path}), '
            f'source_line={line_no}, source_context={context}, '
            f'exists=bool(__import__("os").path.exists(str({stable_path}))), '
            f'is_file=bool(__import__("os").path.isfile(str({stable_path}))))\n'
        ))

    for index, payload in sorted(insertions, key=lambda item: item[0], reverse=True):
        lines[index:index] = payload.splitlines(keepends=True)

    result = "".join(lines)
    ast.parse(result)
    checks = {
        "marker_once": result.count(MARKER) == 1,
        "queue_enter_once": result.count('trace_marker("QUEUE_SCAN_ENTER"') == 1,
        "queue_thread_request_once": result.count('trace_marker("QUEUE_SCAN_THREAD_START_REQUEST"') == 1,
        "queue_thread_started_once": result.count('trace_marker("QUEUE_SCAN_THREAD_STARTED"') == 1,
        "stable_enter_once": result.count('trace_marker("STABLE_ENTER"') == 1,
        "queue_returns_traced": result.count('trace_marker("QUEUE_SCAN_RETURN"') == len(_returns(queue)),
        "stable_returns_traced": result.count('trace_marker("STABLE_RETURN"') == len(_returns(stable)),
        "source_context_present": "source_context=" in result,
    }
    if not all(checks.values()):
        raise RuntimeError(f"queue/stable instrumentation verification failed: {checks}")
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
            raise RuntimeError("existing queue-trace backup does not match current accepted source")
        if not backup.exists():
            backup.write_text(before, encoding="utf-8")
        _atomic_replace(realtime, after)

    return {
        "profile": PROFILE,
        "passed": True,
        "changed": not canonical,
        "status": "patched" if not canonical else "already_canonical",
        "marker_only": True,
        "automatic_destructive_action": False,
        "marker": MARKER,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Trace RealtimeMonitor handler queueing through file stabilization")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    result = apply(Path(args.root))
    print(
        "v0.11 Beta2 B2 queue/stabilization trace V4: PASS | "
        f"status={result['status']} | marker_only=true"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
