from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any

from tools.v011_beta2_b2_live_acceptance import ProductionClient

PROFILE = "v0.11.0-beta.2-runtime-roots-probe-v1"
KEYWORDS = (
    "Settings.defaults",
    "monitored_dirs",
    "ransomware_dirs",
    "RealtimeMonitor",
    "realtime",
    "load_settings",
    "load_config",
    "settings",
    "config",
    "observer",
    "watchdog",
)


def _context_hits(path: Path, radius: int = 3) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    matched: set[int] = set()
    for idx, line in enumerate(lines, start=1):
        folded = line.casefold()
        if any(key.casefold() in folded for key in KEYWORDS):
            for n in range(max(1, idx - radius), min(len(lines), idx + radius) + 1):
                matched.add(n)
    return [{"line": n, "text": lines[n - 1]} for n in sorted(matched)]


def _call_name(node: ast.Call) -> str:
    cur = node.func
    parts: list[str] = []
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _ast_summary(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"exists": False}
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(text, filename=str(path))
    except Exception as exc:
        return {"exists": True, "parse_error": f"{type(exc).__name__}: {exc}"}

    calls: list[dict[str, Any]] = []
    strings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            folded = name.casefold()
            if any(term in folded for term in ("setting", "config", "realtime", "monitor", "watchdog", "load")):
                calls.append({"line": int(getattr(node, "lineno", 0)), "call": name})
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value.strip()
            folded = value.casefold()
            if value and len(value) <= 180 and any(term in folded for term in ("config", "setting", ".json", ".ini", ".yaml", ".toml", "monitor")):
                strings.append({"line": int(getattr(node, "lineno", 0)), "value": value})

    return {
        "exists": True,
        "settings_defaults_count": text.count("Settings.defaults"),
        "monitored_dirs_count": text.count("monitored_dirs"),
        "ransomware_dirs_count": text.count("ransomware_dirs"),
        "realtime_monitor_count": text.count("RealtimeMonitor"),
        "calls": sorted(calls, key=lambda x: (x["line"], x["call"]))[:120],
        "config_like_strings": sorted(strings, key=lambda x: (x["line"], x["value"]))[:120],
    }


def _ipc_status() -> dict[str, Any]:
    client = ProductionClient()
    out: dict[str, Any] = {"surface": client.surface, "operations": {}}
    for op in ("status", "service_status", "protection_status", "runtime_status", "edr_status"):
        try:
            response = client.call(op)
            out["operations"][op] = {"ok": True, "response": response}
        except Exception as exc:
            out["operations"][op] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return out


def run(root: Path, output: Path) -> int:
    core = root / "sentinel" / "protection_service_core.py"
    realtime = root / "sentinel" / "realtime.py"
    config = root / "sentinel" / "config.py"

    result = {
        "profile": PROFILE,
        "passed": True,
        "diagnostic_only": True,
        "files": {
            "protection_service_core": str(core),
            "realtime": str(realtime),
            "config": str(config),
        },
        "source": {
            "protection_service_core": _ast_summary(core),
            "realtime": _ast_summary(realtime),
            "config": _ast_summary(config),
        },
        "source_context": {
            "protection_service_core": _context_hits(core),
            "realtime": _context_hits(realtime),
        },
        "ipc": _ipc_status(),
    }

    core_text = core.read_text(encoding="utf-8", errors="replace") if core.is_file() else ""
    folded = core_text.casefold()
    if "settings.defaults" in folded:
        diagnosis = "service_core_references_settings_defaults_inspect_runtime_order_and_overrides"
    elif "monitored_dirs" in folded or "realtimemonitor" in folded:
        diagnosis = "service_core_constructs_realtime_without_direct_settings_defaults_reference"
    else:
        diagnosis = "service_core_monitor_configuration_path_not_obvious_from_static_probe"
    result["diagnosis"] = diagnosis

    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B2 runtime filesystem-root diagnostic probe")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--output", default="acceptance-v011-beta2-b2-runtime-roots-probe.json")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output
    return run(root, output)


if __name__ == "__main__":
    raise SystemExit(main())
