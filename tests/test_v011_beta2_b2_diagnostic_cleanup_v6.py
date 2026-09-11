from __future__ import annotations

from pathlib import Path

from tools.v011_beta2_b2_diagnostic_cleanup_v6 import (
    ADMISSION_MARKER,
    MARKER_TRACE,
    OBSERVATION_MARKER,
    QUEUE_TRACE,
    TARGETS,
    apply,
)


def _clean_source(name: str) -> str:
    if name == "realtime.py":
        return f'''from __future__ import annotations\n# {OBSERVATION_MARKER}\nclass X:\n    pass\n'''
    if name == "protection_service_core.py":
        return f'''from __future__ import annotations\n# {OBSERVATION_MARKER}\n# {ADMISSION_MARKER}\nclass X:\n    pass\n'''
    return "from __future__ import annotations\nclass X:\n    pass\n"


def test_cleanup_restores_exact_marker_trace_backups(tmp_path: Path):
    root = tmp_path
    sentinel = root / "sentinel"
    sentinel.mkdir()

    expected = {}
    for rel in TARGETS:
        path = root / rel
        clean = _clean_source(path.name)
        expected[str(rel)] = clean
        backup = path.with_name(path.name + ".pre-v011-beta2-marker-trace.bak")
        backup.write_text(clean, encoding="utf-8")
        instrumented = clean + f"\n# {MARKER_TRACE}\n"
        if path.name == "realtime.py":
            instrumented += f"# {QUEUE_TRACE}\n"
        path.write_text(instrumented, encoding="utf-8")

    result = apply(root)
    assert result["passed"] is True
    for rel in TARGETS:
        assert (root / rel).read_text(encoding="utf-8") == expected[str(rel)]


def test_cleanup_is_idempotent_when_sources_are_already_clean(tmp_path: Path):
    root = tmp_path
    sentinel = root / "sentinel"
    sentinel.mkdir()
    for rel in TARGETS:
        path = root / rel
        path.write_text(_clean_source(path.name), encoding="utf-8")

    result = apply(root)
    assert result["passed"] is True
    assert all(item["status"] == "already_clean" for item in result["targets"].values())
