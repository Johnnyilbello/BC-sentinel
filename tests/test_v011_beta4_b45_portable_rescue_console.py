from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sentinel import rescue_console_portable as portable


def _offline_root(base: Path) -> Path:
    root = base / "offline-target"
    config = root / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"B45 TEST SYSTEM")
    (config / "SOFTWARE").write_bytes(b"B45 TEST SOFTWARE")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ B45 TEST KERNEL")
    return root


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*") if path.is_file()
    }


def test_status_payload_contract() -> None:
    payload = portable.status_payload()
    assert payload["profile"] == "v0.11.0-beta.4-b45"
    assert payload["commands"] == ["plan", "scan", "repair-handoff", "data-rescue", "certify"]
    assert payload["installer_required"] is False
    assert payload["service_install"] is False
    assert payload["driver_install"] is False
    assert payload["safety"]["repair_execution_exposed_by_console"] is False
    assert payload["safety"]["repair_handoff_only"] is True
    assert payload["safety"]["format_or_reimage_suppressed"] is False


def test_status_command_outputs_json(capsys) -> None:
    assert portable.main(["status"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True
    assert payload["profile"] == portable.PROFILE


def test_no_command_refused(capsys) -> None:
    assert portable.main([]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "command_required"


def test_unknown_command_refused(capsys) -> None:
    assert portable.main(["repair-execute"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "unknown_command:repair-execute"
    assert "repair-execute" not in payload["available_commands"]


def test_status_extra_arguments_refused(capsys) -> None:
    assert portable.main(["status", "unexpected"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "status_takes_no_arguments"


def test_plan_dispatch_creates_plan_without_target_mutation(tmp_path: Path, capsys) -> None:
    root = _offline_root(tmp_path)
    before = _tree_hashes(root)
    workspace = tmp_path / "workspace"
    output = workspace / "session-plan.json"
    rc = portable.main([
        "plan",
        "--target-root", str(root),
        "--workspace", str(workspace),
        "--output-plan", str(output),
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True
    assert output.is_file()
    assert before == _tree_hashes(root)


def test_scan_dispatch_forwards_arguments(monkeypatch) -> None:
    seen: list[str] = []
    monkeypatch.setitem(portable.COMMANDS, "scan", lambda argv: seen.extend(argv or []) or 7)
    assert portable.main(["scan", "--example", "value"]) == 7
    assert seen == ["--example", "value"]


def test_repair_handoff_dispatch_forwards_arguments(monkeypatch) -> None:
    seen: list[str] = []
    monkeypatch.setitem(portable.COMMANDS, "repair-handoff", lambda argv: seen.extend(argv or []) or 8)
    assert portable.main(["repair-handoff", "--x", "1"]) == 8
    assert seen == ["--x", "1"]


def test_data_rescue_dispatch_forwards_arguments(monkeypatch) -> None:
    seen: list[str] = []
    monkeypatch.setitem(portable.COMMANDS, "data-rescue", lambda argv: seen.extend(argv or []) or 9)
    assert portable.main(["data-rescue", "--x", "2"]) == 9
    assert seen == ["--x", "2"]


def test_certify_dispatch_forwards_arguments(monkeypatch) -> None:
    seen: list[str] = []
    monkeypatch.setitem(portable.COMMANDS, "certify", lambda argv: seen.extend(argv or []) or 10)
    assert portable.main(["certify", "--x", "3"]) == 10
    assert seen == ["--x", "3"]
