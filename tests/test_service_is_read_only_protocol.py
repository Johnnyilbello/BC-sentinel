from pathlib import Path

def test_service_protocol_has_no_remote_control_operations():
    src=Path("sentinel/telemetry_service_core.py").read_text(encoding="utf-8")
    for forbidden in (
        'op == "exec"',
        'op == "shell"',
        'op == "delete"',
        'op == "quarantine"',
        'op == "terminate"',
    ):
        assert forbidden not in src
