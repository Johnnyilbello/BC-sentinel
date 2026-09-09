from pathlib import Path
import ast
from sentinel.correlation_engine import BehavioralCorrelationEngine
from sentinel.core.events import SecurityEvent

def test_network_monitor_is_read_only_by_contract():
    source=Path("sentinel/network_monitor.py").read_text(encoding="utf-8")
    assert "net_connections" in source
    lowered=source.lower()
    assert "netsh" not in lowered
    assert "new-netfirewallrule" not in lowered
    assert "set-netfirewallrule" not in lowered
    assert "terminate(" not in source
    assert "kill(" not in source

def test_interpreter_network_event_adds_correlation():
    engine=BehavioralCorrelationEngine()
    e=SecurityEvent(
        category="network",
        action="connect",
        source="test",
        pid=10,
        process_name="powershell.exe",
        process_path=r"C:\\Windows\\powershell.exe",
        path="1.2.3.4:443",
        data={"remote_addr":"1.2.3.4","remote_port":443},
    )
    result=engine.assess(e,[])
    assert result.score_delta>=8
    assert any("rete" in x.lower() for x in result.reasons)

def test_v03_ui_has_privacy_controls():
    source=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert "self.network_switch" in source
    assert "self.reputation_switch" in source
    assert "def toggle_network" in source
    assert "def toggle_reputation" in source
    ast.parse(source)
