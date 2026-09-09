from sentinel.telemetry_client import TelemetryServiceClient

def test_client_fails_cleanly_without_secret(monkeypatch, tmp_path):
    import sentinel.telemetry_client as mod
    monkeypatch.setattr(mod, "secret_path", lambda: tmp_path/"missing.secret")
    c=TelemetryServiceClient(timeout=0.01)
    result=c.request("status")
    assert not result["ok"]
