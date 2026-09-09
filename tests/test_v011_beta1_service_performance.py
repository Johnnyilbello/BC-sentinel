import inspect

from sentinel.etw_monitor import (
    ETWMonitor,
    ETW_SESSION_MODE,
    FILE_EVENT_DEDUP_SECONDS,
    FILE_PROVIDER,
    KERNEL_FILE_PATH_EVENT_IDS,
    etw_provider_event_filters,
)
from tools.service_hardening_benchmark import _evaluate
from tools.v011_service_readiness import _etw_diagnostics, is_ready
from tools.v011_service_update_windows_compat import (
    DNS_ETW_START_ATTEMPTS,
    DNS_ETW_START_RETRY_DELAY_SECONDS,
    ETW_DNS_SESSION_MODE,
)


class _Tree:
    def get(self, _pid):
        return None


class _Correlator:
    pass


def test_kernel_file_filter_decodes_only_path_bearing_events_used_by_pipeline():
    filters = etw_provider_event_filters()
    assert filters == {FILE_PROVIDER.upper(): [12, 26, 27, 30]}
    assert KERNEL_FILE_PATH_EVENT_IDS == {12, 26, 27, 30}
    assert 15 not in KERNEL_FILE_PATH_EVENT_IDS  # Read has no path in this provider schema
    assert 16 not in KERNEL_FILE_PATH_EVENT_IDS  # Write has no path in this provider schema


def test_file_event_microburst_dedup_is_bounded_and_time_scoped():
    monitor = ETWMonitor(_Tree(), _Correlator(), identity_resolver=object())
    assert monitor._is_duplicate_file_event(42, r"C:\Temp\a.exe", "CREATE", 12, now=10.0) is False
    assert monitor._is_duplicate_file_event(42, r"C:\Temp\a.exe", "CREATE", 12, now=10.1) is True
    assert monitor._is_duplicate_file_event(42, r"C:\Temp\a.exe", "DELETE", 26, now=10.1) is False
    assert monitor._is_duplicate_file_event(42, r"C:\Temp\a.exe", "CREATE", 12, now=10.1 + FILE_EVENT_DEDUP_SECONDS + 0.01) is False


def test_dns_etw_startup_retry_budget_is_bounded():
    assert DNS_ETW_START_ATTEMPTS == 4
    assert 0.0 < DNS_ETW_START_RETRY_DELAY_SECONDS <= 0.5


def test_etw_uses_pywintrace_020_safe_split_sessions():
    assert ETW_DNS_SESSION_MODE == "dedicated"
    assert ETW_SESSION_MODE == "split_process_file_dns"
    monitor = ETWMonitor(_Tree(), _Correlator(), identity_resolver=object())
    assert monitor._capture is None
    assert monitor._file_capture is None
    assert monitor._dns_capture is None
    start_source = inspect.getsource(ETWMonitor.start)
    assert "providers_event_id_filters=" not in start_source
    assert "event_id_filters=sorted(KERNEL_FILE_PATH_EVENT_IDS)" in start_source
    assert start_source.count("etw.ETW(") == 3


def test_service_readiness_requires_real_dns_etw_tracking():
    healthy = {
        "mode": "active_reversible",
        "dns_etw": True,
        "pid_scoped_dns": True,
        "shared_ip_guard": True,
        "mitm_https": False,
        "auto_block": False,
    }
    assert is_ready(healthy) is True
    degraded = dict(healthy)
    degraded["dns_etw"] = False
    assert is_ready(degraded) is False


def test_service_readiness_surfaces_etw_provider_error():
    service_status = {
        "health": "HEALTHY",
        "etw": {
            "running": True,
            "dns_tracking": False,
            "error": "DNS ETW dedicated session unavailable: WinError 5",
        },
    }
    diagnostics = _etw_diagnostics(service_status)
    assert diagnostics["running"] is True
    assert diagnostics["dns_tracking"] is False
    assert "WinError 5" in diagnostics["error"]


def test_service_benchmark_rejects_false_pass_when_idle_cpu_is_excessive():
    passed, checks, reasons = _evaluate(
        idle_cpu_percent=116.55,
        ipc_successful=200,
        ipc_requests=200,
        ipc_rps=31.1,
        storm_cpu_percent=154.68,
        hardening_ok=True,
        max_idle_cpu_percent=25.0,
        min_ipc_rps=10.0,
        max_storm_cpu_percent=250.0,
    )
    assert passed is False
    assert checks["idle_cpu_within_limit"] is False
    assert any("idle CPU" in reason for reason in reasons)


def test_service_benchmark_accepts_healthy_idle_and_workload_metrics():
    passed, checks, reasons = _evaluate(
        idle_cpu_percent=8.0,
        ipc_successful=200,
        ipc_requests=200,
        ipc_rps=30.0,
        storm_cpu_percent=170.0,
        hardening_ok=True,
        max_idle_cpu_percent=25.0,
        min_ipc_rps=10.0,
        max_storm_cpu_percent=250.0,
    )
    assert passed is True
    assert all(checks.values())
    assert reasons == []
