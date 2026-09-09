from __future__ import annotations

import threading
import time

import sentinel.pywintrace_idle as compat


def test_immediate_success_process_trace_is_bounded(monkeypatch):
    done = threading.Event()
    calls = {"count": 0}

    def fake_once(_trace_handle):
        calls["count"] += 1
        if calls["count"] >= 3:
            done.set()
        return 0, 0

    monkeypatch.setattr(compat, "_process_trace_once", fake_once)
    started = time.perf_counter()
    compat._run_low_cpu(object(), done)
    elapsed = time.perf_counter() - started

    assert calls["count"] == 3
    assert elapsed >= compat.PYWINTRACE_IDLE_BACKOFF_SECONDS


def test_process_trace_error_stops_without_spin(monkeypatch):
    done = threading.Event()
    calls = {"count": 0}

    def fake_once(_trace_handle):
        calls["count"] += 1
        return 5, 0

    monkeypatch.setattr(compat, "_process_trace_once", fake_once)
    compat._run_low_cpu(object(), done)

    assert calls["count"] == 1
    assert done.is_set() is True


def test_idle_backoff_constants_are_low_latency_and_nonzero():
    assert 0.0 < compat.PYWINTRACE_IMMEDIATE_RETURN_SECONDS <= 0.01
    assert 0.0 < compat.PYWINTRACE_IDLE_BACKOFF_SECONDS <= 0.02
