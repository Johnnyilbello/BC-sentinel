from __future__ import annotations

import threading
import time

import sentinel.pywintrace_idle as compat


def test_successful_process_trace_reentry_is_bounded(monkeypatch):
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
    assert elapsed >= compat.PYWINTRACE_REENTRY_BACKOFF_SECONDS


def test_process_trace_error_stops_without_reentry(monkeypatch):
    done = threading.Event()
    calls = {"count": 0}

    def fake_once(_trace_handle):
        calls["count"] += 1
        return 5, 0

    monkeypatch.setattr(compat, "_process_trace_once", fake_once)
    compat._run_low_cpu(object(), done)

    assert calls["count"] == 1
    assert done.is_set() is True


def test_reentry_backoff_is_bounded_and_interruptible():
    assert 0.02 <= compat.PYWINTRACE_REENTRY_BACKOFF_SECONDS <= 0.10
    assert compat.PYWINTRACE_REENTRY_MAX_BACKOFF_SECONDS <= 0.50
    assert compat.PYWINTRACE_REENTRY_MAX_BACKOFF_SECONDS >= compat.PYWINTRACE_REENTRY_BACKOFF_SECONDS


def test_adaptive_reentry_backoff_escalates_only_for_repeated_short_returns():
    streak = 0
    delays = []
    for _ in range(5):
        streak, delay = compat._adaptive_reentry_backoff(streak, 0.001)
        delays.append(delay)

    assert delays[0] == compat.PYWINTRACE_REENTRY_BACKOFF_SECONDS
    assert delays[1] == min(compat.PYWINTRACE_REENTRY_BACKOFF_SECONDS * 2, compat.PYWINTRACE_REENTRY_MAX_BACKOFF_SECONDS)
    assert delays[2] == min(compat.PYWINTRACE_REENTRY_BACKOFF_SECONDS * 4, compat.PYWINTRACE_REENTRY_MAX_BACKOFF_SECONDS)
    assert delays[3] == compat.PYWINTRACE_REENTRY_MAX_BACKOFF_SECONDS
    assert delays[4] == compat.PYWINTRACE_REENTRY_MAX_BACKOFF_SECONDS


def test_healthy_process_trace_block_resets_escalation():
    streak, delay = compat._adaptive_reentry_backoff(
        8,
        compat.PYWINTRACE_REENTRY_HEALTHY_BLOCK_SECONDS + 0.1,
    )
    assert streak == 1
    assert delay == compat.PYWINTRACE_REENTRY_BACKOFF_SECONDS


def test_pre_stopped_capture_does_not_wait_or_reenter(monkeypatch):
    done = threading.Event()
    calls = {"count": 0}

    def fake_once(_trace_handle):
        calls["count"] += 1
        done.set()
        return 0, 0

    monkeypatch.setattr(compat, "_process_trace_once", fake_once)
    started = time.perf_counter()
    compat._run_low_cpu(object(), done)
    elapsed = time.perf_counter() - started

    assert calls["count"] == 1
    assert elapsed < compat.PYWINTRACE_REENTRY_BACKOFF_SECONDS
