from __future__ import annotations

import threading

from sentinel.thread_diagnostics import install_thread_attribution, thread_origin


def _sample_target():
    return None


def test_thread_origin_uses_target_module_and_qualname():
    thread = threading.Thread(target=_sample_target)
    origin = thread_origin(thread)
    assert "test_v011_beta1_thread_diagnostics" in origin
    assert "_sample_target" in origin


def test_default_thread_name_is_attributed_without_changing_target_execution():
    install_thread_attribution()
    observed = []

    def worker():
        observed.append(threading.current_thread().name)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=2.0)

    assert observed
    assert observed[0].startswith("BCS-Auto:")
    assert "worker" in observed[0]


def test_explicit_application_thread_name_is_preserved():
    install_thread_attribution()
    observed = []

    def worker():
        observed.append(threading.current_thread().name)

    thread = threading.Thread(target=worker, name="BCS-Explicit-Test")
    thread.start()
    thread.join(timeout=2.0)

    assert observed == ["BCS-Explicit-Test"]
