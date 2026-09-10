import time
from threading import Event
from types import SimpleNamespace

from sentinel.watchdog_coalescing import CoalescingEventHandlerProxy


class _Inner:
    def __init__(self, delay: float = 0.0):
        self.events = []
        self.delay = delay
        self.changed = Event()

    def dispatch(self, event):
        if self.delay:
            time.sleep(self.delay)
        self.events.append(event)
        self.changed.set()
        return "forwarded"


def _event(event_type: str, path: str, *, is_directory: bool = False, dest_path: str = ""):
    return SimpleNamespace(
        event_type=event_type,
        src_path=path,
        dest_path=dest_path,
        is_directory=is_directory,
    )


def _wait_count(inner: _Inner, count: int, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while len(inner.events) < count and time.monotonic() < deadline:
        inner.changed.wait(0.02)
        inner.changed.clear()
    assert len(inner.events) >= count


def test_directory_modified_noise_is_dropped_but_child_security_events_remain_visible():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner, modified_window_seconds=0.05)
    try:
        assert proxy.dispatch(_event("modified", r"C:\\watched", is_directory=True)) is None
        assert proxy.directory_modified_dropped == 1
        assert inner.events == []

        for event_type in ("created", "moved", "deleted"):
            assert proxy.dispatch(
                _event(
                    event_type,
                    rf"C:\\watched\\sample-{event_type}.exe",
                    dest_path=rf"C:\\watched\\dest-{event_type}.exe",
                )
            ) is None

        _wait_count(inner, 3)
        assert [event.event_type for event in inner.events] == ["created", "moved", "deleted"]
    finally:
        proxy.close()


def test_repeated_file_modified_notifications_wait_for_quiet_period_and_collapse_to_one():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner, modified_window_seconds=0.05)
    try:
        for _ in range(8):
            assert proxy.dispatch(_event("modified", r"C:\\watched\\payload.exe")) is None
            time.sleep(0.005)

        assert inner.events == []
        _wait_count(inner, 1)
        assert len(inner.events) == 1
        assert inner.events[0].src_path == r"C:\\watched\\payload.exe"
        assert proxy.coalesced == 7
    finally:
        proxy.close()


def test_zero_modified_window_preserves_every_file_modified_event():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner, modified_window_seconds=0.0)
    try:
        event = _event("modified", r"C:\\watched\\rapid-write.exe")
        assert proxy.dispatch(event) is None
        assert proxy.dispatch(event) is None
        _wait_count(inner, 2)
        assert proxy.coalesced == 0
        assert len(inner.events) == 2
    finally:
        proxy.close()


def test_directory_move_is_not_suppressed():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner)
    try:
        event = _event(
            "moved",
            r"C:\\watched\\folder-a",
            is_directory=True,
            dest_path=r"C:\\watched\\folder-b",
        )
        assert proxy.dispatch(event) is None
        _wait_count(inner, 1)
        assert inner.events == [event]
    finally:
        proxy.close()


def test_heavy_inner_handler_does_not_block_watchdog_observer_dispatch_thread():
    inner = _Inner(delay=0.20)
    proxy = CoalescingEventHandlerProxy(inner)
    try:
        started = time.monotonic()
        assert proxy.dispatch(_event("created", r"C:\\watched\\new.exe")) is None
        elapsed = time.monotonic() - started
        assert elapsed < 0.10
        _wait_count(inner, 1)
    finally:
        proxy.close()


def test_close_flushes_a_pending_modified_event_once():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner, modified_window_seconds=60.0)
    event = _event("modified", r"C:\\watched\\pending.exe")

    assert proxy.dispatch(event) is None
    assert inner.events == []
    proxy.close(timeout=2.0)

    assert inner.events == [event]
    status = proxy.status()
    assert status["forwarded"] == 1
    assert status["worker_alive"] is False


def test_ordered_scheduler_preserves_one_final_event_for_many_unique_modified_paths():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner, modified_window_seconds=60.0)
    events = [_event("modified", rf"C:\\watched\\unique-{i:04d}.bin") for i in range(300)]

    for event in events:
        assert proxy.dispatch(event) is None

    before_close = proxy.status()
    assert before_close["modified_pending"] == len(events)
    assert before_close["scheduler_order_entries"] == len(events)
    assert before_close["scheduler_heap_entries"] == 0
    assert inner.events == []

    proxy.close(timeout=3.0)

    assert len(inner.events) == len(events)
    assert {event.src_path for event in inner.events} == {event.src_path for event in events}
    status = proxy.status()
    assert status["forwarded"] == len(events)
    assert status["modified_pending"] == 0
    assert status["worker_alive"] is False


def test_ordered_scheduler_keeps_single_entry_for_extremely_chatty_same_path():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner, modified_window_seconds=60.0)
    path = r"C:\\watched\\very-chatty.tmp"

    for _ in range(5000):
        assert proxy.dispatch(_event("modified", path)) is None

    status = proxy.status()
    assert status["modified_pending"] == 1
    assert status["scheduler_order_entries"] == 1
    assert status["coalesced"] == 4999
    assert status["scheduler_deadline_updates"] == 5000
    assert status["scheduler_reorders"] == 4999
    assert status["scheduler_heap_entries"] == 0
    assert status["scheduler_stale_pops"] == 0

    proxy.close(timeout=2.0)
    assert len(inner.events) == 1
    assert inner.events[0].src_path == path


def test_ordered_scheduler_moves_extended_path_behind_earlier_deadline():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner, modified_window_seconds=0.08)
    try:
        first = _event("modified", r"C:\\watched\\first.bin")
        second = _event("modified", r"C:\\watched\\second.bin")
        assert proxy.dispatch(first) is None
        time.sleep(0.01)
        assert proxy.dispatch(second) is None
        time.sleep(0.01)
        assert proxy.dispatch(first) is None

        _wait_count(inner, 2)
        assert [event.src_path for event in inner.events] == [second.src_path, first.src_path]
    finally:
        proxy.close()


def test_same_inner_handler_reuses_one_live_dispatch_worker():
    inner = _Inner()
    first = CoalescingEventHandlerProxy(inner, modified_window_seconds=0.05)
    second = CoalescingEventHandlerProxy(inner, modified_window_seconds=0.05)
    try:
        assert first is second
        assert first._worker is second._worker
        assert first.status()["dispatch_sharing_profile"] == "shared_by_inner_v1"
        assert first.status()["shared_reuses"] >= 1

        assert first.dispatch(_event("created", r"C:\\watched-a\\one.exe")) is None
        assert second.dispatch(_event("created", r"C:\\watched-b\\two.exe")) is None
        _wait_count(inner, 2)
        assert [event.src_path for event in inner.events] == [
            r"C:\\watched-a\\one.exe",
            r"C:\\watched-b\\two.exe",
        ]
    finally:
        first.close()


def test_dispatch_diagnostics_attribute_temp_root_and_event(monkeypatch, tmp_path):
    monkeypatch.setenv("TEMP", str(tmp_path))
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner, modified_window_seconds=0.05)
    try:
        path = tmp_path / "diagnostic.exe"
        assert proxy.dispatch(_event("created", str(path))) is None
        _wait_count(inner, 1)

        status = proxy.status()
        assert status["diagnostic_profile"] == "root_event_path_cpu_v2"
        assert status["diagnostic_dominant_bucket"] == "Temp:created"
        assert status["diagnostic_forward_counts"]["Temp:created"] == 1
        assert status["diagnostic_dominant_detail"].startswith("Temp:created|")
        assert proxy._worker.name.startswith("BCS-RealtimeDispatch[Temp:created|")
    finally:
        proxy.close()


def test_dispatch_diagnostics_classify_interactive_user_windows_paths_independent_of_service_identity():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner, modified_window_seconds=0.05)
    try:
        event = _event(
            "deleted",
            r"C:\\Users\\InteractiveUser\\Downloads\\BC_Sentinel_v0_10_0_RC1\\build\\stale.tmp",
        )
        bucket, detail = proxy._diagnostic_identity(event)
        assert bucket == "Downloads:deleted"
        assert detail.startswith("Downloads:deleted|BC_Sentinel_v0_10_0_RC1")
    finally:
        proxy.close()
