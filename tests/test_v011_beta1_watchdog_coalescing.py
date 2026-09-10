from types import SimpleNamespace

from sentinel.watchdog_coalescing import CoalescingEventHandlerProxy


class _Inner:
    def __init__(self):
        self.events = []

    def dispatch(self, event):
        self.events.append(event)
        return "forwarded"


def _event(event_type: str, path: str, *, is_directory: bool = False, dest_path: str = ""):
    return SimpleNamespace(
        event_type=event_type,
        src_path=path,
        dest_path=dest_path,
        is_directory=is_directory,
    )


def test_directory_modified_noise_is_dropped_but_child_security_events_remain_visible():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner, modified_window_seconds=60.0)

    assert proxy.dispatch(_event("modified", r"C:\\watched", is_directory=True)) is None
    assert proxy.directory_modified_dropped == 1
    assert inner.events == []

    for event_type in ("created", "moved", "deleted"):
        result = proxy.dispatch(
            _event(
                event_type,
                rf"C:\\watched\\sample-{event_type}.exe",
                dest_path=rf"C:\\watched\\dest-{event_type}.exe",
            )
        )
        assert result == "forwarded"

    assert [event.event_type for event in inner.events] == ["created", "moved", "deleted"]


def test_repeated_file_modified_notifications_for_same_path_are_coalesced():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner, modified_window_seconds=60.0)

    first = _event("modified", r"C:\\watched\\payload.exe")
    duplicate = _event("modified", r"C:\\watched\\payload.exe")
    other = _event("modified", r"C:\\watched\\other.exe")

    assert proxy.dispatch(first) == "forwarded"
    assert proxy.dispatch(duplicate) is None
    assert proxy.dispatch(other) == "forwarded"
    assert proxy.coalesced == 1
    assert len(inner.events) == 2


def test_zero_modified_window_preserves_every_file_modified_event():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner, modified_window_seconds=0.0)
    event = _event("modified", r"C:\\watched\\rapid-write.exe")

    assert proxy.dispatch(event) == "forwarded"
    assert proxy.dispatch(event) == "forwarded"
    assert proxy.coalesced == 0
    assert len(inner.events) == 2


def test_directory_move_is_not_suppressed():
    inner = _Inner()
    proxy = CoalescingEventHandlerProxy(inner)
    event = _event(
        "moved",
        r"C:\\watched\\folder-a",
        is_directory=True,
        dest_path=r"C:\\watched\\folder-b",
    )

    assert proxy.dispatch(event) == "forwarded"
    assert inner.events == [event]
