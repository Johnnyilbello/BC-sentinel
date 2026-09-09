import time

from sentinel.ransomware import (
    RansomwareHeuristic,
    FsEvent,
)


def test_plain_file_burst_is_not_user_alert():
    h = RansomwareHeuristic()
    now = time.time()
    result = None

    for i in range(45):
        result = h.push(FsEvent(now + i * 0.001, "modified", f"x{i}.txt"))

    for i in range(22):
        result = h.push(FsEvent(now + 0.1 + i * 0.001, "renamed", f"r{i}.txt"))

    for i in range(22):
        result = h.push(FsEvent(now + 0.2 + i * 0.001, "deleted", f"d{i}.txt"))

    assert result.score >= 50
    assert result.level == "SUSPICIOUS"
    assert not h.has_strong_signal(result)
    assert not h.should_alert(result)


def test_mass_extension_change_plus_burst_can_alert():
    h = RansomwareHeuristic()
    now = time.time()
    result = None

    for i in range(45):
        result = h.push(FsEvent(now + i * 0.001, "modified", f"x{i}.docx"))

    for i in range(20):
        result = h.push(FsEvent(
            now + 0.1 + i * 0.001,
            "renamed",
            f"x{i}.locked",
            source_path=f"x{i}.docx",
            extension_changed=True,
        ))

    assert h.has_strong_signal(result)
    assert result.score >= 70
    assert h.should_alert(result)


def test_canary_plus_burst_can_alert():
    h = RansomwareHeuristic()
    now = time.time()
    result = h.push(FsEvent(
        now,
        "modified",
        ".bc_sentinel_canary.txt",
        honeypot=True,
    ))

    for i in range(45):
        result = h.push(FsEvent(
            now + 0.1 + i * 0.001,
            "modified",
            f"x{i}.txt",
        ))

    assert h.has_strong_signal(result)
    assert result.score >= 70
    assert h.should_alert(result)
