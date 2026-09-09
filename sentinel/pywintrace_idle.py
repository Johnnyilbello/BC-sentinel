from __future__ import annotations

import ctypes as ct
import threading
from time import monotonic

# pywintrace 0.2.0 EventConsumer._run() re-enters ProcessTrace() whenever the
# call returns SUCCESS. For a real-time session ProcessTrace is expected to
# remain blocked while the session is active. On some Windows builds it can
# nevertheless return SUCCESS while the session is still active, causing the
# consumer thread to re-enter immediately and spin.
#
# BC Sentinel therefore applies an interruptible adaptive delay after every
# unexpected SUCCESS return while the capture is still active. Normal event
# processing is not delayed: while ProcessTrace is correctly blocking, this
# code is not executing at all. Repeated short SUCCESS returns progressively
# increase the delay, while a healthy blocking call resets the backoff.
PYWINTRACE_REENTRY_BACKOFF_SECONDS = 0.050
PYWINTRACE_REENTRY_MAX_BACKOFF_SECONDS = 0.400
PYWINTRACE_REENTRY_HEALTHY_BLOCK_SECONDS = 0.500
PATCH_MARKER = "bc-sentinel-pywintrace-idle-backoff-v3-adaptive"


def _process_trace_once(trace_handle):
    from etw import etw as impl

    status = impl.et.ProcessTrace(ct.byref(trace_handle), 1, None, None)
    return status, impl.tdh.ERROR_SUCCESS


def _adaptive_reentry_backoff(streak: int, process_trace_elapsed: float) -> tuple[int, float]:
    """Return the next re-entry streak and wait duration.

    A ProcessTrace call that remained blocked for a meaningful interval is
    treated as healthy activity and resets the escalation. Consecutive short
    SUCCESS returns are the pathological case and receive exponential backoff.
    """
    if float(process_trace_elapsed) >= PYWINTRACE_REENTRY_HEALTHY_BLOCK_SECONDS:
        streak = 1
    else:
        streak = max(1, int(streak) + 1)

    delay = min(
        PYWINTRACE_REENTRY_BACKOFF_SECONDS * (2 ** min(streak - 1, 3)),
        PYWINTRACE_REENTRY_MAX_BACKOFF_SECONDS,
    )
    return streak, float(delay)


def _run_low_cpu(trace_handle, end_capture):
    # Make the native consumer visible in service diagnostics/benchmarks instead
    # of leaving it as the opaque default "Thread-N" name.
    current = threading.current_thread()
    if not str(current.name or "").startswith("BCS-ETW-"):
        current.name = "BCS-ETW-ProcessTrace"

    reentry_streak = 0
    while True:
        started = monotonic()
        status, success = _process_trace_once(trace_handle)
        elapsed = max(0.0, monotonic() - started)

        if status != success:
            end_capture.set()

        if end_capture.is_set():
            break

        reentry_streak, delay = _adaptive_reentry_backoff(reentry_streak, elapsed)
        # Event.wait() keeps service shutdown responsive even at maximum backoff.
        end_capture.wait(delay)


def install_pywintrace_idle_backoff() -> bool:
    from etw import etw as impl

    consumer = impl.EventConsumer
    if getattr(consumer, "_bc_sentinel_idle_backoff_marker", "") == PATCH_MARKER:
        return False

    consumer._run = staticmethod(_run_low_cpu)
    consumer._bc_sentinel_idle_backoff_marker = PATCH_MARKER
    return True
