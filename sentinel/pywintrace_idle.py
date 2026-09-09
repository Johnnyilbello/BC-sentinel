from __future__ import annotations

import ctypes as ct
from time import perf_counter

# pywintrace 0.2.0 EventConsumer._run() immediately re-enters ProcessTrace()
# whenever the call returns SUCCESS. On some Windows builds a real-time
# ProcessTrace call can return almost immediately while the session is still
# active, producing a tight loop in each ETW consumer thread. BC Sentinel only
# backs off in that immediate-return case; normally blocking ProcessTrace calls
# are unchanged.
PYWINTRACE_IMMEDIATE_RETURN_SECONDS = 0.005
PYWINTRACE_IDLE_BACKOFF_SECONDS = 0.010
PATCH_MARKER = "bc-sentinel-pywintrace-idle-backoff-v1"


def _process_trace_once(trace_handle):
    from etw import etw as impl

    status = impl.et.ProcessTrace(ct.byref(trace_handle), 1, None, None)
    return status, impl.tdh.ERROR_SUCCESS


def _run_low_cpu(trace_handle, end_capture):
    while True:
        started = perf_counter()
        status, success = _process_trace_once(trace_handle)
        elapsed = perf_counter() - started

        if status != success:
            end_capture.set()

        if end_capture.is_set():
            break

        # Back off only when ProcessTrace returned effectively immediately.
        # Event.wait() keeps shutdown responsive and avoids an unconditional
        # sleep on the normal blocking path.
        if elapsed <= PYWINTRACE_IMMEDIATE_RETURN_SECONDS:
            end_capture.wait(PYWINTRACE_IDLE_BACKOFF_SECONDS)


def install_pywintrace_idle_backoff() -> bool:
    from etw import etw as impl

    consumer = impl.EventConsumer
    if getattr(consumer, "_bc_sentinel_idle_backoff_marker", "") == PATCH_MARKER:
        return False

    consumer._run = staticmethod(_run_low_cpu)
    consumer._bc_sentinel_idle_backoff_marker = PATCH_MARKER
    return True
