from __future__ import annotations

import ctypes as ct

# pywintrace 0.2.0 EventConsumer._run() re-enters ProcessTrace() whenever the
# call returns SUCCESS. For a real-time session ProcessTrace is expected to
# remain blocked while the session is active. On some Windows builds it can
# nevertheless return SUCCESS while the session is still active, causing the
# consumer thread to re-enter immediately and spin.
#
# BC Sentinel therefore applies a bounded, interruptible delay after *every*
# unexpected SUCCESS return while the capture is still active. Normal event
# processing is not delayed: while ProcessTrace is correctly blocking, this
# code is not executing at all.
PYWINTRACE_REENTRY_BACKOFF_SECONDS = 0.050
PATCH_MARKER = "bc-sentinel-pywintrace-idle-backoff-v2"


def _process_trace_once(trace_handle):
    from etw import etw as impl

    status = impl.et.ProcessTrace(ct.byref(trace_handle), 1, None, None)
    return status, impl.tdh.ERROR_SUCCESS


def _run_low_cpu(trace_handle, end_capture):
    while True:
        status, success = _process_trace_once(trace_handle)

        if status != success:
            end_capture.set()

        if end_capture.is_set():
            break

        # A SUCCESS return while the real-time session is still active is an
        # unexpected re-entry condition. Always back off before calling
        # ProcessTrace again. Event.wait() keeps shutdown responsive.
        end_capture.wait(PYWINTRACE_REENTRY_BACKOFF_SECONDS)


def install_pywintrace_idle_backoff() -> bool:
    from etw import etw as impl

    consumer = impl.EventConsumer
    if getattr(consumer, "_bc_sentinel_idle_backoff_marker", "") == PATCH_MARKER:
        return False

    consumer._run = staticmethod(_run_low_cpu)
    consumer._bc_sentinel_idle_backoff_marker = PATCH_MARKER
    return True
