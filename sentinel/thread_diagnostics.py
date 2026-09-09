from __future__ import annotations

import re
import threading

PATCH_MARKER = "bc-sentinel-thread-attribution-v1"
_MAX_ROLE_LENGTH = 112


def _clean(value: object) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text.replace("<", "").replace(">", "")


def thread_origin(thread: threading.Thread) -> str:
    """Return a stable role describing an otherwise anonymous Python thread."""
    target = getattr(thread, "_target", None)
    if target is not None:
        module = _clean(getattr(target, "__module__", ""))
        qualname = _clean(getattr(target, "__qualname__", getattr(target, "__name__", "")))
        bound = getattr(target, "__self__", None)
        if bound is not None and (not module or not qualname):
            cls = type(bound)
            module = module or _clean(getattr(cls, "__module__", ""))
            qualname = qualname or (_clean(getattr(cls, "__qualname__", cls.__name__)) + ".run")
        role = ".".join(part for part in (module, qualname) if part)
        if role:
            return role[:_MAX_ROLE_LENGTH]

    cls = type(thread)
    module = _clean(getattr(cls, "__module__", ""))
    qualname = _clean(getattr(cls, "__qualname__", getattr(cls, "__name__", "Thread")))
    role = ".".join(part for part in (module, qualname + ".run") if part)
    return (role or "python-thread")[:_MAX_ROLE_LENGTH]


def install_thread_attribution() -> bool:
    """Name only default Thread-N workers before they start.

    This is diagnostic-only: scheduling, targets, arguments and daemon state are
    untouched. Explicit BC Sentinel/application thread names are preserved.
    """
    cls = threading.Thread
    if getattr(cls, "_bc_sentinel_thread_attribution_marker", "") == PATCH_MARKER:
        return False

    original_start = cls.start

    def start_with_role(self: threading.Thread, *args, **kwargs):
        try:
            name = str(getattr(self, "name", "") or "")
            if name.startswith("Thread-"):
                self.name = "BCS-Auto:" + thread_origin(self)
        except Exception:
            pass
        return original_start(self, *args, **kwargs)

    cls.start = start_with_role
    cls._bc_sentinel_thread_attribution_marker = PATCH_MARKER
    cls._bc_sentinel_original_start = original_start
    return True
