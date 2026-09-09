from __future__ import annotations
import os, logging

class WindowsNotifier:
    def __init__(self,fallback=None):
        self.fallback=fallback
        self._toaster=None
        self._log=logging.getLogger("bc_sentinel.notifications")
        if os.name=="nt":
            try:
                from windows_toasts import WindowsToaster
                self._toaster=WindowsToaster("BC Sentinel")
            except Exception:
                pass

    @property
    def native_available(self):
        return self._toaster is not None

    def notify(self,title,message,*,level="info"):
        if self._toaster is not None:
            try:
                from windows_toasts import Toast
                toast=Toast(); toast.text_fields=[title,message]
                self._toaster.show_toast(toast)
                return True
            except Exception:
                self._log.exception("Native toast failed")
        if self.fallback:
            try:
                self.fallback(title,message,level); return True
            except Exception:
                pass
        return False
