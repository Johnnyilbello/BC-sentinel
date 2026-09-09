from __future__ import annotations
import os, sys
from pathlib import Path
from .config import APP_ROOT

RUN_KEY=r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME="BC Sentinel"

class StartupManager:
    def command(self,background=True):
        if getattr(sys,"frozen",False):
            cmd=f'"{sys.executable}"'
        else:
            py=Path(sys.executable)
            pythonw=py.with_name("pythonw.exe") if os.name=="nt" else py
            cmd=f'"{pythonw}" "{APP_ROOT/"app"/"main.py"}"'
        return cmd + (" --background" if background else "")

    def enabled(self):
        if os.name!="nt": return False
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,RUN_KEY,0,winreg.KEY_READ) as k:
                value,_=winreg.QueryValueEx(k,VALUE_NAME)
            return bool(value)
        except OSError:
            return False

    def set_enabled(self,enabled):
        if os.name!="nt": return
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,RUN_KEY,0,winreg.KEY_SET_VALUE) as k:
            if enabled:
                winreg.SetValueEx(k,VALUE_NAME,0,winreg.REG_SZ,self.command(True))
            else:
                try: winreg.DeleteValue(k,VALUE_NAME)
                except FileNotFoundError: pass
