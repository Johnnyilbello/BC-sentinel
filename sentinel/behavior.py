from __future__ import annotations
from dataclasses import dataclass
from .scoring import Signal, assess

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe"}
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}

@dataclass(slots=True)
class ProcessObservation:
    name: str
    parent_name: str
    cmdline: str
    path: str

def assess_process(obs: ProcessObservation):
    name = obs.name.lower()
    parent = obs.parent_name.lower()
    cmd = obs.cmdline.lower()
    path = obs.path.lower()
    signals: list[Signal] = []

    if parent in OFFICE and name in SCRIPT_HOSTS:
        signals.append(Signal("office_script_child", 15, "Un'app Office ha avviato un interprete di script."))
    if parent in BROWSERS and name in SCRIPT_HOSTS:
        signals.append(Signal("browser_script_child", 8, "Un browser ha avviato un interprete di script."))
    if name in {"powershell.exe", "pwsh.exe"} and any(x in cmd for x in (" -enc ", "-encodedcommand", "frombase64string")):
        signals.append(Signal("encoded_powershell", 20, "PowerShell è stato avviato con contenuto codificato."))
    if any(x in cmd for x in ("downloadstring", "invoke-webrequest", "curl ", "certutil -urlcache", "bitsadmin")):
        signals.append(Signal("command_download", 15, "La riga di comando contiene una tecnica di download."))
    if any(x in path for x in ("\\temp\\", "\\appdata\\local\\temp\\")):
        signals.append(Signal("process_from_temp", 10, "Il processo viene eseguito da una cartella temporanea."))
    return assess(signals)
