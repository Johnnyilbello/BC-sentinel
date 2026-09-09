from __future__ import annotations
import csv,io,json,os,subprocess,threading
from pathlib import Path
from .database import Database
from .core.events import SecurityEvent

def _persistence_score(key,value,action):
    text=f"{key} {value or ''}".casefold()
    score=18 if action=="added" else 12
    reasons=[f"Persistenza Windows {action}: {key}"]

    suspicious_paths=(
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\users\\public\\",
    )
    interpreters=(
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
    )
    if any(x in text for x in suspicious_paths):
        score += 12
        reasons.append("Persistenza collegata a percorso ad alto rischio")
    if any(x in text for x in interpreters):
        score += 10
        reasons.append("Persistenza avvia un interprete o loader sensibile")
    if "-enc " in text or "-encodedcommand" in text:
        score += 12
        reasons.append("Persistenza con comando PowerShell codificato")

    return min(70,score),reasons

RUN_KEYS=[r"Software\Microsoft\Windows\CurrentVersion\Run",r"Software\Microsoft\Windows\CurrentVersion\RunOnce"]

class PersistenceMonitor:
    def __init__(self,db=None,interval=20.0,callback=None):
        self.db=db or Database(); self.interval=interval; self.callback=callback
        self.snapshot={}; self._stop=threading.Event(); self._thread=None

    def start(self):
        if os.name!="nt":return False
        if self._thread and self._thread.is_alive():return True
        self.snapshot=self.collect(); self._stop.clear()
        self._thread=threading.Thread(target=self._run,name="BCS-PersistenceMonitor",daemon=True); self._thread.start(); return True

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():self._thread.join(timeout=3)
        self._thread=None

    def _run(self):
        while not self._stop.wait(self.interval):
            try:self.poll_changes()
            except Exception:pass

    def collect(self):
        if os.name!="nt":return {}
        out={}; out.update(self._registry()); out.update(self._startup()); out.update(self._tasks()); return out

    def _registry(self):
        import winreg
        out={}; views=[0]
        for flag in (getattr(winreg,"KEY_WOW64_64KEY",0),getattr(winreg,"KEY_WOW64_32KEY",0)):
            if flag and flag not in views:views.append(flag)
        for hn,hive in (("HKCU",winreg.HKEY_CURRENT_USER),("HKLM",winreg.HKEY_LOCAL_MACHINE)):
            for kp in RUN_KEYS:
                for view in views:
                    try:
                        with winreg.OpenKey(hive,kp,0,winreg.KEY_READ|view) as key:
                            i=0
                            while True:
                                try:
                                    name,value,_=winreg.EnumValue(key,i); out[f"registry:{hn}:{view}:{kp}:{name}"]=str(value); i+=1
                                except OSError:break
                    except OSError:pass
        return out

    def _startup(self):
        out={}; candidates=[]
        if os.getenv("APPDATA"):candidates.append(Path(os.getenv("APPDATA"))/"Microsoft/Windows/Start Menu/Programs/Startup")
        if os.getenv("PROGRAMDATA"):candidates.append(Path(os.getenv("PROGRAMDATA"))/"Microsoft/Windows/Start Menu/Programs/Startup")
        for folder in candidates:
            try:
                for item in folder.iterdir():
                    if item.is_file():
                        st=item.stat(); out[f"startup:{item}"]=f"{st.st_size}:{st.st_mtime_ns}"
            except OSError:pass
        return out

    def _tasks(self):
        flags=getattr(subprocess,"CREATE_NO_WINDOW",0)
        try:
            p=subprocess.run(["schtasks.exe","/Query","/FO","CSV","/V"],capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=10,creationflags=flags,check=False)
            if p.returncode!=0:return {}
            out={}
            for row in csv.DictReader(io.StringIO(p.stdout)):
                name=row.get("TaskName") or row.get("Nome attività") or row.get("Task Name") or ""
                command=row.get("Task To Run") or row.get("Attività da eseguire") or row.get("Actions") or ""
                if name:out[f"task:{name}"]=command
            return out
        except Exception:return {}

    def poll_changes(self):
        current=self.collect(); changes=[]
        for key in set(self.snapshot)|set(current):
            old=self.snapshot.get(key); new=current.get(key)
            if old==new:continue
            action="added" if old is None else ("removed" if new is None else "changed")
            detail={"action":action,"value":new if new is not None else old or "","previous":old}
            score,reasons=_persistence_score(key,detail["value"],action)
            self.db.execute(
                "INSERT INTO behavior_events(category,source,detail_json,score) VALUES(?,?,?,?)",
                ("persistence",key,json.dumps(detail),score),
            )
            event=SecurityEvent(
                category="persistence",
                action=action,
                source="persistence_monitor",
                score=score,
                path=key,
                reasons=reasons,
                data=detail,
            )
            changes.append(event)
            if self.callback:self.callback(event)
        self.snapshot=current; return changes
