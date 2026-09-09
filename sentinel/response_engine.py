from __future__ import annotations

from dataclasses import asdict,dataclass,field
import os
from pathlib import Path
from time import time
import psutil

from .path_security import is_reparse_point
from .quarantine import QuarantineManager

CRITICAL={"system","registry","smss.exe","csrss.exe","wininit.exe","winlogon.exe","services.exe","lsass.exe","svchost.exe","dwm.exe"}

@dataclass(slots=True)
class ResponseActionResult:
    action:str
    status:str
    detail:str=""
    incident_id:str=""
    ts:float=field(default_factory=time)
    data:dict=field(default_factory=dict)
    @property
    def succeeded(self):return self.status=="success"
    def to_dict(self):return asdict(self)

class ResponseEngine:
    """Manual-only guarded user-space response foundation for v0.5 beta."""
    def __init__(self,db=None,quarantine=None):
        self.db=db; self.quarantine=quarantine or QuarantineManager(db)
    @staticmethod
    def _v(i,k,d=None):return i.get(k,d) if isinstance(i,dict) else getattr(i,k,d)
    def _audit(self,r):
        if self.db is not None and hasattr(self.db,"record_incident_action"):
            try:self.db.record_incident_action(incident_id=r.incident_id,action=r.action,status=r.status,detail={"message":r.detail,**(r.data or {})})
            except Exception:pass
        return r
    def _deny(self,a,i,msg):return self._audit(ResponseActionResult(a,"blocked",msg,str(self._v(i,"incident_id","") or "")))
    def _allowlisted(self,path,i):
        if not self.db or not hasattr(self.db,"is_allowlisted"):return False
        try:return self.db.is_allowlisted(path,str(self._v(i,"process_sha256","") or "") or None,str(self._v(i,"signer","") or "") or None)
        except Exception:return False
    @staticmethod
    def _protected_windows(path):
        if os.name!="nt" or not path:return False
        windir=os.environ.get("WINDIR") or os.environ.get("SystemRoot") or r"C:\Windows"
        try:
            cand=os.path.normcase(os.path.abspath(path))
            for sub in ("System32","SysWOW64","WinSxS"):
                root=os.path.normcase(os.path.abspath(os.path.join(windir,sub)))
                if os.path.commonpath([cand,root])==root:return True
        except (OSError,ValueError):return True
        return False
    def plan(self,i):
        existing=list(self._v(i,"recommended_actions",[]) or [])
        if existing:return existing
        score=int(self._v(i,"score",0) or 0); conf=float(self._v(i,"confidence",0) or 0)
        out=["review_process_tree","inspect_timeline"]
        if score>=70:out.append("quarantine_candidate_if_verified")
        if score>=80 and conf>=0.72:out.append("terminate_process_if_identity_matches")
        return out
    def terminate_process(self,i,*,approved=False,timeout=2.0):
        a="terminate_process"
        if not approved:return self._deny(a,i,"Explicit operator approval is required.")
        score=int(self._v(i,"score",0) or 0); conf=float(self._v(i,"confidence",0) or 0); pid=int(self._v(i,"pid",0) or 0)
        name=Path(str(self._v(i,"process_name","") or "")).name.casefold(); path=str(self._v(i,"process_path","") or "")
        data=dict(self._v(i,"data",{}) or {}); expected=float(data.get("process_create_time") or 0.0)
        if score<70 or conf<0.60:return self._deny(a,i,"Incident confidence/score is below the manual response gate.")
        if not pid or pid in {0,4,os.getpid()} or name in CRITICAL:return self._deny(a,i,"Protected or invalid process identity.")
        if expected<=0:return self._deny(a,i,"Process generation is unavailable; refusing termination without create-time identity.")
        if path and self._allowlisted(path,i):return self._deny(a,i,"Process matches the BC Sentinel allowlist.")
        if path and self._protected_windows(path):return self._deny(a,i,"Protected Windows system path; v0.5 beta refuses manual termination here.")
        try:
            p=psutil.Process(pid); live=float(p.create_time() or 0.0)
            if expected and abs(live-expected)>0.01:return self._deny(a,i,"PID generation changed; refusing to terminate a reused PID.")
            if (p.name() or "").casefold() in CRITICAL:return self._deny(a,i,"Live process is a protected Windows process.")
            try:live_path=p.exe() or ""
            except (psutil.AccessDenied,psutil.ZombieProcess):live_path=""
            if path and live_path and os.path.normcase(os.path.abspath(live_path))!=os.path.normcase(os.path.abspath(path)):
                return self._deny(a,i,"Live executable path no longer matches the incident identity.")
            p.terminate()
            try:p.wait(timeout=max(.2,float(timeout)))
            except psutil.TimeoutExpired:return self._audit(ResponseActionResult(a,"partial","Terminate signal sent, but process did not exit before timeout; no forced kill was issued.",str(self._v(i,"incident_id","") or ""),data={"pid":pid}))
            return self._audit(ResponseActionResult(a,"success","Process terminated after identity validation.",str(self._v(i,"incident_id","") or ""),data={"pid":pid}))
        except psutil.NoSuchProcess:return self._audit(ResponseActionResult(a,"noop","Process already exited.",str(self._v(i,"incident_id","") or ""),data={"pid":pid}))
        except (psutil.AccessDenied,OSError) as e:return self._audit(ResponseActionResult(a,"failed",f"Process termination failed safely: {e}",str(self._v(i,"incident_id","") or ""),data={"pid":pid}))
    def quarantine_file(self,i,*,candidate_path=None,approved=False):
        a="quarantine_file"
        if not approved:return self._deny(a,i,"Explicit operator approval is required.")
        score=int(self._v(i,"score",0) or 0); data=dict(self._v(i,"data",{}) or {})
        path=str(candidate_path or data.get("file_candidate_path") or self._v(i,"process_path","") or "")
        if score<70:return self._deny(a,i,"Incident score is below the quarantine response gate.")
        if not path:return self._deny(a,i,"No verified file candidate is attached to the incident.")
        if self._allowlisted(path,i):return self._deny(a,i,"File matches the BC Sentinel allowlist.")
        if self._protected_windows(path):return self._deny(a,i,"Protected Windows system path; v0.5 beta refuses quarantine here.")
        p=Path(path)
        try:
            if is_reparse_point(p):return self._deny(a,i,"Refusing to quarantine a symlink/reparse-point candidate.")
            if not p.is_file():return self._deny(a,i,"Quarantine candidate is not a regular existing file.")
            reason="; ".join(list(self._v(i,"reasons",[]) or [])[:3]) or "Correlated incident"
            qid=self.quarantine.quarantine(p,score,reason)
            return self._audit(ResponseActionResult(a,"success","File moved to encrypted BC Sentinel quarantine.",str(self._v(i,"incident_id","") or ""),data={"path":str(p),"quarantine_id":qid}))
        except Exception as e:return self._audit(ResponseActionResult(a,"failed",f"Quarantine failed safely: {e}",str(self._v(i,"incident_id","") or ""),data={"path":path}))
    def contain_network(self,i,*,approved=False):
        a="contain_network"
        if not approved:return self._deny(a,i,"Explicit operator approval is required.")
        return self._audit(ResponseActionResult(a,"unsupported","Network containment is not enabled in v0.5 beta: no firewall rule is created without a hardened privileged service.",str(self._v(i,"incident_id","") or "")))
