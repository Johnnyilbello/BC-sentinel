from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import RLock
from time import time
from uuid import uuid4

from .core.events import SecurityEvent
from .scoring import Signal, assess, level_for

TEMP_HINTS=("\\appdata\\local\\temp\\","\\windows\\temp\\","\\temp\\","/temp/")
BAD_SIG={"notsigned","nottrusted","hashmismatch","unknownerror"}
STRONG_MARKERS=("eicar","yara")

@dataclass(slots=True)
class IncidentTimelineEntry:
    ts: float
    category: str
    action: str
    source: str
    score: int=0
    pid: int|None=None
    path: str=""
    process_name: str=""
    summary: str=""

@dataclass(slots=True)
class IncidentSnapshot:
    incident_id: str
    subject_key: str
    created_ts: float
    updated_ts: float
    status: str="open"
    pid: int|None=None
    ppid: int|None=None
    process_name: str=""
    process_path: str=""
    process_sha256: str=""
    signature_status: str=""
    signer: str=""
    score: int=0
    level: str="SAFE"
    confidence: float=0.0
    categories: list[str]=field(default_factory=list)
    reasons: list[str]=field(default_factory=list)
    timeline: list[IncidentTimelineEntry]=field(default_factory=list)
    recommended_actions: list[str]=field(default_factory=list)
    suppressed: bool=False
    data: dict=field(default_factory=dict)

    def to_dict(self)->dict:
        out=asdict(self)
        out["timeline"]=[asdict(x) for x in self.timeline]
        return out

class IncidentCorrelationEngine:
    """Consolidates explainable telemetry into bounded incidents.

    This layer is advisory only. It never performs response actions; those are
    delegated to ResponseEngine and remain explicit/manual in v0.5 beta.
    """
    def __init__(self,db=None,process_tree=None,*,incident_window_seconds=90.0,max_timeline=80):
        self.db=db
        self.process_tree=process_tree
        self.incident_window_seconds=float(incident_window_seconds)
        self.max_timeline=max(12,int(max_timeline))
        self._active={}
        self._evidence={}
        self._lock=RLock()

    def _subject(self,event:SecurityEvent):
        data=event.data or {}
        create=float(data.get("process_create_time") or data.get("create_time") or 0.0)
        if event.pid and self.process_tree is not None:
            try:
                node=self.process_tree.get(int(event.pid))
                tree_create=float(getattr(node,"create_time",0.0) or 0.0) if node else 0.0
                if tree_create:
                    create=tree_create
            except Exception:
                pass
        if event.pid:
            return f"pid:{int(event.pid)}:{create:.6f}" if create else f"pid:{int(event.pid)}",create
        endpoint=str(data.get("endpoint_indicator") or data.get("remote_addr") or "").casefold()
        if endpoint:return f"network:{endpoint}",0.0
        if event.path:return f"path:{event.path.casefold()}",0.0
        return f"source:{event.category}:{event.source}",0.0

    @staticmethod
    def _strong(event):
        data=event.data or {}
        if str(data.get("endpoint_status") or "").casefold() in {"malicious","blocked"}:return True
        text=" ".join([event.path,event.process_path,event.process_name,*list(event.reasons or [])]).casefold()
        return any(x in text for x in STRONG_MARKERS)

    def _allowlist(self,event):
        if self.db is None or not hasattr(self.db,"allowlist_match"):return None
        data=event.data or {}
        path=event.process_path or event.path or ""
        digest=str(data.get("process_sha256") or data.get("sha256") or "")
        signer=str(data.get("signer") or data.get("publisher") or "")
        if not (path or digest or signer):return None
        try:return self.db.allowlist_match(path,digest or None,signer or None)
        except Exception:return None

    def _signals(self,event,correlation):
        out=[]
        score=max(0,min(100,int(event.score or 0)))
        if score:
            reason=(event.reasons or [f"Segnale {event.category}"])[0]
            out.append(Signal(f"telemetry:{event.category}",score,reason,str(event.source or event.category)))
        delta=int(getattr(correlation,"score_delta",0) or 0) if correlation else 0
        if delta:
            reasons=list(getattr(correlation,"reasons",[]) or [])
            out.append(Signal("behavior:correlation",min(35,delta),reasons[0] if reasons else "Correlazione comportamentale","behavioral_correlation"))
        data=event.data or {}
        endpoint=str(data.get("endpoint_status") or "").casefold()
        if endpoint in {"malicious","blocked"}:
            out.append(Signal("reputation:known-bad-endpoint",70,"Endpoint di rete classificato come malevolo","network_reputation"))
        elif endpoint in {"suspicious","watch"}:
            out.append(Signal("reputation:suspicious-endpoint",28,"Endpoint di rete presente nella watchlist","network_reputation"))
        path=str(event.process_path or event.path or "").casefold()
        sig=str(data.get("signature_status") or "").casefold()
        if any(x in path for x in TEMP_HINTS) and sig in BAD_SIG:
            out.append(Signal("identity:unsigned-temp",18,"Eseguibile non attendibile da percorso temporaneo","process_identity"))
        if event.category=="persistence":
            out.append(Signal("behavior:persistence",16,"Modifica a un meccanismo di persistenza Windows","persistence_monitor"))
        return out

    @staticmethod
    def _recommend(score,confidence,categories):
        actions=["review_process_tree","inspect_timeline"]
        cats=set(categories)
        if "network" in cats:actions.append("inspect_network_endpoint")
        if "persistence" in cats:actions.append("inspect_persistence_change")
        if score>=70:actions.append("quarantine_candidate_if_verified")
        if score>=80 and confidence>=0.72:actions.append("terminate_process_if_identity_matches")
        if score>=85 and "network" in cats:actions.append("contain_network_if_supported")
        return list(dict.fromkeys(actions))

    def _persist(self,incident):
        if self.db is not None and hasattr(self.db,"upsert_incident"):
            try:self.db.upsert_incident(incident.to_dict())
            except Exception:pass

    def ingest(self,event:SecurityEvent,*,correlation=None,ancestry=None):
        now=float(event.ts or time())
        key,create=self._subject(event)
        allow=self._allowlist(event)
        strong=self._strong(event)
        with self._lock:
            incident=self._active.get(key)
            if incident is not None and now-incident.updated_ts>self.incident_window_seconds:
                incident.status="expired"; self._persist(incident); incident=None; self._evidence.pop(key,None)
            if incident is None:
                corr_id=str(getattr(correlation,"incident_id","") or "") if correlation else ""
                incident=IncidentSnapshot(corr_id or f"BCI-{uuid4().hex[:12].upper()}",key,now,now,pid=event.pid,ppid=event.ppid,process_name=event.process_name or "",process_path=event.process_path or "",data={"process_create_time":create} if create else {})
                self._active[key]=incident; self._evidence[key]={}
            evidence=self._evidence.setdefault(key,{})
            for sig in self._signals(event,correlation):
                prev=evidence.get(sig.key)
                if prev is None or int(sig.weight)>int(prev.weight):evidence[sig.key]=sig
            assessment=assess(list(evidence.values()))
            score=int(assessment.score)
            suppressed=bool(allow and not strong)
            if suppressed:score=min(score,49)
            cats=list(dict.fromkeys(incident.categories+([event.category] if event.category else [])))
            corr_reasons=list(getattr(correlation,"reasons",[]) or []) if correlation else []
            reasons=list(dict.fromkeys(incident.reasons+list(assessment.reasons or [])+list(event.reasons or [])+corr_reasons))
            if suppressed:reasons.append(f"Contesto allowlist: {allow.get('kind')}={allow.get('value')}")
            incident.timeline.append(IncidentTimelineEntry(now,event.category,event.action,event.source,int(event.score or 0),event.pid,event.path or "",event.process_name or "",(event.reasons or [event.action or event.category])[0]))
            if len(incident.timeline)>self.max_timeline:del incident.timeline[:-self.max_timeline]
            data=event.data or {}
            incident.updated_ts=now; incident.pid=event.pid or incident.pid; incident.ppid=event.ppid or incident.ppid
            incident.process_name=event.process_name or incident.process_name; incident.process_path=event.process_path or incident.process_path
            incident.process_sha256=str(data.get("process_sha256") or data.get("sha256") or incident.process_sha256)
            incident.signature_status=str(data.get("signature_status") or incident.signature_status)
            incident.signer=str(data.get("signer") or data.get("publisher") or incident.signer)
            incident.score=score; incident.level=level_for(score)
            incident.confidence=round(max(float(assessment.confidence or 0.0),float(getattr(correlation,"confidence",0.0) or 0.0) if correlation else 0.0),3)
            incident.categories=cats; incident.reasons=reasons[:24]; incident.suppressed=suppressed; incident.status="suppressed" if suppressed else "open"
            incident.recommended_actions=self._recommend(score,incident.confidence,cats)
            incident.data.update({"event_count":len(incident.timeline),"evidence_keys":sorted(evidence),"strong_evidence":strong})
            if create:
                incident.data["process_create_time"]=create
            if event.category=="file" and event.path:
                incident.data["file_candidate_path"]=event.path
            if ancestry:
                incident.data["process_chain"]=[{"pid":getattr(n,"pid",None),"ppid":getattr(n,"ppid",None),"name":getattr(n,"name",""),"path":getattr(n,"path","")} for n in ancestry]
            meaningful=score>=50 or len(set(cats))>=3 or strong or suppressed
            if meaningful:self._persist(incident); return incident
            return None
