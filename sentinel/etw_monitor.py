from __future__ import annotations
import ctypes
import ctypes.wintypes as wt
import logging
import os
from time import time

from .core.events import SecurityEvent
from .process_identity import ProcessIdentityResolver
from .web_protection import DNSCorrelationCache, WebProtectionEngine, extract_ip_addresses, normalize_domain

PROCESS_PROVIDER = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
FILE_PROVIDER = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
DNS_PROVIDER = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
DNS_EVENT_IDS = {3006, 3008, 3018, 3020}
FILE_WORDS = ("CREATE", "WRITE", "DELETE", "RENAME", "SETINFORMATION")


def _first(data, *names):
    lower = {str(k).casefold(): v for k, v in data.items()}
    for name in names:
        v = data.get(name, lower.get(name.casefold()))
        if v not in (None, ""):
            return v
    return None


def normalize_etw_event(event):
    if isinstance(event, tuple) and len(event) >= 2 and isinstance(event[1], dict):
        d = dict(event[1])
        d.setdefault("_provider", str(event[0]))
        return d
    return dict(event) if isinstance(event, dict) else {}


def owner_pid_for_thread(thread_id):
    if os.name != "nt" or not thread_id:
        return None
    TH32CS_SNAPTHREAD = 0x4

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
            ("th32ThreadID", wt.DWORD), ("th32OwnerProcessID", wt.DWORD),
            ("tpBasePri", wt.LONG), ("tpDeltaPri", wt.LONG), ("dwFlags", wt.DWORD),
        ]

    k = ctypes.windll.kernel32
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        ok = k.Thread32First(snap, ctypes.byref(entry))
        while ok:
            if int(entry.th32ThreadID) == int(thread_id):
                return int(entry.th32OwnerProcessID)
            ok = k.Thread32Next(snap, ctypes.byref(entry))
    finally:
        k.CloseHandle(snap)
    return None


class ETWMonitor:
    name = "pywintrace-etw"

    def __init__(self, process_tree, correlator, event_callback=None, identity_resolver=None, *, dns_cache=None, web_engine=None):
        self.process_tree = process_tree
        self.correlator = correlator
        self.event_callback = event_callback
        self.available = False
        self.running = False
        self.error = ""
        self._capture = None
        self._log = logging.getLogger("bc_sentinel.etw")
        self._owns_identity = identity_resolver is None
        self.identity_resolver = identity_resolver or ProcessIdentityResolver()
        self.dns_cache = dns_cache or DNSCorrelationCache()
        self.web_engine = web_engine
        self.dns_tracking = False

    def status(self):
        return {"name": self.name, "available": self.available, "running": self.running, "error": self.error, "dns_tracking": bool(self.running and self.dns_tracking)}

    def start(self):
        if self.running:
            return True
        if os.name != "nt":
            self.error = "ETW disponibile solo su Windows."
            return False
        try:
            import etw
            base_providers = [
                etw.ProviderInfo("Microsoft-Windows-Kernel-Process", etw.GUID(PROCESS_PROVIDER)),
                etw.ProviderInfo("Microsoft-Windows-Kernel-File", etw.GUID(FILE_PROVIDER)),
            ]
            dns_provider = etw.ProviderInfo("Microsoft-Windows-DNS-Client", etw.GUID(DNS_PROVIDER))
            last_error = ""
            for providers, dns_tracking in ((base_providers + [dns_provider], True), (base_providers, False)):
                try:
                    self._capture = etw.ETW(
                        providers=providers,
                        event_callback=self._on_event,
                        callback_wait_time=0.003,
                    )
                    self._capture.start()
                    self.available = True
                    self.running = True
                    self.dns_tracking = dns_tracking
                    self.error = last_error if not dns_tracking else ""
                    return True
                except Exception as exc:
                    last_error = str(exc)
                    if self._capture is not None:
                        try:
                            self._capture.stop()
                        except Exception:
                            pass
                    self._capture = None
            raise RuntimeError(last_error or "ETW provider startup failed")
        except Exception as exc:
            self.available = False
            self.running = False
            self.dns_tracking = False
            self.error = str(exc)
            return False

    def stop(self):
        c = self._capture
        self._capture = None
        if c:
            try:
                c.stop()
            except Exception:
                pass
        self.running = False
        self.dns_tracking = False

    def close(self):
        self.stop()
        if self._owns_identity:
            self.identity_resolver.shutdown(wait=False)

    def _enrich(self, pid):
        if not pid:
            return "", "", "", 0, 0.0
        try:
            import psutil
            p = psutil.Process(int(pid))
            return (
                p.name() or "",
                p.exe() or "",
                " ".join(p.cmdline() or []),
                p.ppid(),
                float(p.create_time() or 0.0),
            )
        except Exception:
            n = self.process_tree.get(pid)
            return (
                (n.name, n.path, n.cmdline, n.ppid, n.create_time)
                if n else ("", "", "", 0, 0.0)
            )

    def _schedule_identity(self, node):
        if node is None or not node.path:
            return
        pid = node.pid
        create_time = node.create_time
        future = self.identity_resolver.submit(node.path)

        def done(fut):
            try:
                identity = fut.result()
            except Exception:
                return
            self.process_tree.enrich_identity(
                pid,
                create_time=create_time,
                sha256=identity.sha256,
                signature_status=identity.signature_status,
                signer=identity.signer,
                path=identity.path,
            )

        future.add_done_callback(done)

    def _ensure_process_node(self, pid, *, fallback_image="", fallback_cmd="", fallback_ppid=0):
        if not pid:
            return None
        existing = self.process_tree.get(pid)
        name, path, cmd, ppid, created = self._enrich(pid)
        node = self.process_tree.observe(
            pid,
            fallback_ppid or ppid,
            name or fallback_image,
            path or fallback_image,
            fallback_cmd or cmd,
            create_time=created,
        )
        if existing is None or (not node.sha256 and node.path):
            self._schedule_identity(node)
        return node

    def _on_event(self, event):
        d = normalize_etw_event(event)
        if not d:
            return
        task = str(_first(d, "Task Name", "TaskName", "EventName") or "").upper()
        provider = str(_first(d, "_provider", "Provider Name", "ProviderName") or "")
        pid_raw = _first(d, "ProcessId", "ProcessID", "Process ID", "PID")
        tid_raw = _first(d, "ThreadId", "ThreadID", "Thread ID", "IssuingThreadId")
        try:
            pid = int(pid_raw) if pid_raw not in (None, "") else None
        except Exception:
            pid = None
        try:
            tid = int(tid_raw) if tid_raw not in (None, "") else None
        except Exception:
            tid = None
        if pid is None and tid:
            pid = owner_pid_for_thread(tid)

        if "PROCESS" in task and any(word in task for word in ("START", "DCSTART")):
            ppid_raw = _first(d, "ParentProcessId", "ParentProcessID", "PPID")
            try:
                ppid = int(ppid_raw or 0)
            except Exception:
                ppid = 0
            image = str(_first(d, "ImageName", "ImageFileName", "ProcessName") or "")
            cmd = str(_first(d, "CommandLine", "CmdLine") or "")
            node = self._ensure_process_node(pid, fallback_image=image, fallback_cmd=cmd, fallback_ppid=ppid)
            if node:
                self._emit(SecurityEvent(
                    category="process", action="start", source="etw",
                    pid=node.pid, ppid=node.ppid, path=node.path,
                    process_name=node.name, process_path=node.path,
                    data={
                        "cmdline": node.cmdline,
                        "create_time": node.create_time,
                        "sha256": node.sha256,
                        "signature_status": node.signature_status,
                        "signer": node.signer,
                    },
                ))
            return

        if "PROCESS" in task and any(word in task for word in ("STOP", "END", "DCSTOP")):
            if pid:
                self.process_tree.mark_exit(pid)
                self._emit(SecurityEvent(category="process", action="stop", source="etw", pid=pid))
            return

        event_id_raw = _first(d, "EventId", "EventID", "Id", "ID")
        try:
            event_id = int(event_id_raw) if event_id_raw not in (None, "") else 0
        except Exception:
            event_id = 0
        query_name = str(_first(d, "QueryName", "Name") or "").strip()
        provider_upper = provider.upper()
        dns_guid = DNS_PROVIDER.strip("{}").upper()
        is_dns_provider = "DNS-CLIENT" in provider_upper or dns_guid in provider_upper
        if query_name and is_dns_provider and (event_id in DNS_EVENT_IDS or "QUERY" in task or event_id == 0):
            normalized = normalize_domain(query_name)
            if normalized:
                node = self._ensure_process_node(pid) if pid else None
                results_raw = _first(d, "QueryResults", "Results", "Addresses")
                addresses = extract_ip_addresses(results_raw)
                if addresses and pid:
                    self.dns_cache.observe(pid, normalized, addresses)
                assessment = self.web_engine.assess_domain(normalized) if self.web_engine is not None else None
                query_status = _first(d, "QueryStatus", "Status")
                data = {
                    "remote_domain": normalized,
                    "query_type": str(_first(d, "QueryType", "Type") or ""),
                    "query_status": str(query_status if query_status is not None else ""),
                    "resolved_addresses": addresses,
                    "dns_event_id": event_id,
                    "dns_pid_scoped": bool(pid),
                }
                score = 0
                reasons = []
                if assessment is not None:
                    score = int(assessment.score)
                    reasons = list(assessment.reasons)
                    data.update({
                        "web_status": assessment.status,
                        "web_source": assessment.source,
                        "web_level": assessment.level,
                        "web_decision": assessment.decision,
                        "web_signed_ioc": assessment.signed_ioc,
                        "web_block_recommended": assessment.block_recommended,
                    })
                self._emit(SecurityEvent(
                    category="web",
                    action="dns_resolved" if addresses else "dns_query",
                    source="etw_dns",
                    score=score,
                    path=normalized,
                    pid=int(pid) if pid else None,
                    ppid=node.ppid if node else None,
                    process_name=node.name if node else "",
                    process_path=node.path if node else "",
                    reasons=reasons,
                    data=data,
                ))
            return

        path = str(_first(d, "FileName", "FilePath", "OpenPath", "Path") or "")
        if path and ("KERNEL-FILE" in provider.upper() or any(w in task for w in FILE_WORDS)):
            node = self._ensure_process_node(pid)
            if node:
                name, proc_path, cmd, ppid, created = node.name, node.path, node.cmdline, node.ppid, node.create_time
                sha256, signature_status, signer = node.sha256, node.signature_status, node.signer
            else:
                name, proc_path, cmd, ppid, created = "", "", "", 0, 0.0
                sha256, signature_status, signer = "", "", ""

            self.correlator.record(
                path, pid, name, proc_path, task.lower(), time(),
                ppid=ppid, cmdline=cmd, sha256=sha256,
                signature_status=signature_status, signer=signer,
                create_time=created,
            )
            self._emit(SecurityEvent(
                category="file", action=task.lower() or "io", source="etw",
                path=path, pid=pid, ppid=ppid, process_name=name, process_path=proc_path,
                data={
                    "thread_id": tid, "task": task, "cmdline": cmd,
                    "process_sha256": sha256, "signature_status": signature_status,
                    "signer": signer, "create_time": created,
                },
            ))

    def _emit(self, event):
        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                self._log.exception("ETW event callback failed")
