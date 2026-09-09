from __future__ import annotations
import ctypes
import ctypes.wintypes as wt
import logging
import os
from time import monotonic, sleep, time

from .core.events import SecurityEvent
from .process_identity import ProcessIdentityResolver
from .web_protection import DNSCorrelationCache, WebProtectionEngine, extract_ip_addresses, normalize_domain

PROCESS_PROVIDER = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
FILE_PROVIDER = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
DNS_PROVIDER = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
DNS_EVENT_IDS = {3006, 3008, 3018, 3020}
# Microsoft-Windows-Kernel-File emits a very high volume of events. Most of
# them (Read/Write/Cleanup/QueryInfo/FSCTL...) do not carry a path that this
# monitor can safely attribute. The File provider therefore runs in its own
# ETW session where the pywintrace 0.2.0-compatible event_id_filters argument
# can safely keep only the path-bearing event families used by this pipeline.
KERNEL_FILE_PATH_EVENT_IDS = frozenset({12, 26, 27, 30})  # Create, DeletePath, RenamePath, CreateNewFile
FILE_EVENT_DEDUP_SECONDS = 0.35
FILE_EVENT_DEDUP_MAX = 4096
DNS_ETW_START_ATTEMPTS = 4
DNS_ETW_START_RETRY_DELAY_SECONDS = 0.25
ETW_DNS_SESSION_MODE = "dedicated"
ETW_SESSION_MODE = "split_process_file_dns"
FILE_WORDS = ("CREATE", "WRITE", "DELETE", "RENAME", "SETINFORMATION")


def etw_provider_event_filters():
    # Retained as a deterministic description for regression/acceptance tests.
    # pywintrace 0.2.0 does not accept providers_event_id_filters on ETW(); the
    # actual runtime filtering is applied as event_id_filters on the isolated
    # Kernel-File session.
    return {FILE_PROVIDER.upper(): sorted(KERNEL_FILE_PATH_EVENT_IDS)}


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
        self._file_capture = None
        self._dns_capture = None
        self._log = logging.getLogger("bc_sentinel.etw")
        self._owns_identity = identity_resolver is None
        self.identity_resolver = identity_resolver or ProcessIdentityResolver()
        self.dns_cache = dns_cache or DNSCorrelationCache()
        self.web_engine = web_engine
        self.dns_tracking = False
        self._recent_file_events = {}

    def status(self):
        return {
            "name": self.name,
            "available": self.available,
            "running": self.running,
            "error": self.error,
            "dns_tracking": bool(self.running and self.dns_tracking),
            "session_mode": ETW_SESSION_MODE,
        }

    @staticmethod
    def _stop_capture(capture):
        if capture is not None:
            try:
                capture.stop()
            except Exception:
                pass

    def start(self):
        if self.running:
            return True
        if os.name != "nt":
            self.error = "ETW disponibile solo su Windows."
            return False
        try:
            import etw
            self.error = ""
            self.dns_tracking = False

            # Process telemetry is intentionally isolated from the high-volume
            # Kernel-File provider. This uses only pywintrace 0.2.0 constructor
            # arguments that are available in the pinned dependency.
            try:
                self._capture = etw.ETW(
                    providers=[
                        etw.ProviderInfo("Microsoft-Windows-Kernel-Process", etw.GUID(PROCESS_PROVIDER)),
                    ],
                    event_callback=self._on_event,
                    callback_wait_time=0.003,
                )
                self._capture.start()
            except Exception as exc:
                self._stop_capture(self._capture)
                self._capture = None
                raise RuntimeError("Process ETW startup failed: " + str(exc))

            # File telemetry has its own session so the legacy-compatible global
            # event_id_filters can restrict only this provider without suppressing
            # Process or DNS event IDs.
            try:
                self._file_capture = etw.ETW(
                    providers=[
                        etw.ProviderInfo("Microsoft-Windows-Kernel-File", etw.GUID(FILE_PROVIDER)),
                    ],
                    event_callback=self._on_event,
                    event_id_filters=sorted(KERNEL_FILE_PATH_EVENT_IDS),
                    callback_wait_time=0.003,
                )
                self._file_capture.start()
            except Exception as exc:
                self._stop_capture(self._file_capture)
                self._file_capture = None
                self._stop_capture(self._capture)
                self._capture = None
                raise RuntimeError("Kernel-File ETW startup failed: " + str(exc))

            self.available = True
            self.running = True
            dns_error = ""
            for dns_attempt in range(DNS_ETW_START_ATTEMPTS):
                try:
                    self._dns_capture = etw.ETW(
                        providers=[
                            etw.ProviderInfo("Microsoft-Windows-DNS-Client", etw.GUID(DNS_PROVIDER)),
                        ],
                        event_callback=self._on_event,
                        callback_wait_time=0.003,
                    )
                    self._dns_capture.start()
                    self.dns_tracking = True
                    self.error = ""
                    return True
                except Exception as exc:
                    dns_error = str(exc)
                    self._stop_capture(self._dns_capture)
                    self._dns_capture = None
                    if dns_attempt + 1 < DNS_ETW_START_ATTEMPTS:
                        sleep(DNS_ETW_START_RETRY_DELAY_SECONDS * (dns_attempt + 1))

            self.dns_tracking = False
            self.error = "DNS ETW dedicated session unavailable after bounded retries: " + dns_error
            return True
        except Exception as exc:
            self._stop_capture(self._dns_capture)
            self._dns_capture = None
            self._stop_capture(self._file_capture)
            self._file_capture = None
            self._stop_capture(self._capture)
            self._capture = None
            self.available = False
            self.running = False
            self.dns_tracking = False
            self.error = str(exc)
            return False

    def stop(self):
        dns = self._dns_capture
        file_capture = self._file_capture
        process_capture = self._capture
        self._dns_capture = None
        self._file_capture = None
        self._capture = None
        self._stop_capture(dns)
        self._stop_capture(file_capture)
        self._stop_capture(process_capture)
        self.available = False
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

    def _is_duplicate_file_event(self, pid, path, task, event_id, *, now=None):
        if not path:
            return False
        now = monotonic() if now is None else float(now)
        key = (int(pid or 0), str(path).casefold(), str(task).upper(), int(event_id or 0))
        previous = self._recent_file_events.get(key)
        self._recent_file_events[key] = now
        if len(self._recent_file_events) > FILE_EVENT_DEDUP_MAX:
            cutoff = now - max(2.0, FILE_EVENT_DEDUP_SECONDS * 4.0)
            self._recent_file_events = {k: ts for k, ts in self._recent_file_events.items() if ts >= cutoff}
            if len(self._recent_file_events) > FILE_EVENT_DEDUP_MAX:
                oldest = sorted(self._recent_file_events.items(), key=lambda item: item[1])[: len(self._recent_file_events) - FILE_EVENT_DEDUP_MAX]
                for old_key, _ in oldest:
                    self._recent_file_events.pop(old_key, None)
        return previous is not None and (now - previous) <= FILE_EVENT_DEDUP_SECONDS

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
            if self._is_duplicate_file_event(pid, path, task, event_id):
                return
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
