from __future__ import annotations

import socket
import threading
from time import time

from .core.events import SecurityEvent
from .network_intelligence import NetworkReputationEngine
from .web_protection import DNSCorrelationCache, WebProtectionEngine, classify_browser_process


class NetworkMonitor:
    """Read-only, user-space process→connection telemetry.

    It never blocks traffic and never changes Windows Firewall rules. v0.4
    enriches events with process identity when available and local endpoint
    reputation while keeping collection non-blocking.
    """

    def __init__(
        self,
        callback=None,
        interval=2.0,
        *,
        process_tree=None,
        identity_resolver=None,
        intelligence: NetworkReputationEngine | None = None,
        dns_cache: DNSCorrelationCache | None = None,
        web_engine: WebProtectionEngine | None = None,
    ):
        self.callback=callback
        self.interval=max(1.0,float(interval))
        self.process_tree=process_tree
        self.identity_resolver=identity_resolver
        self.intelligence=intelligence
        self.dns_cache=dns_cache
        self.web_engine=web_engine
        self._stop=threading.Event()
        self._thread=None
        self._seen={}
        self.running=False

    def start(self):
        if self._thread and self._thread.is_alive():
            return True
        self._stop.clear()
        self._thread=threading.Thread(
            target=self._run,
            name="BCS-NetworkMonitor",
            daemon=True,
        )
        self._thread.start()
        self.running=True
        return True

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._thread=None
        self.running=False

    @staticmethod
    def _addr(value):
        if not value:
            return "","",0
        try:
            host=str(value.ip)
            port=int(value.port)
        except AttributeError:
            host=str(value[0])
            port=int(value[1])
        return f"{host}:{port}",host,port

    def _enrich_tree_identity(self, pid: int, path: str, create_time: float) -> None:
        if not path or self.identity_resolver is None or self.process_tree is None:
            return
        try:
            future=self.identity_resolver.submit(path)
        except Exception:
            return

        def done(fut):
            try:
                identity=fut.result()
                self.process_tree.enrich_identity(
                    pid,
                    create_time=create_time,
                    sha256=identity.sha256,
                    signature_status=identity.signature_status,
                    signer=identity.signer,
                    path=identity.path or path,
                )
            except Exception:
                return
        future.add_done_callback(done)

    def _process_context(self, psutil, pid: int):
        process_name=""
        process_path=""
        ppid=None
        create_time=0.0
        cmdline=""
        sha256=""
        signature_status=""
        signer=""

        try:
            proc=psutil.Process(int(pid))
            process_name=proc.name() or ""
            process_path=proc.exe() or ""
            ppid=proc.ppid()
            try:
                create_time=float(proc.create_time() or 0.0)
            except Exception:
                create_time=0.0
            try:
                cmdline=" ".join(proc.cmdline() or [])
            except Exception:
                cmdline=""
        except Exception:
            proc=None

        node=self.process_tree.get(pid) if self.process_tree is not None else None
        if node is not None and (not create_time or not node.create_time or abs(node.create_time-create_time)<=0.001):
            process_name=node.name or process_name
            process_path=node.path or process_path
            ppid=node.ppid or ppid
            cmdline=node.cmdline or cmdline
            sha256=node.sha256 or ""
            signature_status=node.signature_status or ""
            signer=node.signer or ""
        elif self.process_tree is not None:
            self.process_tree.observe(
                pid,
                ppid or 0,
                process_name,
                process_path,
                cmdline=cmdline,
                create_time=create_time,
            )

        if process_path and not sha256:
            self._enrich_tree_identity(pid, process_path, create_time)

        return {
            "process_name":process_name,
            "process_path":process_path,
            "ppid":int(ppid) if ppid else None,
            "create_time":create_time,
            "cmdline":cmdline,
            "process_sha256":sha256,
            "signature_status":signature_status,
            "signer":signer,
        }

    def _build_event(self, *, pid, local_text, remote_host, remote_port, remote_text, protocol, state, context):
        remote_domain = ""
        dns_context = None
        if self.dns_cache is not None:
            try:
                dns_context = self.dns_cache.lookup_context(pid, remote_host)
                remote_domain = dns_context.domain
            except Exception:
                dns_context = None
                remote_domain = ""
        browser_context = classify_browser_process(
            context.get("process_name") or "", context.get("process_path") or "", context.get("signer") or ""
        )
        data={
            "local_addr":local_text,
            "remote_addr":remote_host,
            "remote_domain":remote_domain,
            "dns_correlated": bool(remote_domain),
            "dns_shared_ip": bool(getattr(dns_context, "shared_ip", False)),
            "dns_domain_count": int(getattr(dns_context, "domain_count", 0) or 0),
            "dns_pid_count": int(getattr(dns_context, "pid_count", 0) or 0),
            "dns_domains": list(getattr(dns_context, "domains", ()) or ()),
            "remote_port":remote_port,
            "protocol":protocol,
            "state":state,
            "create_time":context.get("create_time") or 0.0,
            "cmdline":context.get("cmdline") or "",
            "process_sha256":context.get("process_sha256") or "",
            "signature_status":context.get("signature_status") or "",
            "signer":context.get("signer") or "",
            "is_browser": bool(browser_context.get("is_browser")),
            "browser_family": str(browser_context.get("browser_family") or ""),
            "browser_executable": str(browser_context.get("browser_executable") or ""),
        }
        event=SecurityEvent(
            category="network",
            action="connect",
            source="psutil_network",
            score=0,
            path=remote_text,
            pid=int(pid),
            ppid=context.get("ppid"),
            process_name=context.get("process_name") or "",
            process_path=context.get("process_path") or "",
            reasons=[],
            data=data,
        )

        if self.intelligence is not None:
            try:
                result=self.intelligence.assess_event(event)
                event.score=min(100,int(event.score or 0)+int(result.score_delta or 0))
                event.reasons=list(dict.fromkeys((event.reasons or [])+(result.reasons or [])))
                event.data.update({
                    "endpoint_indicator":result.indicator,
                    "endpoint_kind":result.kind,
                    "endpoint_class":result.address_class,
                    "endpoint_status":result.status,
                    "endpoint_source":result.source,
                    "endpoint_confidence":result.confidence,
                    "endpoint_first_seen":result.first_seen,
                    "endpoint_connection_count":result.connection_count,
                    "endpoint_process_count":result.process_count,
                })
            except Exception:
                pass

        if self.web_engine is not None and (remote_domain or remote_host):
            try:
                web = self.web_engine.assess_connection(
                    domain=remote_domain,
                    address=remote_host,
                    shared_ip=bool(getattr(dns_context, "shared_ip", False)),
                    domain_count=int(getattr(dns_context, "domain_count", 0) or 0),
                    pid_count=int(getattr(dns_context, "pid_count", 0) or 0),
                )
                if int(web.score or 0) > int(event.score or 0):
                    event.score = int(web.score)
                event.reasons = list(dict.fromkeys((event.reasons or []) + list(web.reasons or [])))
                event.data.update({
                    "web_status": web.status,
                    "web_source": web.source,
                    "web_level": web.level,
                    "web_decision": web.decision,
                    "web_signed_ioc": bool(web.signed_ioc),
                    "web_block_recommended": bool(web.block_recommended),
                    "web_shared_ip_guard": bool(getattr(dns_context, "shared_ip", False)),
                })
            except Exception:
                pass
        return event

    def _run(self):
        try:
            import psutil
        except ImportError:
            self.running=False
            return

        while not self._stop.wait(self.interval):
            now=time()
            current=set()

            try:
                connections=psutil.net_connections(kind="inet")
            except Exception:
                continue

            for conn in connections:
                if self._stop.is_set():
                    break
                try:
                    if not conn.raddr or not conn.pid:
                        continue
                    if conn.type not in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
                        continue

                    local_text,_,_=self._addr(conn.laddr)
                    remote_text,remote_host,remote_port=self._addr(conn.raddr)
                    protocol="TCP" if conn.type==socket.SOCK_STREAM else "UDP"
                    state=str(conn.status or "")

                    key=(int(conn.pid),local_text,remote_text,protocol)
                    current.add(key)

                    if key in self._seen:
                        self._seen[key]=now
                        continue

                    self._seen[key]=now
                    context=self._process_context(psutil,int(conn.pid))
                    event=self._build_event(
                        pid=int(conn.pid),
                        local_text=local_text,
                        remote_host=remote_host,
                        remote_port=remote_port,
                        remote_text=remote_text,
                        protocol=protocol,
                        state=state,
                        context=context,
                    )
                    if self.callback:
                        self.callback(event)
                except Exception:
                    continue

            cutoff=now-30.0
            for key,seen in list(self._seen.items()):
                if seen<cutoff and key not in current:
                    self._seen.pop(key,None)
