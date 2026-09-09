from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from pathlib import PurePath
import os
import time

from .core.events import SecurityEvent
from .web_protection import WebProtectionEngine, classify_browser_process, normalize_domain

_PARTIAL_EXTENSIONS = (".crdownload", ".part", ".download")
_DOWNLOAD_MARKERS = ("\\downloads\\", "/downloads/")


@dataclass(slots=True, frozen=True)
class BrowserNetworkObservation:
    pid: int
    domain: str
    remote_address: str
    browser_family: str
    process_name: str
    process_path: str
    observed_at: float
    score: int
    status: str
    source: str
    signed_ioc: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class DownloadCorrelation:
    matched: bool = False
    domain: str = ""
    remote_address: str = ""
    browser_family: str = ""
    browser_pid: int = 0
    browser_process_name: str = ""
    browser_process_path: str = ""
    stage: str = ""
    origin_score: int = 0
    origin_status: str = "unknown"
    origin_source: str = ""
    origin_signed_ioc: bool = False
    observed_at: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def is_download_candidate(path: str) -> bool:
    value = str(path or "").strip()
    if not value:
        return False
    folded = value.replace("/", "\\").casefold()
    if any(marker.replace("/", "\\") in folded for marker in _DOWNLOAD_MARKERS):
        return True
    return folded.endswith(_PARTIAL_EXTENSIONS)


def download_stage(path: str) -> str:
    folded = str(path or "").casefold()
    return "partial" if folded.endswith(_PARTIAL_EXTENSIONS) else "materialized"


class BrowserDownloadCorrelation:
    """Bounded browser network -> file correlation for download provenance.

    This engine never marks a file malicious and never performs response actions.
    It only attaches bounded origin evidence to a file event from the same PID.
    """

    def __init__(self, web_engine: WebProtectionEngine, *, window_seconds: float = 45.0, max_events: int = 4096):
        self.web_engine = web_engine
        self.window_seconds = max(5.0, min(float(window_seconds), 180.0))
        self.max_events = max(128, min(int(max_events), 32768))
        self._network = deque(maxlen=self.max_events)

    def observe_network(self, event: SecurityEvent, *, now: float | None = None) -> bool:
        if event.category != "network" or not event.pid:
            return False
        data = dict(event.data or {})
        browser = classify_browser_process(
            event.process_name or "", event.process_path or "", str(data.get("signer") or "")
        )
        if not browser.get("is_browser"):
            return False
        domain = normalize_domain(str(data.get("remote_domain") or ""))
        if not domain:
            return False
        remote = str(data.get("remote_addr") or "")
        assessment = self.web_engine.assess_domain(domain)
        ts = float(time.time() if now is None else now)
        self._network.append(BrowserNetworkObservation(
            pid=int(event.pid), domain=domain, remote_address=remote,
            browser_family=str(browser.get("browser_family") or ""),
            process_name=str(event.process_name or ""), process_path=str(event.process_path or ""),
            observed_at=ts, score=int(assessment.score or 0), status=str(assessment.status or "unknown"),
            source=str(assessment.source or ""), signed_ioc=bool(assessment.signed_ioc),
        ))
        return True

    def correlate_file(self, event: SecurityEvent, *, now: float | None = None) -> DownloadCorrelation:
        if event.category != "file" or not event.pid or not is_download_candidate(event.path):
            return DownloadCorrelation()
        data = dict(event.data or {})
        browser = classify_browser_process(
            event.process_name or "", event.process_path or "", str(data.get("signer") or "")
        )
        if not browser.get("is_browser"):
            return DownloadCorrelation()
        ts = float(time.time() if now is None else now)
        pid = int(event.pid)
        eligible = [
            item for item in reversed(self._network)
            if item.pid == pid and 0 <= ts - float(item.observed_at) <= self.window_seconds
        ]
        if not eligible:
            return DownloadCorrelation()
        # Prefer strongest signed/score evidence; recency breaks ties. This does
        # not change the file verdict—it only chooses the most relevant origin.
        chosen = max(eligible, key=lambda x: (int(bool(x.signed_ioc)), int(x.score), float(x.observed_at)))
        return DownloadCorrelation(
            matched=True, domain=chosen.domain, remote_address=chosen.remote_address,
            browser_family=chosen.browser_family, browser_pid=pid,
            browser_process_name=chosen.process_name, browser_process_path=chosen.process_path,
            stage=download_stage(event.path), origin_score=int(chosen.score), origin_status=chosen.status,
            origin_source=chosen.source, origin_signed_ioc=bool(chosen.signed_ioc), observed_at=chosen.observed_at,
        )

    def status(self) -> dict:
        now = time.time()
        active = [x for x in self._network if now - float(x.observed_at) <= self.window_seconds]
        return {
            "tracking": True,
            "window_seconds": self.window_seconds,
            "recent_browser_connections": len(active),
            "browser_exact_classification": True,
            "origin_only_never_file_malicious": True,
        }
