from __future__ import annotations
from dataclasses import dataclass, field, asdict
from time import time
from typing import Any

@dataclass(slots=True)
class ProcessAttribution:
    pid: int | None = None
    ppid: int | None = None
    name: str = ""
    path: str = ""
    cmdline: str = ""
    sha256: str = ""
    signature_status: str = ""
    signer: str = ""
    create_time: float = 0.0
    source: str = "unknown"
    confidence: float = 0.0
    observed_ts: float = 0.0

    @property
    def available(self) -> bool:
        return bool(self.pid or self.name or self.path)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True)
class SecurityEvent:
    category: str
    action: str
    source: str
    score: int = 0
    path: str = ""
    pid: int | None = None
    ppid: int | None = None
    process_name: str = ""
    process_path: str = ""
    reasons: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
