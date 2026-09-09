from __future__ import annotations
from pathlib import Path
from .config import APP_ROOT, Settings
from .scanner import StaticScanner

class SelfIntegrityScanner:
    """Explicit scanner for BC Sentinel's own files.

    Normal scans exclude APP_ROOT to avoid signature self-detection.
    This mode disables that exclusion and is intentionally separate.
    """
    def __init__(self):
        settings = Settings.defaults()
        settings.exclude_self = False
        self.scanner = StaticScanner(settings)

    def scan(self):
        yield from self.scanner.scan_paths([APP_ROOT])
