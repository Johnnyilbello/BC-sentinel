from __future__ import annotations

"""PyInstaller windowed-runtime compatibility for BC Sentinel Beta11.

PyInstaller windowed applications may expose ``sys.stdout`` / ``sys.stderr`` as
``None``. The canonical desktop entrypoint has diagnostic modes that print JSON,
so bind missing streams to the null device instead of letting diagnostics crash.
This hook does not install, mutate, elevate, access the network, or dispatch any
security action.
"""

import os
import sys


if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")
