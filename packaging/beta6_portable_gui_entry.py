from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from sentinel import home_guided_resolution_window as gui
from sentinel import portable_gui_release as release


CONTRACT_FLAG = "--b67-contract-out"
_NULL_STREAM = None


def _ensure_windowed_streams() -> None:
    """PyInstaller --windowed can expose stdout/stderr as None on Windows.

    Beta6 self-check/offscreen-smoke paths contain bounded diagnostic prints.
    Redirect those writes to the null device rather than letting a noconsole
    artifact fail only because no console stream exists.
    """

    global _NULL_STREAM
    if sys.stdout is not None and sys.stderr is not None:
        return
    if _NULL_STREAM is None:
        _NULL_STREAM = open(os.devnull, "w", encoding="utf-8")
    if sys.stdout is None:
        sys.stdout = _NULL_STREAM
    if sys.stderr is None:
        sys.stderr = _NULL_STREAM


def main(argv: list[str] | None = None) -> int:
    _ensure_windowed_streams()
    args = list(sys.argv[1:] if argv is None else argv)
    if CONTRACT_FLAG in args:
        index = args.index(CONTRACT_FLAG)
        if index + 1 >= len(args):
            return 2
        output = Path(args[index + 1])
        payload = release.runtime_contract()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return 0 if payload.get("passed") is True else 4

    return gui.main(args)


if __name__ == "__main__":
    raise SystemExit(main())
