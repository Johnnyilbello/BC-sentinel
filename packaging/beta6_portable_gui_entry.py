from __future__ import annotations

import json
from pathlib import Path
import sys

from sentinel import home_guided_resolution_window as gui
from sentinel import portable_gui_release as release


CONTRACT_FLAG = "--b67-contract-out"


def main(argv: list[str] | None = None) -> int:
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
