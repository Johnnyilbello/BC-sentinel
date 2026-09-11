from __future__ import annotations

import json
import sys
from typing import Callable, Final

from sentinel import rescue_console as b40
from sentinel import rescue_console_guided_scan as b41
from sentinel import rescue_console_guided_repair as b42
from sentinel import rescue_console_guided_data_rescue as b43
from sentinel import rescue_console_integrated_certification as b44

PROFILE: Final[str] = "v0.11.0-beta.4-b45"
SCHEMA: Final[str] = "bc-sentinel-beta4-portable-rescue-console-v1"

COMMANDS: Final[dict[str, Callable[[list[str] | None], int]]] = {
    "plan": b40.main,
    "scan": b41.main,
    "repair-handoff": b42.main,
    "data-rescue": b43.main,
    "certify": b44.main,
}


def status_payload() -> dict:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "portable": True,
        "installer_required": False,
        "service_install": False,
        "driver_install": False,
        "network_required": False,
        "cloud_required": False,
        "commands": list(COMMANDS.keys()),
        "safety": {
            "automatic_repair": False,
            "automatic_quarantine": False,
            "automatic_destructive_action": False,
            "repair_execution_exposed_by_console": False,
            "repair_handoff_only": True,
            "explicit_data_rescue_execution_required": True,
            "certification_outcomes_preserved": [
                "RECOVERED",
                "NOT_RECOVERED",
                "INDETERMINATE_REFUSED",
            ],
            "format_or_reimage_suppressed": False,
        },
        "component_profiles": {
            "plan": b40.PROFILE,
            "scan": b41.PROFILE,
            "repair_handoff": b42.PROFILE,
            "data_rescue": b43.PROFILE,
            "certification": b44.PROFILE,
        },
    }


def _usage_error(reason: str) -> int:
    print(json.dumps({
        "passed": False,
        "profile": PROFILE,
        "stage": "portable_dispatch",
        "reason": reason,
        "available_commands": ["status", *COMMANDS.keys()],
    }, indent=2))
    return 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return _usage_error("command_required")

    command, rest = args[0], args[1:]
    if command == "status":
        if rest:
            return _usage_error("status_takes_no_arguments")
        print(json.dumps({"passed": True, **status_payload()}, indent=2, sort_keys=True))
        return 0

    handler = COMMANDS.get(command)
    if handler is None:
        return _usage_error(f"unknown_command:{command}")
    return int(handler(rest))


if __name__ == "__main__":
    raise SystemExit(main())
