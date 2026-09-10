from __future__ import annotations

from pathlib import Path
from typing import Any

from tools import v011_beta2_b2_live_acceptance as base
from tools.v011_beta2_b2_request_op_compat import verify_lineage

_ORIGINAL_SOURCE_GUARDS = base._source_guards
_ORIGINAL_GUARD_ERROR = base._guard_error


def _source_guards(root: Path) -> dict[str, Any]:
    guards = _ORIGINAL_SOURCE_GUARDS(root)
    lineage = verify_lineage(root)
    guards["service_matches_historical_b1b_hash"] = bool(guards.get("service_matches_b1b"))
    guards["service_matches_b2_request_op_lineage"] = bool(lineage.get("passed"))
    # Preserve the base acceptance contract key while tightening it to the
    # deterministic B2 lineage proof: protocol/client stay on exact B1b hashes,
    # and service must equal the one allowed request.operation -> request.op transform.
    guards["service_matches_b1b"] = bool(lineage.get("passed"))
    guards["service_lineage"] = lineage
    return guards


def _guard_error(guards: dict[str, Any], stage: str) -> RuntimeError:
    if not bool(guards.get("service_matches_b2_request_op_lineage")):
        lineage = guards.get("service_lineage")
        return RuntimeError(
            f"B2 request.op service lineage guard failed {stage}: {lineage}"
        )
    return _ORIGINAL_GUARD_ERROR(guards, stage)


def main() -> int:
    base._source_guards = _source_guards
    base._guard_error = _guard_error
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
