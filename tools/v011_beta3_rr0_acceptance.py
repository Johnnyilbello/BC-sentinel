from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.rescue_contract import (
    PROFILE,
    RescueCapability,
    RescueExecutionContext,
    RescueSafetyPolicy,
    allowed_capabilities,
    can_certify_recovery,
    rr0_contract_snapshot,
)


def run() -> dict:
    policy = RescueSafetyPolicy()
    policy.validate()

    compromised = allowed_capabilities(RescueExecutionContext.COMPROMISED_WINDOWS)
    external = allowed_capabilities(RescueExecutionContext.TRUSTED_EXTERNAL_MEDIA)
    offline = allowed_capabilities(RescueExecutionContext.OFFLINE_IMAGE)

    checks = {
        "read_only_default": policy.read_only_default is True,
        "no_destructive_actions": policy.allow_destructive_actions is False,
        "no_file_delete": policy.allow_file_delete is False,
        "no_process_kill": policy.allow_process_kill is False,
        "no_host_isolation": policy.allow_host_isolation is False,
        "no_registry_write": policy.allow_registry_write is False,
        "no_boot_write": policy.allow_boot_write is False,
        "no_filesystem_write": policy.allow_filesystem_write is False,
        "no_recovery_certification": policy.allow_recovery_certification is False,
        "sha256_evidence": policy.evidence_hash_algorithm == "sha256",
        "bounded_workers": 1 <= policy.max_workers <= 8,
        "bounded_inflight": 1 <= policy.max_inflight_items <= 256,
        "compromised_host_evidence_only": (
            RescueCapability.PLAN_REPAIR not in compromised
            and RescueCapability.PLAN_QUARANTINE not in compromised
        ),
        "trusted_external_planning_only": (
            RescueCapability.PLAN_REPAIR in external
            and RescueCapability.PLAN_QUARANTINE in external
        ),
        "offline_planning_only": (
            RescueCapability.PLAN_REPAIR in offline
            and RescueCapability.PLAN_QUARANTINE in offline
        ),
        "certification_refused_all_contexts": all(
            can_certify_recovery(context) is False for context in RescueExecutionContext
        ),
    }

    return {
        "profile": PROFILE,
        "checkpoint": "RR-0-architecture-safety",
        "passed": all(checks.values()),
        "checks": checks,
        "contract": rr0_contract_snapshot(),
        "destructive_runtime_actions_added": False,
        "repair_engine_enabled": False,
        "quarantine_execution_enabled": False,
        "recovery_certification_enabled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11 beta3 RR-0 architecture/safety acceptance")
    parser.add_argument("--output", default="acceptance-v011-beta3-rr0.json")
    args = parser.parse_args()

    result = run()
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
