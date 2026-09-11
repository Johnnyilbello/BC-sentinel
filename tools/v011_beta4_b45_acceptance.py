from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
from pathlib import Path

from sentinel import rescue_console_portable as portable


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _root(base: Path) -> Path:
    root = base / "offline-target"
    config = root / "Windows/System32/config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"B45 ACCEPTANCE SYSTEM")
    (config / "SOFTWARE").write_bytes(b"B45 ACCEPTANCE SOFTWARE")
    (root / "Windows/System32/ntoskrnl.exe").write_bytes(b"MZ B45 ACCEPTANCE KERNEL")
    return root


def _tree(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}


def _invoke(args: list[str]) -> tuple[int, dict]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = portable.main(args)
    payload = json.loads(out.getvalue())
    return code, payload


def run_acceptance() -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-b45-") as temp_name:
        base = Path(temp_name)
        root = _root(base)
        workspace = base / "workspace"
        plan = workspace / "session-plan.json"
        before = _tree(root)

        status_code, status = _invoke(["status"])
        plan_code, plan_result = _invoke([
            "plan",
            "--target-root", str(root),
            "--workspace", str(workspace),
            "--output-plan", str(plan),
        ])
        unknown_code, unknown = _invoke(["repair-execute"])
        after = _tree(root)

        checks = {
            "profile": portable.PROFILE == "v0.11.0-beta.4-b45",
            "status_passed": status_code == 0 and status.get("passed") is True,
            "portable": status.get("portable") is True,
            "no_installer": status.get("installer_required") is False,
            "no_service_install": status.get("service_install") is False,
            "no_driver_install": status.get("driver_install") is False,
            "command_surface_exact": status.get("commands") == ["plan", "scan", "repair-handoff", "data-rescue", "certify"],
            "repair_execution_not_exposed": status.get("safety", {}).get("repair_execution_exposed_by_console") is False,
            "repair_handoff_only": status.get("safety", {}).get("repair_handoff_only") is True,
            "outcomes_preserved": status.get("safety", {}).get("certification_outcomes_preserved") == ["RECOVERED", "NOT_RECOVERED", "INDETERMINATE_REFUSED"],
            "reimage_not_suppressed": status.get("safety", {}).get("format_or_reimage_suppressed") is False,
            "plan_dispatch_passed": plan_code == 0 and plan_result.get("passed") is True and plan.is_file(),
            "plan_hash_present": len(str(plan_result.get("plan_sha256") or "")) == 64,
            "target_unchanged": before == after,
            "repair_execute_refused": unknown_code == 2 and str(unknown.get("reason") or "") == "unknown_command:repair-execute",
            "no_network_required": status.get("network_required") is False,
            "no_cloud_required": status.get("cloud_required") is False,
        }
        return {
            "profile": portable.PROFILE,
            "checkpoint": "B4-5-portable-rescue-console",
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "commands": status.get("commands", []),
                "component_profiles": status.get("component_profiles", {}),
                "plan_sha256": plan_result.get("plan_sha256", ""),
                "target_fingerprint": plan_result.get("target_fingerprint", ""),
                "repair_execute_reason": unknown.get("reason", ""),
            },
            "new_mutation_authority_added": False,
            "automatic_destructive_action_enabled": False,
            "service_install_enabled": False,
            "driver_install_enabled": False,
        }


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    result = run_acceptance()
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
