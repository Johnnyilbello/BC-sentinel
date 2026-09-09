from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.config import APP_VERSION
from sentinel.protection_client import ProtectionServiceClient
from sentinel.service_update import version_key
from tools.threat_package_acceptance import run as run_beta1
from tools.threat_channel_beta2_acceptance import run as run_beta2
from tools.threat_channel_beta3_acceptance import run as run_beta3

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DOCS = (
    "README.md",
    "ROADMAP.md",
    "RELEASE-NOTES-v0.8.0-rc.1.md",
    "BC_SENTINEL_V080_RC1_CONSOLIDATION_REPORT.md",
)
PRIVATE_KEY_MARKERS = ("Ed25519" + "PrivateKey", "private" + "_bytes(")
RUNTIME_SCAN_DIRS = ("sentinel", "tools", "packaging")


def _scan_private_key_markers() -> list[str]:
    hits: list[str] = []
    for dirname in RUNTIME_SCAN_DIRS:
        root = ROOT / dirname
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".py", ".ps1", ".bat", ".cmd", ".json", ".md"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for marker in PRIVATE_KEY_MARKERS:
                if marker in text:
                    hits.append(f"{path.relative_to(ROOT)}:{marker}")
    return hits


def run(*, service_live: bool = False) -> dict:
    beta1 = run_beta1(service_live=False)
    beta2 = run_beta2(service_live=False)
    beta3 = run_beta3(service_live=False)
    docs_missing = [name for name in REQUIRED_DOCS if not (ROOT / name).is_file()]
    version_order_ok = version_key("0.8.0-beta.3") < version_key("0.8.0-rc.1") < version_key("0.8.0")
    current_version_at_least_rc1 = version_key(APP_VERSION) >= version_key("0.8.0-rc.1")
    markers = _scan_private_key_markers()

    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "release_candidate": "0.8.0-rc.1",
        "service_live_requested": bool(service_live),
        "consolidation": {
            "release_candidate_artifact": "0.8.0-rc.1",
            "current_version_at_least_rc1": current_version_at_least_rc1,
            "version_order": "0.8.0-beta.3 < 0.8.0-rc.1 < 0.8.0",
            "version_order_valid": version_order_ok,
            "required_docs_present": not docs_missing,
            "missing_docs": docs_missing,
            "private_key_markers_absent": not markers,
            "private_key_marker_hits": markers,
        },
        "regression_gates": {
            "threat_package_beta1": bool(beta1.get("passed")),
            "threat_channel_beta2": bool(beta2.get("passed")),
            "threat_channel_beta3": bool(beta3.get("passed")),
        },
        "release_policy": {
            "cloud_required": False,
            "remote_auto_stage": False,
            "remote_auto_activate": False,
            "arbitrary_code_execution": False,
            "signed_reputation_enforcement": False,
            "https_mitm": False,
            "native_windows_acceptance_required_before_freeze": True,
        },
    }

    local_ok = all((
        current_version_at_least_rc1,
        version_order_ok,
        not docs_missing,
        not markers,
        beta1.get("passed"),
        beta2.get("passed"),
        beta3.get("passed"),
    ))
    result["local_foundation_passed"] = bool(local_ok)

    service_ok = True
    if service_live:
        client = ProtectionServiceClient(timeout=2.0)
        status = client.status() or {}
        threat = status.get("threat_intelligence") if isinstance(status, dict) else None
        if not isinstance(threat, dict):
            # Current service status exposes threat intelligence fields at the subsystem root on some builds.
            threat = status.get("threat_package") if isinstance(status, dict) else None
        # Fall back to the dedicated API through Beta3's live gate if layout differs.
        live_beta3 = run_beta3(service_live=True)
        live_status = live_beta3.get("service") or {}
        remote = live_status.get("remote_channel_policy") if isinstance(live_status, dict) else {}
        scheduler = live_status.get("scheduler") if isinstance(live_status, dict) else {}
        retrieval = live_status.get("retrieval_policy") if isinstance(live_status, dict) else {}
        service_ok = bool(
            live_beta3.get("passed")
            and remote.get("auto_stage") is False
            and remote.get("auto_activate") is False
            and remote.get("cloud_required") is False
            and scheduler.get("auto_activate") is False
            and retrieval.get("https_only") is True
            and retrieval.get("certificate_pin_required") is True
        )
        result["service"] = {
            "health": status.get("health") if isinstance(status, dict) else None,
            "transport": status.get("transport") if isinstance(status, dict) else None,
            "remote_auto_stage": remote.get("auto_stage"),
            "remote_auto_activate": remote.get("auto_activate"),
            "cloud_required": remote.get("cloud_required"),
            "scheduler_auto_activate": scheduler.get("auto_activate"),
            "https_only": retrieval.get("https_only"),
            "certificate_pin_required": retrieval.get("certificate_pin_required"),
        }
        result["service_live_passed"] = service_ok

    result["passed"] = bool(local_ok and service_ok)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.8.0-rc.1 consolidation acceptance")
    parser.add_argument("--service-live", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(service_live=args.service_live)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
