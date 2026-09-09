from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

from sentinel.config import APP_VERSION
from sentinel.database import Database
from sentinel.protection_client import ProtectionServiceClient
from sentinel.release_channel import ReleaseEnvelopeError, SignedReleaseEnvelopeVerifier
from sentinel.threat_packages import SignedThreatPackageVerifier, ThreatPackageError, ThreatPackageManager
from tools.release_envelope_fixture import SAFE_RELEASE_ENVELOPE, SAFE_RELEASE_ENVELOPE_SIGNATURE, SAFE_RELEASE_FILES
from tools.threat_package_fixture import (
    SAFE_THREAT_PACKAGE_A,
    SAFE_THREAT_PACKAGE_A_SIGNATURE,
    SAFE_THREAT_PACKAGE_B,
    SAFE_THREAT_PACKAGE_B_SIGNATURE,
)


def run(*, service_live: bool = False) -> dict:
    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "harmless_fixture": True,
        "service_live_requested": bool(service_live),
        "passed": False,
    }
    verifier = SignedThreatPackageVerifier(product_version=APP_VERSION)
    verified = verifier.verify(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE)
    tampered = copy.deepcopy(SAFE_THREAT_PACKAGE_A)
    tampered["components"]["ioc"]["entries"][0]["value"] = "tampered.test"
    tamper_rejected = False
    try:
        verifier.verify(tampered, SAFE_THREAT_PACKAGE_A_SIGNATURE)
    except ThreatPackageError:
        tamper_rejected = True

    yara_available = importlib.util.find_spec("yara") is not None
    with tempfile.TemporaryDirectory(prefix="bcs-v080-threat-package-") as raw:
        root = Path(raw)
        db = Database(root / "sentinel.sqlite")
        manager = ThreatPackageManager(
            root / "ThreatIntelligence", db=db, verifier=verifier,
            integrity_key=b"A" * 32, require_yara_compile=yara_available,
        )
        stage_a = manager.stage(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE)
        active_a = manager.activate(stage_a["stage_id"])
        a_domain = db.match_ioc_endpoint("sub.malware080.test")
        a_hash = db.match_ioc_hash(hashlib.sha256(b"BCS080_ALPHA_PAYLOAD").hexdigest())
        yara_a = (manager.active_yara_dir / "BCS080_ALPHA.yar").exists()
        behavior_a = json.loads(manager.active_behavior_path.read_text(encoding="utf-8"))

        stage_b = manager.stage(SAFE_THREAT_PACKAGE_B, SAFE_THREAT_PACKAGE_B_SIGNATURE)
        active_b = manager.activate(stage_b["stage_id"])
        b_domain = db.match_ioc_endpoint("malware080b.test")
        rollback = manager.rollback_last_known_good()
        restored_a = db.match_ioc_endpoint("malware080.test")
        high_water = manager.status().get("high_water_sequence")
        rollback_only = False
        try:
            manager.stage(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE)
        except ThreatPackageError:
            rollback_only = True
        history = manager.history(20)
        local_ok = bool(
            verified.sequence == 1
            and tamper_rejected
            and active_a.get("active", {}).get("sequence") == 1
            and a_domain and a_domain.get("source") == "threat_package"
            and a_hash and a_hash.get("source") == "threat_package"
            and yara_a
            and behavior_a.get("advisory_only") is True
            and active_b.get("active", {}).get("sequence") == 2
            and active_b.get("last_known_good", {}).get("sequence") == 1
            and b_domain and b_domain.get("source") == "threat_package"
            and rollback.get("active", {}).get("sequence") == 1
            and restored_a and restored_a.get("source") == "threat_package"
            and int(high_water or 0) == 2
            and rollback_only
            and history and all(bool(row.get("authenticated")) for row in history)
        )
        result.update({
            "signature_verified": True,
            "tamper_rejected": tamper_rejected,
            "local_foundation_passed": local_ok,
            "package": {
                "package_id": verified.package_id,
                "sequence": verified.sequence,
                "payload_sha256": verified.payload_sha256,
                "key_fingerprint": verified.key_fingerprint,
                "component_hashes": verified.component_hashes,
                "ioc_entries": len(verified.ioc_entries),
                "yara_rules": len(verified.yara_rules),
                "behavior_rules": len(verified.behavior_rules),
                "yara_compile_validated": yara_available,
            },
            "activation": {
                "stage_then_activate": True,
                "active_sequence_a": active_a.get("active", {}).get("sequence"),
                "active_sequence_b": active_b.get("active", {}).get("sequence"),
                "last_known_good_sequence": active_b.get("last_known_good", {}).get("sequence"),
                "rollback_restored_sequence": rollback.get("active", {}).get("sequence"),
                "high_water_sequence": high_water,
                "arbitrary_downgrade_rejected": rollback_only,
            },
            "safety": {
                "arbitrary_code_execution": False,
                "behavior_advisory_only": True,
                "private_signing_key_shipped": False,
                "lkg_rollback_only": True,
            },
        })

    release_verifier = SignedReleaseEnvelopeVerifier()
    with tempfile.TemporaryDirectory(prefix="bcs-v080-release-envelope-") as raw_release:
        release_root = Path(raw_release)
        for rel, payload in SAFE_RELEASE_FILES.items():
            (release_root / rel).write_bytes(payload)
        release_ok = release_verifier.verify_tree(
            release_root, SAFE_RELEASE_ENVELOPE, SAFE_RELEASE_ENVELOPE_SIGNATURE
        )
        (release_root / "app.bin").write_bytes(b"tampered")
        release_tamper_rejected = False
        try:
            release_verifier.verify_tree(release_root, SAFE_RELEASE_ENVELOPE, SAFE_RELEASE_ENVELOPE_SIGNATURE)
        except ReleaseEnvelopeError:
            release_tamper_rejected = True
    result["secure_update_channel"] = {
        "publisher_signature": "Ed25519",
        "key_fingerprint": release_verifier.key_fingerprint,
        "envelope_verified": bool(release_ok.get("verified")),
        "exact_file_set": bool(release_ok.get("exact_file_set")),
        "files_checked": int(release_ok.get("files_checked") or 0),
        "tamper_rejected": release_tamper_rejected,
        "local_dev_upgrade_signature_required": False,
        "production_channel_signature_ready": True,
    }
    result["local_foundation_passed"] = bool(
        result.get("local_foundation_passed")
        and release_ok.get("verified")
        and release_tamper_rejected
        and release_ok.get("exact_file_set")
    )

    live_ok = True
    if service_live:
        client = ProtectionServiceClient(timeout=3.0)
        status = client.threat_intel_status()
        validation = client.validate_threat_package(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE)
        live_ok = bool(
            isinstance(status, dict)
            and status.get("channel") == "signed_local_content"
            and status.get("signature") == "Ed25519"
            and status.get("staged_activation") is True
            and status.get("last_known_good_rollback") is True
            and status.get("arbitrary_code_execution") is False
            and status.get("behavior_enforcement") is False
            and status.get("yara_compile_required") is True
            and isinstance(validation, dict)
            and validation.get("valid") is True
            and validation.get("sequence") == 1
            and validation.get("key_fingerprint") == verifier.key_fingerprint
        )
        result["service"] = status if isinstance(status, dict) else {"error": client.last_error or "unavailable"}
        result["service_validation"] = validation if isinstance(validation, dict) else {"error": client.last_error or "unavailable"}
        result["service_live_passed"] = live_ok

    result["passed"] = bool(result.get("local_foundation_passed") and live_ok)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.8.0 Beta 1 signed threat-package safe acceptance")
    parser.add_argument("--service-live", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(service_live=bool(args.service_live))
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
