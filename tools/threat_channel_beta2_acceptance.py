from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile

from sentinel.config import APP_VERSION
from sentinel.database import Database
from sentinel.network_intelligence import NetworkReputationEngine
from sentinel.protection_client import ProtectionServiceClient
from sentinel.threat_packages import SignedThreatPackageVerifier, ThreatPackageError, ThreatPackageManager
from sentinel.threat_retrieval import SecureThreatRetriever, ThreatRetrievalError
from sentinel.threat_trust import ThreatTrustError, ThreatTrustStore
from tools.threat_keyset_fixture import (
    SAFE_THREAT_KEYSET_1,
    SAFE_THREAT_KEYSET_1_SIGNATURE,
    SAFE_THREAT_KEYSET_2,
    SAFE_THREAT_KEYSET_2_SIGNATURE,
)
from tools.threat_package_beta2_fixture import (
    SAFE_THREAT_PACKAGE_C,
    SAFE_THREAT_PACKAGE_C_SIGNATURE,
    SAFE_THREAT_PACKAGE_D,
    SAFE_THREAT_PACKAGE_D_SIGNATURE,
)
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
    now = 1788700000.0

    with tempfile.TemporaryDirectory(prefix="bcs-v080b2-trust-") as raw:
        root = Path(raw)
        db = Database(root / "sentinel.sqlite")
        trust = ThreatTrustStore(root / "Trust", integrity_key=b"T" * 32)
        keyset1 = trust.install_keyset(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE, now=now)
        verifier = SignedThreatPackageVerifier(product_version="0.8.0-beta.2", trust_store=trust)
        verified_c = verifier.verify(SAFE_THREAT_PACKAGE_C, SAFE_THREAT_PACKAGE_C_SIGNATURE, now=now)
        manager = ThreatPackageManager(
            root / "ThreatIntelligence", db=db, verifier=verifier,
            integrity_key=b"P" * 32, require_yara_compile=False,
        )
        stage_c = manager.stage(SAFE_THREAT_PACKAGE_C, SAFE_THREAT_PACKAGE_C_SIGNATURE, now=now)
        active_c = manager.activate(stage_c["stage_id"])
        rep_c = db.match_signed_reputation("sub.badrep080b2.test", now=now)
        network_rep = NetworkReputationEngine(db).assess_endpoint("badrep080b2.test")

        keyset2 = trust.install_keyset(SAFE_THREAT_KEYSET_2, SAFE_THREAT_KEYSET_2_SIGNATURE, now=now)
        revoked_rejected = False
        try:
            verifier.verify(SAFE_THREAT_PACKAGE_C, SAFE_THREAT_PACKAGE_C_SIGNATURE, now=now)
        except ThreatPackageError:
            revoked_rejected = True
        keyset_rollback_rejected = False
        try:
            trust.install_keyset(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE, now=now)
        except ThreatTrustError:
            keyset_rollback_rejected = True
        verified_d = verifier.verify(SAFE_THREAT_PACKAGE_D, SAFE_THREAT_PACKAGE_D_SIGNATURE, now=now)
        stage_d = manager.stage(SAFE_THREAT_PACKAGE_D, SAFE_THREAT_PACKAGE_D_SIGNATURE, now=now)
        active_d = manager.activate(stage_d["stage_id"])
        old_rep_removed = db.match_signed_reputation("badrep080b2.test", now=now) is None
        new_rep = db.match_signed_reputation("watch080b2.test", now=now)

        trust_ok = bool(
            keyset1.get("keyset", {}).get("sequence") == 1
            and verified_c.signing_key_id == "content-2026-a"
            and active_c.get("active", {}).get("sequence") == 3
            and rep_c and rep_c.get("source") == "signed_reputation"
            and network_rep.source == "signed_reputation"
            and network_rep.score_delta < 70
            and keyset2.get("keyset", {}).get("sequence") == 2
            and revoked_rejected
            and keyset_rollback_rejected
            and verified_d.signing_key_id == "content-2026-b"
            and active_d.get("active", {}).get("sequence") == 4
            and old_rep_removed
            and new_rep and new_rep.get("status") == "suspicious"
            and manager.status().get("signed_reputation_enforcement") is False
        )
        result["trust_lifecycle"] = {
            "root_signature": "Ed25519",
            "keyset_sequence_1": keyset1.get("keyset", {}).get("sequence"),
            "keyset_sequence_2": keyset2.get("keyset", {}).get("sequence"),
            "revoked_key_rejected": revoked_rejected,
            "keyset_rollback_rejected": keyset_rollback_rejected,
            "active_signing_key": verified_d.signing_key_id,
            "high_water_sequence": trust.status(now=now).get("high_water_sequence"),
        }
        result["signed_reputation"] = {
            "source": network_rep.source,
            "status": network_rep.status,
            "score_delta": network_rep.score_delta,
            "confidence": network_rep.confidence,
            "advisory_only": True,
            "old_package_reputation_removed": old_rep_removed,
            "active_entries": db.threat_package_reputation_count(now=now),
        }

    with tempfile.TemporaryDirectory(prefix="bcs-v080b2-recovery-") as raw:
        root = Path(raw)
        db = Database(root / "sentinel.sqlite")
        verifier = SignedThreatPackageVerifier(product_version="0.8.0-beta.2")
        base = root / "ThreatIntelligence"
        manager = ThreatPackageManager(base, db=db, verifier=verifier, integrity_key=b"R" * 32, require_yara_compile=False)
        a = manager.stage(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE, now=now)
        manager.activate(a["stage_id"])
        b = manager.stage(SAFE_THREAT_PACKAGE_B, SAFE_THREAT_PACKAGE_B_SIGNATURE, now=now)
        def crash(phase: str):
            if phase == "after_content_publish":
                raise RuntimeError("BC Sentinel harmless activation fault injection")
        manager.fault_injector = crash
        fault_observed = False
        try:
            manager.activate(b["stage_id"])
        except RuntimeError:
            fault_observed = True
        journal_left = manager.activation_journal_path.exists()
        recovered = ThreatPackageManager(base, db=db, verifier=verifier, integrity_key=b"R" * 32, require_yara_compile=False)
        recovery_ok = bool(
            fault_observed and journal_left and not recovered.activation_journal_path.exists()
            and db.match_ioc_endpoint("malware080.test", now=now)
            and db.match_ioc_endpoint("malware080b.test", now=now) is None
            and (recovered.last_recovery or {}).get("action") == "rolled_back_partial_activation"
        )
        result["activation_recovery"] = {
            "fault_injected": fault_observed,
            "authenticated_journal_observed": journal_left,
            "recovered": recovery_ok,
            "recovery_action": (recovered.last_recovery or {}).get("action"),
        }

    cert = b"BC Sentinel harmless certificate pin fixture"
    pin = hashlib.sha256(cert).hexdigest()
    body = json.dumps({"package": SAFE_THREAT_PACKAGE_D, "signature": SAFE_THREAT_PACKAGE_D_SIGNATURE}, sort_keys=True).encode("utf-8")
    body_hash = hashlib.sha256(body).hexdigest()
    def transport(url: str, max_bytes: int, timeout: float):
        return {"status": 200, "certificate_der": cert, "body": body, "content_type": "application/json"}
    retriever = SecureThreatRetriever(
        allowed_hosts={"updates.bcsentinel.test"},
        certificate_pins={"updates.bcsentinel.test": {pin}},
        transport=transport,
    )
    retrieved = retriever.fetch("https://updates.bcsentinel.test/threat/current.json", expected_sha256=body_hash)
    redirect_rejected = False
    bad_redirect = SecureThreatRetriever(
        allowed_hosts={"updates.bcsentinel.test"},
        certificate_pins={"updates.bcsentinel.test": {pin}},
        transport=lambda *args: {"status": 302, "location": "https://other.test/x", "certificate_der": cert, "body": b""},
    )
    try:
        bad_redirect.fetch("https://updates.bcsentinel.test/threat/current.json")
    except ThreatRetrievalError:
        redirect_rejected = True
    policy = retriever.policy()
    retrieval_ok = bool(
        retrieved.sha256 == body_hash and redirect_rejected and policy.get("https_only")
        and policy.get("certificate_pin_required") and policy.get("auto_stage") is False
        and policy.get("auto_activate") is False and policy.get("cloud_required") is False
    )
    result["secure_retrieval"] = {
        "https_only": policy.get("https_only"),
        "host_allowlist_required": policy.get("host_allowlist_required"),
        "certificate_pin_required": policy.get("certificate_pin_required"),
        "redirect_rejected": redirect_rejected,
        "retrieved_sha256": retrieved.sha256,
        "auto_stage": policy.get("auto_stage"),
        "auto_activate": policy.get("auto_activate"),
        "cloud_required": policy.get("cloud_required"),
    }

    result["local_foundation_passed"] = bool(trust_ok and recovery_ok and retrieval_ok)
    live_ok = True
    if service_live:
        client = ProtectionServiceClient(timeout=3.0)
        status = client.threat_intel_status()
        validation = client.validate_threat_keyset(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE)
        trust_status = status.get("trust") if isinstance(status, dict) else None
        retrieval_status = status.get("retrieval_policy") if isinstance(status, dict) else None
        live_ok = bool(
            isinstance(status, dict)
            and status.get("activation_recovery") is True
            and status.get("signed_reputation_enforcement") is False
            and isinstance(trust_status, dict)
            and trust_status.get("key_rotation") is True
            and trust_status.get("key_revocation") is True
            and trust_status.get("keyset_rollback_allowed") is False
            and isinstance(retrieval_status, dict)
            and retrieval_status.get("https_only") is True
            and retrieval_status.get("certificate_pin_required") is True
            and retrieval_status.get("auto_activate") is False
            and retrieval_status.get("cloud_required") is False
            and isinstance(validation, dict)
            and validation.get("valid") is True
            and validation.get("sequence") == 1
        )
        result["service"] = status if isinstance(status, dict) else {"error": client.last_error or "unavailable"}
        result["service_keyset_validation"] = validation if isinstance(validation, dict) else {"error": client.last_error or "unavailable"}
        result["service_live_passed"] = live_ok

    result["passed"] = bool(result.get("local_foundation_passed") and live_ok)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.8.0 Beta 2 trust/reputation/recovery/retrieval acceptance")
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
