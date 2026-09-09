from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile

from sentinel.config import APP_VERSION
from sentinel.database import Database
from sentinel.protection_client import ProtectionServiceClient
from sentinel.threat_index import SignedThreatIndexVerifier, ThreatContentCache, ThreatIndexError, ThreatIndexStore
from sentinel.threat_packages import SignedThreatPackageVerifier, ThreatPackageManager
from sentinel.threat_retrieval import SecureThreatRetriever
from sentinel.threat_scheduler import ThreatCheckScheduler, ThreatRemoteCoordinator
from sentinel.threat_trust import ThreatTrustStore
from tools.threat_index_fixture import (
    SAFE_PACKAGE_C_ENVELOPE,
    SAFE_PACKAGE_D_ENVELOPE,
    SAFE_THREAT_INDEX_1,
    SAFE_THREAT_INDEX_1_ENVELOPE,
    SAFE_THREAT_INDEX_1_ENVELOPE_SHA256,
    SAFE_THREAT_INDEX_1_SIGNATURE,
    SAFE_THREAT_INDEX_2,
    SAFE_THREAT_INDEX_2_SIGNATURE,
)
from tools.threat_keyset_fixture import (
    SAFE_THREAT_KEYSET_1,
    SAFE_THREAT_KEYSET_1_SIGNATURE,
    SAFE_THREAT_KEYSET_2,
    SAFE_THREAT_KEYSET_2_SIGNATURE,
)
from tools.threat_package_beta2_fixture import SAFE_THREAT_PACKAGE_C, SAFE_THREAT_PACKAGE_C_SIGNATURE
from tools.threat_package_fixture import (
    SAFE_THREAT_PACKAGE_A,
    SAFE_THREAT_PACKAGE_A_SIGNATURE,
    SAFE_THREAT_PACKAGE_B,
    SAFE_THREAT_PACKAGE_B_SIGNATURE,
)

NOW = 1788700000.0
FAULT_PHASES = (
    "after_package_promote",
    "after_journal_prepare",
    "after_ioc_publish",
    "after_reputation_publish",
    "after_yara_publish",
    "after_behavior_publish",
    "after_content_journal_commit",
    "after_content_publish",
    "after_state_commit",
    "before_journal_clear",
    "after_journal_clear",
)


def _fault_matrix(root: Path) -> dict:
    rows: list[dict] = []
    ok = True
    for phase in FAULT_PHASES:
        case = root / phase
        case.mkdir(parents=True, exist_ok=True)
        db = Database(case / "sentinel.sqlite")
        verifier = SignedThreatPackageVerifier(product_version=APP_VERSION)
        base = case / "ThreatIntelligence"
        manager = ThreatPackageManager(base, db=db, verifier=verifier, integrity_key=b"F" * 32, require_yara_compile=False)
        a = manager.stage(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE, now=NOW)
        manager.activate(a["stage_id"])
        b = manager.stage(SAFE_THREAT_PACKAGE_B, SAFE_THREAT_PACKAGE_B_SIGNATURE, now=NOW)

        def crash(observed: str):
            if observed == phase:
                raise RuntimeError(f"fault:{phase}")

        manager.fault_injector = crash
        injected = False
        try:
            manager.activate(b["stage_id"])
        except RuntimeError:
            injected = True
        recovered = ThreatPackageManager(base, db=db, verifier=verifier, integrity_key=b"F" * 32, require_yara_compile=False)
        active = recovered.status().get("active") or {}
        sequence = int(active.get("sequence") or 0)
        expected = 2 if phase in {"after_state_commit", "before_journal_clear", "after_journal_clear"} else 1
        old_present = db.match_ioc_endpoint("malware080.test", now=NOW) is not None
        new_present = db.match_ioc_endpoint("malware080b.test", now=NOW) is not None
        complete = bool(
            injected
            and sequence == expected
            and ((expected == 1 and old_present and not new_present) or (expected == 2 and new_present and not old_present))
        )
        ok = ok and complete
        rows.append({
            "phase": phase,
            "fault_injected": injected,
            "active_sequence": sequence,
            "expected_sequence": expected,
            "complete_state_only": complete,
        })
    return {"passed": ok, "phases": rows, "mixed_state_observed": not ok}


def run(*, service_live: bool = False) -> dict:
    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "harmless_fixture": True,
        "service_live_requested": bool(service_live),
        "passed": False,
    }

    with tempfile.TemporaryDirectory(prefix="bcs-v080b3-index-") as raw:
        root = Path(raw)
        verifier = SignedThreatIndexVerifier(product_version=APP_VERSION)
        verified = verifier.verify(SAFE_THREAT_INDEX_1, SAFE_THREAT_INDEX_1_SIGNATURE, now=NOW)
        tampered = copy.deepcopy(SAFE_THREAT_INDEX_1)
        tampered["packages"][0]["sha256"] = "0" * 64
        tamper_rejected = False
        try:
            verifier.verify(tampered, SAFE_THREAT_INDEX_1_SIGNATURE, now=NOW)
        except ThreatIndexError:
            tamper_rejected = True
        store = ThreatIndexStore(root / "RemoteIndex", verifier=verifier, integrity_key=b"I" * 32)
        one = store.accept(SAFE_THREAT_INDEX_1, SAFE_THREAT_INDEX_1_SIGNATURE, now=NOW)
        two = store.accept(SAFE_THREAT_INDEX_2, SAFE_THREAT_INDEX_2_SIGNATURE, now=NOW)
        rollback_rejected = False
        try:
            store.accept(SAFE_THREAT_INDEX_1, SAFE_THREAT_INDEX_1_SIGNATURE, now=NOW)
        except ThreatIndexError:
            rollback_rejected = True
        result["signed_remote_index"] = {
            "signature": "Ed25519",
            "sequence_1": one.get("index", {}).get("sequence"),
            "sequence_2": two.get("index", {}).get("sequence"),
            "high_water_sequence": store.status(now=NOW).get("high_water_sequence"),
            "tamper_rejected": tamper_rejected,
            "rollback_rejected": rollback_rejected,
            "package_count": len(verified.packages),
        }
        index_ok = bool(
            verified.sequence == 1 and tamper_rejected and rollback_rejected
            and store.status(now=NOW).get("high_water_sequence") == 2
        )

    with tempfile.TemporaryDirectory(prefix="bcs-v080b3-channel-") as raw:
        root = Path(raw)
        trust = ThreatTrustStore(root / "Trust", integrity_key=b"T" * 32)
        trust.install_keyset(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE, now=NOW)
        trust.install_keyset(SAFE_THREAT_KEYSET_2, SAFE_THREAT_KEYSET_2_SIGNATURE, now=NOW)
        package_verifier = SignedThreatPackageVerifier(product_version=APP_VERSION, trust_store=trust)
        cert = b"BC Sentinel Beta3 harmless pinned certificate fixture"
        pin = hashlib.sha256(cert).hexdigest()
        bodies = {
            "https://updates.bcsentinel.test/threat/index.json": SAFE_THREAT_INDEX_1_ENVELOPE,
            "https://updates.bcsentinel.test/threat/packages/bcsentinel-v080b2-safe-c.json": SAFE_PACKAGE_C_ENVELOPE,
            "https://updates.bcsentinel.test/threat/packages/bcsentinel-v080b2-safe-d.json": SAFE_PACKAGE_D_ENVELOPE,
        }

        def transport(url: str, max_bytes: int, timeout: float):
            return {"status": 200, "certificate_der": cert, "body": bodies[url], "content_type": "application/json"}

        retriever = SecureThreatRetriever(
            allowed_hosts={"updates.bcsentinel.test"},
            certificate_pins={"updates.bcsentinel.test": {pin}},
            transport=transport,
        )
        index_store = ThreatIndexStore(root / "RemoteIndex", integrity_key=b"I" * 32)
        cache = ThreatContentCache(root / "ThreatCache")
        scheduler = ThreatCheckScheduler(root / "Scheduler", integrity_key=b"S" * 32, interval_seconds=3600)
        coordinator = ThreatRemoteCoordinator(
            retriever=retriever,
            index_store=index_store,
            cache=cache,
            package_verifier=package_verifier,
            trust_store=trust,
            scheduler=scheduler,
            product_version=APP_VERSION,
        )
        checked = coordinator.check(
            "https://updates.bcsentinel.test/threat/index.json",
            active_sequence=2,
            expected_index_sha256=SAFE_THREAT_INDEX_1_ENVELOPE_SHA256,
            now=NOW,
            force=True,
        )
        candidate = checked.get("candidate") or {}
        meta = candidate.get("metadata") or {}
        cached = candidate.get("cache") or {}
        cache_status = cache.status()
        scheduler_status = scheduler.status(now=NOW)
        channel_ok = bool(
            checked.get("checked") is True
            and meta.get("package_id") == "bcsentinel-v080b2-safe-d"
            and meta.get("signing_key_id") == "content-2026-b"
            and candidate.get("ready_for_manual_stage") is True
            and checked.get("auto_stage") is False
            and checked.get("auto_activate") is False
            and cache.read(str(cached.get("sha256"))) == SAFE_PACKAGE_D_ENVELOPE
            and cache_status.get("content_addressed") is True
            and cache_status.get("executable_content") is False
            and scheduler_status.get("due") is False
        )
        result["controlled_retrieval"] = {
            "candidate_package_id": meta.get("package_id"),
            "candidate_signing_key_id": meta.get("signing_key_id"),
            "revoked_signer_skipped": meta.get("signing_key_id") == "content-2026-b",
            "content_addressed_cache": cache_status.get("content_addressed"),
            "cache_entries": cache_status.get("entries"),
            "ready_for_manual_stage": candidate.get("ready_for_manual_stage"),
            "auto_stage": checked.get("auto_stage"),
            "auto_activate": checked.get("auto_activate"),
            "scheduler_due_after_success": scheduler_status.get("due"),
            "cloud_required": coordinator.policy().get("cloud_required"),
        }

    with tempfile.TemporaryDirectory(prefix="bcs-v080b3-revocation-") as raw:
        root = Path(raw)
        db = Database(root / "sentinel.sqlite")
        trust = ThreatTrustStore(root / "Trust", integrity_key=b"T" * 32)
        trust.install_keyset(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE, now=NOW)
        verifier = SignedThreatPackageVerifier(product_version=APP_VERSION, trust_store=trust)
        manager = ThreatPackageManager(root / "ThreatIntelligence", db=db, verifier=verifier, integrity_key=b"R" * 32, require_yara_compile=False)
        staged = manager.stage(SAFE_THREAT_PACKAGE_C, SAFE_THREAT_PACKAGE_C_SIGNATURE, now=NOW)
        manager.activate(staged["stage_id"])
        trust.install_keyset(SAFE_THREAT_KEYSET_2, SAFE_THREAT_KEYSET_2_SIGNATURE, now=NOW)
        status = manager.status()
        policy = status.get("revocation_policy") or {}
        retained = db.match_ioc_endpoint("ioc080b2.test", now=NOW) is not None
        revocation_ok = bool(
            status.get("active_signer_revoked") is True
            and policy.get("state") == "critical_replacement_required"
            and policy.get("active_content_retained") is True
            and policy.get("automatic_destructive_action") is False
            and policy.get("fail_open") is False
            and retained
        )
        result["revocation_operations"] = {
            "active_signer_revoked": status.get("active_signer_revoked"),
            "state": policy.get("state"),
            "active_content_retained": retained,
            "replacement_required": policy.get("replacement_required"),
            "automatic_destructive_action": policy.get("automatic_destructive_action"),
            "fail_open": policy.get("fail_open"),
        }

    with tempfile.TemporaryDirectory(prefix="bcs-v080b3-faults-") as raw:
        fault = _fault_matrix(Path(raw))
        result["fault_matrix"] = fault
        fault_ok = bool(fault.get("passed"))

    result["local_foundation_passed"] = bool(index_ok and channel_ok and revocation_ok and fault_ok)

    live_ok = True
    if service_live:
        client = ProtectionServiceClient(timeout=3.0)
        status = client.threat_intel_status()
        validation = client.validate_threat_index(SAFE_THREAT_INDEX_1, SAFE_THREAT_INDEX_1_SIGNATURE)
        remote_index = status.get("remote_index") if isinstance(status, dict) else {}
        cache_status = status.get("remote_cache") if isinstance(status, dict) else {}
        scheduler_status = status.get("scheduler") if isinstance(status, dict) else {}
        channel_policy = status.get("remote_channel_policy") if isinstance(status, dict) else {}
        revocation_policy = status.get("revocation_policy") if isinstance(status, dict) else {}
        live_ok = bool(
            isinstance(status, dict)
            and isinstance(validation, dict) and validation.get("valid") is True and validation.get("sequence") == 1
            and isinstance(remote_index, dict) and remote_index.get("signature") == "Ed25519" and remote_index.get("anti_rollback") is True
            and isinstance(cache_status, dict) and cache_status.get("content_addressed") is True and cache_status.get("executable_content") is False
            and isinstance(scheduler_status, dict) and scheduler_status.get("auto_activate") is False and scheduler_status.get("cloud_required") is False
            and isinstance(channel_policy, dict) and channel_policy.get("signed_remote_index") is True and channel_policy.get("auto_activate") is False
            and isinstance(revocation_policy, dict) and revocation_policy.get("automatic_destructive_action") is False and revocation_policy.get("fail_open") is False
        )
        result["service"] = status if isinstance(status, dict) else {"error": client.last_error or "unavailable"}
        result["service_index_validation"] = validation if isinstance(validation, dict) else {"error": client.last_error or "unavailable"}
        result["service_live_passed"] = live_ok

    result["passed"] = bool(result.get("local_foundation_passed") and live_ok)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.8.0 Beta 3 signed remote index/controlled retrieval acceptance")
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
