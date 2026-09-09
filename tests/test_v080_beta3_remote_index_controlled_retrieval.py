from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from sentinel.service_update import version_key
from sentinel.database import Database
from sentinel.protection_protocol import ProtocolError, validate_request
from sentinel.threat_index import (
    SignedThreatIndexVerifier,
    ThreatContentCache,
    ThreatIndexError,
    ThreatIndexStore,
)
from sentinel.threat_packages import SignedThreatPackageVerifier, ThreatPackageManager
from sentinel.threat_retrieval import SecureThreatRetriever
from sentinel.threat_scheduler import ThreatCheckScheduler, ThreatRemoteCoordinator, ThreatSchedulerError
from sentinel.threat_trust import ThreatTrustStore
from tools.threat_index_fixture import (
    SAFE_PACKAGE_C_ENVELOPE,
    SAFE_PACKAGE_D_ENVELOPE,
    SAFE_THREAT_INDEX_1,
    SAFE_THREAT_INDEX_1_ENVELOPE,
    SAFE_THREAT_INDEX_1_ENVELOPE_SHA256,
    SAFE_THREAT_INDEX_1_SIGNATURE,
    SAFE_THREAT_INDEX_2,
    SAFE_THREAT_INDEX_2_ENVELOPE,
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


def _req(op: str, **payload):
    return {
        "version": 1,
        "request_id": "v080b3-test",
        "op": op,
        "token": "a" * 64,
        "payload": payload,
    }


def _trust(tmp_path: Path) -> ThreatTrustStore:
    return ThreatTrustStore(tmp_path / "Trust", integrity_key=b"t" * 32)


def test_v080b3_signed_index_verifies_tamper_fails_and_index_antirollback_holds(tmp_path):
    verifier = SignedThreatIndexVerifier(product_version="0.9.0-beta.3")
    verified = verifier.verify(SAFE_THREAT_INDEX_1, SAFE_THREAT_INDEX_1_SIGNATURE, now=NOW)
    assert verified.sequence == 1
    assert len(verified.packages) == 2
    assert len(verified.key_fingerprint) == 24

    tampered = copy.deepcopy(SAFE_THREAT_INDEX_1)
    tampered["packages"][1]["sha256"] = "0" * 64
    with pytest.raises(ThreatIndexError, match="signature verification failed"):
        verifier.verify(tampered, SAFE_THREAT_INDEX_1_SIGNATURE, now=NOW)

    store = ThreatIndexStore(tmp_path / "RemoteIndex", verifier=verifier, integrity_key=b"i" * 32)
    one = store.accept(SAFE_THREAT_INDEX_1, SAFE_THREAT_INDEX_1_SIGNATURE, now=NOW)
    two = store.accept(SAFE_THREAT_INDEX_2, SAFE_THREAT_INDEX_2_SIGNATURE, now=NOW)
    assert one["index"]["sequence"] == 1
    assert two["index"]["sequence"] == 2
    assert store.status(now=NOW)["high_water_sequence"] == 2
    with pytest.raises(ThreatIndexError, match="anti-rollback"):
        store.accept(SAFE_THREAT_INDEX_1, SAFE_THREAT_INDEX_1_SIGNATURE, now=NOW)


def test_v080b3_candidate_selection_skips_revoked_signer_and_requires_newer_sequence(tmp_path):
    trust = _trust(tmp_path)
    trust.install_keyset(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE, now=NOW)
    trust.install_keyset(SAFE_THREAT_KEYSET_2, SAFE_THREAT_KEYSET_2_SIGNATURE, now=NOW)
    store = ThreatIndexStore(tmp_path / "RemoteIndex", integrity_key=b"i" * 32)
    store.accept(SAFE_THREAT_INDEX_2, SAFE_THREAT_INDEX_2_SIGNATURE, now=NOW)
    candidate = store.select_candidate(
        active_sequence=2, product_version="0.9.0-beta.3", trust_store=trust, now=NOW
    )
    assert candidate is not None
    assert candidate["package_id"] == "bcsentinel-v080b2-safe-d"
    assert candidate["signing_key_id"] == "content-2026-b"
    assert store.select_candidate(
        active_sequence=4, product_version="0.9.0-beta.3", trust_store=trust, now=NOW
    ) is None


def test_v080b3_remote_coordinator_retrieves_signed_index_and_verified_candidate_without_activation(tmp_path):
    trust = _trust(tmp_path)
    trust.install_keyset(SAFE_THREAT_KEYSET_2, SAFE_THREAT_KEYSET_2_SIGNATURE, now=NOW)
    pkg_verifier = SignedThreatPackageVerifier(product_version="0.9.0-beta.3", trust_store=trust)
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
    index_store = ThreatIndexStore(tmp_path / "RemoteIndex", integrity_key=b"i" * 32)
    cache = ThreatContentCache(tmp_path / "ThreatCache")
    scheduler = ThreatCheckScheduler(tmp_path / "Scheduler", integrity_key=b"s" * 32, interval_seconds=3600)
    channel = ThreatRemoteCoordinator(
        retriever=retriever,
        index_store=index_store,
        cache=cache,
        package_verifier=pkg_verifier,
        trust_store=trust,
        scheduler=scheduler,
        product_version="0.9.0-beta.3",
    )
    result = channel.check(
        "https://updates.bcsentinel.test/threat/index.json",
        active_sequence=2,
        expected_index_sha256=SAFE_THREAT_INDEX_1_ENVELOPE_SHA256,
        now=NOW,
        force=True,
    )
    assert result["checked"] is True
    assert result["auto_stage"] is False and result["auto_activate"] is False
    candidate = result["candidate"]
    assert candidate and candidate["metadata"]["package_id"] == "bcsentinel-v080b2-safe-d"
    assert candidate["ready_for_manual_stage"] is True
    assert candidate["verified_package"]["signing_key_id"] == "content-2026-b"
    cached = cache.read(candidate["cache"]["sha256"])
    assert cached == SAFE_PACKAGE_D_ENVELOPE
    assert scheduler.status(now=NOW)["due"] is False
    assert channel.policy()["cloud_required"] is False


def test_v080b3_cache_is_content_addressed_bounded_and_detects_tamper(tmp_path):
    cache = ThreatContentCache(tmp_path / "ThreatCache", max_entries=2, max_bytes=512 * 1024)
    bodies = [b'{"x":1}', b'{"x":2}', b'{"x":3}']
    records = []
    for body in bodies:
        digest = hashlib.sha256(body).hexdigest()
        records.append(cache.store(body, expected_sha256=digest))
    status = cache.status()
    assert status["entries"] <= 2
    assert status["content_addressed"] is True
    assert status["executable_content"] is False
    latest = records[-1]
    path = (tmp_path / "ThreatCache" / latest["cache_name"])
    path.write_bytes(b"tampered")
    with pytest.raises(ThreatIndexError, match="hash verification failed"):
        cache.read(latest["sha256"])


def test_v080b3_revoked_active_signer_enters_critical_state_without_deleting_active_content(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    trust = _trust(tmp_path)
    trust.install_keyset(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE, now=NOW)
    verifier = SignedThreatPackageVerifier(product_version="0.9.0-beta.3", trust_store=trust)
    manager = ThreatPackageManager(
        tmp_path / "ThreatIntelligence", db=db, verifier=verifier,
        integrity_key=b"r" * 32, require_yara_compile=False,
    )
    staged = manager.stage(SAFE_THREAT_PACKAGE_C, SAFE_THREAT_PACKAGE_C_SIGNATURE, now=NOW)
    manager.activate(staged["stage_id"])
    assert db.match_ioc_endpoint("ioc080b2.test", now=NOW)
    trust.install_keyset(SAFE_THREAT_KEYSET_2, SAFE_THREAT_KEYSET_2_SIGNATURE, now=NOW)
    status = manager.status()
    assert status["active_signer_revoked"] is True
    assert status["revocation_policy"]["state"] == "critical_replacement_required"
    assert status["revocation_policy"]["active_content_retained"] is True
    assert status["revocation_policy"]["automatic_destructive_action"] is False
    assert status["revocation_policy"]["fail_open"] is False
    assert db.match_ioc_endpoint("ioc080b2.test", now=NOW)


@pytest.mark.parametrize(
    "phase,expected_sequence",
    [
        ("after_package_promote", 1),
        ("after_journal_prepare", 1),
        ("after_ioc_publish", 1),
        ("after_reputation_publish", 1),
        ("after_yara_publish", 1),
        ("after_behavior_publish", 1),
        ("after_content_journal_commit", 1),
        ("after_content_publish", 1),
        ("after_state_commit", 2),
        ("before_journal_clear", 2),
        ("after_journal_clear", 2),
    ],
)
def test_v080b3_fault_matrix_recovers_to_only_complete_old_or_new_state(tmp_path, phase, expected_sequence):
    root = tmp_path / phase
    root.mkdir(parents=True, exist_ok=True)
    db = Database(root / "sentinel.sqlite")
    verifier = SignedThreatPackageVerifier(product_version="0.9.0-beta.3")
    base = root / "ThreatIntelligence"
    manager = ThreatPackageManager(base, db=db, verifier=verifier, integrity_key=b"f" * 32, require_yara_compile=False)
    a = manager.stage(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE, now=NOW)
    manager.activate(a["stage_id"])
    b = manager.stage(SAFE_THREAT_PACKAGE_B, SAFE_THREAT_PACKAGE_B_SIGNATURE, now=NOW)

    def crash(observed: str):
        if observed == phase:
            raise RuntimeError(f"fault:{phase}")

    manager.fault_injector = crash
    with pytest.raises(RuntimeError, match="fault:"):
        manager.activate(b["stage_id"])
    recovered = ThreatPackageManager(base, db=db, verifier=verifier, integrity_key=b"f" * 32, require_yara_compile=False)
    active = recovered.status()["active"]
    assert active and active["sequence"] == expected_sequence
    old_present = db.match_ioc_endpoint("malware080.test", now=NOW) is not None
    new_present = db.match_ioc_endpoint("malware080b.test", now=NOW) is not None
    if expected_sequence == 1:
        assert old_present is True and new_present is False
    else:
        assert old_present is False and new_present is True


def test_v080b3_scheduler_is_bounded_and_never_autoactivates(tmp_path):
    scheduler = ThreatCheckScheduler(tmp_path / "Scheduler", integrity_key=b"s" * 32, interval_seconds=1)
    status = scheduler.status(now=NOW)
    assert status["interval_seconds"] == 3600
    assert status["due"] is True
    scheduler.record_failure("fixture failure", now=NOW)
    failed = scheduler.status(now=NOW)
    assert failed["next_due"] == NOW + 3600
    assert failed["auto_stage"] is False and failed["auto_activate"] is False
    scheduler.record_success(now=NOW + 3600)
    ok = scheduler.status(now=NOW + 3600)
    assert ok["failures"] == 0 and ok["cloud_required"] is False


def test_v080b3_protocol_index_validation_is_readonly_and_bounded():
    request = validate_request(_req(
        "threat_index_validate", index=SAFE_THREAT_INDEX_1, signature=SAFE_THREAT_INDEX_1_SIGNATURE
    ))
    assert request.op == "threat_index_validate"
    bad = copy.deepcopy(SAFE_THREAT_INDEX_1)
    bad["packages"] = []
    with pytest.raises(ProtocolError):
        validate_request(_req("threat_index_validate", index=bad, signature=SAFE_THREAT_INDEX_1_SIGNATURE))


def test_v080b3_fixtures_and_runtime_ship_no_private_index_key_material():
    root = Path(__file__).resolve().parents[1]
    paths = [
        root / "tools" / "threat_index_fixture.py",
        root / "sentinel" / "threat_index.py",
        root / "sentinel" / "threat_scheduler.py",
    ]
    forbidden = ["Ed25519PrivateKey", "private_bytes(", "BEGIN PRIVATE KEY", "PRIVATE KEY-----"]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for marker in forbidden:
            assert marker not in text


def test_v080b3_windows_acceptance_contains_beta3_foundation_and_live_gates():
    root = Path(__file__).resolve().parents[1]
    text = (root / "tools" / "windows_acceptance.py").read_text(encoding="utf-8")
    assert "threat-channel-v080-beta3-foundation" in text
    assert "threat-channel-v080-beta3-live" in text
    assert "run_threat_channel_beta3_acceptance" in text


def test_v080b3_release_version_and_notes_are_aligned():
    from sentinel.config import APP_VERSION
    root = Path(__file__).resolve().parents[1]
    assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")
    assert (root / "sentinel" / "__init__.py").read_text(encoding="utf-8").strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in (root / "pyproject.toml").read_text(encoding="utf-8")
    assert (root / "RELEASE-NOTES-v0.9.0-beta.3.md").exists()
