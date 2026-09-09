from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

from sentinel.service_update import version_key
from sentinel.database import Database
from sentinel.network_intelligence import NetworkReputationEngine
from sentinel.protection_protocol import ClientContext, ProtocolError, validate_request
from sentinel.threat_packages import SignedThreatPackageVerifier, ThreatPackageError, ThreatPackageManager
from sentinel.threat_retrieval import SecureThreatRetriever, ThreatRetrievalError
from sentinel.threat_trust import ThreatKeysetVerifier, ThreatTrustError, ThreatTrustStore
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

NOW = 1788700000.0


def _req(op: str, **payload):
    return {
        "version": 1,
        "request_id": "v080b2-test",
        "op": op,
        "token": "a" * 64,
        "payload": payload,
    }


def _trust(tmp_path: Path) -> ThreatTrustStore:
    return ThreatTrustStore(tmp_path / "Trust", integrity_key=b"t" * 32)


def test_v080b2_root_signed_keyset_verifies_tamper_fails_and_antirollback_holds(tmp_path):
    verifier = ThreatKeysetVerifier()
    verified = verifier.verify(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE, now=NOW)
    assert verified.sequence == 1
    assert verified.keys[0].key_id == "content-2026-a"
    assert len(verified.root_key_fingerprint) == 24

    tampered = copy.deepcopy(SAFE_THREAT_KEYSET_1)
    tampered["keys"][0]["public_key_b64"] = SAFE_THREAT_KEYSET_2["keys"][0]["public_key_b64"]
    with pytest.raises(ThreatTrustError, match="root signature verification failed"):
        verifier.verify(tampered, SAFE_THREAT_KEYSET_1_SIGNATURE, now=NOW)

    trust = _trust(tmp_path)
    one = trust.install_keyset(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE, now=NOW)
    two = trust.install_keyset(SAFE_THREAT_KEYSET_2, SAFE_THREAT_KEYSET_2_SIGNATURE, now=NOW)
    assert one["keyset"]["sequence"] == 1
    assert two["keyset"]["sequence"] == 2
    assert trust.status(now=NOW)["high_water_sequence"] == 2
    assert "content-2026-a" in trust.status(now=NOW)["revoked_key_ids"]
    with pytest.raises(ThreatTrustError, match="anti-rollback"):
        trust.install_keyset(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE, now=NOW)


def test_v080b2_rotated_content_key_and_revocation_are_enforced(tmp_path):
    trust = _trust(tmp_path)
    trust.install_keyset(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE, now=NOW)
    verifier = SignedThreatPackageVerifier(product_version="0.8.0-beta.2", trust_store=trust)
    c = verifier.verify(SAFE_THREAT_PACKAGE_C, SAFE_THREAT_PACKAGE_C_SIGNATURE, now=NOW)
    assert c.signing_key_id == "content-2026-a"
    assert len(c.reputation_entries) == 2

    trust.install_keyset(SAFE_THREAT_KEYSET_2, SAFE_THREAT_KEYSET_2_SIGNATURE, now=NOW)
    with pytest.raises(ThreatPackageError, match="revoked"):
        verifier.verify(SAFE_THREAT_PACKAGE_C, SAFE_THREAT_PACKAGE_C_SIGNATURE, now=NOW)
    d = verifier.verify(SAFE_THREAT_PACKAGE_D, SAFE_THREAT_PACKAGE_D_SIGNATURE, now=NOW)
    assert d.signing_key_id == "content-2026-b"


def test_v080b2_signed_reputation_is_advisory_and_replaced_atomically(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    trust = _trust(tmp_path)
    trust.install_keyset(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE, now=NOW)
    verifier = SignedThreatPackageVerifier(product_version="0.8.0-beta.2", trust_store=trust)
    manager = ThreatPackageManager(
        tmp_path / "ThreatIntelligence", db=db, verifier=verifier,
        integrity_key=b"k" * 32, require_yara_compile=False,
    )
    staged = manager.stage(SAFE_THREAT_PACKAGE_C, SAFE_THREAT_PACKAGE_C_SIGNATURE, now=NOW)
    manager.activate(staged["stage_id"])
    rep = db.match_signed_reputation("sub.badrep080b2.test", now=NOW)
    assert rep and rep["source"] == "signed_reputation" and rep["status"] == "malicious"
    result = NetworkReputationEngine(db).assess_endpoint("badrep080b2.test")
    assert result.source == "signed_reputation"
    assert result.status == "malicious"
    assert 1 <= result.score_delta < 70
    assert manager.status()["signed_reputation_enforcement"] is False

    trust.install_keyset(SAFE_THREAT_KEYSET_2, SAFE_THREAT_KEYSET_2_SIGNATURE, now=NOW)
    staged2 = manager.stage(SAFE_THREAT_PACKAGE_D, SAFE_THREAT_PACKAGE_D_SIGNATURE, now=NOW)
    manager.activate(staged2["stage_id"])
    assert db.match_signed_reputation("badrep080b2.test", now=NOW) is None
    watch = db.match_signed_reputation("watch080b2.test", now=NOW)
    assert watch and watch["status"] == "suspicious"


def test_v080b2_activation_journal_recovers_partial_publish(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    verifier = SignedThreatPackageVerifier(product_version="0.8.0-beta.2")
    base = tmp_path / "ThreatIntelligence"
    manager = ThreatPackageManager(base, db=db, verifier=verifier, integrity_key=b"r" * 32, require_yara_compile=False)
    a = manager.stage(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE, now=NOW)
    manager.activate(a["stage_id"])
    assert db.match_ioc_endpoint("malware080.test", now=NOW)

    b = manager.stage(SAFE_THREAT_PACKAGE_B, SAFE_THREAT_PACKAGE_B_SIGNATURE, now=NOW)
    def crash(phase: str):
        if phase == "after_content_publish":
            raise RuntimeError("simulated activation crash")
    manager.fault_injector = crash
    with pytest.raises(RuntimeError, match="simulated activation crash"):
        manager.activate(b["stage_id"])
    assert manager.activation_journal_path.exists()
    assert db.match_ioc_endpoint("malware080b.test", now=NOW)

    recovered = ThreatPackageManager(
        base, db=db, verifier=verifier, integrity_key=b"r" * 32, require_yara_compile=False,
    )
    assert not recovered.activation_journal_path.exists()
    assert db.match_ioc_endpoint("malware080.test", now=NOW)
    assert db.match_ioc_endpoint("malware080b.test", now=NOW) is None
    assert recovered.last_recovery and recovered.last_recovery["action"] == "rolled_back_partial_activation"


def test_v080b2_recovery_confirms_commit_if_state_was_written(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    verifier = SignedThreatPackageVerifier(product_version="0.8.0-beta.2")
    base = tmp_path / "ThreatIntelligence"
    manager = ThreatPackageManager(base, db=db, verifier=verifier, integrity_key=b"q" * 32, require_yara_compile=False)
    a = manager.stage(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE, now=NOW)
    manager.activate(a["stage_id"])
    b = manager.stage(SAFE_THREAT_PACKAGE_B, SAFE_THREAT_PACKAGE_B_SIGNATURE, now=NOW)
    def crash(phase: str):
        if phase == "after_state_commit":
            raise RuntimeError("simulated post-commit crash")
    manager.fault_injector = crash
    with pytest.raises(RuntimeError):
        manager.activate(b["stage_id"])
    recovered = ThreatPackageManager(base, db=db, verifier=verifier, integrity_key=b"q" * 32, require_yara_compile=False)
    assert recovered.status()["active"]["sequence"] == 2
    assert recovered.last_recovery and recovered.last_recovery["action"] == "commit_confirmed"


def test_v080b2_secure_retrieval_is_pinned_bounded_and_never_autoactivates():
    cert = b"BC Sentinel harmless pinned certificate fixture"
    pin = hashlib.sha256(cert).hexdigest()
    body = b'{"package":{"schema":"fixture"},"signature":"fixture"}'
    digest = hashlib.sha256(body).hexdigest()

    def transport(url: str, max_bytes: int, timeout: float):
        assert max_bytes == 256 * 1024
        return {"status": 200, "certificate_der": cert, "body": body, "content_type": "application/json"}

    retriever = SecureThreatRetriever(
        allowed_hosts={"updates.bcsentinel.test"},
        certificate_pins={"updates.bcsentinel.test": {pin}},
        transport=transport,
    )
    result = retriever.fetch("https://updates.bcsentinel.test/threat/current.json", expected_sha256=digest)
    assert result.sha256 == digest
    assert result.json_object()["package"]["schema"] == "fixture"
    policy = retriever.policy()
    assert policy["auto_stage"] is False and policy["auto_activate"] is False and policy["cloud_required"] is False

    with pytest.raises(ThreatRetrievalError, match="HTTPS"):
        retriever.fetch("http://updates.bcsentinel.test/threat/current.json")
    with pytest.raises(ThreatRetrievalError, match="credentials"):
        retriever.fetch("https://user:pass@updates.bcsentinel.test/threat/current.json")
    with pytest.raises(ThreatRetrievalError, match="not allowlisted"):
        retriever.fetch("https://other.test/threat/current.json")
    with pytest.raises(ThreatRetrievalError, match="hash mismatch"):
        retriever.fetch("https://updates.bcsentinel.test/threat/current.json", expected_sha256="0" * 64)

    bad_pin = SecureThreatRetriever(
        allowed_hosts={"updates.bcsentinel.test"},
        certificate_pins={"updates.bcsentinel.test": {"0" * 64}},
        transport=transport,
    )
    with pytest.raises(ThreatRetrievalError, match="pin verification failed"):
        bad_pin.fetch("https://updates.bcsentinel.test/threat/current.json")


def test_v080b2_protocol_keeps_keyset_validation_readonly_and_install_privileged():
    validate = validate_request(_req(
        "threat_keyset_validate", keyset=SAFE_THREAT_KEYSET_1, signature=SAFE_THREAT_KEYSET_1_SIGNATURE
    ))
    assert validate.op == "threat_keyset_validate"
    install = validate_request(_req(
        "threat_keyset_install", keyset=SAFE_THREAT_KEYSET_1,
        signature=SAFE_THREAT_KEYSET_1_SIGNATURE, approved=True,
    ))
    assert install.op == "threat_keyset_install"
    with pytest.raises(ProtocolError):
        validate_request(_req("threat_keyset_install", keyset=SAFE_THREAT_KEYSET_1, signature=SAFE_THREAT_KEYSET_1_SIGNATURE))


def test_v080b2_fixtures_ship_no_private_key_material():
    root = Path(__file__).resolve().parents[1]
    paths = [
        root / "tools" / "threat_keyset_fixture.py",
        root / "tools" / "threat_package_beta2_fixture.py",
        root / "sentinel" / "threat_trust.py",
    ]
    forbidden = ["Ed25519PrivateKey", "private_bytes(", "BEGIN PRIVATE KEY", "PRIVATE KEY-----"]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for marker in forbidden:
            assert marker not in text


def test_v080b2_release_version_and_notes_are_aligned():
    from sentinel.config import APP_VERSION
    root = Path(__file__).resolve().parents[1]
    assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")
    assert (root / "sentinel" / "__init__.py").read_text(encoding="utf-8").strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in (root / "pyproject.toml").read_text(encoding="utf-8")
    assert (root / "RELEASE-NOTES-v0.9.0-beta.3.md").exists()


def test_v080b2_status_marks_active_package_signer_revoked(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    trust = _trust(tmp_path)
    trust.install_keyset(SAFE_THREAT_KEYSET_1, SAFE_THREAT_KEYSET_1_SIGNATURE, now=NOW)
    verifier = SignedThreatPackageVerifier(product_version="0.8.0-beta.2", trust_store=trust)
    manager = ThreatPackageManager(tmp_path / "ThreatIntelligence", db=db, verifier=verifier, integrity_key=b"m" * 32, require_yara_compile=False)
    staged = manager.stage(SAFE_THREAT_PACKAGE_C, SAFE_THREAT_PACKAGE_C_SIGNATURE, now=NOW)
    manager.activate(staged["stage_id"])
    assert manager.status()["active_signer_revoked"] is False
    trust.install_keyset(SAFE_THREAT_KEYSET_2, SAFE_THREAT_KEYSET_2_SIGNATURE, now=NOW)
    assert manager.status()["active_signer_revoked"] is True


def test_v080b2_windows_acceptance_contains_beta2_foundation_and_live_gates():
    root = Path(__file__).resolve().parents[1]
    text = (root / "tools" / "windows_acceptance.py").read_text(encoding="utf-8")
    assert "threat-channel-v080-beta2-foundation" in text
    assert "threat-channel-v080-beta2-live" in text
    assert "run_threat_channel_beta2_acceptance" in text
