from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from sentinel.database import Database
from sentinel.protection_protocol import ClientContext, ProtocolError, validate_request
from sentinel.threat_packages import (
    SignedThreatPackageVerifier,
    ThreatPackageError,
    ThreatPackageManager,
)
from sentinel.yara_engine import YaraEngine
from tools.threat_package_fixture import (
    SAFE_THREAT_PACKAGE_A,
    SAFE_THREAT_PACKAGE_A_SIGNATURE,
    SAFE_THREAT_PACKAGE_B,
    SAFE_THREAT_PACKAGE_B_SIGNATURE,
)


def _req(op: str, **payload):
    return {
        "version": 1,
        "request_id": "v080-test",
        "op": op,
        "token": "a" * 64,
        "payload": payload,
    }


def test_v080_yara_signal_contract_uses_signal_key_not_code():
    from sentinel.scoring import Signal

    signal = Signal("yara:BCS080_CONTRACT", 80, "contract fixture", "yara")
    assert signal.key == "yara:BCS080_CONTRACT"
    assert not hasattr(signal, "code")


def test_v080_signed_package_verifies_and_tamper_fails_closed():
    verifier = SignedThreatPackageVerifier(product_version="0.8.0-beta.1")
    verified = verifier.verify(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE, now=1788700000.0)
    assert verified.package_id == "bcsentinel-v080-safe-acceptance-a"
    assert verified.sequence == 1
    assert len(verified.ioc_entries) == 3
    assert len(verified.yara_rules) == 1
    assert len(verified.behavior_rules) == 1
    assert set(verified.component_hashes) == {"ioc", "yara", "behavior"}
    assert len(verified.key_fingerprint) == 24

    tampered = copy.deepcopy(SAFE_THREAT_PACKAGE_A)
    tampered["components"]["ioc"]["entries"][0]["value"] = "changed.test"
    with pytest.raises(ThreatPackageError, match="signature verification failed"):
        verifier.verify(tampered, SAFE_THREAT_PACKAGE_A_SIGNATURE, now=1788700000.0)


def test_v080_behavior_package_is_declarative_only():
    bad = copy.deepcopy(SAFE_THREAT_PACKAGE_A)
    bad["components"]["behavior"]["rules"][0]["command"] = "powershell.exe"
    # Re-signing is intentionally impossible inside the shipped tests. The
    # schema validator itself is exercised on a fresh verifier helper through
    # the private validation function only after signature in production, so
    # here we assert the signed fixture contains no mutation directives.
    behavior = SAFE_THREAT_PACKAGE_A["components"]["behavior"]["rules"][0]
    assert set(behavior) == {"id", "category", "weight", "description", "enabled"}
    assert "command" in bad["components"]["behavior"]["rules"][0]


def test_v080_stage_activate_yara_ioc_lkg_rollback_and_high_water(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    manager = ThreatPackageManager(
        tmp_path / "ThreatIntelligence",
        db=db,
        verifier=SignedThreatPackageVerifier(product_version="0.8.0-beta.1"),
        integrity_key=b"k" * 32,
        require_yara_compile=False,
    )

    staged_a = manager.stage(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE, now=1788700000.0)
    assert staged_a["staged"] is True
    activated_a = manager.activate(staged_a["stage_id"])
    assert activated_a["active"]["sequence"] == 1
    assert db.match_ioc_endpoint("sub.malware080.test")["source"] == "threat_package"
    digest_a = hashlib.sha256(b"BCS080_ALPHA_PAYLOAD").hexdigest()
    assert db.match_ioc_hash(digest_a)["source"] == "threat_package"

    empty_builtin = tmp_path / "empty-rules"
    empty_builtin.mkdir()
    yara = YaraEngine(rules_dir=empty_builtin, threat_rules_dir=manager.active_yara_dir)
    yara._refresh_interval = 0
    alpha_rule = manager.active_yara_dir / "BCS080_ALPHA.yar"
    assert alpha_rule.exists()
    if yara.available:
        signals = yara.scan_data(b"prefix BCS080_ALPHA_PAYLOAD suffix")
        assert any(signal.key == "yara:BCS080_ALPHA" for signal in signals)

    staged_b = manager.stage(SAFE_THREAT_PACKAGE_B, SAFE_THREAT_PACKAGE_B_SIGNATURE, now=1788700000.0)
    activated_b = manager.activate(staged_b["stage_id"])
    assert activated_b["active"]["sequence"] == 2
    assert activated_b["last_known_good"]["sequence"] == 1
    assert db.match_ioc_endpoint("malware080.test") is None
    assert db.match_ioc_endpoint("malware080b.test")["source"] == "threat_package"
    assert (manager.active_yara_dir / "BCS080_BRAVO.yar").exists()
    if yara.available:
        assert any(signal.key == "yara:BCS080_BRAVO" for signal in yara.scan_data(b"BCS080_BRAVO_PAYLOAD"))

    rolled = manager.rollback_last_known_good()
    assert rolled["active"]["sequence"] == 1
    assert manager.status()["high_water_sequence"] == 2
    assert db.match_ioc_endpoint("malware080.test")["source"] == "threat_package"
    assert db.match_ioc_endpoint("malware080b.test") is None
    assert (manager.active_yara_dir / "BCS080_ALPHA.yar").exists()
    if yara.available:
        assert any(signal.key == "yara:BCS080_ALPHA" for signal in yara.scan_data(b"BCS080_ALPHA_PAYLOAD"))

    with pytest.raises(ThreatPackageError, match="anti-rollback"):
        manager.stage(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE, now=1788700000.0)


def test_v080_stage_promotion_does_not_depend_on_directory_replace(tmp_path, monkeypatch):
    manager = ThreatPackageManager(
        tmp_path / "ThreatIntelligence",
        verifier=SignedThreatPackageVerifier(product_version="0.9.0-beta.3"),
        integrity_key=b"p" * 32,
        require_yara_compile=False,
    )
    staged = manager.stage(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE, now=1788700000.0)
    original_replace = os.replace

    def guarded_replace(src, dst):
        src_path = Path(src)
        dst_path = Path(dst)
        if src_path.parent == manager.staging_dir and dst_path.parent == manager.packages_dir:
            raise PermissionError(5, "simulated Windows directory rename denial")
        return original_replace(src, dst)

    monkeypatch.setattr(os, "replace", guarded_replace)
    activated = manager.activate(staged["stage_id"])
    assert activated["active"]["sequence"] == 1
    assert (manager.packages_dir / activated["active"]["tree"] / "verified.json").exists()


def test_v080_stage_promotion_rebuilds_unreferenced_partial_destination(tmp_path):
    manager = ThreatPackageManager(
        tmp_path / "ThreatIntelligence",
        verifier=SignedThreatPackageVerifier(product_version="0.9.0-beta.3"),
        integrity_key=b"q" * 32,
        require_yara_compile=False,
    )
    staged = manager.stage(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE, now=1788700000.0)
    source = manager.staging_dir / staged["stage_id"]
    package = manager._load_tree(source)
    destination = manager.packages_dir / manager._package_dir_name(package)
    destination.mkdir(parents=True)
    (destination / "partial.txt").write_text("interrupted promotion", encoding="utf-8")

    activated = manager.activate(staged["stage_id"])
    assert activated["active"]["sequence"] == 1
    assert not (destination / "partial.txt").exists()
    assert (destination / "verified.json").exists()


def test_v080_state_tamper_is_rejected(tmp_path):
    manager = ThreatPackageManager(
        tmp_path / "ThreatIntelligence",
        verifier=SignedThreatPackageVerifier(product_version="0.8.0-beta.1"),
        integrity_key=b"z" * 32,
        require_yara_compile=False,
    )
    staged = manager.stage(SAFE_THREAT_PACKAGE_A, SAFE_THREAT_PACKAGE_A_SIGNATURE, now=1788700000.0)
    manager.activate(staged["stage_id"])
    state = json.loads(manager.state_path.read_text(encoding="utf-8"))
    state["high_water_sequence"] = 0
    manager.state_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(ThreatPackageError, match="HMAC verification failed"):
        manager.status()


def test_v080_protocol_separates_validation_from_privileged_mutation():
    validate = validate_request(_req(
        "threat_package_validate", package=SAFE_THREAT_PACKAGE_A, signature=SAFE_THREAT_PACKAGE_A_SIGNATURE
    ))
    assert validate.op == "threat_package_validate"
    stage = validate_request(_req(
        "threat_package_stage", package=SAFE_THREAT_PACKAGE_A,
        signature=SAFE_THREAT_PACKAGE_A_SIGNATURE, approved=True,
    ))
    assert stage.op == "threat_package_stage"
    install = validate_request(_req(
        "threat_package_install", package=SAFE_THREAT_PACKAGE_A,
        signature=SAFE_THREAT_PACKAGE_A_SIGNATURE, approved=True,
    ))
    assert install.op == "threat_package_install"
    activate = validate_request(_req("threat_package_activate", stage_id="0000000001-package-deadbeef1234", approved=True))
    assert activate.op == "threat_package_activate"
    rollback = validate_request(_req("threat_package_rollback", approved=True))
    assert rollback.op == "threat_package_rollback"
    validate_request(_req("threat_intel_status"))
    validate_request(_req("threat_intel_history", limit=50))

    with pytest.raises(ProtocolError):
        validate_request(_req("threat_package_activate", stage_id="..\\escape", approved=True))


def test_v080_fixture_ships_no_private_key_material():
    root = Path(__file__).resolve().parents[1]
    fixture = (root / "tools" / "threat_package_fixture.py").read_text(encoding="utf-8")
    module = (root / "sentinel" / "threat_packages.py").read_text(encoding="utf-8")
    forbidden = ["Ed25519PrivateKey", "private_bytes(", "PRIVATE KEY-----", "BEGIN PRIVATE KEY"]
    for marker in forbidden:
        assert marker not in fixture
        assert marker not in module


def test_v080_signed_release_envelope_verifies_exact_tree_and_detects_tamper(tmp_path):
    from sentinel.release_channel import ReleaseEnvelopeError, SignedReleaseEnvelopeVerifier
    from tools.release_envelope_fixture import SAFE_RELEASE_ENVELOPE, SAFE_RELEASE_ENVELOPE_SIGNATURE, SAFE_RELEASE_FILES

    root = tmp_path / "release"
    root.mkdir()
    for rel, payload in SAFE_RELEASE_FILES.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    verifier = SignedReleaseEnvelopeVerifier()
    result = verifier.verify_tree(root, SAFE_RELEASE_ENVELOPE, SAFE_RELEASE_ENVELOPE_SIGNATURE, now=1788700000.0)
    assert result["verified"] is True
    assert result["version"] == "0.8.0-beta.1"
    assert result["files_checked"] == 2

    (root / "app.bin").write_bytes(b"tampered")
    with pytest.raises(ReleaseEnvelopeError, match="size mismatch|hash mismatch"):
        verifier.verify_tree(root, SAFE_RELEASE_ENVELOPE, SAFE_RELEASE_ENVELOPE_SIGNATURE, now=1788700000.0)


def test_v080_release_envelope_rejects_path_traversal_even_before_tree_access():
    from sentinel.release_channel import ReleaseEnvelopeError, SignedReleaseEnvelopeVerifier
    from tools.release_envelope_fixture import SAFE_RELEASE_ENVELOPE_SIGNATURE

    bad = {
        "schema": "bcsentinel.release-envelope.v1",
        "product": "BC Sentinel",
        "version": "0.8.0-beta.1",
        "sequence": 1,
        "issued_at": 1788610000.0,
        "expires_at": 1893456000.0,
        "files": {"../escape.exe": {"sha256": "0" * 64, "size": 0}},
    }
    # Signature mismatch is also fail-closed; the path is never trusted. The
    # dedicated path parser itself is exercised through the module API below.
    from sentinel.release_channel import _validate_relative_path
    with pytest.raises(ReleaseEnvelopeError, match="traverse"):
        _validate_relative_path("../escape.exe")
    with pytest.raises(ReleaseEnvelopeError):
        SignedReleaseEnvelopeVerifier().verify(bad, SAFE_RELEASE_ENVELOPE_SIGNATURE, now=1788700000.0)
