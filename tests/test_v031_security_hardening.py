from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from sentinel.config import Settings
from sentinel.correlation import FileProcessCorrelator
from sentinel.database import Database
from sentinel.process_tree import ProcessTree
from sentinel.scanner import StaticScanner
from sentinel.scoring import Signal, assess


def _scanner(tmp_path):
    settings = Settings.defaults()
    settings.exclude_self = False
    settings.reputation_enabled = False
    return StaticScanner(settings, db=Database(tmp_path / "cache.sqlite"))


def test_hash_cache_hits_then_invalidates_after_change(tmp_path):
    scanner = _scanner(tmp_path)
    p = tmp_path / "sample.txt"
    p.write_bytes(b"alpha")

    first = scanner.scan_file(p)
    second = scanner.scan_file(p)
    assert not first.hashes_cached
    assert second.hashes_cached
    assert first.sha256 == second.sha256

    time.sleep(0.002)
    p.write_bytes(b"beta changed")
    third = scanner.scan_file(p)
    assert not third.hashes_cached
    assert third.sha256 != first.sha256


def test_allowlist_directory_is_boundary_safe(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    allowed = tmp_path / "allowed"
    sibling = tmp_path / "allowed-evil"
    allowed.mkdir()
    sibling.mkdir()
    db.add_allowlist("directory", str(allowed))

    assert db.is_allowlisted(str(allowed / "x.exe"))
    assert not db.is_allowlisted(str(sibling / "x.exe"))


def test_allowlist_hash_requires_real_digest(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    with pytest.raises(ValueError):
        db.add_allowlist("hash", "not-a-hash")
    digest = "a" * 64
    db.add_allowlist("hash", digest.upper())
    assert db.is_allowlisted(str(tmp_path / "anything.exe"), sha256=digest)


def test_hash_allowlist_suppresses_exact_content_scan(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    settings = Settings.defaults()
    settings.exclude_self = False
    settings.reputation_enabled = False
    p = tmp_path / "script.ps1"
    p.write_text("powershell -encodedcommand " + "A" * 600, encoding="utf-8")
    scanner = StaticScanner(settings, db=db)
    initial = scanner.scan_file(p)
    db.add_allowlist("hash", initial.sha256)
    allowed = scanner.scan_file(p)
    assert allowed.assessment.score == 0
    assert allowed.assessment.level == "SAFE"


def test_process_pid_reuse_does_not_merge_identity():
    tree = ProcessTree()
    old = tree.observe(42, 1, "old.exe", r"C:\\old.exe", create_time=10.0)
    tree.enrich_identity(42, create_time=10.0, sha256="a" * 64, signer="CN=Old")
    new = tree.observe(42, 2, "new.exe", r"C:\\new.exe", create_time=20.0)
    assert new is not old
    assert new.name == "new.exe"
    assert new.sha256 == ""
    assert new.signer == ""


def test_correlator_returns_parent_hash_signer_and_modified_file():
    tree = ProcessTree()
    node = tree.observe(123, 77, "writer.exe", r"C:\\writer.exe", "writer --go", create_time=12.5)
    tree.enrich_identity(
        123, create_time=12.5, sha256="b" * 64,
        signature_status="Valid", signer="CN=Trusted",
    )
    corr = FileProcessCorrelator(process_tree=tree)
    corr.record(r"C:\\Docs\\changed.txt", 123, action="write")
    attr = corr.attribute(r"C:\\Docs\\changed.txt")

    assert attr.pid == 123
    assert attr.ppid == 77
    assert attr.cmdline == "writer --go"
    assert attr.sha256 == "b" * 64
    assert attr.signature_status == "Valid"
    assert attr.signer == "CN=Trusted"
    assert r"C:\\Docs\\changed.txt" in node.modified_files


def test_weak_heuristics_alone_cannot_become_detection():
    result = assess([
        Signal("a", 12, "a"), Signal("b", 12, "b"),
        Signal("c", 12, "c"), Signal("d", 12, "d"),
    ])
    assert result.score <= 35
    assert result.level in {"LOW", "SAFE"}


def test_independent_medium_signals_get_bounded_synergy():
    result = assess([
        Signal("encoded", 20, "encoded"),
        Signal("obfuscation", 15, "obfuscation"),
        Signal("temp", 10, "temp"),
        Signal("rep", 15, "rep", "local-reputation"),
    ])
    assert 60 <= result.score < 85
    assert result.evidence_count == 4
    assert result.confidence > 0.5


def test_valid_trust_dampens_but_does_not_erase_heuristics():
    base = assess([Signal("encoded", 20, "encoded"), Signal("obfuscation", 15, "obfuscation")])
    trusted = assess([
        Signal("encoded", 20, "encoded"),
        Signal("obfuscation", 15, "obfuscation"),
        Signal("valid_authenticode", -6, "trusted", "local-trust"),
    ])
    assert 0 < trusted.score < base.score


def test_scanner_rejects_symlink_leaf(tmp_path):
    target = tmp_path / "target.exe"
    link = tmp_path / "link.exe"
    target.write_bytes(b"harmless")
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink unavailable")
    scanner = _scanner(tmp_path)
    with pytest.raises(ValueError, match="symlink|reparse"):
        scanner.scan_file(link)


def test_realtime_accepted_executable_events_are_content_scanned_each_time(tmp_path):
    from sentinel.realtime import RealtimeMonitor

    settings = Settings.defaults()
    settings.monitored_dirs = [str(tmp_path)]
    settings.ransomware_dirs = []
    settings.ransomware_enabled = False
    settings.reputation_enabled = False
    db = Database(tmp_path / "rt.sqlite")
    monitor = RealtimeMonitor(settings, db=db)
    p = tmp_path / "repeat.cmd"
    p.write_text("@echo off\nrem harmless\n", encoding="utf-8")

    original = monitor.scanner.scan_file
    calls = {"n": 0}

    def wrapped(path):
        calls["n"] += 1
        return original(path)

    monitor.scanner.scan_file = wrapped
    monitor._scan_when_stable(str(p))
    monitor._scan_when_stable(str(p))

    # The 2-second event debounce still collapses observer storms, but once an
    # executable event reaches the stable-scan stage it is not trusted merely
    # because mtime+size match a previous observation.
    assert calls["n"] == 2


def test_publisher_allowlist_requires_valid_authenticode(tmp_path):
    from sentinel.reputation import ReputationResult

    db = Database(tmp_path / "pub.sqlite")
    db.add_allowlist("publisher", "CN=Trusted Publisher")
    p = tmp_path / "sample.ps1"
    p.write_text(
        "powershell -encodedcommand " + "A" * 600 + "\nInvoke-Expression('x')",
        encoding="utf-8",
    )

    class FakeReputation:
        def __init__(self, status):
            self.db = db
            self.status = status
        def assess_file(self, *args, **kwargs):
            return ReputationResult(
                signature_status=self.status,
                publisher="CN=Trusted Publisher",
                local_trust="unknown",
                score_delta=15 if self.status != "Valid" else 0,
                reasons=["signature context"],
            )

    settings = Settings.defaults()
    settings.exclude_self = False
    invalid = StaticScanner(settings, reputation_engine=FakeReputation("HashMismatch"), db=db).scan_file(p)
    assert invalid.assessment.score > 0

    valid = StaticScanner(settings, reputation_engine=FakeReputation("Valid"), db=db).scan_file(p)
    assert valid.assessment.score == 0


def test_executable_hash_cache_cannot_be_reused_after_timestamp_restoration(tmp_path):
    scanner = _scanner(tmp_path)
    p = tmp_path / "same.cmd"
    first_bytes = b"@echo off\nrem alpha-0000\n"
    second_bytes = b"@echo off\nrem bravo-0000\n"
    assert len(first_bytes) == len(second_bytes)
    p.write_bytes(first_bytes)
    before = p.stat()

    first = scanner.scan_file(p)
    second = scanner.scan_file(p)
    assert not second.hashes_cached

    p.write_bytes(second_bytes)
    os.utime(p, ns=(before.st_atime_ns, before.st_mtime_ns))
    changed = scanner.scan_file(p)

    assert not changed.hashes_cached
    assert changed.sha256 != first.sha256


def test_hash_allowlist_reverifies_cached_bytes_before_bypass(tmp_path):
    db = Database(tmp_path / "hash-trust.sqlite")
    settings = Settings.defaults()
    settings.exclude_self = False
    settings.reputation_enabled = False
    scanner = StaticScanner(settings, db=db)
    p = tmp_path / "document.txt"
    first_bytes = b"trusted-content-A"
    second_bytes = b"changed-content-B"
    assert len(first_bytes) == len(second_bytes)
    p.write_bytes(first_bytes)
    before = p.stat()

    first = scanner.scan_file(p)
    cached = scanner.scan_file(p)
    assert cached.hashes_cached
    db.add_allowlist("hash", first.sha256)

    p.write_bytes(second_bytes)
    os.utime(p, ns=(before.st_atime_ns, before.st_mtime_ns))
    changed = scanner.scan_file(p)

    assert changed.sha256 != first.sha256
    assert (changed.reputation or {}).get("allowlist_kind") != "hash"


def test_process_identity_rehashes_same_metadata_content(tmp_path):
    from sentinel.process_identity import ProcessIdentityResolver

    p = tmp_path / "identity.exe"
    first_bytes = b"MZ" + b"A" * 126
    second_bytes = b"MZ" + b"B" * 126
    p.write_bytes(first_bytes)
    before = p.stat()
    resolver = ProcessIdentityResolver(db=None)
    try:
        first = resolver.resolve(p)
        p.write_bytes(second_bytes)
        os.utime(p, ns=(before.st_atime_ns, before.st_mtime_ns))
        second = resolver.resolve(p)
    finally:
        resolver.shutdown(wait=True)

    assert first.sha256
    assert second.sha256
    assert second.sha256 != first.sha256


def test_file_reputation_cache_is_bound_to_sha256(tmp_path):
    db = Database(tmp_path / "rep.sqlite")
    p = tmp_path / "signed.exe"
    p.write_bytes(b"MZ harmless")
    st = p.stat()
    db.upsert_file_reputation(
        path=str(p), mtime_ns=st.st_mtime_ns, size=st.st_size,
        sha256="a" * 64, signature_status="Valid", publisher="CN=Trusted",
    )
    assert db.get_file_reputation(str(p), st.st_mtime_ns, st.st_size, sha256="a" * 64)
    assert db.get_file_reputation(str(p), st.st_mtime_ns, st.st_size, sha256="b" * 64) is None


def test_database_rechecks_reparse_path_on_each_connection(tmp_path):
    db_path = tmp_path / "sentinel.sqlite"
    db = Database(db_path)
    db.set_setting("probe", "ok")
    real = tmp_path / "real.sqlite"
    db_path.replace(real)
    try:
        db_path.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlink unavailable")

    with pytest.raises(ValueError, match="symlink|reparse"):
        db.get_setting("probe")
