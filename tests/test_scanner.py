from pathlib import Path
import pytest
import sentinel.scanner as scanner_mod
from sentinel.scanner import hash_file, shannon_entropy, StaticScanner, EICAR_TEST_STRING, is_exact_eicar

def test_hash(tmp_path):
    p=tmp_path/"a.txt"; p.write_bytes(b"abc")
    assert hash_file(p) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_entropy():
    assert shannon_entropy(b"\x00"*1000) == 0.0
    assert shannon_entropy(bytes(range(256))*4) > 7.9

def test_canonical_eicar_signature_is_recognized_in_memory():
    assert is_exact_eicar(EICAR_TEST_STRING)

def test_eicar_with_trailing_newline_is_recognized_in_memory():
    assert is_exact_eicar(EICAR_TEST_STRING + b"\r\n")

def test_scanner_eicar_flow_without_real_signature_on_disk(tmp_path, monkeypatch):
    marker=b"BC-SENTINEL-HARMLESS-EICAR-SIMULATION"
    p=tmp_path/"eicar-simulation.com"; p.write_bytes(marker)
    original=scanner_mod.is_exact_eicar
    monkeypatch.setattr(scanner_mod,"is_exact_eicar",lambda data: data.rstrip(b"\r\n") == marker)
    report=StaticScanner().scan_file(p)
    assert report.assessment.score == 100
    assert report.assessment.level == "CRITICAL"
    assert len([x for x in report.assessment.reasons if "EICAR" in x]) == 1
    assert original(EICAR_TEST_STRING)

def test_source_code_mentioning_eicar_name_is_not_eicar(tmp_path):
    p=tmp_path/"test_scanner.py"
    p.write_bytes(b'NAME = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"\n')
    r=StaticScanner().scan_file(p)
    assert "EICAR" not in " ".join(r.assessment.reasons)

def test_documentation_mention_fragment_is_not_eicar(tmp_path):
    p=tmp_path/"README.txt"
    p.write_text("Documentation: EICAR-STANDARD-ANTIVIRUS-TEST-FILE is a harmless test.",encoding="utf-8")
    r=StaticScanner().scan_file(p)
    assert r.assessment.score < 85
