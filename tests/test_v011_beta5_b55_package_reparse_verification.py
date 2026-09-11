from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import rescue_technician_report as b55
from tests.test_v011_beta5_b55_technician_report_evidence_package import build_fixture


def test_verify_refuses_listed_file_replaced_by_symlink(tmp_path: Path) -> None:
    target, decision, package = build_fixture(tmp_path)
    b55.create_package(b55.ReportRequest(target, decision, package))
    manifest = json.loads((package / b55.MANIFEST_JSON).read_text(encoding="utf-8"))
    rel = next(row["path"] for row in manifest["files"] if row["path"].startswith("evidence/") and row["path"] != "evidence/b54-decision.json")
    listed = package / rel
    backup = tmp_path / "outside-copy.json"
    backup.write_bytes(listed.read_bytes())
    listed.unlink()
    try:
        listed.symlink_to(backup)
    except OSError:
        pytest.skip("symlink unavailable")
    result = b55.verify_package(package)
    assert result["passed"] is False
    assert any("reparse" in item for item in result["errors"])
