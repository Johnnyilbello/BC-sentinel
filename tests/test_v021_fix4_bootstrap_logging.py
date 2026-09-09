from pathlib import Path

def _source():
    return Path("bootstrap.ps1").read_text(encoding="utf-8-sig")

def test_log_path_initialized_before_pytest():
    source=_source()
    init_pos=source.find(
        '$script:LogPath = Join-Path $PSScriptRoot "BC-Sentinel-install.log"'
    )
    test_pos=source.find("Eseguo i test...")
    assert init_pos >= 0
    assert test_pos >= 0
    assert init_pos < test_pos

def test_safe_logger_exists():
    source=_source()
    assert "function Write-BCLog" in source
    assert "-ErrorAction SilentlyContinue" in source
    assert "logging is non-critical" in source

def test_pytest_and_app_streams_use_safe_logger():
    source=_source()
    assert "Write-BCLog -Message ([string]$_)" in source

    helper_start=source.index("function Write-BCLog")
    helper_end=source.index("\n}\n", helper_start)+3
    outside=source[:helper_start]+source[helper_end:]

    assert "Add-Content -Path $script:LogPath -Value $_" not in outside

def test_logging_cannot_be_the_reason_a_build_fails():
    source=_source()
    assert "catch {" in source
    assert "# Intentionally ignored: logging is non-critical." in source
