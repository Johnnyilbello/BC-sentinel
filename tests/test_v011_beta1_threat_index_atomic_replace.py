from pathlib import Path

from tools.v011_threat_index_windows_compat import apply_compat_patch


def _baseline_source() -> str:
    return (
        "from pathlib import Path\n"
        "import os\n\n"
        "class ThreatIndexError(RuntimeError):\n"
        "    pass\n\n"
        "class ThreatIndexStore:\n"
        "    def _write_state(self, body: dict[str, object]) -> None:\n"
        "        tmp = self.state_path.with_suffix('.json.tmp')\n"
        "        tmp.write_text('x', encoding='utf-8')\n"
        "        os.replace(tmp, self.state_path)\n"
    )


def test_threat_index_patch_is_idempotent_and_replaces_only_state_publication(tmp_path: Path):
    target = tmp_path / "threat_index.py"
    target.write_text(_baseline_source(), encoding="utf-8")

    first = apply_compat_patch(target)
    second = apply_compat_patch(target)
    text = target.read_text(encoding="utf-8")

    assert first["patched"] is True
    assert second["patched"] is False
    assert text.count("def _replace_state_with_retry(") == 1
    assert text.count("self._replace_state_with_retry(tmp, self.state_path)") == 1
    assert "os.replace(tmp, self.state_path)" not in text
    assert "retryable = {5, 32, 33}" in text
    assert "time.sleep(min(0.05 * (2 ** attempt), 0.8))" in text
    assert "raise ThreatIndexError" in text


def test_threat_index_patch_refuses_ambiguous_source_shape(tmp_path: Path):
    target = tmp_path / "threat_index.py"
    target.write_text(
        _baseline_source().replace(
            "        os.replace(tmp, self.state_path)\n",
            "        os.replace(tmp, self.state_path)\n        os.replace(tmp, self.state_path)\n",
        ),
        encoding="utf-8",
    )

    try:
        apply_compat_patch(target)
    except RuntimeError as exc:
        assert "expected exactly one state os.replace call" in str(exc)
    else:
        raise AssertionError("ambiguous threat-index source shape must fail closed")
