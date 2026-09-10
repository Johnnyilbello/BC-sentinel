from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "test_v071_firewall_hardening_threat_decision.py"
FUNCTION_HEADER = "def test_v071_version_and_release_artifacts_are_consistent():\n"

CANONICAL_BLOCK = '''def test_v071_version_and_release_artifacts_are_consistent():
    from sentinel.config import APP_VERSION
    assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")
    assert Path("sentinel/__init__.py").read_text(encoding="utf-8").strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in Path("pyproject.toml").read_text(encoding="utf-8")
    assert Path("RELEASE-NOTES-v0.7.2-beta.2.md").exists()
    roadmap = Path("ROADMAP.md").read_text(encoding="utf-8")
    assert "Threat Decision Center" in roadmap
    assert "Firewall & Network Threat Prevention" in roadmap

'''

REQUIRED_ANCHORS = (
    'assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")',
    'Path("sentinel/__init__.py")',
    'Path("pyproject.toml")',
    'Path("RELEASE-NOTES-v0.7.2-beta.2.md").exists()',
    'roadmap = Path("ROADMAP.md").read_text(encoding="utf-8")',
    'assert "Threat Decision Center" in roadmap',
)


def _function_bounds(text: str) -> tuple[int, int]:
    start = text.find(FUNCTION_HEADER)
    if start < 0:
        raise RuntimeError("Legacy v0.7 release-artifact regression function not found")

    search_from = start + len(FUNCTION_HEADER)
    next_def = text.find("\ndef ", search_from)
    end = len(text) if next_def < 0 else next_def + 1
    return start, end


def apply_compat_patch(path: Path = TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"Legacy regression test missing: {path}")

    text = path.read_text(encoding="utf-8")
    start, end = _function_bounds(text)
    current = text[start:end]

    if current == CANONICAL_BLOCK:
        return {"patched": False, "already_compatible": True, "path": str(path)}

    missing = [anchor for anchor in REQUIRED_ANCHORS if anchor not in current]
    if missing:
        raise RuntimeError(
            "Unexpected legacy regression-test shape: refusing to normalize the function; "
            f"missing anchors={missing}"
        )

    updated = text[:start] + CANONICAL_BLOCK + text[end:]
    path.write_text(updated, encoding="utf-8")

    verify = path.read_text(encoding="utf-8")
    verify_start, verify_end = _function_bounds(verify)
    if verify[verify_start:verify_end] != CANONICAL_BLOCK:
        raise RuntimeError("Legacy regression-test canonicalization verification failed")

    return {"patched": True, "already_compatible": False, "path": str(path)}


def main() -> int:
    result = apply_compat_patch()
    if result["patched"]:
        print("v0.11 legacy regression compatibility: canonicalized contaminated v0.7 ROADMAP test")
    else:
        print("v0.11 legacy regression compatibility: already canonical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
