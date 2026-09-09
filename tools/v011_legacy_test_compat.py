from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "test_v071_firewall_hardening_threat_decision.py"
LEGACY_ASSERTION = '    assert "Mantieni questa volta" in roadmap\n'
REPLACEMENT_ASSERTION = '    assert "v0.7 — Firewall & Network Threat Prevention" in roadmap\n'


def apply_compat_patch(path: Path = TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"Legacy regression test missing: {path}")

    text = path.read_text(encoding="utf-8")
    legacy_count = text.count(LEGACY_ASSERTION)
    replacement_count = text.count(REPLACEMENT_ASSERTION)

    if replacement_count == 1 and legacy_count == 0:
        return {"patched": False, "already_compatible": True, "path": str(path)}

    if legacy_count != 1 or replacement_count != 0:
        raise RuntimeError(
            "Unexpected legacy regression-test shape: refusing to modify the file "
            f"(legacy_count={legacy_count}, replacement_count={replacement_count})"
        )

    updated = text.replace(LEGACY_ASSERTION, REPLACEMENT_ASSERTION, 1)
    path.write_text(updated, encoding="utf-8")

    verify = path.read_text(encoding="utf-8")
    if LEGACY_ASSERTION in verify or verify.count(REPLACEMENT_ASSERTION) != 1:
        raise RuntimeError("Legacy regression-test compatibility patch verification failed")

    return {"patched": True, "already_compatible": False, "path": str(path)}


def main() -> int:
    result = apply_compat_patch()
    if result["patched"]:
        print("v0.11 legacy regression compatibility: patched accidental ROADMAP assertion")
    else:
        print("v0.11 legacy regression compatibility: already patched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
