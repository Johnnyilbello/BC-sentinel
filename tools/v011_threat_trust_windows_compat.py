from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "sentinel" / "threat_trust.py"

HELPER_MARKER = "bc-sentinel-v011-threat-trust-atomic-retry-v1"
HELPER = f'''# {HELPER_MARKER}\ndef _bcsentinel_threat_trust_replace_with_retry(source: Path, target: Path, *, attempts: int = 8) -> None:\n    \"\"\"Atomically publish trust state while tolerating only transient Windows locks.\n\n    Defender, indexers, or concurrent readers can briefly hold a freshly written\n    file without FILE_SHARE_DELETE, causing os.replace() to fail with WinError\n    5/32/33. Retry only those known transient conditions with bounded backoff.\n    Any unrelated or persistent failure remains fail-closed.\n    \"\"\"\n    import time\n\n    retryable = {{5, 32, 33}}\n    total_attempts = max(1, int(attempts))\n    last_error: OSError | None = None\n    for attempt in range(total_attempts):\n        try:\n            os.replace(source, target)\n            return\n        except OSError as exc:\n            winerror = getattr(exc, \"winerror\", None)\n            errno_value = getattr(exc, \"errno\", None)\n            if winerror not in retryable and errno_value not in retryable:\n                raise\n            last_error = exc\n            if attempt + 1 >= total_attempts:\n                break\n            time.sleep(min(0.05 * (2 ** attempt), 0.8))\n    detail = f\": {{last_error}}\" if last_error is not None else \"\"\n    raise ThreatTrustError(f\"cannot atomically publish threat-trust state{{detail}}\")\n\n\n'''

CLASS_ANCHOR_RE = re.compile(r"(?m)^class ThreatTrustStore(?:\([^\r\n]*\))?:\r?$\n")
DIRECT_REPLACE_RE = re.compile(
    r"(?m)^(?P<indent>[ \t]+)os\.replace\(tmp, self\.(?P<attr>[A-Za-z_][A-Za-z0-9_]*)\)\s*$"
)


def _replace_calls(text: str) -> tuple[str, list[str]]:
    class_match = CLASS_ANCHOR_RE.search(text)
    if not class_match:
        raise RuntimeError("Unexpected threat-trust source shape: ThreatTrustStore class anchor missing")
    if "class ThreatTrustError" not in text[: class_match.start()]:
        raise RuntimeError("Unexpected threat-trust source shape: ThreatTrustError must be defined before ThreatTrustStore")

    prefix = text[: class_match.start()]
    body = text[class_match.start() :]
    attrs: list[str] = []

    def repl(match: re.Match[str]) -> str:
        attr = match.group("attr")
        attrs.append(attr)
        return (
            f'{match.group("indent")}_bcsentinel_threat_trust_replace_with_retry('
            f'tmp, self.{attr})'
        )

    updated_body = DIRECT_REPLACE_RE.sub(repl, body)
    if "keyset_path" not in attrs:
        raise RuntimeError(
            "Unexpected threat-trust source shape: install_keyset keyset_path os.replace call missing; refusing patch"
        )
    return prefix + HELPER + updated_body, attrs


def _verify(text: str) -> dict[str, object]:
    if text.count(HELPER_MARKER) != 1:
        raise RuntimeError("Threat-trust retry helper marker missing/ambiguous")
    if text.count("def _bcsentinel_threat_trust_replace_with_retry(") != 1:
        raise RuntimeError("Threat-trust retry helper definition missing/ambiguous")
    if "_bcsentinel_threat_trust_replace_with_retry(tmp, self.keyset_path)" not in text:
        raise RuntimeError("Threat-trust keyset publication is not hardened")

    class_match = CLASS_ANCHOR_RE.search(text)
    if not class_match:
        raise RuntimeError("ThreatTrustStore class missing after patch")
    remaining = DIRECT_REPLACE_RE.findall(text[class_match.start() :])
    if remaining:
        attrs = ", ".join(sorted({attr for _indent, attr in remaining}))
        raise RuntimeError("Unhardened ThreatTrustStore os.replace call(s) remain: " + attrs)

    hardened = re.findall(
        r"_bcsentinel_threat_trust_replace_with_retry\(tmp, self\.([A-Za-z_][A-Za-z0-9_]*)\)",
        text[class_match.start() :],
    )
    if "keyset_path" not in hardened:
        raise RuntimeError("Threat-trust keyset hardened call missing after patch")
    return {"hardened_targets": sorted(set(hardened)), "hardened_call_count": len(hardened)}


def apply_compat_patch(path: Path = TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"Threat-trust source missing: {path}")

    text = path.read_text(encoding="utf-8")
    if HELPER_MARKER in text:
        info = _verify(text)
        return {
            "patched": False,
            "already_compatible": True,
            "path": str(path),
            **info,
        }

    updated, attrs = _replace_calls(text)
    info = _verify(updated)

    # No partial/corrupt source promotion: validate Python syntax before writing.
    compile(updated, str(path), "exec")
    path.write_text(updated, encoding="utf-8")
    persisted = path.read_text(encoding="utf-8")
    persisted_info = _verify(persisted)
    compile(persisted, str(path), "exec")

    return {
        "patched": True,
        "already_compatible": False,
        "path": str(path),
        "replaced_targets": sorted(set(attrs)),
        **persisted_info,
    }


def main() -> int:
    result = apply_compat_patch()
    targets = ",".join(result.get("hardened_targets") or [])
    if result["patched"]:
        print(
            "v0.11 threat-trust Windows compatibility: bounded atomic replace retry installed"
            + (f" ({targets})" if targets else "")
        )
    else:
        print(
            "v0.11 threat-trust Windows compatibility: already canonical"
            + (f" ({targets})" if targets else "")
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
