from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "sentinel" / "threat_index.py"

HELPER = '''    @staticmethod
    def _replace_state_with_retry(source: Path, target: Path, *, attempts: int = 8) -> None:
        """Atomically publish threat-index state while tolerating transient Windows locks.

        Windows antivirus, indexers, or concurrent readers can briefly hold a newly
        written file without FILE_SHARE_DELETE, making os.replace() fail with
        WinError 5/32/33. Retry only those known transient conditions with a bounded
        exponential backoff. Any unrelated or persistent error still fails closed.
        """
        import time

        last_error: OSError | None = None
        retryable = {5, 32, 33}
        total_attempts = max(1, int(attempts))
        for attempt in range(total_attempts):
            try:
                os.replace(source, target)
                return
            except OSError as exc:
                winerror = getattr(exc, "winerror", None)
                errno_value = getattr(exc, "errno", None)
                if winerror not in retryable and errno_value not in retryable:
                    raise
                last_error = exc
                if attempt + 1 >= total_attempts:
                    break
                time.sleep(min(0.05 * (2 ** attempt), 0.8))
        detail = f": {last_error}" if last_error is not None else ""
        raise ThreatIndexError(f"cannot atomically publish threat-index state{detail}")

'''

WRITE_STATE_ANCHOR_RE = re.compile(
    r"(?m)^    def _write_state\(self, body: [^\r\n]+\) -> None:\r?\n"
)
OLD_REPLACE = "        os.replace(tmp, self.state_path)\n"
NEW_REPLACE = "        self._replace_state_with_retry(tmp, self.state_path)\n"


def _verify(text: str) -> None:
    if "def _replace_state_with_retry(" not in text:
        raise RuntimeError("Threat-index atomic replace helper missing after patch")
    if text.count(NEW_REPLACE.strip()) != 1:
        raise RuntimeError("Threat-index state replace call count is not canonical")
    if OLD_REPLACE.strip() in text:
        raise RuntimeError("Unhardened threat-index state os.replace still present")


def apply_compat_patch(path: Path = TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"Threat-index source missing: {path}")

    text = path.read_text(encoding="utf-8")
    if "def _replace_state_with_retry(" in text:
        _verify(text)
        return {"patched": False, "already_compatible": True, "path": str(path)}

    replace_count = text.count(OLD_REPLACE)
    if replace_count != 1:
        raise RuntimeError(
            "Unexpected threat-index source shape: expected exactly one state os.replace call, "
            f"found {replace_count}"
        )

    anchors = list(WRITE_STATE_ANCHOR_RE.finditer(text))
    if len(anchors) != 1:
        raise RuntimeError("Unexpected threat-index source shape: _write_state anchor missing/ambiguous")

    anchor = anchors[0]
    updated = text[: anchor.start()] + HELPER + text[anchor.start() :]
    updated = updated.replace(OLD_REPLACE, NEW_REPLACE, 1)
    _verify(updated)
    path.write_text(updated, encoding="utf-8")
    persisted = path.read_text(encoding="utf-8")
    _verify(persisted)
    return {"patched": True, "already_compatible": False, "path": str(path)}


def main() -> int:
    result = apply_compat_patch()
    if result["patched"]:
        print("v0.11 threat-index Windows compatibility: atomic state replace retry installed")
    else:
        print("v0.11 threat-index Windows compatibility: already canonical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
