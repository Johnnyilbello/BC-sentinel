from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "sentinel" / "service_update.py"
ETW_TARGET = ROOT / "sentinel" / "etw_monitor.py"
MARKER = "def apply_update_transaction("
EXPECTED_DIRECT_REPLACES = 9
DNS_ETW_START_ATTEMPTS = 4
DNS_ETW_START_RETRY_DELAY_SECONDS = 0.25
ETW_DNS_SESSION_MODE = "dedicated"
ETW_SESSION_MODE = "split_process_file_dns"


def apply_compat_patch(path: Path = TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"service_update.py missing: {path}")
    text = path.read_text(encoding="utf-8")
    marker = text.find(MARKER)
    if marker < 0:
        raise RuntimeError("apply_update_transaction() not found; refusing compatibility patch")

    head = text[:marker]
    tail = text[marker:]
    direct_count = tail.count("os.replace(")
    hardened_count = tail.count("_replace_with_retry(")

    if direct_count == 0 and hardened_count >= EXPECTED_DIRECT_REPLACES:
        return {
            "patched": False,
            "already_compatible": True,
            "path": str(path),
            "hardened_calls": hardened_count,
        }
    if direct_count != EXPECTED_DIRECT_REPLACES:
        raise RuntimeError(
            "Unexpected service_update directory-promotion shape: "
            f"expected {EXPECTED_DIRECT_REPLACES} direct os.replace calls after apply_update_transaction, got {direct_count}"
        )
    if "def _replace_with_retry(" not in head:
        raise RuntimeError("Existing bounded replace helper missing; refusing to inject alternate behavior")

    lines = tail.splitlines(keepends=True)
    converted = 0
    out: list[str] = []
    for line in lines:
        if "os.replace(" in line:
            if line.count("os.replace(") != 1:
                raise RuntimeError("Unexpected multiple os.replace calls on one line")
            before, rest = line.split("os.replace(", 1)
            call, suffix = rest.rsplit(")", 1)
            line = before + "_replace_with_retry(" + call + ", attempts=12, delay=0.05)" + suffix
            converted += 1
        out.append(line)
    if converted != EXPECTED_DIRECT_REPLACES:
        raise RuntimeError(f"Converted {converted} directory replace calls; expected {EXPECTED_DIRECT_REPLACES}")

    updated = head + "".join(out)
    path.write_text(updated, encoding="utf-8")

    verify = path.read_text(encoding="utf-8")
    verify_tail = verify[verify.find(MARKER):]
    if verify_tail.count("os.replace(") != 0:
        raise RuntimeError("Direct directory os.replace calls remain after compatibility patch")
    if verify_tail.count("_replace_with_retry(") < EXPECTED_DIRECT_REPLACES:
        raise RuntimeError("Not all directory promotions were hardened")
    return {
        "patched": True,
        "already_compatible": False,
        "path": str(path),
        "hardened_calls": verify_tail.count("_replace_with_retry("),
    }


def verify_etw_dns_architecture(path: Path = ETW_TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"etw_monitor.py missing: {path}")
    text = path.read_text(encoding="utf-8")
    required = (
        'ETW_DNS_SESSION_MODE = "dedicated"',
        'ETW_SESSION_MODE = "split_process_file_dns"',
        "self._file_capture = None",
        "self._dns_capture = None",
        "for dns_attempt in range(DNS_ETW_START_ATTEMPTS):",
        'etw.ProviderInfo("Microsoft-Windows-Kernel-Process", etw.GUID(PROCESS_PROVIDER))',
        'etw.ProviderInfo("Microsoft-Windows-Kernel-File", etw.GUID(FILE_PROVIDER))',
        'etw.ProviderInfo("Microsoft-Windows-DNS-Client", etw.GUID(DNS_PROVIDER))',
        "event_id_filters=sorted(KERNEL_FILE_PATH_EVENT_IDS)",
        "DNS ETW dedicated session unavailable after bounded retries:",
        "self._stop_capture(self._file_capture)",
        "self._stop_capture(self._dns_capture)",
    )
    missing = [marker for marker in required if marker not in text]
    if missing:
        raise RuntimeError(
            "Split Process/File/DNS ETW architecture missing or incomplete: "
            + "; ".join(missing)
        )
    if "providers_event_id_filters=" in text:
        raise RuntimeError(
            "Unsupported providers_event_id_filters remains in ETW runtime; pywintrace 0.2.0 compatibility not satisfied"
        )
    return {
        "path": str(path),
        "mode": ETW_SESSION_MODE,
        "dns_mode": ETW_DNS_SESSION_MODE,
        "attempts": DNS_ETW_START_ATTEMPTS,
        "retry_delay_seconds": DNS_ETW_START_RETRY_DELAY_SECONDS,
    }


def main() -> int:
    update_result = apply_compat_patch()
    etw_result = verify_etw_dns_architecture()
    if update_result["patched"]:
        print("v0.11 service-update Windows compatibility: bounded directory replace retry installed")
    else:
        print("v0.11 service-update Windows compatibility: already canonical")
    print(
        "v0.11 ETW Windows compatibility: split Process/File/DNS sessions verified; "
        "pywintrace 0.2.0-safe File event filter active; "
        f"DNS retry budget={etw_result['attempts']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
