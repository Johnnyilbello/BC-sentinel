from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "sentinel" / "service_update.py"
ETW_TARGET = ROOT / "sentinel" / "etw_monitor.py"
IDLE_COMPAT_TARGET = ROOT / "sentinel" / "pywintrace_idle.py"
MARKER = "def apply_update_transaction("
EXPECTED_DIRECT_REPLACES = 9
DNS_ETW_START_ATTEMPTS = 4
DNS_ETW_START_RETRY_DELAY_SECONDS = 0.25
ETW_DNS_SESSION_MODE = "dedicated"
ETW_SESSION_MODE = "split_process_file_dns"
ETW_PROVIDER_FILTER_MODE = "provider_side_event_id_v2"
PYWINTRACE_IDLE_IMPORT = "from .pywintrace_idle import install_pywintrace_idle_backoff"
PYWINTRACE_IDLE_CALL = "install_pywintrace_idle_backoff()"


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


def apply_pywintrace_idle_patch(path: Path = ETW_TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"etw_monitor.py missing: {path}")
    if not IDLE_COMPAT_TARGET.is_file():
        raise FileNotFoundError(f"pywintrace idle compatibility module missing: {IDLE_COMPAT_TARGET}")

    text = path.read_text(encoding="utf-8")
    patched = False

    if PYWINTRACE_IDLE_IMPORT not in text:
        import_anchor = "from .web_protection import DNSCorrelationCache, WebProtectionEngine, extract_ip_addresses, normalize_domain\n"
        if text.count(import_anchor) != 1:
            raise RuntimeError("Unexpected etw_monitor import shape; refusing idle-spin compatibility injection")
        text = text.replace(import_anchor, import_anchor + PYWINTRACE_IDLE_IMPORT + "\n", 1)
        patched = True

    if PYWINTRACE_IDLE_CALL not in text:
        start_anchor = "            import etw\n            self.error = \"\"\n"
        if text.count(start_anchor) != 1:
            raise RuntimeError("Unexpected ETW start shape; refusing idle-spin compatibility injection")
        text = text.replace(
            start_anchor,
            "            import etw\n            install_pywintrace_idle_backoff()\n            self.error = \"\"\n",
            1,
        )
        patched = True

    if patched:
        path.write_text(text, encoding="utf-8")

    verify = path.read_text(encoding="utf-8")
    if verify.count(PYWINTRACE_IDLE_IMPORT) != 1:
        raise RuntimeError("pywintrace idle compatibility import missing or duplicated")
    if verify.count(PYWINTRACE_IDLE_CALL) != 1:
        raise RuntimeError("pywintrace idle compatibility call missing or duplicated")

    return {
        "patched": patched,
        "already_compatible": not patched,
        "path": str(path),
    }


def verify_etw_dns_architecture(path: Path = ETW_TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"etw_monitor.py missing: {path}")
    text = path.read_text(encoding="utf-8")
    required = (
        'ETW_DNS_SESSION_MODE = "dedicated"',
        'ETW_SESSION_MODE = "split_process_file_dns"',
        'ETW_PROVIDER_FILTER_MODE = "provider_side_event_id_v2"',
        "PROCESS_EVENT_IDS = frozenset({1, 2})",
        "DNS_EVENT_IDS = frozenset({3006, 3008, 3018, 3020})",
        "KERNEL_FILE_PATH_EVENT_IDS = frozenset({12, 26, 27, 30})",
        "def _make_provider_with_event_id_filter(",
        "EVENT_FILTER_EVENT_ID(common.TRUE, ids).get()",
        "ProviderParameters(0, [descriptor])",
        "params=params.get()",
        "self._provider_filter_keepalive = []",
        "self._file_capture = None",
        "self._dns_capture = None",
        "for dns_attempt in range(DNS_ETW_START_ATTEMPTS):",
        '"Microsoft-Windows-Kernel-Process"',
        '"Microsoft-Windows-Kernel-File"',
        '"Microsoft-Windows-DNS-Client"',
        "event_id_filters=sorted(PROCESS_EVENT_IDS)",
        "event_id_filters=sorted(KERNEL_FILE_PATH_EVENT_IDS)",
        "event_id_filters=sorted(DNS_EVENT_IDS)",
        PYWINTRACE_IDLE_IMPORT,
        PYWINTRACE_IDLE_CALL,
        "DNS ETW dedicated session unavailable after bounded retries:",
        "self._stop_capture(self._file_capture)",
        "self._stop_capture(self._dns_capture)",
    )
    missing = [marker for marker in required if marker not in text]
    if missing:
        raise RuntimeError(
            "Provider-filtered split Process/File/DNS ETW architecture missing or incomplete: "
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
        "provider_filter_mode": ETW_PROVIDER_FILTER_MODE,
        "attempts": DNS_ETW_START_ATTEMPTS,
        "retry_delay_seconds": DNS_ETW_START_RETRY_DELAY_SECONDS,
        "idle_backoff": True,
    }


def main() -> int:
    update_result = apply_compat_patch()
    idle_result = apply_pywintrace_idle_patch()
    etw_result = verify_etw_dns_architecture()
    if update_result["patched"]:
        print("v0.11 service-update Windows compatibility: bounded directory replace retry installed")
    else:
        print("v0.11 service-update Windows compatibility: already canonical")
    if idle_result["patched"]:
        print("v0.11 pywintrace idle compatibility: immediate-success ProcessTrace backoff installed")
    else:
        print("v0.11 pywintrace idle compatibility: already canonical")
    print(
        "v0.11 ETW Windows compatibility: split Process/File/DNS sessions verified; "
        "provider-side Event ID filters active; low-CPU consumer backoff active; "
        f"DNS retry budget={etw_result['attempts']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
