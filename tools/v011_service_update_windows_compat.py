from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'sentinel' / 'service_update.py'
ETW_TARGET = ROOT / 'sentinel' / 'etw_monitor.py'
MARKER = 'def apply_update_transaction('
EXPECTED_DIRECT_REPLACES = 9
DNS_ETW_START_ATTEMPTS = 4
DNS_ETW_START_RETRY_DELAY_SECONDS = 0.25


def apply_compat_patch(path: Path = TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f'service_update.py missing: {path}')
    text = path.read_text(encoding='utf-8')
    marker = text.find(MARKER)
    if marker < 0:
        raise RuntimeError('apply_update_transaction() not found; refusing compatibility patch')

    head = text[:marker]
    tail = text[marker:]
    direct_count = tail.count('os.replace(')
    hardened_count = tail.count('_replace_with_retry(')

    if direct_count == 0 and hardened_count >= EXPECTED_DIRECT_REPLACES:
        return {'patched': False, 'already_compatible': True, 'path': str(path), 'hardened_calls': hardened_count}
    if direct_count != EXPECTED_DIRECT_REPLACES:
        raise RuntimeError(
            'Unexpected service_update directory-promotion shape: '
            f'expected {EXPECTED_DIRECT_REPLACES} direct os.replace calls after apply_update_transaction, got {direct_count}'
        )
    if 'def _replace_with_retry(' not in head:
        raise RuntimeError('Existing bounded replace helper missing; refusing to inject alternate behavior')

    original_tail = text[marker:]
    lines = original_tail.splitlines(keepends=True)
    converted = 0
    out: list[str] = []
    for line in lines:
        if 'os.replace(' in line:
            if line.count('os.replace(') != 1:
                raise RuntimeError('Unexpected multiple os.replace calls on one line')
            before, rest = line.split('os.replace(', 1)
            call, suffix = rest.rsplit(')', 1)
            line = before + '_replace_with_retry(' + call + ', attempts=12, delay=0.05)' + suffix
            converted += 1
        out.append(line)
    if converted != EXPECTED_DIRECT_REPLACES:
        raise RuntimeError(f'Converted {converted} directory replace calls; expected {EXPECTED_DIRECT_REPLACES}')

    updated = head + ''.join(out)
    path.write_text(updated, encoding='utf-8')

    verify = path.read_text(encoding='utf-8')
    verify_tail = verify[verify.find(MARKER):]
    if verify_tail.count('os.replace(') != 0:
        raise RuntimeError('Direct directory os.replace calls remain after compatibility patch')
    if verify_tail.count('_replace_with_retry(') < EXPECTED_DIRECT_REPLACES:
        raise RuntimeError('Not all directory promotions were hardened')
    return {'patched': True, 'already_compatible': False, 'path': str(path), 'hardened_calls': verify_tail.count('_replace_with_retry(')}


def apply_etw_dns_startup_patch(path: Path = ETW_TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f'etw_monitor.py missing: {path}')
    text = path.read_text(encoding='utf-8')
    canonical_marker = 'for dns_attempt in range(DNS_ETW_START_ATTEMPTS):'
    if canonical_marker in text and 'DNS_ETW_START_ATTEMPTS = 4' in text:
        return {'patched': False, 'already_compatible': True, 'path': str(path)}

    old_import = 'from time import monotonic, time\n'
    if old_import not in text:
        raise RuntimeError('Unexpected etw_monitor time import; refusing DNS startup patch')
    text = text.replace(old_import, 'from time import monotonic, sleep, time\n', 1)

    constant_anchor = 'FILE_EVENT_DEDUP_MAX = 4096\n'
    if constant_anchor not in text:
        raise RuntimeError('ETW dedup constant anchor missing; refusing DNS startup patch')
    text = text.replace(
        constant_anchor,
        constant_anchor
        + f'DNS_ETW_START_ATTEMPTS = {DNS_ETW_START_ATTEMPTS}\n'
        + f'DNS_ETW_START_RETRY_DELAY_SECONDS = {DNS_ETW_START_RETRY_DELAY_SECONDS}\n',
        1,
    )

    old_start = '''    def start(self):
        if self.running:
            return True
        if os.name != "nt":
            self.error = "ETW disponibile solo su Windows."
            return False
        try:
            import etw
            base_providers = [
                etw.ProviderInfo("Microsoft-Windows-Kernel-Process", etw.GUID(PROCESS_PROVIDER)),
                etw.ProviderInfo("Microsoft-Windows-Kernel-File", etw.GUID(FILE_PROVIDER)),
            ]
            dns_provider = etw.ProviderInfo("Microsoft-Windows-DNS-Client", etw.GUID(DNS_PROVIDER))
            last_error = ""
            for providers, dns_tracking in ((base_providers + [dns_provider], True), (base_providers, False)):
                try:
                    self._capture = etw.ETW(
                        providers=providers,
                        event_callback=self._on_event,
                        providers_event_id_filters=etw_provider_event_filters(),
                        callback_wait_time=0.003,
                    )
                    self._capture.start()
                    self.available = True
                    self.running = True
                    self.dns_tracking = dns_tracking
                    self.error = last_error if not dns_tracking else ""
                    return True
                except Exception as exc:
                    last_error = str(exc)
                    if self._capture is not None:
                        try:
                            self._capture.stop()
                        except Exception:
                            pass
                    self._capture = None
            raise RuntimeError(last_error or "ETW provider startup failed")
        except Exception as exc:
            self.available = False
            self.running = False
            self.dns_tracking = False
            self.error = str(exc)
            return False
'''

    new_start = '''    def start(self):
        if self.running:
            return True
        if os.name != "nt":
            self.error = "ETW disponibile solo su Windows."
            return False
        try:
            import etw

            def providers(include_dns):
                result = [
                    etw.ProviderInfo("Microsoft-Windows-Kernel-Process", etw.GUID(PROCESS_PROVIDER)),
                    etw.ProviderInfo("Microsoft-Windows-Kernel-File", etw.GUID(FILE_PROVIDER)),
                ]
                if include_dns:
                    result.append(etw.ProviderInfo("Microsoft-Windows-DNS-Client", etw.GUID(DNS_PROVIDER)))
                return result

            last_error = ""
            for dns_attempt in range(DNS_ETW_START_ATTEMPTS):
                try:
                    self._capture = etw.ETW(
                        providers=providers(True),
                        event_callback=self._on_event,
                        providers_event_id_filters=etw_provider_event_filters(),
                        callback_wait_time=0.003,
                    )
                    self._capture.start()
                    self.available = True
                    self.running = True
                    self.dns_tracking = True
                    self.error = ""
                    return True
                except Exception as exc:
                    last_error = str(exc)
                    if self._capture is not None:
                        try:
                            self._capture.stop()
                        except Exception:
                            pass
                    self._capture = None
                    if dns_attempt + 1 < DNS_ETW_START_ATTEMPTS:
                        sleep(DNS_ETW_START_RETRY_DELAY_SECONDS * (dns_attempt + 1))

            try:
                self._capture = etw.ETW(
                    providers=providers(False),
                    event_callback=self._on_event,
                    providers_event_id_filters=etw_provider_event_filters(),
                    callback_wait_time=0.003,
                )
                self._capture.start()
                self.available = True
                self.running = True
                self.dns_tracking = False
                self.error = "DNS ETW unavailable after bounded startup retries: " + last_error
                return True
            except Exception as exc:
                last_error = str(exc)
                if self._capture is not None:
                    try:
                        self._capture.stop()
                    except Exception:
                        pass
                self._capture = None
                raise RuntimeError(last_error or "ETW provider startup failed")
        except Exception as exc:
            self.available = False
            self.running = False
            self.dns_tracking = False
            self.error = str(exc)
            return False
'''
    if old_start not in text:
        raise RuntimeError('Unexpected ETW start() shape; refusing DNS startup patch')
    text = text.replace(old_start, new_start, 1)
    path.write_text(text, encoding='utf-8')

    verify = path.read_text(encoding='utf-8')
    if canonical_marker not in verify or 'DNS_ETW_START_ATTEMPTS = 4' not in verify:
        raise RuntimeError('DNS ETW startup retry patch verification failed')
    return {'patched': True, 'already_compatible': False, 'path': str(path)}


def main() -> int:
    update_result = apply_compat_patch()
    etw_result = apply_etw_dns_startup_patch()
    if update_result['patched']:
        print('v0.11 service-update Windows compatibility: bounded directory replace retry installed')
    else:
        print('v0.11 service-update Windows compatibility: already canonical')
    if etw_result['patched']:
        print('v0.11 ETW Windows compatibility: bounded DNS provider startup retry installed')
    else:
        print('v0.11 ETW Windows compatibility: already canonical')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
