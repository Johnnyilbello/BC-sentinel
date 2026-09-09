# BC Sentinel v0.7.2-beta.4 — Browser Download Protection & Web Incident Chain

## Scope

This beta extends the accepted v0.7.2 Web Protection line from domain/process context into a bounded browser-download provenance chain:

`browser process → domain/IP → file materialization → scanner verdict → execution → incident`.

## Security invariants

- Download origin never overrides the independent file verdict.
- A signed malicious domain can raise provenance priority but cannot by itself quarantine or delete the downloaded file.
- Quarantine/delete remain restricted to the existing HIGH/CRITICAL file Threat Decision path.
- Browser attribution is exact-executable based; signer text alone cannot classify a process as a browser.
- Domain-to-download correlation is same-PID and time bounded.
- Non-browser processes, wrong PIDs, expired observations and unrelated paths do not inherit browser provenance.
- No MITM HTTPS, root certificate, TLS interception or automatic browser traffic blocking is introduced.

## New capabilities

- `BrowserDownloadCorrelation` bounded same-PID network→file correlation.
- Persistent `BCD-*` download records with domain, IP, browser, stage and provenance.
- Independent file-verdict fields (`file_sha256`, `file_score`, `file_level`).
- Realtime scanner verdict updates for previously tracked downloads.
- Download execution evidence is attached to process-start events and may feed the existing incident correlation engine.
- Read-only Protection Service APIs for download list/detail.
- Web Protection Center exposes a Download Protection table and detail view.
- Local database is bounded to 5,000 download-provenance rows.

## Explicit non-goals

- No browser extension yet.
- No download interception/cancellation before browser write.
- No automatic quarantine from URL/domain reputation alone.
- No SSL/TLS interception.
- No claim of native WFP download enforcement.

## Acceptance target

Native Windows release acceptance requires:

- complete pytest suite passing;
- previous Web Protection Beta1/Beta2/Beta3 gates still passing;
- `web-download-v072-beta4-foundation` PASS;
- `web-download-v072-beta4-live` PASS;
- service remains HEALTHY;
- `critical_failures=[]`.
