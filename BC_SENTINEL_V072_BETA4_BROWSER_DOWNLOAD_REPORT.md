# BC Sentinel v0.7.2-beta.4 Development Report

## Browser Download Protection & Web Incident Chain

### Architecture

The Beta 4 download layer is deliberately a provenance/correlation component, not a second malware scanner. `BrowserDownloadCorrelation` observes already-existing BC Sentinel network events and links them to ETW file writes only when:

1. the process executable is an exact known browser executable;
2. the browser PID matches the network observation PID;
3. a normalized domain was already associated with that connection;
4. the observation is still inside the bounded correlation window;
5. the file path is a supported download candidate (Downloads path or browser partial-download extension).

The resulting `BCD-*` record stores origin evidence separately from file verdict evidence.

### Origin/file separation

`origin_score`, `origin_status`, `origin_source`, and `origin_signed_ioc` describe where the file came from. They do not set `file_score` or `file_level`.

The realtime scanner can later update `file_sha256`, `file_score`, and `file_level`. Only the existing Threat Decision policy may perform quarantine/delete for qualified HIGH/CRITICAL file verdicts.

### Execution chain

If a process starts from a path already tracked as a browser download, the process event gains bounded download provenance. This is behavioral incident evidence; signed malicious origin is stronger context but still does not retroactively define the file as malware.

### Service/API/UI

- `web_downloads` — authenticated local read.
- `web_download_detail` — authenticated local read by `BCD-*` id.
- `web_status` reports download-tracking safety invariants.
- Security Center/Web Protection Center shows tracked downloads and detailed origin/file verdict separation.

### Safety limits

- 45-second default browser network→file correlation window.
- bounded in-memory network observation queue.
- max 5,000 persistent download provenance records.
- no automatic destructive action from origin evidence.
- no MITM HTTPS.
- no wildcard browser process classification.
