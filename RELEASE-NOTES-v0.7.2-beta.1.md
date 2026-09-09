# BC Sentinel v0.7.2-beta.1 — Web Protection & Anti-Phishing Foundation

## Scope
This beta introduces a local, explainable Web Protection foundation without TLS interception. It extends the accepted v0.7.1-beta.3 service, signed IOC, firewall and reversible-containment architecture.

## New protection capabilities
- Microsoft-Windows-DNS-Client ETW telemetry is added alongside the existing process/file providers, with safe fallback when DNS telemetry is unavailable.
- DNS answers are correlated to later connections only for the same PID and only for a short bounded TTL. There is deliberately no global IP→domain attribution because shared hosting/CDNs make that unsafe.
- Signed `domain` IOC indicators now participate in deterministic web verdicts. Exact domains and subdomains may produce a HIGH/CRITICAL malicious verdict and `containment_recommended`.
- Structural anti-phishing checks cover IDN/Punycode, unusual subdomain depth, very long hostnames, excessive hyphenation, raw-IP URLs and URL userinfo/credentials.
- Local heuristic-only findings are capped below the action threshold: they can request review but cannot automatically block.
- Network events may carry a PID-scoped `remote_domain`; existing signed-IOC Network Intelligence can then correlate domain evidence with the actual process connection.

## Safety boundaries
- No HTTPS MITM, local TLS proxy, root certificate installation or decryption of user traffic.
- No heuristic-only automatic web blocking.
- The Web Protection engine is observe/recommend-only in Beta 1 and never creates firewall rules directly.
- Any future enforcement of a resolved IP must reuse the existing BC-owned BLOCK/containment safety path, with exact qualification, explicit/reversible policy and no third-party/global firewall mutation.

## Security Center / UI
- Protection now exposes Web Protection / Anti-Phishing posture.
- History/Security Center includes a Web Protection Center with recent DNS/web findings and manual domain/URL analysis.
- Signed-domain findings clearly distinguish IOC evidence from local heuristics and expose the recommended action without silently executing it.

## Acceptance
- `tools.web_protection_acceptance` validates signed-domain recommendation, bounded heuristic scoring, PID-scoped DNS correlation and no-MITM/no-auto-block invariants.
- `tools.windows_acceptance` adds critical `web-protection-v072-beta1-foundation` and `web-protection-v072-beta1-live` gates.
- Native Windows live acceptance requires DNS ETW tracking active in the installed Protection Service.
