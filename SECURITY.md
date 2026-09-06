# Security Policy

## Development-stage project

BC Sentinel is currently under active development and is not yet a production-ready endpoint-security product.

During development:

- keep Microsoft Defender and Windows Firewall enabled;
- use harmless fixtures such as EICAR and TEST-NET addresses where possible;
- use disposable virtual machines for higher-risk validation;
- do not expose an everyday workstation to live malware for testing;
- do not assume a beta release provides complete protection against unknown threats.

## Security boundaries

BC Sentinel currently follows these design rules:

- deterministic protection must not depend on AI or cloud availability;
- privileged mutations pass through authenticated local IPC and protected UAC/service boundaries;
- firewall management is limited to BC Sentinel-owned BLOCK rules;
- global Windows Firewall policy and third-party rules are not modified;
- destructive file response is separated from detection and requires protected Threat Decision gates;
- signed IOC/threat-package evidence has higher precedence than older local trust;
- private signing keys are not included in release artifacts;
- current Web Protection does not install a root CA or perform HTTPS MITM.

## Reporting security issues

Until a dedicated public security-reporting channel is established, avoid publishing exploit details for an unresolved BC Sentinel vulnerability in a public issue. If this repository is made public, establish a private security-contact/advisory process before inviting external vulnerability reports.

## Production readiness

A version number marked `beta`, `rc` or development preview should not be interpreted as production certification. BC Sentinel reaches production status only after native acceptance evidence, signed packaging/update infrastructure, compatibility and false-positive testing, rollback procedures and operational runbooks are complete.
