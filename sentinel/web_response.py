from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

WEB_RESPONSE_PROFILE = "v0.10.0-beta.2"
WEB_CONTAINMENT_TTL_MIN = 60
WEB_CONTAINMENT_TTL_MAX = 3600


@dataclass(slots=True, frozen=True)
class WebContainmentQualification:
    eligible: bool
    qualification: str = ""
    reason: str = ""
    signed_evidence: bool = False
    requires_same_pid_network: bool = True
    shared_ip_guard: bool = True
    heuristic_only_blocked: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def qualify_web_containment(
    *,
    source: str,
    score: int,
    block_recommended: bool,
    event_category: str,
    domain: str,
    remote_address: str,
    dns_domain: str = "",
    shared_ip: bool = False,
    signed_network_active: bool = False,
    signed_domain_active: bool = False,
) -> WebContainmentQualification:
    """Pure fail-closed v0.10 Beta2 containment policy.

    The response layer never promotes local heuristics into an address block.
    A persisted finding must be backed by an active signed network/domain IOC.
    Domain IOC containment additionally requires a same-PID observed network
    connection and fresh PID-scoped DNS correlation. Any shared/CDN address is
    rejected at this address-containment layer, even if the UI recommends review.
    """
    src = str(source or "").strip().casefold()
    domain = str(domain or "").strip().rstrip(".").casefold()
    dns_domain = str(dns_domain or "").strip().rstrip(".").casefold()
    remote = str(remote_address or "").strip()

    if int(score or 0) < 70 or not bool(block_recommended):
        return WebContainmentQualification(False, reason="finding_not_qualified")
    if not remote:
        return WebContainmentQualification(False, reason="missing_remote_address")
    if bool(shared_ip):
        return WebContainmentQualification(False, reason="shared_ip_guard")

    if src == "signed_ioc_network":
        if not signed_network_active:
            return WebContainmentQualification(False, reason="signed_network_ioc_inactive")
        if str(event_category or "").casefold() != "network":
            return WebContainmentQualification(False, reason="network_observation_required")
        return WebContainmentQualification(
            True, qualification="signed_network_ioc", reason="active_signed_network_ioc",
            signed_evidence=True, requires_same_pid_network=True,
        )

    if src in {"signed_ioc_domain", "signed_ioc"}:
        if not signed_domain_active:
            return WebContainmentQualification(False, reason="signed_domain_ioc_inactive")
        if str(event_category or "").casefold() != "network":
            return WebContainmentQualification(False, reason="network_observation_required")
        if not domain or dns_domain != domain:
            return WebContainmentQualification(False, reason="same_pid_dns_revalidation_failed")
        return WebContainmentQualification(
            True, qualification="signed_domain_nonshared_ip", reason="signed_domain_same_pid_network",
            signed_evidence=True, requires_same_pid_network=True,
        )

    return WebContainmentQualification(False, reason="heuristic_only_never_blocks")
