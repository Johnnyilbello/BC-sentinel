from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import os
from pathlib import PureWindowsPath
import re
import secrets
import threading
import time
from typing import Any, Callable, Protocol

from .core.events import SecurityEvent

MANAGED_FIREWALL_GROUP = "BC Sentinel Managed Protection"
MANAGED_RULE_PREFIX = "BC Sentinel - "
RULE_ID_RE = re.compile(r"^BCSF-[A-F0-9]{16}$")
ALLOWED_DIRECTIONS = {"outbound", "inbound"}
ALLOWED_PROTOCOLS = {"any", "tcp", "udp"}


class FirewallPolicyError(ValueError):
    pass


@dataclass(slots=True, frozen=True)
class ManagedFirewallRule:
    rule_id: str
    remote_address: str
    direction: str = "outbound"
    protocol: str = "any"
    remote_port: int | None = None
    application_path: str = ""
    reason: str = ""
    incident_id: str = ""
    enabled: bool = True
    created_at: float = 0.0

    @property
    def name(self) -> str:
        return f"{MANAGED_RULE_PREFIX}{self.rule_id}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FirewallBackend(Protocol):
    mode: str

    def status(self) -> dict[str, Any]: ...
    def list_rules(self, *, limit: int = 200) -> list[dict[str, Any]]: ...
    def add_block_rule(self, rule: ManagedFirewallRule) -> dict[str, Any]: ...
    def remove_rule(self, rule_id: str) -> bool: ...
    def set_managed_enabled(self, enabled: bool) -> int: ...
    def list_policy_conflicts(self, expected_rules: list[ManagedFirewallRule], *, limit: int = 100) -> list[dict[str, Any]]: ...


class FirewallDesiredStateStore(Protocol):
    def upsert_firewall_expected_rule(self, rule) -> None: ...
    def list_firewall_expected_rules(self): ...
    def delete_firewall_expected_rule(self, rule_id: str) -> None: ...
    def set_firewall_expected_enabled(self, enabled: bool) -> None: ...


def _canonical_remote_network(value: object) -> tuple[int, int, int] | None:
    raw = str(value or "").strip()
    if not raw or "," in raw:
        return None
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None
    return network.version, int(network.network_address), network.prefixlen


def remote_addresses_equivalent(expected: object, observed: object) -> bool:
    """Compare Windows Firewall host/network forms semantically.

    Windows may round-trip a host as an address, CIDR /32 or a dotted netmask.
    Drift detection must not classify those equivalent representations as a
    policy mutation.
    """
    left = _canonical_remote_network(expected)
    right = _canonical_remote_network(observed)
    return left is not None and left == right


def normalize_remote_address(value: str) -> str:
    raw = str(value or "").strip()
    if not raw or len(raw) > 128 or any(ch.isspace() for ch in raw):
        raise FirewallPolicyError("remote_address is invalid")
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise FirewallPolicyError("remote_address must be an IPv4/IPv6 address or CIDR network") from exc
    if network.prefixlen == 0 or network.is_unspecified or network.is_multicast or network.is_loopback:
        raise FirewallPolicyError("loopback, multicast and unspecified networks cannot be managed by this action")
    min_prefix = 8 if network.version == 4 else 16
    if network.prefixlen < min_prefix:
        raise FirewallPolicyError(f"remote network is too broad for the v0.7 safety policy (minimum /{min_prefix})")
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return str(network)


def normalize_application_path(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if len(raw) > 32768 or "\x00" in raw or "*" in raw or "?" in raw:
        raise FirewallPolicyError("application_path is invalid")
    path = PureWindowsPath(raw)
    if not path.is_absolute() or len(path.drive) != 2 or path.drive[1] != ":":
        raise FirewallPolicyError("application_path must be an absolute local Windows drive path")
    return str(path)


def validate_rule_id(value: str) -> str:
    rule_id = str(value or "").strip().upper()
    if not RULE_ID_RE.fullmatch(rule_id):
        raise FirewallPolicyError("rule_id is invalid")
    return rule_id


def build_block_rule(
    *,
    remote_address: str,
    direction: str = "outbound",
    protocol: str = "any",
    remote_port: int | None = None,
    application_path: str = "",
    reason: str = "",
    incident_id: str = "",
    rule_id: str | None = None,
    enabled: bool = True,
    created_at: float | None = None,
) -> ManagedFirewallRule:
    direction = str(direction or "").strip().lower()
    protocol = str(protocol or "").strip().lower()
    if direction not in ALLOWED_DIRECTIONS:
        raise FirewallPolicyError("direction must be inbound or outbound")
    if protocol not in ALLOWED_PROTOCOLS:
        raise FirewallPolicyError("protocol must be any, tcp or udp")
    if remote_port is not None:
        if isinstance(remote_port, bool) or not isinstance(remote_port, int) or not 1 <= remote_port <= 65535:
            raise FirewallPolicyError("remote_port must be between 1 and 65535")
        if protocol == "any":
            raise FirewallPolicyError("remote_port requires tcp or udp")
    normalized_reason = " ".join(str(reason or "").split())
    normalized_incident = str(incident_id or "").strip()
    if len(normalized_reason) > 256:
        raise FirewallPolicyError("reason is too long")
    if len(normalized_incident) > 128:
        raise FirewallPolicyError("incident_id is too long")
    if normalized_incident and not re.fullmatch(r"[A-Za-z0-9._:-]+", normalized_incident):
        raise FirewallPolicyError("incident_id contains unsupported characters")
    rid = validate_rule_id(rule_id) if rule_id else f"BCSF-{secrets.token_hex(8).upper()}"
    return ManagedFirewallRule(
        rule_id=rid,
        remote_address=normalize_remote_address(remote_address),
        direction=direction,
        protocol=protocol,
        remote_port=remote_port,
        application_path=normalize_application_path(application_path),
        reason=normalized_reason,
        incident_id=normalized_incident,
        enabled=bool(enabled),
        created_at=float(time.time() if created_at is None else created_at),
    )


def _rule_from_mapping(payload: dict[str, Any]) -> ManagedFirewallRule:
    return build_block_rule(
        rule_id=str(payload.get("rule_id") or ""),
        remote_address=str(payload.get("remote_address") or ""),
        direction=str(payload.get("direction") or "outbound"),
        protocol=str(payload.get("protocol") or "any"),
        remote_port=payload.get("remote_port"),
        application_path=str(payload.get("application_path") or ""),
        reason=str(payload.get("reason") or ""),
        incident_id=str(payload.get("incident_id") or ""),
        enabled=bool(payload.get("enabled", True)),
        created_at=float(payload.get("created_at") or 0.0),
    )


class InMemoryFirewallBackend:
    """Deterministic non-Windows/test backend. It never changes host networking."""

    mode = "memory_test"

    def __init__(self):
        self._rules: dict[str, ManagedFirewallRule] = {}
        self._enabled = True
        self._lock = threading.RLock()
        self.policy_conflicts: list[dict[str, Any]] = []

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "available": True,
                "mode": self.mode,
                "managed_group": MANAGED_FIREWALL_GROUP,
                "managed_enabled": bool(self._enabled),
                "managed_rules": len(self._rules),
                "system_firewall": {"development": True},
                "capabilities": [
                    "block_remote", "remove_rule", "managed_enable_disable",
                    "drift_detection", "drift_reconciliation",
                ],
            }

    def list_rules(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            return [rule.to_dict() for rule in list(self._rules.values())[: max(1, min(int(limit), 500))]]

    def list_group_anomalies(self, *, limit: int = 200) -> list[dict[str, Any]]:
        return []

    def list_policy_conflicts(self, expected_rules: list[ManagedFirewallRule], *, limit: int = 100) -> list[dict[str, Any]]:
        return [dict(row) for row in self.policy_conflicts[: max(1, min(int(limit), 100))]]

    def add_block_rule(self, rule: ManagedFirewallRule) -> dict[str, Any]:
        with self._lock:
            if rule.rule_id in self._rules:
                raise FirewallPolicyError("managed firewall rule already exists")
            self._rules[rule.rule_id] = rule
            return rule.to_dict()

    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            return self._rules.pop(validate_rule_id(rule_id), None) is not None

    def set_managed_enabled(self, enabled: bool) -> int:
        with self._lock:
            self._enabled = bool(enabled)
            count = len(self._rules)
            if count:
                self._rules = {
                    rid: ManagedFirewallRule(**{**rule.to_dict(), "enabled": self._enabled})
                    for rid, rule in self._rules.items()
                }
            return count


class FirewallManager:
    """Narrow policy boundary for BC Sentinel-owned Windows Firewall rules.

    v0.7.1 adds desired-state tracking and drift detection. Reconciliation never
    touches non-BC-Sentinel rules, remains BLOCK-only, and requires an explicit
    privileged approval at the service protocol boundary.
    """

    def __init__(
        self,
        backend: FirewallBackend,
        *,
        event_callback: Callable[[SecurityEvent], None] | None = None,
        desired_state_store: FirewallDesiredStateStore | None = None,
    ):
        self.backend = backend
        self.event_callback = event_callback
        self.desired_state_store = desired_state_store
        self._memory_expected: dict[str, ManagedFirewallRule] = {}
        self._status_lock = threading.RLock()
        self._status_cache: dict[str, Any] | None = None
        self._status_cache_until = 0.0
        self._last_drift_fingerprint = ""
        self._last_conflict_fingerprint = ""

    def _invalidate_status(self) -> None:
        with self._status_lock:
            self._status_cache = None
            self._status_cache_until = 0.0

    def status(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._status_lock:
            if self._status_cache is not None and now < self._status_cache_until:
                return dict(self._status_cache)
        status = dict(self.backend.status())
        status["desired_rules"] = len(self._expected_rules())
        with self._status_lock:
            self._status_cache = dict(status)
            self._status_cache_until = now + 1.5
        return status

    def list_rules(self, limit: int = 200) -> list[dict[str, Any]]:
        return list(self.backend.list_rules(limit=max(1, min(int(limit), 500))))

    def _save_expected(self, rule: ManagedFirewallRule) -> None:
        if self.desired_state_store is not None:
            self.desired_state_store.upsert_firewall_expected_rule(rule)
        else:
            self._memory_expected[rule.rule_id] = rule

    def _delete_expected(self, rule_id: str) -> None:
        if self.desired_state_store is not None:
            self.desired_state_store.delete_firewall_expected_rule(rule_id)
        else:
            self._memory_expected.pop(rule_id, None)

    def _set_expected_enabled(self, enabled: bool) -> None:
        if self.desired_state_store is not None:
            self.desired_state_store.set_firewall_expected_enabled(enabled)
        else:
            self._memory_expected = {
                rid: ManagedFirewallRule(**{**rule.to_dict(), "enabled": bool(enabled)})
                for rid, rule in self._memory_expected.items()
            }

    def _expected_rules(self) -> list[ManagedFirewallRule]:
        if self.desired_state_store is None:
            return list(self._memory_expected.values())
        rows = self.desired_state_store.list_firewall_expected_rules()
        result: list[ManagedFirewallRule] = []
        for row in rows:
            # Desired-state corruption is fail-closed. Do not silently discard a
            # malformed protected record and then claim there is no drift.
            result.append(_rule_from_mapping(dict(row)))
        return result

    def block_remote(self, **kwargs) -> dict[str, Any]:
        rule = build_block_rule(**kwargs)
        result = dict(self.backend.add_block_rule(rule))
        try:
            self._save_expected(rule)
        except Exception:
            # Never leave a newly-created managed rule without a desired-state
            # record. Roll back only the exact rule just created.
            try:
                self.backend.remove_rule(rule.rule_id)
            finally:
                self._invalidate_status()
            raise
        self._invalidate_status()
        self._emit("block_remote", rule, score=0)
        return result

    def remove_rule(self, rule_id: str) -> bool:
        rid = validate_rule_id(rule_id)
        existing = next((r for r in self.list_rules(500) if str(r.get("rule_id")) == rid), None)
        removed = bool(self.backend.remove_rule(rid))
        if removed:
            self._delete_expected(rid)
            self._invalidate_status()
            data = existing or {"rule_id": rid}
            event = SecurityEvent(
                category="firewall",
                action="remove_rule",
                source="firewall_policy",
                data=dict(data),
            )
            if self.event_callback:
                self.event_callback(event)
        return removed

    def set_managed_enabled(self, enabled: bool) -> int:
        count = int(self.backend.set_managed_enabled(bool(enabled)))
        self._set_expected_enabled(bool(enabled))
        self._invalidate_status()
        if self.event_callback:
            self.event_callback(SecurityEvent(
                category="firewall",
                action="managed_rules_enabled" if enabled else "managed_rules_disabled",
                source="firewall_policy",
                data={"enabled": bool(enabled), "affected_rules": count},
            ))
        return count

    @staticmethod
    def _normalized_port(value: object) -> int | None:
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return -1

    @classmethod
    def _differences(cls, expected: ManagedFirewallRule, observed: dict[str, Any]) -> list[str]:
        diffs: list[str] = []
        if not remote_addresses_equivalent(expected.remote_address, observed.get("remote_address")):
            diffs.append("remote_address")
        if str(observed.get("direction") or "").casefold() != expected.direction.casefold():
            diffs.append("direction")
        if str(observed.get("protocol") or "").casefold() != expected.protocol.casefold():
            diffs.append("protocol")
        if cls._normalized_port(observed.get("remote_port")) != cls._normalized_port(expected.remote_port):
            diffs.append("remote_port")
        expected_app = str(PureWindowsPath(expected.application_path)).casefold() if expected.application_path else ""
        observed_raw = str(observed.get("application_path") or "").strip()
        observed_app = str(PureWindowsPath(observed_raw)).casefold() if observed_raw else ""
        if expected_app != observed_app:
            diffs.append("application_path")
        if bool(observed.get("enabled")) != bool(expected.enabled):
            diffs.append("enabled")
        return diffs

    def drift_report(self) -> dict[str, Any]:
        expected = {rule.rule_id: rule for rule in self._expected_rules()}
        observed_rows = self.list_rules(500)
        observed = {str(row.get("rule_id") or ""): row for row in observed_rows if row.get("rule_id")}
        issues: list[dict[str, Any]] = []

        for rule_id, rule in expected.items():
            actual = observed.get(rule_id)
            if actual is None:
                issues.append({"type": "missing", "rule_id": rule_id, "expected": rule.to_dict()})
                continue
            diffs = self._differences(rule, actual)
            if diffs:
                kind = "disabled" if diffs == ["enabled"] and rule.enabled else "modified"
                issues.append({
                    "type": kind,
                    "rule_id": rule_id,
                    "differences": diffs,
                    "expected": rule.to_dict(),
                    "observed": dict(actual),
                })

        for rule_id, actual in observed.items():
            if rule_id not in expected:
                issues.append({"type": "untracked_owned", "rule_id": rule_id, "observed": dict(actual)})

        anomalies = []
        inspector = getattr(self.backend, "list_group_anomalies", None)
        if callable(inspector):
            try:
                anomalies = list(inspector(limit=200))
            except Exception as exc:
                anomalies = [{"type": "inspection_error", "detail": str(exc)}]
        for item in anomalies:
            issues.append({"type": "collision", **dict(item)})

        report = {
            "ok": not issues,
            "expected_rules": len(expected),
            "observed_owned_rules": len(observed),
            "issues": issues,
            "reconcilable": sum(1 for x in issues if x.get("type") in {"missing", "disabled", "modified"}),
            "collisions": sum(1 for x in issues if x.get("type") == "collision"),
        }
        fingerprint = repr([
            (
                str(x.get("type") or ""),
                str(x.get("rule_id") or x.get("logical_rule_id") or ""),
                tuple(x.get("differences") or ()),
                str(x.get("name") or ""),
                str(x.get("action") or ""),
            )
            for x in issues
        ]) if issues else ""
        if self.event_callback and fingerprint != self._last_drift_fingerprint:
            if issues:
                self.event_callback(SecurityEvent(
                    category="firewall",
                    action="rule_drift_detected",
                    source="firewall_policy",
                    score=35,
                    reasons=[str(x.get("type") or "drift") for x in issues[:8]],
                    data={"issue_count": len(issues), "issues": issues[:20]},
                ))
            elif self._last_drift_fingerprint:
                self.event_callback(SecurityEvent(
                    category="firewall",
                    action="rule_drift_cleared",
                    source="firewall_policy",
                    data={"issue_count": 0},
                ))
        self._last_drift_fingerprint = fingerprint
        return report

    def policy_conflict_report(self) -> dict[str, Any]:
        expected = self._expected_rules()
        advisories: list[dict[str, Any]] = []
        blocking: list[dict[str, Any]] = []

        # Managed BLOCK rules cannot contradict each other, but exact duplicate
        # scopes are operationally redundant and worth surfacing before the rule
        # set becomes unnecessarily large.
        for index, left in enumerate(expected):
            for right in expected[index + 1:]:
                if (
                    remote_addresses_equivalent(left.remote_address, right.remote_address)
                    and left.direction == right.direction
                    and left.protocol == right.protocol
                    and left.remote_port == right.remote_port
                    and left.application_path.casefold() == right.application_path.casefold()
                    and left.enabled == right.enabled
                ):
                    advisories.append({
                        "type": "redundant_managed_rule",
                        "rule_id": left.rule_id,
                        "other_rule_id": right.rule_id,
                        "effect": "redundant_only",
                    })

        inspector = getattr(self.backend, "list_policy_conflicts", None)
        if callable(inspector):
            try:
                advisories.extend(list(inspector(expected, limit=100)))
            except Exception as exc:
                blocking.append({"type": "inspection_error", "detail": str(exc)})

        anomaly_inspector = getattr(self.backend, "list_group_anomalies", None)
        if callable(anomaly_inspector):
            try:
                for item in anomaly_inspector(limit=100):
                    blocking.append({"type": "managed_group_collision", **dict(item)})
            except Exception as exc:
                blocking.append({"type": "collision_inspection_error", "detail": str(exc)})

        report = {
            "ok": not blocking,
            "blocking_conflicts": blocking,
            "advisories": advisories,
            "blocking_count": len(blocking),
            "advisory_count": len(advisories),
            "expected_rules": len(expected),
        }
        fingerprint = repr((blocking, advisories)) if (blocking or advisories) else ""
        if self.event_callback and fingerprint != self._last_conflict_fingerprint:
            if blocking or advisories:
                self.event_callback(SecurityEvent(
                    category="firewall",
                    action="policy_conflict_detected",
                    source="firewall_policy",
                    score=45 if blocking else 10,
                    reasons=[str(x.get("type") or "conflict") for x in (blocking + advisories)[:8]],
                    data={
                        "blocking_count": len(blocking),
                        "advisory_count": len(advisories),
                        "blocking_conflicts": blocking[:20],
                        "advisories": advisories[:20],
                    },
                ))
            elif self._last_conflict_fingerprint:
                self.event_callback(SecurityEvent(
                    category="firewall",
                    action="policy_conflict_cleared",
                    source="firewall_policy",
                    data={"blocking_count": 0, "advisory_count": 0},
                ))
        self._last_conflict_fingerprint = fingerprint
        return report

    def reconcile_drift(self, *, approved: bool) -> dict[str, Any]:
        if not approved:
            raise FirewallPolicyError("explicit operator approval is required for firewall reconciliation")
        before = self.drift_report()
        expected = {rule.rule_id: rule for rule in self._expected_rules()}
        actions: list[dict[str, Any]] = []

        for issue in before.get("issues", []):
            kind = str(issue.get("type") or "")
            rule_id = str(issue.get("rule_id") or "")
            if kind not in {"missing", "disabled", "modified"} or rule_id not in expected:
                actions.append({"rule_id": rule_id, "type": kind, "status": "not_acted"})
                continue
            rule = expected[rule_id]
            try:
                if kind in {"disabled", "modified"}:
                    removed = self.backend.remove_rule(rule_id)
                    if not removed:
                        raise FirewallPolicyError("owned drifted rule could not be removed safely")
                self.backend.add_block_rule(rule)
                self._emit("rule_restored", rule, score=0)
                actions.append({"rule_id": rule_id, "type": kind, "status": "restored"})
            except Exception as exc:
                actions.append({"rule_id": rule_id, "type": kind, "status": "failed", "detail": str(exc)})

        self._invalidate_status()
        after = self.drift_report()
        return {
            "ok": bool(after.get("ok")) and not any(a.get("status") == "failed" for a in actions),
            "before": before,
            "actions": actions,
            "after": after,
        }

    def _emit(self, action: str, rule: ManagedFirewallRule, *, score: int = 0) -> None:
        if not self.event_callback:
            return
        self.event_callback(SecurityEvent(
            category="firewall",
            action=action,
            source="firewall_policy",
            score=int(score),
            path=rule.application_path,
            reasons=[rule.reason] if rule.reason else [],
            data={
                "rule_id": rule.rule_id,
                "remote_address": rule.remote_address,
                "direction": rule.direction,
                "protocol": rule.protocol,
                "remote_port": rule.remote_port,
                "application_path": rule.application_path,
                "incident_id": rule.incident_id,
                "managed_group": MANAGED_FIREWALL_GROUP,
            },
        ))


def create_firewall_backend() -> FirewallBackend:
    if os.name != "nt":
        return InMemoryFirewallBackend()
    from .firewall_windows import WindowsFirewallBackend
    return WindowsFirewallBackend()
