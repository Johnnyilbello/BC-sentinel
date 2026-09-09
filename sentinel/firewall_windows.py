from __future__ import annotations

from contextlib import contextmanager
import gc
import os
from typing import Any

from .firewall_policy import (
    MANAGED_FIREWALL_GROUP,
    MANAGED_RULE_PREFIX,
    FirewallPolicyError,
    ManagedFirewallRule,
    remote_addresses_equivalent,
    validate_rule_id,
)

# Windows Firewall with Advanced Security COM constants.
NET_FW_PROFILE2_DOMAIN = 1
NET_FW_PROFILE2_PRIVATE = 2
NET_FW_PROFILE2_PUBLIC = 4
NET_FW_PROFILE2_ALL = 0x7FFFFFFF
NET_FW_RULE_DIR_IN = 1
NET_FW_RULE_DIR_OUT = 2
NET_FW_ACTION_BLOCK = 0
NET_FW_ACTION_ALLOW = 1
NET_FW_IP_PROTOCOL_TCP = 6
NET_FW_IP_PROTOCOL_UDP = 17
NET_FW_IP_PROTOCOL_ANY = 256
NET_FW_MODIFY_STATE_OK = 0
NET_FW_MODIFY_STATE_GP_OVERRIDE = 1
NET_FW_MODIFY_STATE_NO_EXCEPTIONS = 2


class WindowsFirewallBackend:
    """User-mode Windows Firewall backend using the documented NetFwPolicy2 COM API.

    It owns only rules carrying BC Sentinel's exact group + name prefix and only
    creates BLOCK rules. No global default policy, profile enablement, existing
    third-party rule, or ALLOW rule is modified by this backend.
    """

    mode = "windows_firewall_com"

    @contextmanager
    def _policy(self):
        try:
            import pythoncom
            import win32com.client
        except Exception as exc:  # pragma: no cover - Windows packaging/runtime only
            raise RuntimeError(f"Windows Firewall COM support unavailable: {exc}") from exc
        pythoncom.CoInitialize()
        policy = None
        try:
            policy = win32com.client.Dispatch("HNetCfg.FwPolicy2")
            yield policy
        finally:
            # pywin32 can otherwise defer IUnknown release until after the COM
            # apartment is uninitialized, producing noisy release exceptions.
            policy = None
            gc.collect()
            pythoncom.CoUninitialize()

    @staticmethod
    @contextmanager
    def _materialized_rules(policy):
        """Materialize and release the COM rule enumerator inside its apartment.

        pywin32's lazy IEnumVARIANT wrapper can otherwise survive until after
        CoUninitialize(), which is the source of the noisy ``releasing IUnknown``
        message observed by the native drift acceptance. Plain Python copies are
        produced while every COM proxy is still released before leaving _policy.
        """
        collection = None
        rules = []
        try:
            collection = policy.Rules
            rules = list(collection)
            yield rules
        finally:
            rules.clear()
            rules = []
            collection = None
            gc.collect()

    @staticmethod
    def _rule_id_from_label(value: str) -> str:
        label = str(value or "").strip()
        if not label.startswith(MANAGED_RULE_PREFIX):
            return ""
        candidate = label[len(MANAGED_RULE_PREFIX):].strip().upper()
        try:
            return validate_rule_id(candidate)
        except FirewallPolicyError:
            return ""

    @classmethod
    def _rule_id_from_rule(cls, rule) -> str:
        # INetFwRule.Name is the friendly label on the native COM surface, while
        # PowerShell/CIM may expose an internal GUID as Name and our label as
        # DisplayName. Support both representations so identity is stable across
        # Windows management surfaces and pywin32 dispatch variants.
        for attr in ("Name", "DisplayName"):
            try:
                rule_id = cls._rule_id_from_label(getattr(rule, attr, ""))
            except Exception:
                rule_id = ""
            if rule_id:
                return rule_id
        # beta.2 writes a machine-readable marker into Description. This is a
        # recovery path, not an ownership shortcut: exact group + BLOCK action
        # are still required by _is_owned().
        try:
            description = str(getattr(rule, "Description", "") or "")
        except Exception:
            description = ""
        marker = "bcsentinel-rule-id="
        for part in description.split(";"):
            part = part.strip()
            if part.casefold().startswith(marker):
                candidate = part[len(marker):].strip().upper()
                try:
                    return validate_rule_id(candidate)
                except FirewallPolicyError:
                    return ""
        return ""

    @classmethod
    def _is_owned(cls, rule) -> bool:
        try:
            return (
                str(getattr(rule, "Grouping", "") or "") == MANAGED_FIREWALL_GROUP
                and bool(cls._rule_id_from_rule(rule))
                and int(getattr(rule, "Action", -1)) == NET_FW_ACTION_BLOCK
            )
        except Exception:
            return False

    @staticmethod
    def _profile_states(policy) -> tuple[int, dict[str, bool | None]]:
        current = int(policy.CurrentProfileTypes)
        profiles: dict[str, bool | None] = {}
        for name, flag in (
            ("domain", NET_FW_PROFILE2_DOMAIN),
            ("private", NET_FW_PROFILE2_PRIVATE),
            ("public", NET_FW_PROFILE2_PUBLIC),
        ):
            try:
                profiles[name] = bool(policy.FirewallEnabled(flag))
            except Exception:
                profiles[name] = None
        return current, profiles

    @staticmethod
    def _modify_state_name(value: int) -> str:
        return {
            NET_FW_MODIFY_STATE_OK: "ok",
            NET_FW_MODIFY_STATE_GP_OVERRIDE: "group_policy_override",
            NET_FW_MODIFY_STATE_NO_EXCEPTIONS: "no_exceptions",
        }.get(int(value), f"unknown_{int(value)}")

    def _require_effective_local_policy(self, policy) -> None:
        current, profiles = self._profile_states(policy)
        modify_state = int(policy.LocalPolicyModifyState)
        if modify_state != NET_FW_MODIFY_STATE_OK:
            raise FirewallPolicyError(
                f"local Windows Firewall policy is not fully effective: {self._modify_state_name(modify_state)}"
            )
        if current <= 0:
            raise FirewallPolicyError("Windows Firewall has no active profile")
        active = []
        for name, flag in (("domain", 1), ("private", 2), ("public", 4)):
            if current & flag:
                active.append(name)
                if profiles.get(name) is not True:
                    raise FirewallPolicyError(f"Windows Firewall is disabled for active profile: {name}")
        if not active:
            raise FirewallPolicyError("Windows Firewall active profile could not be determined")

    def status(self) -> dict[str, Any]:
        with self._policy() as policy:
            current, profiles = self._profile_states(policy)
            try:
                modify_state = int(policy.LocalPolicyModifyState)
            except Exception:
                modify_state = -1
            active_names = [name for name, flag in (("domain", 1), ("private", 2), ("public", 4)) if current & flag]
            enforcement_ready = bool(
                modify_state == NET_FW_MODIFY_STATE_OK
                and active_names
                and all(profiles.get(name) is True for name in active_names)
            )
            managed = self._list_rules_from_policy(policy, limit=500)
            return {
                "available": True,
                "mode": self.mode,
                "managed_group": MANAGED_FIREWALL_GROUP,
                "managed_enabled": all(bool(r.get("enabled")) for r in managed) if managed else True,
                "managed_rules": len(managed),
                "current_profile_types": current,
                "active_profiles": active_names,
                "system_firewall": profiles,
                "local_policy_modify_state": self._modify_state_name(modify_state),
                "enforcement_ready": enforcement_ready,
                "capabilities": ["block_remote", "remove_rule", "managed_enable_disable", "drift_detection", "drift_reconciliation"],
                "global_policy_modified": False,
            }

    def _list_rules_from_policy(self, policy, *, limit: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        cap = max(1, min(int(limit), 500))
        rule = None
        with self._materialized_rules(policy) as rules:
            for rule in rules:
                if not self._is_owned(rule):
                    continue
                rule_id = self._rule_id_from_rule(rule)
                if not rule_id:
                    continue
                protocol_value = int(getattr(rule, "Protocol", NET_FW_IP_PROTOCOL_ANY))
                protocol = {
                    NET_FW_IP_PROTOCOL_TCP: "tcp",
                    NET_FW_IP_PROTOCOL_UDP: "udp",
                    NET_FW_IP_PROTOCOL_ANY: "any",
                }.get(protocol_value, str(protocol_value))
                direction = "outbound" if int(getattr(rule, "Direction", 0)) == NET_FW_RULE_DIR_OUT else "inbound"
                remote_port_raw = str(getattr(rule, "RemotePorts", "") or "").strip()
                try:
                    remote_port = int(remote_port_raw) if remote_port_raw and remote_port_raw.isdigit() else None
                except Exception:
                    remote_port = None
                rows.append({
                    "rule_id": rule_id,
                    "name": str(getattr(rule, "Name", "") or ""),
                    "display_name": str(getattr(rule, "DisplayName", "") or ""),
                    "remote_address": str(getattr(rule, "RemoteAddresses", "") or ""),
                    "direction": direction,
                    "protocol": protocol,
                    "remote_port": remote_port,
                    "application_path": str(getattr(rule, "ApplicationName", "") or ""),
                    "enabled": bool(getattr(rule, "Enabled", False)),
                    "description": str(getattr(rule, "Description", "") or ""),
                    "managed_group": MANAGED_FIREWALL_GROUP,
                })
                if len(rows) >= cap:
                    break
            rule = None
        return rows

    def list_rules(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._policy() as policy:
            return self._list_rules_from_policy(policy, limit=limit)

    def list_group_anomalies(self, *, limit: int = 200) -> list[dict[str, Any]]:
        """Return exact-group rules that fail BC Sentinel ownership validation."""
        rows: list[dict[str, Any]] = []
        cap = max(1, min(int(limit), 200))
        with self._policy() as policy:
            rule = None
            with self._materialized_rules(policy) as rules:
                for rule in rules:
                    try:
                        if str(getattr(rule, "Grouping", "") or "") != MANAGED_FIREWALL_GROUP:
                            continue
                    except Exception:
                        continue
                    if self._is_owned(rule):
                        continue
                    try:
                        action = int(getattr(rule, "Action", -1))
                    except Exception:
                        action = -1
                    rows.append({
                        "name": str(getattr(rule, "Name", "") or ""),
                        "display_name": str(getattr(rule, "DisplayName", "") or ""),
                        "logical_rule_id": self._rule_id_from_rule(rule),
                        "action": action,
                        "enabled": bool(getattr(rule, "Enabled", False)),
                        "managed_group": MANAGED_FIREWALL_GROUP,
                        "reason": "exact managed group rule failed closed ownership validation",
                    })
                    if len(rows) >= cap:
                        break
                rule = None
        return rows

    @staticmethod
    def _protocol_overlap(expected: ManagedFirewallRule, observed_protocol: int) -> bool:
        if observed_protocol == NET_FW_IP_PROTOCOL_ANY or expected.protocol == "any":
            return True
        return observed_protocol == {
            "tcp": NET_FW_IP_PROTOCOL_TCP,
            "udp": NET_FW_IP_PROTOCOL_UDP,
        }.get(expected.protocol, -999)

    @staticmethod
    def _remote_overlap(expected: ManagedFirewallRule, observed_remote: str) -> bool:
        raw = str(observed_remote or "").strip()
        # Do not turn generic Windows/third-party ALLOW rules into noisy
        # "conflicts". BLOCK has precedence; only an explicit overlap with the
        # same remote host/network is useful operator context here.
        if not raw or raw in {"*", "Any"}:
            return False
        for part in raw.split(","):
            candidate = part.strip()
            if candidate and remote_addresses_equivalent(expected.remote_address, candidate):
                return True
        return False

    def list_policy_conflicts(
        self,
        expected_rules: list[ManagedFirewallRule],
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Read-only overlap analysis against external ALLOW rules."""
        findings: list[dict[str, Any]] = []
        cap = max(1, min(int(limit), 100))
        with self._policy() as policy:
            candidate = None
            with self._materialized_rules(policy) as rules:
                for candidate in rules:
                    try:
                        if self._is_owned(candidate):
                            continue
                        if not bool(getattr(candidate, "Enabled", False)):
                            continue
                        if int(getattr(candidate, "Action", -1)) != NET_FW_ACTION_ALLOW:
                            continue
                        direction_value = int(getattr(candidate, "Direction", 0))
                        protocol_value = int(getattr(candidate, "Protocol", NET_FW_IP_PROTOCOL_ANY))
                        remote = str(getattr(candidate, "RemoteAddresses", "") or "")
                        app = str(getattr(candidate, "ApplicationName", "") or "").strip()
                        name = str(getattr(candidate, "Name", "") or "")
                        grouping = str(getattr(candidate, "Grouping", "") or "")
                    except Exception:
                        continue
                    for expected in expected_rules:
                        expected_direction = NET_FW_RULE_DIR_OUT if expected.direction == "outbound" else NET_FW_RULE_DIR_IN
                        if direction_value != expected_direction:
                            continue
                        if not self._protocol_overlap(expected, protocol_value):
                            continue
                        if app and expected.application_path and os.path.normcase(app) != os.path.normcase(expected.application_path):
                            continue
                        if not self._remote_overlap(expected, remote):
                            continue
                        findings.append({
                            "type": "external_allow_overlap",
                            "rule_id": expected.rule_id,
                            "external_name": name,
                            "external_group": grouping,
                            "external_remote_address": remote,
                            "external_application_path": app,
                            "effect": "advisory_only_windows_block_precedence_retained",
                        })
                        if len(findings) >= cap:
                            candidate = None
                            return findings
                candidate = None
        return findings

    def add_block_rule(self, rule: ManagedFirewallRule) -> dict[str, Any]:
        with self._policy() as policy:
            self._require_effective_local_policy(policy)
            for existing in self._list_rules_from_policy(policy, limit=500):
                if existing.get("rule_id") == rule.rule_id:
                    raise FirewallPolicyError("managed firewall rule already exists")
            import win32com.client
            fw_rule = win32com.client.Dispatch("HNetCfg.FWRule")
            fw_rule.Name = rule.name
            description_parts = [
                "Managed by BC Sentinel v0.7",
                f"bcsentinel-rule-id={rule.rule_id}",
            ]
            if rule.incident_id:
                description_parts.append(f"incident={rule.incident_id}")
            if rule.reason:
                description_parts.append(f"reason={rule.reason}")
            fw_rule.Description = "; ".join(description_parts)[:1024]
            fw_rule.Grouping = MANAGED_FIREWALL_GROUP
            fw_rule.Enabled = bool(rule.enabled)
            fw_rule.Action = NET_FW_ACTION_BLOCK
            fw_rule.Direction = NET_FW_RULE_DIR_OUT if rule.direction == "outbound" else NET_FW_RULE_DIR_IN
            fw_rule.Profiles = NET_FW_PROFILE2_ALL
            fw_rule.RemoteAddresses = rule.remote_address
            protocol_value = {
                "any": NET_FW_IP_PROTOCOL_ANY,
                "tcp": NET_FW_IP_PROTOCOL_TCP,
                "udp": NET_FW_IP_PROTOCOL_UDP,
            }[rule.protocol]
            fw_rule.Protocol = protocol_value
            if rule.remote_port is not None:
                fw_rule.RemotePorts = str(rule.remote_port)
            if rule.application_path:
                fw_rule.ApplicationName = rule.application_path
            policy.Rules.Add(fw_rule)
            result = rule.to_dict()
            fw_rule = None
            gc.collect()
            return result

    def remove_rule(self, rule_id: str) -> bool:
        rid = validate_rule_id(rule_id)
        with self._policy() as policy:
            target = None
            candidate = None
            native_name = ""
            display_name = ""
            with self._materialized_rules(policy) as rules:
                for candidate in rules:
                    if not self._is_owned(candidate):
                        continue
                    if self._rule_id_from_rule(candidate) == rid:
                        target = candidate
                        native_name = str(getattr(target, "Name", "") or "").strip()
                        display_name = str(getattr(target, "DisplayName", "") or "").strip()
                        break
                candidate = None
                target = None
            if not native_name:
                return False
            try:
                policy.Rules.Remove(native_name)
            except Exception:
                if not display_name or display_name == native_name:
                    raise
                policy.Rules.Remove(display_name)
            gc.collect()
            return True

    def set_managed_enabled(self, enabled: bool) -> int:
        affected = 0
        with self._policy() as policy:
            if enabled:
                self._require_effective_local_policy(policy)
            rule = None
            with self._materialized_rules(policy) as rules:
                for rule in rules:
                    if not self._is_owned(rule):
                        continue
                    rule.Enabled = bool(enabled)
                    affected += 1
                rule = None
        return affected

