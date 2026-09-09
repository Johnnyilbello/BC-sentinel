from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.service_update import version_key
from sentinel.config import APP_VERSION
from sentinel.firewall_policy import (
    FirewallManager,
    FirewallPolicyError,
    InMemoryFirewallBackend,
    MANAGED_FIREWALL_GROUP,
    MANAGED_RULE_PREFIX,
    build_block_rule,
    normalize_application_path,
    normalize_remote_address,
    validate_rule_id,
)
from sentinel.protection_protocol import ClientContext, ProtocolError, build_request
from sentinel.protection_service_core import ProtectionServiceCore


SECRET = "f" * 64
STANDARD = ClientContext(
    local=True,
    authenticated=True,
    is_admin=False,
    sid="S-1-5-21-700",
    session_id=1,
    transport="test",
    process_id=700,
)
ADMIN = ClientContext(
    local=True,
    authenticated=True,
    is_admin=True,
    sid="S-1-5-21-700",
    session_id=1,
    transport="test",
    process_id=701,
)


class _Audit:
    def append(self, record):
        pass


class _Events:
    sequence = 0
    def since(self, seq, limit):
        return []


class FirewallRuntimeStub:
    def __init__(self):
        self.secret = SECRET
        self.events = _Events()
        self.firewall = FirewallManager(InMemoryFirewallBackend())
        self.audit_writer = _Audit()
        self._hardening_status = {"ok": True, "mode": "development"}

    def status(self):
        return {
            "service": "BCSentinelProtection",
            "health": "HEALTHY",
            "protection_enabled": True,
            "network": True,
            "firewall": self.firewall.status(),
        }

    def firewall_status(self):
        return self.firewall.status()

    def firewall_rules(self, limit=200):
        return self.firewall.list_rules(limit)

    def firewall_block_remote(self, payload):
        return self.firewall.block_remote(
            remote_address=payload["remote_address"],
            direction=payload["direction"],
            protocol=payload["protocol"],
            remote_port=payload.get("remote_port"),
            application_path=payload.get("application_path", ""),
            reason=payload.get("reason", ""),
            incident_id=payload.get("incident_id", ""),
        )

    def firewall_remove_rule(self, rule_id):
        return self.firewall.remove_rule(rule_id)

    def firewall_set_managed_enabled(self, enabled):
        return self.firewall.set_managed_enabled(enabled)


def _core():
    core = ProtectionServiceCore(FirewallRuntimeStub(), secret=SECRET)
    core._audit = lambda *args, **kwargs: None
    core._audit_broker = lambda *args, **kwargs: None
    return core


def test_v070_remote_address_canonicalization():
    assert normalize_remote_address("203.0.113.7") == "203.0.113.7"
    assert normalize_remote_address("203.0.113.7/24") == "203.0.113.0/24"
    assert normalize_remote_address("2001:db8::1/64") == "2001:db8::/64"


@pytest.mark.parametrize("value", ["", "127.0.0.1", "::1", "0.0.0.0/0", "0.0.0.0/1", "::/8", "224.0.0.1", "not-an-ip"])
def test_v070_remote_address_rejects_unsafe_or_invalid_values(value):
    with pytest.raises(FirewallPolicyError):
        normalize_remote_address(value)


def test_v070_application_path_is_absolute_and_wildcard_free():
    assert normalize_application_path(r"C:\Program Files\Browser\browser.exe").lower().endswith("browser.exe")
    with pytest.raises(FirewallPolicyError):
        normalize_application_path(r"Browser\browser.exe")
    with pytest.raises(FirewallPolicyError):
        normalize_application_path(r"C:\Program Files\*\browser.exe")
    with pytest.raises(FirewallPolicyError):
        normalize_application_path(r"\\server\share\browser.exe")


def test_v070_rule_builder_is_block_only_policy_shape():
    rule = build_block_rule(
        remote_address="198.51.100.25",
        direction="outbound",
        protocol="tcp",
        remote_port=443,
        reason="acceptance",
        incident_id="BCI-TEST",
        rule_id="BCSF-0123456789ABCDEF",
    )
    assert rule.rule_id == "BCSF-0123456789ABCDEF"
    assert rule.name == MANAGED_RULE_PREFIX + rule.rule_id
    assert rule.remote_address == "198.51.100.25"
    assert rule.protocol == "tcp"
    assert rule.remote_port == 443


def test_v070_rule_builder_rejects_port_with_any_protocol():
    with pytest.raises(FirewallPolicyError):
        build_block_rule(remote_address="198.51.100.1", protocol="any", remote_port=443)


def test_v070_rule_id_namespace_is_closed():
    assert validate_rule_id("bcsf-0123456789abcdef") == "BCSF-0123456789ABCDEF"
    with pytest.raises(FirewallPolicyError):
        validate_rule_id("Windows Defender Firewall")


def test_v070_memory_backend_manages_only_its_rules_and_toggle():
    backend = InMemoryFirewallBackend()
    manager = FirewallManager(backend)
    rule = manager.block_remote(
        remote_address="192.0.2.77",
        protocol="udp",
        remote_port=53,
        reason="test",
        rule_id="BCSF-1111111111111111",
    )
    assert rule["rule_id"] == "BCSF-1111111111111111"
    assert manager.status()["managed_rules"] == 1
    assert manager.set_managed_enabled(False) == 1
    assert manager.list_rules()[0]["enabled"] is False
    assert manager.remove_rule(rule["rule_id"]) is True
    assert manager.status()["managed_rules"] == 0


def test_v070_protocol_rejects_unknown_firewall_payload_fields():
    with pytest.raises(ProtocolError) as exc:
        build_request(
            "firewall_block_remote",
            SECRET,
            remote_address="192.0.2.1",
            approved=True,
            shell="cmd.exe",
        )
    assert exc.value.code == "invalid_payload"


def test_v070_protocol_requires_approval_field():
    with pytest.raises(ProtocolError) as exc:
        build_request("firewall_block_remote", SECRET, remote_address="192.0.2.1")
    assert exc.value.code == "invalid_payload"


def test_v070_firewall_read_ops_are_available_to_authenticated_standard_client():
    core = _core()
    status = core.dispatch(build_request("firewall_status", SECRET), STANDARD)
    rules = core.dispatch(build_request("firewall_rules", SECRET, limit=10), STANDARD)
    assert status["ok"] is True
    assert status["firewall"]["managed_group"] == MANAGED_FIREWALL_GROUP
    assert rules["ok"] is True and rules["rules"] == []


def test_v070_direct_firewall_mutation_requires_admin():
    core = _core()
    request = build_request(
        "firewall_block_remote",
        SECRET,
        remote_address="192.0.2.50",
        approved=True,
    )
    blocked = core.dispatch(request, STANDARD)
    assert blocked["ok"] is False
    assert blocked["error"]["code"] == "admin_required"


def test_v070_admin_firewall_mutation_still_requires_explicit_approval():
    core = _core()
    result = core.dispatch(
        build_request(
            "firewall_block_remote",
            SECRET,
            remote_address="192.0.2.51",
            approved=False,
        ),
        ADMIN,
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "approval_required"
    assert core.runtime.firewall_rules() == []


def test_v070_admin_can_add_and_remove_owned_block_rule():
    core = _core()
    added = core.dispatch(
        build_request(
            "firewall_block_remote",
            SECRET,
            remote_address="192.0.2.52",
            direction="outbound",
            protocol="tcp",
            remote_port=443,
            approved=True,
            reason="manual containment",
            incident_id="BCI-TEST-070",
        ),
        ADMIN,
    )
    assert added["ok"] is True
    rule_id = added["rule"]["rule_id"]
    assert rule_id.startswith("BCSF-")
    removed = core.dispatch(
        build_request("firewall_remove_rule", SECRET, rule_id=rule_id, approved=True),
        ADMIN,
    )
    assert removed["ok"] is True
    assert core.runtime.firewall_rules() == []


def test_v070_standard_user_can_broker_one_exact_firewall_action():
    core = _core()
    prepared = core.dispatch(
        build_request(
            "prepare_privileged_action",
            SECRET,
            action="firewall_block_remote",
            payload={
                "remote_address": "192.0.2.53",
                "direction": "outbound",
                "protocol": "any",
                "approved": True,
                "reason": "broker test",
            },
        ),
        STANDARD,
    )
    assert prepared["ok"] is True
    executed = core.dispatch(
        build_request("execute_privileged_ticket", SECRET, ticket_id=prepared["ticket_id"]),
        ADMIN,
    )
    assert executed["ok"] is True
    assert executed["action_ok"] is True
    result = core.dispatch(
        build_request("privileged_ticket_result", SECRET, ticket_id=prepared["ticket_id"]),
        STANDARD,
    )
    assert result["ok"] is True and result["pending"] is False
    assert result["action_result"]["rule"]["remote_address"] == "192.0.2.53"


def test_v070_managed_toggle_does_not_touch_global_firewall_contract():
    core = _core()
    added = core.dispatch(
        build_request("firewall_block_remote", SECRET, remote_address="192.0.2.54", approved=True),
        ADMIN,
    )
    assert added["ok"]
    toggled = core.dispatch(
        build_request("firewall_set_managed_enabled", SECRET, enabled=False, approved=True),
        ADMIN,
    )
    assert toggled["ok"] is True
    assert toggled["affected_rules"] == 1
    assert core.runtime.firewall_rules()[0]["enabled"] is False


def test_v070_windows_backend_is_narrow_and_has_no_shell_or_global_firewall_toggle():
    source = Path("sentinel/firewall_windows.py").read_text(encoding="utf-8")
    assert "HNetCfg.FwPolicy2" in source
    assert "HNetCfg.FWRule" in source
    assert "NET_FW_ACTION_BLOCK" in source
    assert "MANAGED_FIREWALL_GROUP" in source
    assert "subprocess" not in source
    assert "os.system" not in source
    assert "shell=True" not in source
    assert "netsh" not in source.casefold()
    assert "FirewallEnabled(flag) =" not in source
    assert "DefaultInboundAction =" not in source
    assert "DefaultOutboundAction =" not in source


def test_v070_build_collects_windows_firewall_com_runtime():
    source = Path("BUILD-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert '"--hidden-import", "win32com.client"' in source
    assert '"--hidden-import", "pythoncom"' in source


def test_v070_client_exposes_firewall_methods_through_privileged_broker():
    source = Path("sentinel/protection_client.py").read_text(encoding="utf-8")
    assert "def firewall_status" in source
    assert "def firewall_rules" in source
    assert 'self._privileged_request("firewall_block_remote"' in source
    assert 'self._privileged_request(\n            "firewall_remove_rule"' in source


def test_v070_version_consistency():
    assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")
    assert Path("sentinel/__init__.py").read_text(encoding="utf-8").strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in Path("pyproject.toml").read_text(encoding="utf-8")


def test_v070_legacy_monitor_pause_does_not_silently_disable_firewall_rules():
    source = Path("sentinel/protection_service_core.py").read_text(encoding="utf-8")
    assert 'if name in {"self_protection", "firewall"}' in source
    assert "firewall_set_managed_enabled" in source


def test_v070_incident_link_is_persisted_for_firewall_containment():
    source = Path("sentinel/protection_service_core.py").read_text(encoding="utf-8")
    assert 'action="firewall_block_remote"' in source
    assert "record_incident_action" in source


def test_v070_windows_backend_requires_effective_local_policy():
    from sentinel.firewall_windows import (
        NET_FW_MODIFY_STATE_GP_OVERRIDE,
        NET_FW_MODIFY_STATE_OK,
        NET_FW_PROFILE2_PRIVATE,
        WindowsFirewallBackend,
    )

    class FakePolicy:
        CurrentProfileTypes = NET_FW_PROFILE2_PRIVATE
        LocalPolicyModifyState = NET_FW_MODIFY_STATE_OK

        def __init__(self, enabled=True):
            self.enabled = enabled

        def FirewallEnabled(self, profile):
            return self.enabled

    backend = WindowsFirewallBackend()
    backend._require_effective_local_policy(FakePolicy(enabled=True))

    disabled = FakePolicy(enabled=False)
    with pytest.raises(FirewallPolicyError, match="disabled for active profile"):
        backend._require_effective_local_policy(disabled)

    gp = FakePolicy(enabled=True)
    gp.LocalPolicyModifyState = NET_FW_MODIFY_STATE_GP_OVERRIDE
    with pytest.raises(FirewallPolicyError, match="group_policy_override"):
        backend._require_effective_local_policy(gp)


def test_v070_windows_backend_source_checks_enforcement_before_add():
    source = Path("sentinel/firewall_windows.py").read_text(encoding="utf-8")
    assert "LocalPolicyModifyState" in source
    assert "FirewallEnabled" in source
    assert "_require_effective_local_policy(policy)" in source
    assert '"enforcement_ready"' in source


def test_v070_live_acceptance_requires_effective_firewall_policy():
    source = Path("tools/windows_acceptance.py").read_text(encoding="utf-8")
    assert 'firewall.get("enforcement_ready") is True' in source
    assert "local_policy_modify_state" in source


def test_v070_firewall_acceptance_requires_enforcement_ready():
    source = Path("tools/firewall_acceptance.py").read_text(encoding="utf-8")
    assert 'firewall_before.get("enforcement_ready") is not True' in source
    assert 'firewall_after.get("enforcement_ready") is True' in source
    assert "will not override Group Policy" in source


def test_v070_beta2_windows_identity_accepts_cim_guid_plus_display_name():
    from sentinel.firewall_windows import NET_FW_ACTION_BLOCK, WindowsFirewallBackend

    class Rule:
        Name = "{49F6DAD2-3265-4BCA-8E89-4F98335DC5D7}"
        DisplayName = "BC Sentinel - BCSF-FA7E28D9369AEB20"
        Grouping = MANAGED_FIREWALL_GROUP
        Action = NET_FW_ACTION_BLOCK
        Description = "Managed by BC Sentinel v0.7"

    rule = Rule()
    assert WindowsFirewallBackend._rule_id_from_rule(rule) == "BCSF-FA7E28D9369AEB20"
    assert WindowsFirewallBackend._is_owned(rule) is True


def test_v070_beta2_windows_identity_recovers_from_description_marker():
    from sentinel.firewall_windows import NET_FW_ACTION_BLOCK, WindowsFirewallBackend

    class Rule:
        Name = "{0E06BF93-3BC7-4C13-B7F7-39630D803E9C}"
        DisplayName = ""
        Grouping = MANAGED_FIREWALL_GROUP
        Action = NET_FW_ACTION_BLOCK
        Description = "Managed by BC Sentinel v0.7; bcsentinel-rule-id=BCSF-DB369B33F4720049; reason=test"

    assert WindowsFirewallBackend._rule_id_from_rule(Rule()) == "BCSF-DB369B33F4720049"


def test_v070_beta2_remove_enumerates_owned_rule_and_uses_native_identity():
    from contextlib import contextmanager
    from sentinel.firewall_windows import NET_FW_ACTION_BLOCK, WindowsFirewallBackend

    class Rule:
        Name = "{49F6DAD2-3265-4BCA-8E89-4F98335DC5D7}"
        DisplayName = "BC Sentinel - BCSF-FA7E28D9369AEB20"
        Grouping = MANAGED_FIREWALL_GROUP
        Action = NET_FW_ACTION_BLOCK
        Description = "Managed by BC Sentinel v0.7"

    class Rules:
        def __init__(self):
            self.values = [Rule()]
            self.removed = []

        def __iter__(self):
            return iter(self.values)

        def Remove(self, name):
            self.removed.append(name)
            self.values.clear()

    class Policy:
        def __init__(self):
            self.Rules = Rules()

    policy = Policy()
    backend = WindowsFirewallBackend()

    @contextmanager
    def fake_policy():
        yield policy

    backend._policy = fake_policy
    assert backend.remove_rule("BCSF-FA7E28D9369AEB20") is True
    assert policy.Rules.removed == ["{49F6DAD2-3265-4BCA-8E89-4F98335DC5D7}"]


def test_v070_beta2_firewall_acceptance_is_transactional_and_baseline_aware():
    source = Path("tools/firewall_acceptance.py").read_text(encoding="utf-8")
    assert "finally:" in source
    assert "baseline_managed_rules" in source
    assert "baseline_restored" in source
    assert "_wait_for_rule" in source
    assert "OBSERVABILITY_TIMEOUT_SECONDS" in source
    assert "cleanup_required_rule_id" in source


def test_v070_beta2_description_contains_machine_readable_rule_identity():
    source = Path("sentinel/firewall_windows.py").read_text(encoding="utf-8")
    assert 'f"bcsentinel-rule-id={rule.rule_id}"' in source
    assert 'for attr in ("Name", "DisplayName")' in source


def test_v070_beta3_acceptance_treats_windows_ipv4_host_forms_as_equivalent():
    from tools.firewall_acceptance import _remote_address_matches

    assert _remote_address_matches("192.0.2.77", "192.0.2.77/32") is True
    assert _remote_address_matches("192.0.2.77", "192.0.2.77/255.255.255.255") is True
    assert _remote_address_matches("192.0.2.77/24", "192.0.2.0/255.255.255.0") is True
    assert _remote_address_matches("192.0.2.77", "192.0.2.78/255.255.255.255") is False


def test_v070_beta3_acceptance_treats_ipv6_host_forms_as_equivalent():
    from tools.firewall_acceptance import _remote_address_matches

    assert _remote_address_matches("2001:db8::77", "2001:db8::77/128") is True
    assert _remote_address_matches("2001:db8::77/64", "2001:db8::/64") is True


def test_v070_beta3_probe_match_requires_identity_scope_and_semantic_address():
    from tools.firewall_acceptance import _rule_matches_probe

    rule_id = "BCSF-0123456789ABCDEF"
    row = {
        "rule_id": rule_id,
        "managed_group": MANAGED_FIREWALL_GROUP,
        "remote_address": "192.0.2.77/255.255.255.255",
        "direction": "outbound",
        "protocol": "any",
        "remote_port": None,
        "application_path": "",
        "enabled": True,
    }
    assert _rule_matches_probe(row, rule_id) is True
    assert _rule_matches_probe({**row, "direction": "inbound"}, rule_id) is False
    assert _rule_matches_probe({**row, "managed_group": "Other"}, rule_id) is False
    assert _rule_matches_probe({**row, "remote_address": "192.0.2.78/255.255.255.255"}, rule_id) is False


def test_v070_beta3_acceptance_no_longer_uses_raw_remote_address_equality():
    source = Path("tools/firewall_acceptance.py").read_text(encoding="utf-8")
    assert "_remote_address_matches" in source
    assert "_rule_matches_probe" in source
    assert 'str(matching.get("remote_address") or "") == TEST_NET_ADDRESS' not in source
