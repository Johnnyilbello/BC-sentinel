from __future__ import annotations

from dataclasses import dataclass
import hmac
import json
import re
import uuid
from typing import Any

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 256 * 1024
MAX_REQUEST_ID = 64
MAX_PATH_CHARS = 32768

READ_OPERATIONS = frozenset({
    "ping",
    "status",
    "events",
    "attribute",
    "process_chain",
    "incident",
    "incidents",
    "quarantine_items",
    "hardening_status",
    "antispyware_status",
    "advanced_antimalware_status",
    "advanced_antimalware_findings",
    "antispyware_findings",
    "antispyware_remediation_plan",
    "antispyware_remediation_plans",
    "firewall_status",
    "firewall_rules",
    "firewall_drift",
    "firewall_conflicts",
    "web_status",
    "web_findings",
    "web_downloads",
    "web_download_detail",
    "web_assess",
    "web_clone_scam_assess",
    "web_domain_trust",
    "web_domain_reputation",
    "web_finding_decide",
    "ioc_status",
    "ioc_entries",
    "threat_intel_status",
    "threat_intel_history",
    "threat_package_validate",
    "threat_keyset_validate",
    "threat_index_validate",
    "containment_leases",
    "pending_threats",
    "threat_decision_ack",
    "prepare_privileged_action",
    "privileged_ticket_result",
})

PRIVILEGED_OPERATIONS = frozenset({
    "set_network_collection",
    "set_protection_config",
    "set_protection_enabled",
    "terminate_process",
    "quarantine_file",
    "restore_quarantine",
    "threat_file_action",
    "add_exclusion",
    "remove_exclusion",
    "firewall_block_remote",
    "firewall_remove_rule",
    "firewall_set_managed_enabled",
    "firewall_reconcile",
    "ioc_import",
    "threat_package_stage",
    "threat_package_install",
    "threat_package_activate",
    "threat_package_rollback",
    "threat_keyset_install",
    "antispyware_remediation_apply",
    "antispyware_remediation_restore",
    "containment_lease_create",
    "containment_lease_release",
    "web_containment_create",
    "web_domain_trust_add",
    "web_domain_trust_remove",
    "execute_privileged_ticket",
})

ALL_OPERATIONS = READ_OPERATIONS | PRIVILEGED_OPERATIONS

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


class ProtocolError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = str(code)
        self.message = str(message)


@dataclass(slots=True, frozen=True)
class ClientContext:
    """Transport-authenticated local client metadata.

    `authenticated` means the transport verified the local peer context. On
    Windows named pipes this is populated from a kernel-derived client token:
    named-pipe impersonation when available, otherwise the process token for
    GetNamedPipeClientProcessId. It is distinct from the installation token.
    """

    local: bool = True
    authenticated: bool = False
    is_admin: bool = False
    sid: str = ""
    session_id: int | None = None
    transport: str = "direct"
    process_id: int | None = None


@dataclass(slots=True, frozen=True)
class ValidatedRequest:
    version: int
    request_id: str
    op: str
    token: str
    payload: dict[str, Any]


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_type(payload: dict, key: str, expected, *, optional: bool = False):
    if key not in payload:
        if optional:
            return None
        raise ProtocolError("invalid_payload", f"Missing payload field: {key}")
    value = payload[key]
    if expected is int:
        valid = _is_int(value)
    else:
        valid = isinstance(value, expected)
    if not valid:
        raise ProtocolError("invalid_payload", f"Invalid type for payload field: {key}")
    return value


def _reject_unknown(payload: dict, allowed: set[str]):
    unknown = set(payload) - allowed
    if unknown:
        raise ProtocolError("invalid_payload", f"Unknown payload field(s): {', '.join(sorted(unknown))}")


def _validate_path(value: str, *, field: str = "path") -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProtocolError("invalid_payload", f"{field} must be a non-empty string")
    if "\x00" in value or len(value) > MAX_PATH_CHARS:
        raise ProtocolError("invalid_payload", f"{field} is invalid or too long")
    return value


def _validate_payload(op: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ProtocolError("invalid_payload", "payload must be an object")

    p = dict(payload)
    if op in {"ping", "status", "quarantine_items", "hardening_status", "antispyware_status", "advanced_antimalware_status", "firewall_status", "firewall_drift", "firewall_conflicts", "web_status", "web_domain_trust", "ioc_status", "threat_intel_status", "containment_leases", "pending_threats"}:
        _reject_unknown(p, set())
    elif op == "threat_decision_ack":
        _reject_unknown(p, {"sha256", "action", "detail"})
        sha256 = _require_type(p, "sha256", str).strip().casefold()
        action = _require_type(p, "action", str).strip().casefold()
        detail = str(p.get("detail") or "")
        if len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256):
            raise ProtocolError("invalid_payload", "sha256 must be a 64-character hexadecimal digest")
        if action not in {"allowed_once", "allowlisted_hash", "missing", "superseded", "no_longer_qualified"}:
            raise ProtocolError("invalid_payload", "unsupported threat decision acknowledgement")
        if len(detail) > 256:
            raise ProtocolError("invalid_payload", "detail is too long")
        p = {"sha256": sha256, "action": action, "detail": detail}
    elif op == "antispyware_findings":
        _reject_unknown(p, {"limit", "min_score"})
        limit = p.get("limit", 200)
        min_score = p.get("min_score", 0)
        if not _is_int(limit) or not 1 <= limit <= 500:
            raise ProtocolError("invalid_payload", "limit must be between 1 and 500")
        if not _is_int(min_score) or not 0 <= min_score <= 100:
            raise ProtocolError("invalid_payload", "min_score must be between 0 and 100")
        p = {"limit": int(limit), "min_score": int(min_score)}
    elif op == "advanced_antimalware_findings":
        _reject_unknown(p, {"limit", "min_score"})
        limit = p.get("limit", 200)
        min_score = p.get("min_score", 0)
        if not _is_int(limit) or not 1 <= limit <= 500:
            raise ProtocolError("invalid_payload", "limit must be between 1 and 500")
        if not _is_int(min_score) or not 0 <= min_score <= 100:
            raise ProtocolError("invalid_payload", "min_score must be between 0 and 100")
        p = {"limit": int(limit), "min_score": int(min_score)}
    elif op == "antispyware_remediation_plan":
        _reject_unknown(p, {"finding_id"})
        finding_id = _require_type(p, "finding_id", str).strip().upper()
        if not re.fullmatch(r"BCP-[0-9A-F]{20}", finding_id):
            raise ProtocolError("invalid_payload", "finding_id is invalid")
        p = {"finding_id": finding_id}
    elif op == "antispyware_remediation_plans":
        _reject_unknown(p, {"limit"})
        limit = p.get("limit", 100)
        if not _is_int(limit) or not 1 <= limit <= 500:
            raise ProtocolError("invalid_payload", "limit must be between 1 and 500")
        p = {"limit": int(limit)}
    elif op in {"antispyware_remediation_apply", "antispyware_remediation_restore"}:
        _reject_unknown(p, {"plan_id", "approved"})
        plan_id = _require_type(p, "plan_id", str).strip().upper()
        approved = _require_type(p, "approved", bool)
        if not re.fullmatch(r"BCR-[0-9A-F]{20}", plan_id):
            raise ProtocolError("invalid_payload", "plan_id is invalid")
        p = {"plan_id": plan_id, "approved": approved}
    elif op == "web_findings":
        _reject_unknown(p, {"limit"})
        limit = p.get("limit", 100)
        if not _is_int(limit) or not 1 <= limit <= 500:
            raise ProtocolError("invalid_payload", "limit must be between 1 and 500")
        p = {"limit": int(limit)}
    elif op == "web_downloads":
        _reject_unknown(p, {"limit"})
        limit = p.get("limit", 100)
        if not _is_int(limit) or not 1 <= limit <= 500:
            raise ProtocolError("invalid_payload", "limit must be between 1 and 500")
        p = {"limit": int(limit)}
    elif op == "web_download_detail":
        _reject_unknown(p, {"download_id"})
        download_id = _require_type(p, "download_id", str).strip().upper()
        if not re.fullmatch(r"BCD-[0-9A-F]{20}", download_id):
            raise ProtocolError("invalid_payload", "download_id is invalid")
        p = {"download_id": download_id}
    elif op == "web_assess":
        _reject_unknown(p, {"value"})
        value = _require_type(p, "value", str).strip()
        if not value or len(value) > 4096 or "\x00" in value:
            raise ProtocolError("invalid_payload", "web assessment value is invalid")
        p = {"value": value}
    elif op == "web_clone_scam_assess":
        allowed = {"url", "declared_identity", "page_title", "visible_text", "form_action", "form_fields", "payment_methods", "link_hosts", "redirect_chain"}
        _reject_unknown(p, allowed)
        url = _require_type(p, "url", str).strip()
        if not url or len(url) > 4096 or "\x00" in url:
            raise ProtocolError("invalid_payload", "clone/scam url is invalid")
        out = {"url": url}
        for key, limit in (("declared_identity", 128), ("page_title", 512), ("visible_text", 20000), ("form_action", 4096)):
            value = p.get(key, "")
            if not isinstance(value, str) or "\x00" in value or len(value) > limit:
                raise ProtocolError("invalid_payload", f"{key} is invalid")
            out[key] = value
        for key, max_items, item_limit in (("form_fields", 64, 128), ("payment_methods", 32, 128), ("link_hosts", 128, 2048), ("redirect_chain", 32, 4096)):
            value = p.get(key, [])
            if not isinstance(value, list) or len(value) > max_items or any(not isinstance(item, str) or "\x00" in item or len(item) > item_limit for item in value):
                raise ProtocolError("invalid_payload", f"{key} is invalid")
            out[key] = list(value)
        p = out
    elif op == "web_domain_reputation":
        _reject_unknown(p, {"domain"})
        domain = _require_type(p, "domain", str).strip().rstrip(".")
        if not domain or len(domain) > 253 or "\x00" in domain or "://" in domain or "*" in domain:
            raise ProtocolError("invalid_payload", "domain is invalid")
        p = {"domain": domain}
    elif op == "web_finding_decide":
        _reject_unknown(p, {"finding_id", "action", "detail"})
        finding_id = _require_type(p, "finding_id", str).strip().upper()
        action = _require_type(p, "action", str).strip().casefold()
        detail = str(p.get("detail") or "")
        if not re.fullmatch(r"BCW-[0-9A-F]{20}", finding_id):
            raise ProtocolError("invalid_payload", "finding_id is invalid")
        if action not in {"ignore_once", "reviewed"}:
            raise ProtocolError("invalid_payload", "unsupported web finding decision")
        if len(detail) > 256:
            raise ProtocolError("invalid_payload", "detail is too long")
        p = {"finding_id": finding_id, "action": action, "detail": detail}
    elif op == "firewall_rules":
        _reject_unknown(p, {"limit"})
        limit = p.get("limit", 200)
        if not _is_int(limit) or not 1 <= limit <= 500:
            raise ProtocolError("invalid_payload", "limit must be between 1 and 500")
        p = {"limit": limit}
    elif op == "events":
        _reject_unknown(p, {"since", "limit"})
        since = p.get("since", 0)
        limit = p.get("limit", 250)
        if not _is_int(since) or since < 0:
            raise ProtocolError("invalid_payload", "since must be a non-negative integer")
        if not _is_int(limit) or not 1 <= limit <= 500:
            raise ProtocolError("invalid_payload", "limit must be between 1 and 500")
        p = {"since": since, "limit": limit}
    elif op == "attribute":
        _reject_unknown(p, {"path"})
        p["path"] = _validate_path(_require_type(p, "path", str))
    elif op == "process_chain":
        _reject_unknown(p, {"pid"})
        pid = _require_type(p, "pid", int)
        if pid <= 0 or pid > 2**31 - 1:
            raise ProtocolError("invalid_payload", "pid is outside the supported range")
    elif op == "incident":
        _reject_unknown(p, {"incident_id"})
        value = _require_type(p, "incident_id", str).strip()
        if not value or len(value) > 128:
            raise ProtocolError("invalid_payload", "incident_id is invalid")
        p["incident_id"] = value
    elif op == "incidents":
        _reject_unknown(p, {"limit", "min_score"})
        limit = p.get("limit", 100)
        min_score = p.get("min_score", 0)
        if not _is_int(limit) or not 1 <= limit <= 500:
            raise ProtocolError("invalid_payload", "limit must be between 1 and 500")
        if not _is_int(min_score) or not 0 <= min_score <= 100:
            raise ProtocolError("invalid_payload", "min_score must be between 0 and 100")
        p = {"limit": limit, "min_score": min_score}
    elif op in {"set_network_collection", "set_protection_enabled"}:
        _reject_unknown(p, {"enabled"})
        _require_type(p, "enabled", bool)
    elif op == "set_protection_config":
        _reject_unknown(p, {"settings"})
        settings = _require_type(p, "settings", dict)
        allowed = {
            "realtime_enabled", "ransomware_enabled", "behavior_enabled",
            "etw_enabled", "persistence_enabled", "network_enabled",
            "reputation_enabled", "exclude_self", "scan_size_limit_mb",
            "monitored_dirs", "ransomware_dirs", "ransomware_startup_grace_seconds",
        }
        _reject_unknown(settings, allowed)
        for key in (
            "realtime_enabled", "ransomware_enabled", "behavior_enabled", "etw_enabled",
            "persistence_enabled", "network_enabled", "reputation_enabled", "exclude_self",
        ):
            if key in settings and not isinstance(settings[key], bool):
                raise ProtocolError("invalid_payload", f"settings.{key} must be boolean")
        for key in ("monitored_dirs", "ransomware_dirs"):
            if key in settings:
                values = settings[key]
                if not isinstance(values, list) or len(values) > 128:
                    raise ProtocolError("invalid_payload", f"settings.{key} must be a bounded list")
                settings[key] = [_validate_path(v, field=f"settings.{key}") for v in values]
        for key, low, high in (
            ("scan_size_limit_mb", 1, 4096),
            ("ransomware_startup_grace_seconds", 0, 600),
        ):
            if key in settings:
                value = settings[key]
                if not _is_int(value) or not low <= value <= high:
                    raise ProtocolError("invalid_payload", f"settings.{key} is outside the supported range")
        p = {"settings": settings}
    elif op in {"terminate_process", "quarantine_file"}:
        _reject_unknown(p, {"incident_id", "approved", "candidate_path"})
        incident_id = _require_type(p, "incident_id", str).strip()
        approved = _require_type(p, "approved", bool)
        if not incident_id or len(incident_id) > 128:
            raise ProtocolError("invalid_payload", "incident_id is invalid")
        p["incident_id"] = incident_id
        if op == "quarantine_file" and p.get("candidate_path"):
            p["candidate_path"] = _validate_path(p["candidate_path"], field="candidate_path")
        if not approved:
            # The service accepts the request so that the response engine can
            # audit a denied action, but never treats omitted approval as true.
            p["approved"] = False
    elif op == "restore_quarantine":
        _reject_unknown(p, {"item_id", "destination", "approved"})
        item_id = _require_type(p, "item_id", str).strip().lower()
        approved = _require_type(p, "approved", bool)
        if len(item_id) != 32 or any(c not in "0123456789abcdef" for c in item_id):
            raise ProtocolError("invalid_payload", "item_id must be a 32-character hex identifier")
        p["item_id"] = item_id
        if p.get("destination"):
            p["destination"] = _validate_path(p["destination"], field="destination")
        p["approved"] = approved
    elif op == "threat_file_action":
        _reject_unknown(p, {"action", "path", "sha256", "score", "level", "reasons", "approved"})
        action = _require_type(p, "action", str).strip().lower()
        if action not in {"quarantine", "delete"}:
            raise ProtocolError("invalid_payload", "threat file action must be quarantine or delete")
        path = _validate_path(_require_type(p, "path", str), field="path")
        sha256 = _require_type(p, "sha256", str).strip().lower()
        if len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256):
            raise ProtocolError("invalid_payload", "sha256 must be a 64-character hexadecimal digest")
        score = _require_type(p, "score", int)
        if not 0 <= score <= 100:
            raise ProtocolError("invalid_payload", "score must be between 0 and 100")
        level = _require_type(p, "level", str).strip().upper()
        if not level or len(level) > 32:
            raise ProtocolError("invalid_payload", "level is invalid")
        reasons = _require_type(p, "reasons", list)
        if len(reasons) > 16 or any(not isinstance(item, str) or len(item) > 256 for item in reasons):
            raise ProtocolError("invalid_payload", "reasons must be a bounded list of strings")
        approved = _require_type(p, "approved", bool)
        p = {
            "action": action,
            "path": path,
            "sha256": sha256,
            "score": score,
            "level": level,
            "reasons": [str(item) for item in reasons],
            "approved": approved,
        }
    elif op == "add_exclusion":
        _reject_unknown(p, {"kind", "value"})
        kind = _require_type(p, "kind", str).strip().lower()
        value = _require_type(p, "value", str).strip()
        if kind not in {"file", "directory", "hash", "publisher"}:
            raise ProtocolError("invalid_payload", "unsupported exclusion kind")
        if not value or len(value) > MAX_PATH_CHARS:
            raise ProtocolError("invalid_payload", "exclusion value is invalid")
        p = {"kind": kind, "value": value}
    elif op == "remove_exclusion":
        _reject_unknown(p, {"id"})
        ident = _require_type(p, "id", int)
        if ident <= 0:
            raise ProtocolError("invalid_payload", "id must be positive")
    elif op == "firewall_block_remote":
        _reject_unknown(p, {"remote_address", "direction", "protocol", "remote_port", "application_path", "reason", "incident_id", "approved"})
        from .firewall_policy import build_block_rule
        approved = _require_type(p, "approved", bool)
        remote_address = _require_type(p, "remote_address", str)
        direction = p.get("direction", "outbound")
        protocol = p.get("protocol", "any")
        remote_port = p.get("remote_port")
        application_path = p.get("application_path", "")
        reason = p.get("reason", "")
        incident_id = p.get("incident_id", "")
        if not isinstance(direction, str) or not isinstance(protocol, str):
            raise ProtocolError("invalid_payload", "direction and protocol must be strings")
        if remote_port is not None and not _is_int(remote_port):
            raise ProtocolError("invalid_payload", "remote_port must be an integer")
        if not isinstance(application_path, str) or not isinstance(reason, str) or not isinstance(incident_id, str):
            raise ProtocolError("invalid_payload", "application_path, reason and incident_id must be strings")
        try:
            rule = build_block_rule(
                remote_address=remote_address, direction=direction, protocol=protocol,
                remote_port=remote_port, application_path=application_path,
                reason=reason, incident_id=incident_id, rule_id="BCSF-0000000000000000",
            )
        except ValueError as exc:
            raise ProtocolError("invalid_payload", str(exc)) from exc
        p = {
            "remote_address": rule.remote_address, "direction": rule.direction,
            "protocol": rule.protocol, "remote_port": rule.remote_port,
            "application_path": rule.application_path, "reason": rule.reason,
            "incident_id": rule.incident_id, "approved": approved,
        }
    elif op == "firewall_remove_rule":
        _reject_unknown(p, {"rule_id", "approved"})
        from .firewall_policy import validate_rule_id
        approved = _require_type(p, "approved", bool)
        try:
            rule_id = validate_rule_id(_require_type(p, "rule_id", str))
        except ValueError as exc:
            raise ProtocolError("invalid_payload", str(exc)) from exc
        p = {"rule_id": rule_id, "approved": approved}
    elif op == "firewall_set_managed_enabled":
        _reject_unknown(p, {"enabled", "approved"})
        p = {
            "enabled": _require_type(p, "enabled", bool),
            "approved": _require_type(p, "approved", bool),
        }
    elif op == "firewall_reconcile":
        _reject_unknown(p, {"approved"})
        p = {"approved": _require_type(p, "approved", bool)}
    elif op == "ioc_import":
        _reject_unknown(p, {"bundle", "signature", "approved"})
        bundle = _require_type(p, "bundle", dict)
        signature = _require_type(p, "signature", str).strip()
        approved = _require_type(p, "approved", bool)
        entries = bundle.get("entries")
        if not isinstance(entries, list) or len(entries) > 1000:
            raise ProtocolError("invalid_payload", "IOC bundle entries must be a bounded list")
        if not signature or len(signature) > 256:
            raise ProtocolError("invalid_payload", "IOC signature is invalid")
        p = {"bundle": bundle, "signature": signature, "approved": approved}
    elif op == "ioc_entries":
        _reject_unknown(p, {"limit"})
        limit = p.get("limit", 500)
        if not _is_int(limit) or not 1 <= limit <= 1000:
            raise ProtocolError("invalid_payload", "limit must be between 1 and 1000")
        p = {"limit": int(limit)}
    elif op == "threat_intel_history":
        _reject_unknown(p, {"limit"})
        limit = p.get("limit", 50)
        if not _is_int(limit) or not 1 <= limit <= 200:
            raise ProtocolError("invalid_payload", "limit must be between 1 and 200")
        p = {"limit": int(limit)}
    elif op == "threat_index_validate":
        _reject_unknown(p, {"index", "signature"})
        index = _require_type(p, "index", dict)
        signature = _require_type(p, "signature", str).strip()
        if not signature or len(signature) > 256:
            raise ProtocolError("invalid_payload", "threat index signature is invalid")
        packages = index.get("packages")
        if not isinstance(packages, list) or not packages or len(packages) > 128:
            raise ProtocolError("invalid_payload", "threat index packages must be a bounded non-empty list")
        p = {"index": index, "signature": signature}
    elif op in {"threat_keyset_validate", "threat_keyset_install"}:
        allowed = {"keyset", "signature"} if op == "threat_keyset_validate" else {"keyset", "signature", "approved"}
        _reject_unknown(p, allowed)
        keyset = _require_type(p, "keyset", dict)
        signature = _require_type(p, "signature", str).strip()
        if not signature or len(signature) > 256:
            raise ProtocolError("invalid_payload", "threat keyset signature is invalid")
        keys = keyset.get("keys")
        if not isinstance(keys, list) or not 1 <= len(keys) <= 16:
            raise ProtocolError("invalid_payload", "threat keyset keys must be a bounded non-empty list")
        revoked = keyset.get("revoked_key_ids", [])
        if not isinstance(revoked, list) or len(revoked) > 64:
            raise ProtocolError("invalid_payload", "threat keyset revocation list is invalid")
        if op == "threat_keyset_install":
            p = {"keyset": keyset, "signature": signature, "approved": _require_type(p, "approved", bool)}
        else:
            p = {"keyset": keyset, "signature": signature}
    elif op in {"threat_package_validate", "threat_package_stage", "threat_package_install"}:
        allowed = {"package", "signature"} if op == "threat_package_validate" else {"package", "signature", "approved"}
        _reject_unknown(p, allowed)
        package = _require_type(p, "package", dict)
        signature = _require_type(p, "signature", str).strip()
        if not signature or len(signature) > 256:
            raise ProtocolError("invalid_payload", "threat package signature is invalid")
        components = package.get("components")
        if not isinstance(components, dict) or not components:
            raise ProtocolError("invalid_payload", "threat package components must be a non-empty object")
        if op in {"threat_package_stage", "threat_package_install"}:
            approved = _require_type(p, "approved", bool)
            p = {"package": package, "signature": signature, "approved": approved}
        else:
            p = {"package": package, "signature": signature}
    elif op == "threat_package_activate":
        _reject_unknown(p, {"stage_id", "approved"})
        stage_id = _require_type(p, "stage_id", str).strip()
        approved = _require_type(p, "approved", bool)
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,220}", stage_id):
            raise ProtocolError("invalid_payload", "stage_id is invalid")
        p = {"stage_id": stage_id, "approved": approved}
    elif op == "threat_package_rollback":
        _reject_unknown(p, {"approved"})
        p = {"approved": _require_type(p, "approved", bool)}
    elif op == "containment_lease_create":
        _reject_unknown(p, {"remote_address", "ttl_seconds", "reason", "incident_id", "approved"})
        remote_address = _require_type(p, "remote_address", str)
        ttl_seconds = _require_type(p, "ttl_seconds", int)
        approved = _require_type(p, "approved", bool)
        reason = str(p.get("reason") or "")
        incident_id = str(p.get("incident_id") or "")
        if not 60 <= ttl_seconds <= 86400:
            raise ProtocolError("invalid_payload", "ttl_seconds must be between 60 and 86400")
        from .firewall_policy import build_block_rule
        try:
            probe = build_block_rule(
                remote_address=remote_address, direction="outbound", protocol="any",
                reason=reason, incident_id=incident_id, rule_id="BCSF-0000000000000000",
            )
        except ValueError as exc:
            raise ProtocolError("invalid_payload", str(exc)) from exc
        p = {
            "remote_address": probe.remote_address, "ttl_seconds": int(ttl_seconds),
            "reason": probe.reason, "incident_id": probe.incident_id, "approved": approved,
        }
    elif op == "containment_lease_release":
        _reject_unknown(p, {"lease_id", "approved"})
        lease_id = _require_type(p, "lease_id", str).strip().casefold()
        approved = _require_type(p, "approved", bool)
        if len(lease_id) != 32 or any(ch not in "0123456789abcdef" for ch in lease_id):
            raise ProtocolError("invalid_payload", "lease_id must be a 32-character hex identifier")
        p = {"lease_id": lease_id, "approved": approved}
    elif op == "web_containment_create":
        _reject_unknown(p, {"finding_id", "ttl_seconds", "reason", "approved"})
        finding_id = _require_type(p, "finding_id", str).strip().upper()
        ttl_seconds = _require_type(p, "ttl_seconds", int)
        approved = _require_type(p, "approved", bool)
        reason = str(p.get("reason") or "")
        if not re.fullmatch(r"BCW-[0-9A-F]{20}", finding_id):
            raise ProtocolError("invalid_payload", "finding_id is invalid")
        if not 60 <= ttl_seconds <= 3600:
            raise ProtocolError("invalid_payload", "ttl_seconds must be between 60 and 3600")
        if len(reason) > 256:
            raise ProtocolError("invalid_payload", "reason is too long")
        p = {"finding_id": finding_id, "ttl_seconds": int(ttl_seconds), "reason": reason, "approved": approved}
    elif op == "web_domain_trust_add":
        _reject_unknown(p, {"domain", "reason", "finding_id", "approved"})
        domain = _require_type(p, "domain", str).strip().rstrip(".")
        approved = _require_type(p, "approved", bool)
        reason = str(p.get("reason") or "")
        finding_id = str(p.get("finding_id") or "").strip().upper()
        if not domain or len(domain) > 253 or "\x00" in domain or "://" in domain or "*" in domain:
            raise ProtocolError("invalid_payload", "trusted domain must be one exact domain without wildcards")
        if len(reason) > 256:
            raise ProtocolError("invalid_payload", "reason is too long")
        if finding_id and not re.fullmatch(r"BCW-[0-9A-F]{20}", finding_id):
            raise ProtocolError("invalid_payload", "finding_id is invalid")
        p = {"domain": domain, "reason": reason, "finding_id": finding_id, "approved": approved}
    elif op == "web_domain_trust_remove":
        _reject_unknown(p, {"domain", "approved"})
        domain = _require_type(p, "domain", str).strip().rstrip(".")
        approved = _require_type(p, "approved", bool)
        if not domain or len(domain) > 253 or "\x00" in domain or "://" in domain or "*" in domain:
            raise ProtocolError("invalid_payload", "trusted domain must be one exact domain without wildcards")
        p = {"domain": domain, "approved": approved}
    elif op == "prepare_privileged_action":
        _reject_unknown(p, {"action", "payload"})
        target_op = _require_type(p, "action", str).strip()
        if target_op not in PRIVILEGED_OPERATIONS or target_op == "execute_privileged_ticket":
            raise ProtocolError("invalid_payload", "unsupported broker target operation")
        target_payload = _require_type(p, "payload", dict)
        p = {"action": target_op, "payload": _validate_payload(target_op, target_payload)}
    elif op in {"execute_privileged_ticket", "privileged_ticket_result"}:
        _reject_unknown(p, {"ticket_id"})
        ticket_id = _require_type(p, "ticket_id", str).strip()
        if not (32 <= len(ticket_id) <= 128) or any(ch.isspace() for ch in ticket_id):
            raise ProtocolError("invalid_payload", "ticket_id is invalid")
        p = {"ticket_id": ticket_id}
    else:
        raise ProtocolError("unsupported_operation", "Unsupported operation")
    return p


def decode_request(raw: bytes) -> ValidatedRequest:
    if not isinstance(raw, (bytes, bytearray)):
        raise ProtocolError("invalid_message", "request must be bytes")
    if len(raw) == 0:
        raise ProtocolError("invalid_message", "empty request")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message_too_large", "request exceeds maximum message size")
    try:
        obj = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("malformed_json", "request is not valid UTF-8 JSON") from exc
    return validate_request(obj, encoded_size=len(raw))


def validate_request(obj: Any, *, encoded_size: int | None = None) -> ValidatedRequest:
    if not isinstance(obj, dict):
        raise ProtocolError("invalid_message", "request must be a JSON object")
    allowed = {"version", "request_id", "op", "token", "payload"}
    unknown = set(obj) - allowed
    if unknown:
        raise ProtocolError("invalid_message", f"Unknown request field(s): {', '.join(sorted(unknown))}")
    if encoded_size is None:
        try:
            encoded_size = len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        except Exception as exc:
            raise ProtocolError("invalid_message", "request is not JSON serializable") from exc
    if encoded_size > MAX_MESSAGE_BYTES:
        raise ProtocolError("message_too_large", "request exceeds maximum message size")

    version = obj.get("version")
    if not _is_int(version) or version != PROTOCOL_VERSION:
        raise ProtocolError("unsupported_version", f"protocol version {version!r} is not supported")
    request_id = obj.get("request_id")
    if not isinstance(request_id, str) or not _REQUEST_ID_RE.match(request_id):
        raise ProtocolError("invalid_request_id", "request_id is invalid")
    op = obj.get("op")
    if not isinstance(op, str) or op not in ALL_OPERATIONS:
        raise ProtocolError("unsupported_operation", "Unsupported operation")
    token = obj.get("token")
    if not isinstance(token, str) or not 32 <= len(token) <= 256:
        raise ProtocolError("unauthorized", "installation token is missing or invalid")
    payload = _validate_payload(op, obj.get("payload", {}))
    return ValidatedRequest(version, request_id, op, token, payload)


def build_request(op: str, token: str, **payload) -> dict[str, Any]:
    request_id = uuid.uuid4().hex
    obj = {
        "version": PROTOCOL_VERSION,
        "request_id": request_id,
        "op": op,
        "token": str(token),
        "payload": payload,
    }
    validate_request(obj)
    return obj


def encode_message(obj: dict[str, Any]) -> bytes:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message_too_large", "message exceeds maximum message size")
    return raw


def authorized_token(supplied: str, expected: str) -> bool:
    if not supplied or not expected:
        return False
    return hmac.compare_digest(str(supplied), str(expected))


def response_ok(request_id: str, **payload) -> dict[str, Any]:
    return {"version": PROTOCOL_VERSION, "request_id": request_id, "ok": True, **payload}


def response_error(request_id: str, code: str, message: str, **details) -> dict[str, Any]:
    payload = {
        "version": PROTOCOL_VERSION,
        "request_id": request_id or "unknown",
        "ok": False,
        "error": {"code": str(code), "message": str(message)},
    }
    if details:
        payload["error"].update(details)
    return payload
