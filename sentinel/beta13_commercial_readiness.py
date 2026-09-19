from __future__ import annotations

"""B13-6 trial, licensing, privacy, support and diagnostics readiness.

This milestone makes the commercial/product-support surfaces explicit without
allowing entitlement failures to weaken the accepted protection baseline.
Licensing is advisory for commercial entitlement; core protection remains
available even when trial state is expired, activation is unavailable, or an
entitlement token is invalid.
"""

from dataclasses import asdict, dataclass
import base64
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Final, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sentinel import beta13_installer as b133

SCHEMA: Final[str] = "bc-sentinel-beta13-commercial-readiness-v1"
PROFILE: Final[str] = "v0.13.0-b136-trial-licensing-privacy-support-readiness"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v013-b135-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "cbead4c4e01818f5764ebeb82f85eb69f64e1f67"

TRIAL_SCHEMA: Final[str] = "bc-sentinel-trial-state-v1"
ENTITLEMENT_SCHEMA: Final[str] = "bc-sentinel-signed-entitlement-v1"
DIAGNOSTIC_SCHEMA: Final[str] = "bc-sentinel-support-diagnostics-v1"

PRODUCT_NAME: Final[str] = "BC Sentinel"
PRODUCT_VERSION: Final[str] = "0.13.0"
PUBLISHER: Final[str] = "BC TECH Studio"
SUPPORT_URL: Final[str] = "https://bctechstudio.com"
DEFAULT_TRIAL_DAYS: Final[int] = 14

LICENSED: Final[str] = "LICENSED"
TRIAL_ACTIVE: Final[str] = "TRIAL_ACTIVE"
TRIAL_EXPIRED: Final[str] = "TRIAL_EXPIRED"
UNAVAILABLE: Final[str] = "UNAVAILABLE"
INVALID: Final[str] = "INVALID"

POLICY_SURFACES: Final[tuple[dict[str, str], ...]] = (
    {
        "surface_id": "PRIVACY",
        "title": "Privacy",
        "version": "2026-09-b136",
        "summary": (
            "BC Sentinel is local-first. Core protection does not require a cloud account. "
            "Support diagnostics are exported only after an explicit user action and use a "
            "minimal allowlist of product-state fields."
        ),
    },
    {
        "surface_id": "EULA",
        "title": "Condizioni d'uso",
        "version": "2026-09-b136",
        "summary": (
            "The product presents its commercial entitlement state separately from security "
            "protection. Expired or unavailable licensing cannot silently disable the accepted "
            "core protection baseline."
        ),
    },
    {
        "surface_id": "SUPPORT",
        "title": "Supporto",
        "version": "2026-09-b136",
        "summary": (
            "The support surface exposes publisher identity, the BC TECH Studio support site "
            "and an explicit sanitized diagnostic export."
        ),
    },
)

BOUNDARIES: Final[dict[str, bool]] = {
    "core_protection_may_be_disabled_by_license_failure": False,
    "trial_expiry_may_disable_core_protection": False,
    "invalid_entitlement_may_disable_core_protection": False,
    "mandatory_account_for_core_protection": False,
    "mandatory_cloud_for_core_protection": False,
    "automatic_license_network_request": False,
    "private_activation_key_embedded": False,
    "diagnostic_export_automatic": False,
    "diagnostic_export_includes_raw_paths": False,
    "diagnostic_export_includes_command_lines": False,
    "diagnostic_export_includes_usernames": False,
    "diagnostic_export_includes_license_token": False,
    "diagnostic_export_includes_license_id": False,
    "diagnostic_export_includes_file_contents": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}


@dataclass(frozen=True)
class CommercialState:
    status: str
    mode: str
    protection_enabled: bool
    trial_days: int | None = None
    trial_remaining_days: int | None = None
    entitlement_verified: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _b64decode(value: object) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("b136:base64_required")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:
        raise ValueError("b136:base64_invalid") from exc


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def initialize_trial(
    path: str | Path,
    *,
    now: float,
    trial_days: int = DEFAULT_TRIAL_DAYS,
) -> dict[str, Any]:
    target = Path(path)
    if trial_days <= 0 or trial_days > 365:
        raise ValueError("b136:trial_days_invalid")
    if target.exists():
        return json.loads(target.read_text(encoding="utf-8"))
    payload = {
        "schema": TRIAL_SCHEMA,
        "started_at": float(now),
        "trial_days": int(trial_days),
    }
    _atomic_write_json(target, payload)
    return payload


def evaluate_trial(
    data: object,
    *,
    now: float,
) -> CommercialState:
    if not isinstance(data, dict):
        return CommercialState(
            status=UNAVAILABLE,
            mode="TRIAL",
            protection_enabled=True,
            reason="trial_state_not_object",
        )
    if set(data) != {"schema", "started_at", "trial_days"}:
        return CommercialState(
            status=UNAVAILABLE,
            mode="TRIAL",
            protection_enabled=True,
            reason="trial_state_fields_invalid",
        )
    if data.get("schema") != TRIAL_SCHEMA:
        return CommercialState(
            status=UNAVAILABLE,
            mode="TRIAL",
            protection_enabled=True,
            reason="trial_schema_invalid",
        )
    try:
        started_at = float(data["started_at"])
        trial_days = int(data["trial_days"])
    except (TypeError, ValueError):
        return CommercialState(
            status=UNAVAILABLE,
            mode="TRIAL",
            protection_enabled=True,
            reason="trial_state_values_invalid",
        )
    if trial_days <= 0 or trial_days > 365:
        return CommercialState(
            status=UNAVAILABLE,
            mode="TRIAL",
            protection_enabled=True,
            reason="trial_days_invalid",
        )
    if started_at > float(now) + 300:
        return CommercialState(
            status=UNAVAILABLE,
            mode="TRIAL",
            protection_enabled=True,
            trial_days=trial_days,
            reason="clock_anomaly",
        )

    expires_at = started_at + trial_days * 86400
    remaining_seconds = expires_at - float(now)
    if remaining_seconds >= 0:
        remaining_days = max(0, int(math.ceil(remaining_seconds / 86400)))
        return CommercialState(
            status=TRIAL_ACTIVE,
            mode="TRIAL",
            protection_enabled=True,
            trial_days=trial_days,
            trial_remaining_days=remaining_days,
            reason="trial_active",
        )
    return CommercialState(
        status=TRIAL_EXPIRED,
        mode="TRIAL",
        protection_enabled=True,
        trial_days=trial_days,
        trial_remaining_days=0,
        reason="trial_expired_protection_retained",
    )


def load_trial(
    path: str | Path,
    *,
    now: float,
    initialize_if_missing: bool = True,
    trial_days: int = DEFAULT_TRIAL_DAYS,
) -> CommercialState:
    target = Path(path)
    if not target.exists():
        if not initialize_if_missing:
            return CommercialState(
                status=UNAVAILABLE,
                mode="TRIAL",
                protection_enabled=True,
                reason="trial_state_missing",
            )
        try:
            data = initialize_trial(target, now=now, trial_days=trial_days)
        except Exception:
            return CommercialState(
                status=UNAVAILABLE,
                mode="TRIAL",
                protection_enabled=True,
                reason="trial_state_initialization_failed",
            )
        return evaluate_trial(data, now=now)

    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return CommercialState(
            status=UNAVAILABLE,
            mode="TRIAL",
            protection_enabled=True,
            reason="trial_state_unreadable",
        )
    return evaluate_trial(data, now=now)


def entitlement_payload(
    *,
    license_id: str,
    edition: str,
    issued_at: float,
    expires_at: float | None,
) -> dict[str, Any]:
    if not license_id.strip():
        raise ValueError("b136:license_id_required")
    if not edition.strip():
        raise ValueError("b136:edition_required")
    return {
        "schema": ENTITLEMENT_SCHEMA,
        "product": PRODUCT_NAME,
        "license_id": license_id.strip(),
        "edition": edition.strip().upper(),
        "issued_at": float(issued_at),
        "expires_at": None if expires_at is None else float(expires_at),
    }


def attach_entitlement_signature(payload: Mapping[str, Any], signature: bytes) -> dict[str, Any]:
    return {**dict(payload), "signature": _b64encode(signature)}


def verify_signed_entitlement(
    token: object,
    *,
    public_key: bytes | str | None,
    now: float,
) -> CommercialState:
    if public_key is None:
        return CommercialState(
            status=UNAVAILABLE,
            mode="LICENSE",
            protection_enabled=True,
            reason="activation_public_key_unavailable",
        )
    if not isinstance(token, dict):
        return CommercialState(
            status=INVALID,
            mode="LICENSE",
            protection_enabled=True,
            reason="entitlement_not_object",
        )
    required = {
        "schema",
        "product",
        "license_id",
        "edition",
        "issued_at",
        "expires_at",
        "signature",
    }
    if set(token) != required:
        return CommercialState(
            status=INVALID,
            mode="LICENSE",
            protection_enabled=True,
            reason="entitlement_fields_invalid",
        )

    payload = {key: token[key] for key in required if key != "signature"}
    if payload.get("schema") != ENTITLEMENT_SCHEMA or payload.get("product") != PRODUCT_NAME:
        return CommercialState(
            status=INVALID,
            mode="LICENSE",
            protection_enabled=True,
            reason="entitlement_identity_invalid",
        )

    try:
        issued_at = float(payload["issued_at"])
        expires_at = (
            None if payload["expires_at"] is None else float(payload["expires_at"])
        )
        if isinstance(public_key, str):
            key_bytes = _b64decode(public_key)
        else:
            key_bytes = bytes(public_key)
        if len(key_bytes) != 32:
            raise ValueError("b136:activation_public_key_invalid")
        signature = _b64decode(token["signature"])
        verifier = Ed25519PublicKey.from_public_bytes(key_bytes)
        verifier.verify(signature, _canonical(payload))
    except (ValueError, TypeError, InvalidSignature):
        return CommercialState(
            status=INVALID,
            mode="LICENSE",
            protection_enabled=True,
            reason="entitlement_signature_invalid",
        )

    if issued_at > float(now) + 300:
        return CommercialState(
            status=INVALID,
            mode="LICENSE",
            protection_enabled=True,
            entitlement_verified=True,
            reason="entitlement_issued_in_future",
        )
    if expires_at is not None and float(now) > expires_at:
        return CommercialState(
            status=TRIAL_EXPIRED,
            mode="LICENSE",
            protection_enabled=True,
            entitlement_verified=True,
            reason="entitlement_expired_protection_retained",
        )
    return CommercialState(
        status=LICENSED,
        mode="LICENSE",
        protection_enabled=True,
        entitlement_verified=True,
        reason="signed_entitlement_verified",
    )


def resolve_commercial_state(
    *,
    trial: CommercialState,
    entitlement: CommercialState | None = None,
) -> CommercialState:
    if entitlement is not None and entitlement.status == LICENSED:
        return entitlement
    return trial


def projected_readiness() -> dict[str, Any]:
    baseline = b133.projected_readiness()
    counts = dict(baseline["pillar_counts"])
    blockers = list(baseline["release_blockers"])

    if "LICENSING_TRIAL" in blockers:
        blockers.remove("LICENSING_TRIAL")
        counts["READY"] += 1
        counts["BLOCKED"] -= 1
    if "PRIVACY_SUPPORT" in blockers:
        blockers.remove("PRIVACY_SUPPORT")
        counts["READY"] += 1
        counts["PARTIAL"] -= 1

    return {
        "schema": "bc-sentinel-beta13-readiness-projection-v6",
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "pillar_counts": counts,
        "release_blockers": blockers,
        "release_blocker_count": len(blockers),
        "ready_for_public_launch": not blockers,
        "ready_for_paid_launch": not blockers,
        "resolved_by_b136": ["LICENSING_TRIAL", "PRIVACY_SUPPORT"],
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def policy_surfaces() -> list[dict[str, str]]:
    return [dict(item) for item in POLICY_SURFACES]


def diagnostic_snapshot(
    *,
    commercial_state: CommercialState,
) -> dict[str, Any]:
    return {
        "schema": DIAGNOSTIC_SCHEMA,
        "product": PRODUCT_NAME,
        "product_version": PRODUCT_VERSION,
        "publisher": PUBLISHER,
        "support_url": SUPPORT_URL,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "coverage": {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7},
        "commercial_status": commercial_state.status,
        "commercial_mode": commercial_state.mode,
        "core_protection_enabled": commercial_state.protection_enabled,
        "entitlement_verified": commercial_state.entitlement_verified,
        "code_signing_public_trust_verified": False,
        "smartscreen_reputation_guaranteed": False,
        "network_required_for_core_protection": False,
        "cloud_required_for_core_protection": False,
        "raw_paths_included": False,
        "command_lines_included": False,
        "usernames_included": False,
        "license_token_included": False,
        "license_id_included": False,
        "file_contents_included": False,
    }


def validate_diagnostic_snapshot(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b136:diagnostic_not_object",)
    expected_keys = set(
        diagnostic_snapshot(
            commercial_state=CommercialState(
                status=UNAVAILABLE,
                mode="TRIAL",
                protection_enabled=True,
            )
        )
    )
    failures: list[str] = []
    if set(data) != expected_keys:
        failures.append("b136:diagnostic_fields_invalid")
    if data.get("schema") != DIAGNOSTIC_SCHEMA:
        failures.append("b136:diagnostic_schema_invalid")
    if data.get("core_protection_enabled") is not True:
        failures.append("b136:diagnostic_protection_disabled")
    for key in (
        "raw_paths_included",
        "command_lines_included",
        "usernames_included",
        "license_token_included",
        "license_id_included",
        "file_contents_included",
    ):
        if data.get(key) is not False:
            failures.append(f"b136:diagnostic_privacy_boundary:{key}")
    return tuple(dict.fromkeys(failures))


def export_diagnostics(
    destination: str | Path,
    *,
    commercial_state: CommercialState,
) -> dict[str, Any]:
    target = Path(destination)
    payload = diagnostic_snapshot(commercial_state=commercial_state)
    failures = validate_diagnostic_snapshot(payload)
    if failures:
        raise ValueError(";".join(failures))
    _atomic_write_json(target, payload)
    return {
        "exported": True,
        "path": str(target),
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "bytes": target.stat().st_size,
        "diagnostic_digest": _digest(payload),
    }


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "product": PRODUCT_NAME,
        "product_version": PRODUCT_VERSION,
        "publisher": PUBLISHER,
        "support_url": SUPPORT_URL,
        "default_trial_days": DEFAULT_TRIAL_DAYS,
        "policy_surfaces": policy_surfaces(),
        "boundaries": dict(BOUNDARIES),
        "readiness_projection": projected_readiness(),
    }


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures: list[str] = []

    readiness = projected_readiness()
    if first != second:
        failures.append("b136:contract_not_deterministic")
    if readiness["pillar_counts"] != {"READY": 9, "PARTIAL": 0, "BLOCKED": 1}:
        failures.append("b136:readiness_counts_invalid")
    if readiness["release_blockers"] != ["CODE_SIGNING"]:
        failures.append("b136:readiness_blockers_invalid")
    if readiness["release_blocker_count"] != 1:
        failures.append("b136:readiness_blocker_count_invalid")
    if len(policy_surfaces()) != 3:
        failures.append("b136:policy_surface_count_invalid")
    if any(BOUNDARIES.values()):
        failures.append("b136:privacy_or_authority_boundary_widened")

    expired = evaluate_trial(
        {
            "schema": TRIAL_SCHEMA,
            "started_at": 0.0,
            "trial_days": DEFAULT_TRIAL_DAYS,
        },
        now=float(DEFAULT_TRIAL_DAYS * 86400 + 1),
    )
    if expired.status != TRIAL_EXPIRED or expired.protection_enabled is not True:
        failures.append("b136:expired_trial_weakened_protection")

    unavailable = verify_signed_entitlement({}, public_key=None, now=0.0)
    if unavailable.status != UNAVAILABLE or unavailable.protection_enabled is not True:
        failures.append("b136:unavailable_activation_weakened_protection")

    diagnostics = diagnostic_snapshot(commercial_state=expired)
    failures.extend(validate_diagnostic_snapshot(diagnostics))

    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "contract_digest": _digest(first),
        "deterministic_contract": first == second,
        "readiness_projection": readiness,
        "trial_days": DEFAULT_TRIAL_DAYS,
        "expired_trial_keeps_protection": expired.protection_enabled,
        "activation_unavailable_keeps_protection": unavailable.protection_enabled,
        "policy_surface_count": len(policy_surfaces()),
        "diagnostic_export_privacy_valid": not validate_diagnostic_snapshot(diagnostics),
        "network_required": False,
        "cloud_required": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


if __name__ == "__main__":
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)
