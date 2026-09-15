from __future__ import annotations

"""B6-5.9 read-only persistent quarantine integrity visibility.

B6-5.8 intentionally fails closed when a persistent recovery record, journal,
artifact or original target state no longer validates.  B6-5.9 keeps that
security boundary unchanged, but stops silently hiding those degraded states
from the Quarantine page.

Discovery remains read-only.  A verified active quarantine still exposes the
existing explicit ``Ripristina file`` action.  A degraded persistent record is
shown as ``Verifica richiesta`` / ``Ripristino bloccato`` and receives no
restore key, so the UI cannot attach a mutating control to it.

No automatic cleanup, repair, deletion, target overwrite, process control or
trust mutation is introduced by this milestone.
"""

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Final

from sentinel import home_quarantine as b658

PROFILE: Final[str] = "v0.11.0-beta.6-b65.9-quarantine-integrity"
SCHEMA: Final[str] = "bc-sentinel-beta6-home-quarantine-integrity-v1"

INTEGRITY_VERIFIED: Final[str] = "VERIFIED"
INTEGRITY_BLOCKED: Final[str] = "BLOCKED"


@dataclass(frozen=True)
class QuarantineIntegrityIssue:
    record_path: Path
    issue_code: str
    reason: str
    finding_id: str = ""
    target_locator: str = ""
    severity: str = ""
    title: str = ""
    observed_at: float = 0.0

    def to_row(self) -> dict:
        target = str(self.target_locator or "")
        display_file = Path(target).name if target else self.record_path.name
        display_path = target if target else f"Metadati quarantena: {self.record_path.name}"
        try:
            date = (
                datetime.fromtimestamp(float(self.observed_at)).astimezone().strftime("%d/%m/%Y %H:%M")
                if self.observed_at
                else ""
            )
        except (OverflowError, OSError, ValueError):
            date = ""
        return {
            "file": display_file,
            "path": display_path,
            "date": date,
            "risk": self.severity or "—",
            "reason": self.reason,
            "status": "Verifica richiesta",
            "action": "Ripristino bloccato",
            "restore_key": "",
            "integrity_state": INTEGRITY_BLOCKED,
            "integrity_issue_code": self.issue_code,
            "finding_id": self.finding_id,
            "title": self.title,
        }


def _issue_reason(code: str) -> str:
    mapping = {
        "record_unreadable": "I metadati persistenti della quarantena non sono leggibili.",
        "record_integrity": "I metadati persistenti della quarantena non superano la verifica di integrità.",
        "record_identity": "L'identità del record persistente non corrisponde al rilevamento atteso.",
        "permit_invalid": "Il permesso persistito non supera più le verifiche di integrità.",
        "result_invalid": "Il risultato persistito non supera più le verifiche di integrità.",
        "journal_integrity": "Il journal di quarantena non supera la verifica della catena SHA-256.",
        "journal_binding": "Il journal non corrisponde più al permesso persistito.",
        "journal_anchor": "Manca o non coincide l'ancora verificata dell'azione di quarantena.",
        "target_collision": "La posizione originale è occupata: il ripristino è bloccato per evitare sovrascritture.",
        "artifact_path": "Un artefatto di recovery risulta fuori dalle directory protette previste.",
        "artifact_missing": "Quarantena o snapshot di rollback non sono più disponibili.",
        "artifact_hash": "Quarantena o snapshot non corrispondono più allo SHA-256 originale.",
        "finding_binding": "Il rilevamento persistito non corrisponde al permesso di quarantena.",
        "persistent_state": "Lo stato persistente non è verificabile in sicurezza.",
    }
    return mapping.get(code, mapping["persistent_state"])


def _classify_error(exc: BaseException) -> str:
    text = str(exc or "")
    mapping = (
        ("b658_recovery_record_unreadable", "record_unreadable"),
        ("b658_recovery_record_invalid", "record_unreadable"),
        ("b658_recovery_record_integrity_mismatch", "record_integrity"),
        ("b658_recovery_record_identity_mismatch", "record_identity"),
        ("b658_recovery_permit_invalid", "permit_invalid"),
        ("b656_permit_", "permit_invalid"),
        ("b658_recovery_result_invalid", "result_invalid"),
        ("b656_result_", "result_invalid"),
        ("b658_journal_integrity_mismatch", "journal_integrity"),
        ("b658_journal_unreadable", "journal_integrity"),
        ("b658_journal_entry_invalid", "journal_integrity"),
        ("b658_journal_permit_binding_mismatch", "journal_binding"),
        ("b658_recovery_journal_anchor_missing", "journal_anchor"),
        ("b658_recovery_journal_anchor_invalid", "journal_anchor"),
        ("b658_recovery_target_collision", "target_collision"),
        ("b658_recovery_artifact_path_invalid", "artifact_path"),
        ("b658_recovery_artifact_missing", "artifact_missing"),
        ("b658_recovery_artifact_hash_mismatch", "artifact_hash"),
        ("b658_recovery_finding_binding_mismatch", "finding_binding"),
        ("b658_recovery_result_binding_mismatch", "finding_binding"),
    )
    for marker, code in mapping:
        if marker in text:
            return code
    return "persistent_state"


def _trusted_metadata(path: Path) -> dict:
    """Return display metadata only after the B6-5.8 record hash validates."""

    payload = b658._read_record(path)
    display = payload.get("display") if isinstance(payload.get("display"), dict) else {}
    permit = b658._permit_from_dict(payload.get("permit"))
    return {
        "finding_id": str(payload.get("finding_id") or ""),
        "target_locator": str(permit.target_locator or ""),
        "severity": str(display.get("severity") or ""),
        "title": str(display.get("title") or ""),
        "updated_at": float(payload.get("updated_at") or 0.0),
        "state": str(payload.get("state") or ""),
    }


def audit_persistent_quarantine() -> list[QuarantineIntegrityIssue]:
    """Inspect persistent recovery records without writing or creating storage."""

    root = b658._recovery_root()
    if not root.is_dir():
        return []
    try:
        paths = sorted(path for path in root.glob("*.json") if path.is_file())
    except OSError:
        return []

    issues: list[QuarantineIntegrityIssue] = []
    for path in paths:
        trusted: dict = {}
        try:
            trusted = _trusted_metadata(path)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            code = _classify_error(exc)
            try:
                observed = path.stat().st_mtime
            except OSError:
                observed = 0.0
            issues.append(
                QuarantineIntegrityIssue(
                    record_path=path,
                    issue_code=code,
                    reason=_issue_reason(code),
                    observed_at=observed,
                )
            )
            continue

        if trusted.get("state") == b658.RECOVERY_RESTORED:
            continue

        try:
            persistent = b658._persistent_from_path(path)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            code = _classify_error(exc)
            issues.append(
                QuarantineIntegrityIssue(
                    record_path=path,
                    issue_code=code,
                    reason=_issue_reason(code),
                    finding_id=str(trusted.get("finding_id") or ""),
                    target_locator=str(trusted.get("target_locator") or ""),
                    severity=str(trusted.get("severity") or ""),
                    title=str(trusted.get("title") or ""),
                    observed_at=float(trusted.get("updated_at") or 0.0),
                )
            )
            continue

        # ``None`` is not automatically an integrity failure.  It also covers
        # legitimate terminal journal states after a verified restore and a
        # PREPARED record where no quarantine action ever completed.
        if persistent is None:
            continue

    return issues


def integrity_summary() -> dict:
    issues = audit_persistent_quarantine()
    counts: dict[str, int] = {}
    for issue in issues:
        counts[issue.issue_code] = counts.get(issue.issue_code, 0) + 1
    return {
        "issue_count": len(issues),
        "issue_codes": counts,
        "read_only": True,
    }


class HomeQuarantineController(b658.HomeQuarantineController):
    """B6-5.8 controller plus read-only degraded-state visibility."""

    def integrity_issues(self) -> list[QuarantineIntegrityIssue]:
        return audit_persistent_quarantine()

    def quarantine_rows(self) -> list[dict]:
        rows = list(super().quarantine_rows())
        for row in rows:
            row.setdefault("integrity_state", INTEGRITY_VERIFIED)
            row.setdefault("integrity_issue_code", "")
        rows.extend(issue.to_row() for issue in self.integrity_issues())
        return rows


def validate_b659_contract() -> dict:
    predecessor = b658.validate_b658_contract()
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": predecessor.get("passed") is True,
        "b658_predecessor_green": predecessor.get("passed") is True,
        "persistent_restore_after_restart": predecessor.get("persistent_restore_after_restart") is True,
        "degraded_persistent_state_visible": True,
        "integrity_audit_read_only": True,
        "blocked_rows_have_no_restore_key": True,
        "verified_rows_keep_explicit_restore": True,
        "automatic_cleanup": False,
        "automatic_quarantine": False,
        "automatic_restore": False,
        "automatic_repair": False,
        "general_home_execution_authorized": False,
        "delete_authorized": False,
        "repair_authorized": False,
        "terminate_process_authorized": False,
        "trust_allowlist_mutation_authorized": False,
        "next_execution_owner": "B6-5.10+",
    }
