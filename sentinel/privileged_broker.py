from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import secrets
import threading
import time
from typing import Any

from .protection_protocol import ClientContext

BROKER_TICKET_TTL_SECONDS = 60.0
BROKER_RESULT_TTL_SECONDS = 120.0
BROKER_MAX_ACTIVE_TICKETS = 128
BROKER_MAX_TICKETS_PER_SID = 16


def canonical_action_digest(op: str, payload: dict[str, Any]) -> str:
    body = {"op": str(op), "payload": payload}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(slots=True)
class BrokerTicket:
    ticket_id: str
    op: str
    payload: dict[str, Any]
    payload_digest: str
    requester_sid: str
    requester_session_id: int | None
    requester_process_id: int | None
    issued_at: float
    expires_at: float
    consumed_at: float = 0.0
    elevated_sid: str = ""
    elevated_process_id: int | None = None
    result: dict[str, Any] | None = None
    result_expires_at: float = 0.0

    @property
    def consumed(self) -> bool:
        return self.consumed_at > 0


class PrivilegeTicketStore:
    """In-memory one-action elevation tickets.

    Tickets never contain a generic command line.  The service stores the
    already-validated privileged operation and payload, while the UAC broker
    receives only an unpredictable ticket identifier.  Consumption requires an
    authenticated elevated local client in the same Windows session.
    """

    def __init__(self, *, ttl_seconds: float = BROKER_TICKET_TTL_SECONDS):
        self.ttl_seconds = max(5.0, min(float(ttl_seconds), 300.0))
        self._tickets: dict[str, BrokerTicket] = {}
        self._lock = threading.RLock()
        self._issued = 0
        self._consumed = 0
        self._completed = 0
        self._rejected = 0

    def _prune_locked(self, now: float) -> None:
        stale = []
        for ident, ticket in self._tickets.items():
            if ticket.result is not None:
                if ticket.result_expires_at and now > ticket.result_expires_at:
                    stale.append(ident)
            elif now > ticket.expires_at:
                stale.append(ident)
        for ident in stale:
            self._tickets.pop(ident, None)

    def issue(self, context: ClientContext, op: str, payload: dict[str, Any]) -> BrokerTicket:
        if not context.local or not context.authenticated or not context.sid:
            raise PermissionError("authenticated local requester identity is required")
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            if len(self._tickets) >= BROKER_MAX_ACTIVE_TICKETS:
                raise RuntimeError("privileged ticket capacity reached")
            per_sid = sum(
                1 for x in self._tickets.values()
                if x.requester_sid == context.sid and x.result is None and now <= x.expires_at
            )
            if per_sid >= BROKER_MAX_TICKETS_PER_SID:
                raise RuntimeError("too many pending privileged requests for this user")
            ident = secrets.token_urlsafe(32)
            ticket = BrokerTicket(
                ticket_id=ident,
                op=str(op),
                payload=dict(payload),
                payload_digest=canonical_action_digest(op, payload),
                requester_sid=context.sid,
                requester_session_id=context.session_id,
                requester_process_id=context.process_id,
                issued_at=now,
                expires_at=now + self.ttl_seconds,
            )
            self._tickets[ident] = ticket
            self._issued += 1
            return ticket

    def consume(self, ticket_id: str, broker_context: ClientContext) -> BrokerTicket:
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            ticket = self._tickets.get(str(ticket_id))
            if ticket is None:
                self._rejected += 1
                raise KeyError("privileged ticket not found or expired")
            if ticket.consumed:
                self._rejected += 1
                raise PermissionError("privileged ticket was already consumed")
            if now > ticket.expires_at:
                self._tickets.pop(ticket.ticket_id, None)
                self._rejected += 1
                raise PermissionError("privileged ticket expired")
            if not broker_context.local or not broker_context.authenticated or not broker_context.is_admin:
                self._rejected += 1
                raise PermissionError("ticket consumption requires an elevated authenticated local client")
            if (
                ticket.requester_session_id is not None
                and broker_context.session_id is not None
                and ticket.requester_session_id != broker_context.session_id
            ):
                self._rejected += 1
                raise PermissionError("elevated broker session does not match the requester session")
            ticket.consumed_at = now
            ticket.elevated_sid = broker_context.sid
            ticket.elevated_process_id = broker_context.process_id
            self._consumed += 1
            return ticket

    def complete(self, ticket_id: str, result: dict[str, Any]) -> None:
        now = time.time()
        with self._lock:
            ticket = self._tickets.get(str(ticket_id))
            if ticket is None or not ticket.consumed:
                raise KeyError("consumed privileged ticket not found")
            ticket.result = dict(result)
            ticket.result_expires_at = now + BROKER_RESULT_TTL_SECONDS
            self._completed += 1

    def result_for(self, ticket_id: str, requester_context: ClientContext) -> dict[str, Any] | None:
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            ticket = self._tickets.get(str(ticket_id))
            if ticket is None:
                return None
            if not requester_context.local or not requester_context.authenticated:
                raise PermissionError("authenticated local requester identity is required")
            if requester_context.sid != ticket.requester_sid:
                raise PermissionError("privileged result belongs to a different requester")
            if (
                ticket.requester_session_id is not None
                and requester_context.session_id is not None
                and requester_context.session_id != ticket.requester_session_id
            ):
                raise PermissionError("privileged result belongs to a different session")
            if (
                ticket.requester_process_id is not None
                and requester_context.process_id is not None
                and requester_context.process_id != ticket.requester_process_id
            ):
                raise PermissionError("privileged result belongs to a different requester process")
            return None if ticket.result is None else dict(ticket.result)

    def metrics(self) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            pending = sum(1 for x in self._tickets.values() if not x.consumed and now <= x.expires_at)
            return {
                "mode": "one_action_uac",
                "ttl_seconds": self.ttl_seconds,
                "issued": self._issued,
                "consumed": self._consumed,
                "completed": self._completed,
                "rejected": self._rejected,
                "pending": pending,
            }

    def status_for(self, ticket_id: str, requester_context: ClientContext) -> dict[str, Any] | None:
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            ticket = self._tickets.get(str(ticket_id))
            if ticket is None:
                return None
            if requester_context.sid != ticket.requester_sid:
                raise PermissionError("privileged ticket belongs to a different requester")
            if (
                ticket.requester_process_id is not None
                and requester_context.process_id is not None
                and requester_context.process_id != ticket.requester_process_id
            ):
                raise PermissionError("privileged ticket belongs to a different requester process")
            return {
                "ticket_id": ticket.ticket_id,
                "op": ticket.op,
                "payload_digest": ticket.payload_digest,
                "issued_at": ticket.issued_at,
                "expires_at": ticket.expires_at,
                "consumed": ticket.consumed,
                "completed": ticket.result is not None,
            }
