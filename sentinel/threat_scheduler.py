from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import time
from typing import Any

from .config import APP_VERSION
from .path_security import has_reparse_component, is_reparse_point, secure_write_parent
from .service_hardening import ensure_integrity_key
from .threat_index import ThreatContentCache, ThreatIndexError, ThreatIndexStore
from .threat_packages import SignedThreatPackageVerifier, ThreatPackageError
from .threat_retrieval import SecureThreatRetriever, ThreatRetrievalError
from .threat_trust import ThreatTrustStore

MIN_CHECK_INTERVAL_SECONDS = 3600
MAX_CHECK_INTERVAL_SECONDS = 24 * 3600
SCHEDULER_STATE_SCHEMA = 1


class ThreatSchedulerError(ValueError):
    pass


class ThreatCheckScheduler:
    """Bounded periodic-check state. It schedules retrieval only, never activation."""

    def __init__(
        self,
        base_dir: str | Path,
        *,
        integrity_key: bytes | None = None,
        interval_seconds: int = 6 * 3600,
    ):
        self.base_dir = Path(base_dir).resolve()
        self.integrity_key = bytes(integrity_key) if integrity_key is not None else ensure_integrity_key()
        self.interval_seconds = max(MIN_CHECK_INTERVAL_SECONDS, min(int(interval_seconds), MAX_CHECK_INTERVAL_SECONDS))
        self.state_path = self.base_dir / "scheduler-state.json"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        if has_reparse_component(self.base_dir, include_leaf=False) or is_reparse_point(self.base_dir):
            raise ThreatSchedulerError("threat scheduler path cannot traverse a reparse point")

    @staticmethod
    def _canonical(body: dict[str, Any]) -> bytes:
        return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _read(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {
                "schema": SCHEDULER_STATE_SCHEMA,
                "last_check": 0.0,
                "last_success": 0.0,
                "next_due": 0.0,
                "failures": 0,
                "last_error": "",
            }
        try:
            obj = json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ThreatSchedulerError(f"cannot read threat scheduler state: {exc}") from exc
        supplied = str(obj.pop("hmac", ""))
        expected = hmac.new(self.integrity_key, self._canonical(obj), hashlib.sha256).hexdigest()
        if not supplied or not hmac.compare_digest(supplied, expected):
            raise ThreatSchedulerError("threat scheduler state HMAC verification failed")
        if int(obj.get("schema") or 0) != SCHEDULER_STATE_SCHEMA:
            raise ThreatSchedulerError("threat scheduler state schema is invalid")
        return obj

    def _write(self, body: dict[str, Any]) -> None:
        payload = dict(body)
        payload.pop("hmac", None)
        payload["hmac"] = hmac.new(self.integrity_key, self._canonical(payload), hashlib.sha256).hexdigest()
        secure_write_parent(self.state_path)
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.state_path)

    def due(self, *, now: float | None = None) -> bool:
        current = time.time() if now is None else float(now)
        return current >= float(self._read().get("next_due") or 0.0)

    def record_success(self, *, now: float | None = None) -> dict[str, Any]:
        current = time.time() if now is None else float(now)
        state = self._read()
        state.update({
            "last_check": current,
            "last_success": current,
            "next_due": current + self.interval_seconds,
            "failures": 0,
            "last_error": "",
        })
        self._write(state)
        return self.status(now=current)

    def record_failure(self, error: str, *, now: float | None = None) -> dict[str, Any]:
        current = time.time() if now is None else float(now)
        state = self._read()
        failures = min(20, int(state.get("failures") or 0) + 1)
        # Bounded retry backoff; never faster than hourly.
        delay = min(self.interval_seconds, MIN_CHECK_INTERVAL_SECONDS * (2 ** min(failures - 1, 4)))
        state.update({
            "last_check": current,
            "next_due": current + delay,
            "failures": failures,
            "last_error": str(error or "")[:300],
        })
        self._write(state)
        return self.status(now=current)

    def status(self, *, now: float | None = None) -> dict[str, Any]:
        current = time.time() if now is None else float(now)
        state = self._read()
        return {
            "schema": SCHEDULER_STATE_SCHEMA,
            "enabled": True,
            "interval_seconds": self.interval_seconds,
            "min_interval_seconds": MIN_CHECK_INTERVAL_SECONDS,
            "max_interval_seconds": MAX_CHECK_INTERVAL_SECONDS,
            "last_check": float(state.get("last_check") or 0.0),
            "last_success": float(state.get("last_success") or 0.0),
            "next_due": float(state.get("next_due") or 0.0),
            "due": current >= float(state.get("next_due") or 0.0),
            "failures": int(state.get("failures") or 0),
            "last_error": str(state.get("last_error") or ""),
            "auto_stage": False,
            "auto_activate": False,
            "cloud_required": False,
        }


class ThreatRemoteCoordinator:
    """Retrieves and verifies remote metadata/content, but never stages or activates it."""

    def __init__(
        self,
        *,
        retriever: SecureThreatRetriever,
        index_store: ThreatIndexStore,
        cache: ThreatContentCache,
        package_verifier: SignedThreatPackageVerifier,
        trust_store: ThreatTrustStore | None = None,
        scheduler: ThreatCheckScheduler | None = None,
        product_version: str = APP_VERSION,
    ):
        self.retriever = retriever
        self.index_store = index_store
        self.cache = cache
        self.package_verifier = package_verifier
        self.trust_store = trust_store
        self.scheduler = scheduler
        self.product_version = str(product_version)

    @staticmethod
    def _decode_envelope(body: bytes, *, kind: str) -> dict[str, Any]:
        try:
            obj = json.loads(bytes(body).decode("utf-8"))
        except Exception as exc:
            raise ThreatSchedulerError(f"retrieved {kind} envelope is invalid UTF-8 JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise ThreatSchedulerError(f"retrieved {kind} envelope must be an object")
        return obj

    def check(
        self,
        index_url: str,
        *,
        active_sequence: int = 0,
        expected_index_sha256: str = "",
        now: float | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        current = time.time() if now is None else float(now)
        if self.scheduler is not None and not force and not self.scheduler.due(now=current):
            return {"checked": False, "reason": "not_due", "candidate": None, "auto_stage": False, "auto_activate": False}
        try:
            retrieved_index = self.retriever.fetch(index_url, expected_sha256=expected_index_sha256)
            envelope = self._decode_envelope(retrieved_index.body, kind="index")
            if set(envelope) != {"index", "signature"} or not isinstance(envelope.get("index"), dict) or not isinstance(envelope.get("signature"), str):
                raise ThreatSchedulerError("retrieved index envelope fields are invalid")
            accepted = self.index_store.accept(envelope["index"], envelope["signature"], now=current)
            candidate = self.index_store.select_candidate(
                active_sequence=active_sequence,
                product_version=self.product_version,
                trust_store=self.trust_store,
                now=current,
            )
            candidate_result = None
            if candidate is not None:
                retrieved_package = self.retriever.fetch(candidate["url"], expected_sha256=candidate["sha256"])
                if len(retrieved_package.body) != int(candidate["size"]):
                    raise ThreatSchedulerError("retrieved package size does not match signed index metadata")
                cache_record = self.cache.store(retrieved_package.body, expected_sha256=candidate["sha256"])
                pkg_env = self._decode_envelope(retrieved_package.body, kind="package")
                if set(pkg_env) != {"package", "signature"} or not isinstance(pkg_env.get("package"), dict) or not isinstance(pkg_env.get("signature"), str):
                    raise ThreatSchedulerError("retrieved package envelope fields are invalid")
                verified = self.package_verifier.verify(pkg_env["package"], pkg_env["signature"], now=current)
                if verified.package_id != candidate["package_id"] or verified.sequence != int(candidate["sequence"]):
                    raise ThreatSchedulerError("retrieved package identity does not match signed index metadata")
                if verified.payload_sha256 == candidate["sha256"]:
                    # The index hashes the retrieval envelope, not the inner canonical package.
                    raise ThreatSchedulerError("index package hash must address the retrieval envelope, not the inner package")
                if verified.signing_key_id != candidate["signing_key_id"]:
                    raise ThreatSchedulerError("retrieved package signer does not match signed index metadata")
                component_names = sorted(pkg_env["package"].get("components", {}).keys())
                if component_names != sorted(candidate["components"]):
                    raise ThreatSchedulerError("retrieved package components do not match signed index metadata")
                candidate_result = {
                    "metadata": dict(candidate),
                    "cache": cache_record,
                    "verified_package": {
                        "package_id": verified.package_id,
                        "sequence": verified.sequence,
                        "signing_key_id": verified.signing_key_id,
                        "payload_sha256": verified.payload_sha256,
                    },
                    "ready_for_manual_stage": True,
                }
            if self.scheduler is not None:
                self.scheduler.record_success(now=current)
            return {
                "checked": True,
                "index": accepted.get("index"),
                "candidate": candidate_result,
                "auto_stage": False,
                "auto_activate": False,
            }
        except (ThreatRetrievalError, ThreatIndexError, ThreatPackageError, ThreatSchedulerError) as exc:
            if self.scheduler is not None:
                self.scheduler.record_failure(str(exc), now=current)
            raise ThreatSchedulerError(str(exc)) from exc

    @classmethod
    def policy(cls) -> dict[str, Any]:
        return {
            "signed_remote_index": True,
            "index_anti_rollback": True,
            "content_addressed_cache": True,
            "controlled_scheduled_retrieval": True,
            "auto_stage": False,
            "auto_activate": False,
            "cloud_required": False,
        }
