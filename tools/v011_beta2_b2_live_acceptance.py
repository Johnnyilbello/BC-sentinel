from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import tempfile
from time import sleep, time
from typing import Any, Callable

from sentinel.config import EDR_DB_PATH
from sentinel.edr import EdrIncident, EdrTelemetryStore

PROFILE = "v0.11.0-beta.2"
EXPECTED_PROTOCOL_SHA256 = "2e39ec0422f820e107832b3ba20c62c103ea15cc99639159ea2ec1be211505b1"
EXPECTED_SERVICE_SHA256 = "d5395dc2bb086941796703910143a0598e8fd4da36e53c19e2a910030498fe46"
EXPECTED_CLIENT_SHA256 = "6910eb42f6e7c5ba4d87b1f1533dfacff99483fbf4ffb06810595effa66cc9d1"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_guards(root: Path) -> dict[str, Any]:
    protocol = root / "sentinel" / "protection_protocol.py"
    service = root / "sentinel" / "protection_service_core.py"
    client = root / "sentinel" / "protection_client.py"
    return {
        "protocol_sha256": _sha(protocol),
        "service_sha256": _sha(service),
        "client_sha256": _sha(client),
        "protocol_matches_b1b": _sha(protocol) == EXPECTED_PROTOCOL_SHA256,
        "service_matches_b1b": _sha(service) == EXPECTED_SERVICE_SHA256,
        "client_matches_b1b": _sha(client) == EXPECTED_CLIENT_SHA256,
    }


def _instantiate(cls: type) -> Any | None:
    try:
        sig = inspect.signature(cls)
    except (TypeError, ValueError):
        sig = None
    if sig is not None:
        for p in sig.parameters.values():
            if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
                continue
            if p.default is inspect.Parameter.empty:
                return None
    try:
        return cls()
    except Exception:
        return None


def _generic_methods(obj: Any) -> list[tuple[int, str, Callable[..., Any]]]:
    ranked: list[tuple[int, str, Callable[..., Any]]] = []
    preferred = {"request": 0, "_request": 1, "call": 2, "invoke": 3, "send_request": 4, "exchange": 5, "_exchange": 6}
    for name in dir(obj):
        try:
            fn = getattr(obj, name)
        except Exception:
            continue
        if not callable(fn):
            continue
        try:
            sig = inspect.signature(fn)
            params = list(sig.parameters.values())
        except (TypeError, ValueError):
            continue
        names = {p.name.casefold() for p in params}
        if not ({"op", "operation"} & names):
            continue
        score = preferred.get(name.casefold(), 20)
        try:
            source = inspect.getsource(fn)
        except Exception:
            source = ""
        if "build_request" in source:
            score -= 5
        ranked.append((score, name, fn))
    return sorted(ranked, key=lambda item: (item[0], item[1]))


def _call_generic(fn: Callable[..., Any], operation: str, payload: dict[str, Any]) -> Any:
    sig = inspect.signature(fn)
    params = list(sig.parameters.values())
    kwargs: dict[str, Any] = {}
    positional: list[Any] = []
    op_bound = False
    payload_bound = False
    for p in params:
        folded = p.name.casefold()
        if folded in {"op", "operation"} and not op_bound:
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD):
                positional.append(operation)
            else:
                kwargs[p.name] = operation
            op_bound = True
        elif folded in {"payload", "data", "params", "arguments"} and not payload_bound:
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD):
                positional.append(payload)
            else:
                kwargs[p.name] = payload
            payload_bound = True
        elif p.default is inspect.Parameter.empty and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            raise RuntimeError(f"unsupported required client parameter: {p.name}")
    if not op_bound:
        raise RuntimeError("generic client method has no operation parameter")
    if payload and not payload_bound:
        raise RuntimeError("generic client method has no payload parameter")
    return fn(*positional, **kwargs)


class ProductionClient:
    def __init__(self):
        import sentinel.protection_client as module

        candidates: list[tuple[int, str, Any, Callable[..., Any]]] = []
        for name, obj in vars(module).items():
            if not inspect.isclass(obj) or getattr(obj, "__module__", "") != module.__name__:
                continue
            instance = _instantiate(obj)
            if instance is None:
                continue
            for score, method_name, fn in _generic_methods(instance):
                candidates.append((score, f"{name}.{method_name}", instance, fn))
        for score, method_name, fn in _generic_methods(module):
            candidates.append((score, f"module.{method_name}", module, fn))
        if not candidates:
            classes = sorted(
                name for name, obj in vars(module).items()
                if inspect.isclass(obj) and getattr(obj, "__module__", "") == module.__name__
            )
            raise RuntimeError("production client generic request surface not discovered; classes=" + ",".join(classes))
        candidates.sort(key=lambda item: (item[0], item[1]))
        _, self.surface, self.owner, self.fn = candidates[0]

    def call(self, operation: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            value = _call_generic(self.fn, operation, dict(payload or {}))
        except Exception as exc:
            raise RuntimeError(f"production IPC {operation} failed via {self.surface}: {type(exc).__name__}: {exc}") from exc
        if not isinstance(value, dict):
            raise RuntimeError(f"production IPC {operation} returned non-object response")
        if value.get("ok") is False:
            code = str(value.get("code") or value.get("error") or "service_error")
            message = str(value.get("message") or value)
            raise RuntimeError(f"production IPC {operation} rejected: {code}: {message}")
        return value


def _find_incident(value: Any, incident_id: str) -> bool:
    if isinstance(value, dict):
        if str(value.get("incident_id") or "") == incident_id:
            return True
        return any(_find_incident(v, incident_id) for v in value.values())
    if isinstance(value, list):
        return any(_find_incident(v, incident_id) for v in value)
    return False


def _wait_hunt(client: ProductionClient, marker: str, *, timeout_seconds: float = 12.0) -> dict[str, Any]:
    deadline = time() + max(1.0, timeout_seconds)
    last: dict[str, Any] = {}
    while time() < deadline:
        last = client.call("edr_hunt", {"indicator": marker, "kind": "path", "limit": 20})
        items = last.get("items")
        if isinstance(items, list) and items:
            return last
        sleep(0.35)
    raise RuntimeError("native TEMP marker was not observed by service-owned EDR within timeout")


def _seed_review_only_incident() -> str:
    token = hashlib.sha256(f"{os.getpid()}:{time()}".encode()).hexdigest()[:20].upper()
    incident_id = "BCEDR-" + token
    store = EdrTelemetryStore(EDR_DB_PATH)
    store.save_incident(EdrIncident(
        incident_id=incident_id,
        score=88,
        severity="HIGH",
        confidence=0.95,
        event_ids=[],
        pids=[],
        signal_codes=["b2_harmless_acceptance_fixture"],
        evidence_families=["deterministic", "execution", "persistence"],
        reasons=["Harmless B2 Security Center persistence acceptance fixture."],
        first_seen=time(),
        last_seen=time(),
        automatic_destructive_action=False,
        host_isolation=False,
        response_mode="operator_review",
    ))
    return incident_id


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def run_pre_restart(root: Path, output: Path) -> int:
    guards = _source_guards(root)
    if not all(guards[k] for k in ("protocol_matches_b1b", "service_matches_b1b", "client_matches_b1b")):
        raise RuntimeError("B1b source SHA guard failed before B2 live acceptance")

    client = ProductionClient()
    status = client.call("edr_status")
    if not bool(status.get("service_owned_store")) or not bool(status.get("authenticated_ipc_required")):
        raise RuntimeError("service-owned/authenticated EDR status invariants are not active")
    if bool(status.get("automatic_process_kill")) or bool(status.get("automatic_file_delete")) or bool(status.get("automatic_host_isolation")):
        raise RuntimeError("automatic destructive EDR response unexpectedly enabled")

    policy = client.call("edr_retention_policy")
    retention = float(policy.get("retention_seconds") or 0)
    max_events = int(policy.get("max_events") or 0)
    if retention <= 0 or max_events <= 0:
        raise RuntimeError("EDR retention policy is not queryable over production IPC")

    # Exercise the privileged endpoint without changing the effective policy.
    same_policy = client.call("edr_update_retention", {
        "retention_seconds": retention,
        "max_events": max_events,
        "prune": False,
    })
    if int(same_policy.get("max_events") or 0) != max_events:
        raise RuntimeError("privileged retention round-trip changed effective policy unexpectedly")

    marker_path = Path(tempfile.gettempdir()) / f"bcs-v011-beta2-b2-native-{hashlib.sha256(str(time()).encode()).hexdigest()[:16]}.tmp"
    marker_path.write_text("BC Sentinel Beta2 harmless native-ingestion acceptance marker\n", encoding="utf-8")
    hunt = _wait_hunt(client, str(marker_path))

    incident_id = _seed_review_only_incident()
    pending: dict[str, Any] = {}
    deadline = time() + 8.0
    while time() < deadline:
        pending = client.call("pending_threats", {"limit": 500})
        if _find_incident(pending, incident_id):
            break
        sleep(0.25)
    if not _find_incident(pending, incident_id):
        raise RuntimeError("qualified review-only EDR incident is not visible in production Security Center pending_threats")

    result = {
        "profile": PROFILE,
        "checkpoint": "B2-pre-restart",
        "passed": True,
        "client_surface": client.surface,
        "guards": guards,
        "marker_path": str(marker_path),
        "marker_event_ids": [str(item.get("event_id") or "") for item in hunt.get("items", []) if isinstance(item, dict)],
        "incident_id": incident_id,
        "service_owned_store": True,
        "authenticated_ipc": True,
        "privileged_retention_same_policy": True,
        "security_center_visible": True,
        "automatic_process_kill": False,
        "automatic_file_delete": False,
        "automatic_host_isolation": False,
    }
    _write_json(output, result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def run_post_restart(root: Path, marker: str, incident_id: str, output: Path) -> int:
    guards = _source_guards(root)
    if not all(guards[k] for k in ("protocol_matches_b1b", "service_matches_b1b", "client_matches_b1b")):
        raise RuntimeError("B1b source SHA guard failed after service restart")
    client = ProductionClient()
    status = client.call("edr_status")
    hunt = _wait_hunt(client, marker, timeout_seconds=8.0)
    pending = client.call("pending_threats", {"limit": 500})
    if not _find_incident(pending, incident_id):
        raise RuntimeError("review-only EDR incident did not persist across service restart")
    result = {
        "profile": PROFILE,
        "checkpoint": "B2-post-restart",
        "passed": True,
        "client_surface": client.surface,
        "guards": guards,
        "marker_path": marker,
        "marker_persisted": bool(hunt.get("items")),
        "incident_id": incident_id,
        "incident_persisted_in_security_center": True,
        "service_owned_store": bool(status.get("service_owned_store")),
        "automatic_process_kill": bool(status.get("automatic_process_kill", False)),
        "automatic_file_delete": bool(status.get("automatic_file_delete", False)),
        "automatic_host_isolation": bool(status.get("automatic_host_isolation", False)),
    }
    if result["automatic_process_kill"] or result["automatic_file_delete"] or result["automatic_host_isolation"]:
        raise RuntimeError("automatic destructive response enabled after restart")
    _write_json(output, result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def run_standard_user(root: Path, output: Path) -> int:
    guards = _source_guards(root)
    if not all(guards[k] for k in ("protocol_matches_b1b", "service_matches_b1b", "client_matches_b1b")):
        raise RuntimeError("B1b source SHA guard failed for standard-user acceptance")
    client = ProductionClient()
    status = client.call("edr_status")
    client.call("edr_retention_policy")
    rejected = False
    rejection = ""
    try:
        client.call("edr_update_retention", {"max_events": 100000, "prune": False})
    except Exception as exc:
        rejection = str(exc)
        folded = rejection.casefold()
        rejected = any(term in folded for term in ("admin", "privileg", "unauthor", "elevat"))
    if not rejected:
        raise RuntimeError("standard-user direct privileged EDR retention call was not rejected")
    result = {
        "profile": PROFILE,
        "checkpoint": "B2-standard-user",
        "passed": True,
        "client_surface": client.surface,
        "authenticated_read": bool(status.get("authenticated_ipc_required")),
        "privileged_direct_call_rejected": True,
        "rejection": rejection,
    }
    _write_json(output, result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11 Beta2 B2 production live acceptance")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--mode", choices=("pre-restart", "post-restart", "standard-user"), required=True)
    parser.add_argument("--marker", default="")
    parser.add_argument("--incident-id", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(args.root).resolve()
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output
    try:
        if args.mode == "pre-restart":
            return run_pre_restart(root, output)
        if args.mode == "post-restart":
            if not args.marker or not args.incident_id:
                raise RuntimeError("post-restart mode requires marker and incident id")
            return run_post_restart(root, args.marker, args.incident_id, output)
        return run_standard_user(root, output)
    except Exception as exc:
        result = {"profile": PROFILE, "checkpoint": f"B2-{args.mode}", "passed": False, "error": f"{type(exc).__name__}: {exc}"}
        _write_json(output, result)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
