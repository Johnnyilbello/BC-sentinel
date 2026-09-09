from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import json
import ssl
from urllib.parse import urlsplit
from typing import Any, Callable

MAX_RETRIEVAL_BYTES = 256 * 1024


class ThreatRetrievalError(ValueError):
    pass


@dataclass(slots=True, frozen=True)
class RetrievedThreatContent:
    url: str
    host: str
    body: bytes
    sha256: str
    certificate_sha256: str
    content_type: str

    def json_object(self) -> dict[str, Any]:
        try:
            obj = json.loads(self.body.decode("utf-8"))
        except Exception as exc:
            raise ThreatRetrievalError(f"retrieved threat content is not valid UTF-8 JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise ThreatRetrievalError("retrieved threat content must be a JSON object")
        return obj


class SecureThreatRetriever:
    """HTTPS-only bounded retrieval. Retrieval never stages or activates content."""

    def __init__(
        self,
        *,
        allowed_hosts: set[str] | list[str] | tuple[str, ...],
        certificate_pins: dict[str, set[str] | list[str] | tuple[str, ...]],
        max_bytes: int = MAX_RETRIEVAL_BYTES,
        timeout: float = 5.0,
        transport: Callable[[str, int, float], dict[str, Any]] | None = None,
    ):
        self.allowed_hosts = {str(host).strip().casefold().rstrip(".") for host in allowed_hosts if str(host).strip()}
        self.certificate_pins = {
            str(host).strip().casefold().rstrip("."): {str(pin).strip().casefold() for pin in pins if str(pin).strip()}
            for host, pins in certificate_pins.items()
        }
        self.max_bytes = max(1024, min(int(max_bytes), MAX_RETRIEVAL_BYTES))
        self.timeout = max(1.0, min(float(timeout), 30.0))
        self.transport = transport

    @staticmethod
    def _validate_url(url: str) -> tuple[str, int, str]:
        raw = str(url or "").strip()
        try:
            parsed = urlsplit(raw)
        except Exception as exc:
            raise ThreatRetrievalError(f"threat retrieval URL is invalid: {exc}") from exc
        if parsed.scheme.casefold() != "https":
            raise ThreatRetrievalError("threat retrieval requires HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise ThreatRetrievalError("threat retrieval URL cannot contain credentials")
        host = str(parsed.hostname or "").casefold().rstrip(".")
        if not host or parsed.fragment:
            raise ThreatRetrievalError("threat retrieval URL host/fragment is invalid")
        port = int(parsed.port or 443)
        if port != 443:
            raise ThreatRetrievalError("threat retrieval only permits TCP/443")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return host, port, path

    def _real_transport(self, url: str, max_bytes: int, timeout: float) -> dict[str, Any]:
        host, port, path = self._validate_url(url)
        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=context)
        try:
            conn.request("GET", path, headers={"Accept": "application/json", "User-Agent": "BC-Sentinel-Threat-Channel/0.8"})
            response = conn.getresponse()
            status = int(response.status)
            location = str(response.getheader("Location") or "")
            content_type = str(response.getheader("Content-Type") or "")
            cert_der = b""
            try:
                if conn.sock is not None:
                    cert_der = conn.sock.getpeercert(binary_form=True) or b""
            except Exception:
                cert_der = b""
            body = response.read(max_bytes + 1)
            return {"status": status, "location": location, "content_type": content_type, "certificate_der": cert_der, "body": body}
        finally:
            conn.close()

    def fetch(self, url: str, *, expected_sha256: str = "") -> RetrievedThreatContent:
        host, _, _ = self._validate_url(url)
        if host not in self.allowed_hosts:
            raise ThreatRetrievalError("threat retrieval host is not allowlisted")
        pins = self.certificate_pins.get(host) or set()
        if not pins:
            raise ThreatRetrievalError("threat retrieval certificate pin is required for the selected host")
        transport = self.transport or self._real_transport
        result = transport(str(url), self.max_bytes, self.timeout)
        if not isinstance(result, dict):
            raise ThreatRetrievalError("threat retrieval transport returned an invalid result")
        status = int(result.get("status") or 0)
        if 300 <= status < 400:
            raise ThreatRetrievalError("threat retrieval redirects are forbidden")
        if status != 200:
            raise ThreatRetrievalError(f"threat retrieval HTTP status is not accepted: {status}")
        body = bytes(result.get("body") or b"")
        if len(body) > self.max_bytes:
            raise ThreatRetrievalError("retrieved threat content exceeds the configured size limit")
        cert_der = bytes(result.get("certificate_der") or b"")
        if not cert_der:
            raise ThreatRetrievalError("peer certificate is unavailable for pin verification")
        cert_sha = hashlib.sha256(cert_der).hexdigest()
        if cert_sha.casefold() not in pins:
            raise ThreatRetrievalError("peer certificate pin verification failed")
        digest = hashlib.sha256(body).hexdigest()
        expected = str(expected_sha256 or "").strip().casefold()
        if expected and digest != expected:
            raise ThreatRetrievalError("retrieved threat content hash mismatch")
        return RetrievedThreatContent(
            url=str(url), host=host, body=body, sha256=digest,
            certificate_sha256=cert_sha, content_type=str(result.get("content_type") or ""),
        )

    @classmethod
    def policy(cls) -> dict[str, Any]:
        return {
            "https_only": True,
            "tcp_port": 443,
            "host_allowlist_required": True,
            "certificate_pin_required": True,
            "redirects_allowed": False,
            "url_credentials_allowed": False,
            "max_bytes": MAX_RETRIEVAL_BYTES,
            "auto_stage": False,
            "auto_activate": False,
            "cloud_required": False,
            "signed_index_required": True,
            "retrieval_implies_activation": False,
        }
