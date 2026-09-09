from __future__ import annotations

import hashlib
import json

from tools.threat_package_beta2_fixture import (
    SAFE_THREAT_PACKAGE_C,
    SAFE_THREAT_PACKAGE_C_SIGNATURE,
    SAFE_THREAT_PACKAGE_D,
    SAFE_THREAT_PACKAGE_D_SIGNATURE,
)


def package_envelope_bytes(package: dict, signature: str) -> bytes:
    return json.dumps(
        {"package": package, "signature": signature},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


SAFE_PACKAGE_C_ENVELOPE = package_envelope_bytes(SAFE_THREAT_PACKAGE_C, SAFE_THREAT_PACKAGE_C_SIGNATURE)
SAFE_PACKAGE_D_ENVELOPE = package_envelope_bytes(SAFE_THREAT_PACKAGE_D, SAFE_THREAT_PACKAGE_D_SIGNATURE)
SAFE_PACKAGE_C_ENVELOPE_SHA256 = hashlib.sha256(SAFE_PACKAGE_C_ENVELOPE).hexdigest()
SAFE_PACKAGE_D_ENVELOPE_SHA256 = hashlib.sha256(SAFE_PACKAGE_D_ENVELOPE).hexdigest()

_SAFE_PACKAGES = [
    {
        "package_id": "bcsentinel-v080b2-safe-c",
        "sequence": 3,
        "version": "0.8.0-beta.2-c",
        "sha256": SAFE_PACKAGE_C_ENVELOPE_SHA256,
        "size": len(SAFE_PACKAGE_C_ENVELOPE),
        "url": "https://updates.bcsentinel.test/threat/packages/bcsentinel-v080b2-safe-c.json",
        "signing_key_id": "content-2026-a",
        "components": ["behavior", "ioc", "reputation", "yara"],
        "min_product_version": "0.8.0-beta.2",
    },
    {
        "package_id": "bcsentinel-v080b2-safe-d",
        "sequence": 4,
        "version": "0.8.0-beta.2-d",
        "sha256": SAFE_PACKAGE_D_ENVELOPE_SHA256,
        "size": len(SAFE_PACKAGE_D_ENVELOPE),
        "url": "https://updates.bcsentinel.test/threat/packages/bcsentinel-v080b2-safe-d.json",
        "signing_key_id": "content-2026-b",
        "components": ["behavior", "ioc", "reputation", "yara"],
        "min_product_version": "0.8.0-beta.2",
    },
]

SAFE_THREAT_INDEX_1 = {
    "schema": "bcsentinel.threat-index.v1",
    "index_id": "bcsentinel-threat-index",
    "sequence": 1,
    "generated_at": 1788610300.0,
    "expires_at": 1893456000.0,
    "packages": _SAFE_PACKAGES,
}
SAFE_THREAT_INDEX_1_SIGNATURE = "EOST13uAX3pImqbT14J6REnPMLwCzZgJBZxIgXQZw74GBGqe+aMI5qBjhkKwVlTngU1DcOyujirBQ29vJg3mBw=="

SAFE_THREAT_INDEX_2 = {
    "schema": "bcsentinel.threat-index.v1",
    "index_id": "bcsentinel-threat-index",
    "sequence": 2,
    "generated_at": 1788610360.0,
    "expires_at": 1893456000.0,
    "packages": _SAFE_PACKAGES,
}
SAFE_THREAT_INDEX_2_SIGNATURE = "LEhTPZ7ZH15Ar0rtH2Mwp/7m6mCwDUBMFr0pihj0wRHu9qzlen8USL0g+mew+IpB0YBzTYaOBcaoNcszf1cyDQ=="


def index_envelope_bytes(index: dict, signature: str) -> bytes:
    return json.dumps(
        {"index": index, "signature": signature},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


SAFE_THREAT_INDEX_1_ENVELOPE = index_envelope_bytes(SAFE_THREAT_INDEX_1, SAFE_THREAT_INDEX_1_SIGNATURE)
SAFE_THREAT_INDEX_2_ENVELOPE = index_envelope_bytes(SAFE_THREAT_INDEX_2, SAFE_THREAT_INDEX_2_SIGNATURE)
SAFE_THREAT_INDEX_1_ENVELOPE_SHA256 = hashlib.sha256(SAFE_THREAT_INDEX_1_ENVELOPE).hexdigest()
SAFE_THREAT_INDEX_2_ENVELOPE_SHA256 = hashlib.sha256(SAFE_THREAT_INDEX_2_ENVELOPE).hexdigest()
