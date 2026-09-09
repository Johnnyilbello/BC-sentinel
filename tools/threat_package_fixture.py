from __future__ import annotations

import hashlib

SAFE_THREAT_PACKAGE_A = {
    "schema": "bcsentinel.threat-package.v1",
    "package_id": "bcsentinel-v080-safe-acceptance-a",
    "sequence": 1,
    "issued_at": 1788610000.0,
    "expires_at": 1893456000.0,
    "min_product_version": "0.7.2-beta.4",
    "components": {
        "ioc": {"entries": [
            {"kind": "domain", "value": "malware080.test", "severity": "critical", "label": "BC Sentinel harmless v0.8 signed package fixture"},
            {"kind": "network", "value": "192.0.2.180", "severity": "high", "label": "TEST-NET v0.8 signed package fixture"},
            {"kind": "sha256", "value": hashlib.sha256(b"BCS080_ALPHA_PAYLOAD").hexdigest(), "severity": "high", "label": "Synthetic v0.8 hash fixture"},
        ]},
        "yara": {"rules": [
            {"name": "BCS080_ALPHA", "source": 'rule BCS080_ALPHA { meta: weight = 23 description = "BC Sentinel v0.8 harmless signed YARA fixture" strings: $a = "BCS080_ALPHA_PAYLOAD" condition: $a }'}
        ]},
        "behavior": {"rules": [
            {"id": "bcs080.download_exec_context", "category": "download", "weight": 8, "description": "Signed advisory context for tracked download execution", "enabled": True}
        ]},
    },
}

SAFE_THREAT_PACKAGE_A_SIGNATURE = "sUNEjYUe02nWIHFdRYjayY9VjuYmmu7+6dnVnJMUFZLtUs0H5zsl//mMr7GDl57PjCKrslE9mYcsMDvNWKIrBg=="

SAFE_THREAT_PACKAGE_B = {
    "schema": "bcsentinel.threat-package.v1",
    "package_id": "bcsentinel-v080-safe-acceptance-b",
    "sequence": 2,
    "issued_at": 1788610000.0,
    "expires_at": 1893456000.0,
    "min_product_version": "0.7.2-beta.4",
    "components": {
        "ioc": {"entries": [
            {"kind": "domain", "value": "malware080b.test", "severity": "critical", "label": "BC Sentinel harmless v0.8 signed package fixture B"},
            {"kind": "network", "value": "198.51.100.180", "severity": "high", "label": "TEST-NET v0.8 signed package fixture B"},
            {"kind": "sha256", "value": hashlib.sha256(b"BCS080_BRAVO_PAYLOAD").hexdigest(), "severity": "high", "label": "Synthetic v0.8 hash fixture B"},
        ]},
        "yara": {"rules": [
            {"name": "BCS080_BRAVO", "source": 'rule BCS080_BRAVO { meta: weight = 21 description = "BC Sentinel v0.8 harmless signed YARA fixture B" strings: $a = "BCS080_BRAVO_PAYLOAD" condition: $a }'}
        ]},
        "behavior": {"rules": [
            {"id": "bcs080.network_context", "category": "network", "weight": 6, "description": "Signed advisory context for network correlation", "enabled": True}
        ]},
    },
}

SAFE_THREAT_PACKAGE_B_SIGNATURE = "rqCg6Gk7YVq2QGqeoUQtXJX+uDfVgkNkLOLCFL1WfmVWKE1AxmOSbgXWr2TgddvX3Okt/g3VIwSHtKEknjc/BA=="
