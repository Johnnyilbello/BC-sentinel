from __future__ import annotations

SAFE_THREAT_PACKAGE_C = {
    "schema": "bcsentinel.threat-package.v1",
    "package_id": "bcsentinel-v080b2-safe-c",
    "sequence": 3,
    "issued_at": 1788610120.0,
    "expires_at": 1893456000.0,
    "min_product_version": "0.8.0-beta.2",
    "signing_key_id": "content-2026-a",
    "components": {
        "ioc": {"entries": [{
            "kind": "domain", "value": "ioc080b2.test", "severity": "high",
            "label": "BC Sentinel Beta2 rotated-key harmless IOC",
        }]},
        "reputation": {"entries": [
            {
                "kind": "domain", "value": "badrep080b2.test", "status": "malicious",
                "confidence": 93, "label": "BC Sentinel signed reputation harmless fixture",
            },
            {
                "kind": "network", "value": "192.0.2.0/24", "status": "suspicious",
                "confidence": 81, "label": "TEST-NET signed reputation fixture",
            },
        ]},
        "yara": {"rules": [{
            "name": "BCS080B2_CHARLIE",
            "source": 'rule BCS080B2_CHARLIE { strings: $a = "BCS080B2_CHARLIE_PAYLOAD" condition: $a }',
        }]},
        "behavior": {"rules": [{
            "id": "v080b2.download.context", "category": "download", "weight": 8,
            "description": "Harmless Beta2 advisory behavior fixture", "enabled": True,
        }]},
    },
}
SAFE_THREAT_PACKAGE_C_SIGNATURE = "CYgFC6VBWWR5NPVbAFAYw+lajpiA2Ews652xTDtnMQADxKR65XS3eixwyjFYRJ6Fxf+Nb3hLriuOl+Oh8TumBQ=="

SAFE_THREAT_PACKAGE_D = {
    "schema": "bcsentinel.threat-package.v1",
    "package_id": "bcsentinel-v080b2-safe-d",
    "sequence": 4,
    "issued_at": 1788610180.0,
    "expires_at": 1893456000.0,
    "min_product_version": "0.8.0-beta.2",
    "signing_key_id": "content-2026-b",
    "components": {
        "ioc": {"entries": [{
            "kind": "domain", "value": "ioc080b2b.test", "severity": "critical",
            "label": "BC Sentinel Beta2 post-rotation harmless IOC",
        }]},
        "reputation": {"entries": [{
            "kind": "domain", "value": "watch080b2.test", "status": "suspicious",
            "confidence": 88, "label": "BC Sentinel post-rotation signed reputation",
        }]},
        "yara": {"rules": [{
            "name": "BCS080B2_DELTA",
            "source": 'rule BCS080B2_DELTA { strings: $a = "BCS080B2_DELTA_PAYLOAD" condition: $a }',
        }]},
        "behavior": {"rules": []},
    },
}
SAFE_THREAT_PACKAGE_D_SIGNATURE = "pDytp9ZLE0sdhRVkGeB/LfrpaunSe3gHJNnfqWx052JVvNWnK80wFr30BW4zVLwRPKql/k+0Q4hezeWsLILABQ=="
