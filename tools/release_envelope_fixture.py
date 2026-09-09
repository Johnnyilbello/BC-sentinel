from __future__ import annotations

SAFE_RELEASE_FILES = {
    "app.bin": b"BCS UPDATE SAFE A",
    "manifest.txt": b"v080",
}

SAFE_RELEASE_ENVELOPE = {
    "schema": "bcsentinel.release-envelope.v1",
    "product": "BC Sentinel",
    "version": "0.8.0-beta.1",
    "sequence": 1,
    "issued_at": 1788610000.0,
    "expires_at": 1893456000.0,
    "files": {
        "app.bin": {"sha256": "5b31f17651ac0dd86c00243b744d2b2976dae58d8ffda7473fd569ac54229f3c", "size": 17},
        "manifest.txt": {"sha256": "3c465e97ae1c1b067976de2bfcde2564f573cafd4584b65dc74a6cae848a80a0", "size": 4},
    },
}

SAFE_RELEASE_ENVELOPE_SIGNATURE = "nxUE7h+9BasXGkMvpSafBi6ZA8nxskg6kg/DdItNhAknFBieiQB1p2uWiIYps7/hay+RZ8SCl//WzOS2Zgs8Cw=="
