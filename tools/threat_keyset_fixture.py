from __future__ import annotations

SAFE_THREAT_KEYSET_1 = {
    "schema": "bcsentinel.threat-keyset.v1",
    "keyset_id": "bcsentinel-content-keys",
    "sequence": 1,
    "issued_at": 1788610000.0,
    "expires_at": 1893456000.0,
    "keys": [{
        "key_id": "content-2026-a",
        "public_key_b64": "hxNF5Quer0zgFqmKInkPQAs0x/yoEKM7VkXYDg0LkTM=",
        "not_before": 1788609940.0,
        "not_after": 1893456000.0,
    }],
    "revoked_key_ids": [],
}
SAFE_THREAT_KEYSET_1_SIGNATURE = "KGgc+fZNVb1lTmWRJmtcCZUlilI067TqHyr4iUDaVLGA26k1DGl9EelCT5hgpmvJ4RrzL7WD07q/I+6SaIc5Cg=="

SAFE_THREAT_KEYSET_2 = {
    "schema": "bcsentinel.threat-keyset.v1",
    "keyset_id": "bcsentinel-content-keys",
    "sequence": 2,
    "issued_at": 1788610060.0,
    "expires_at": 1893456000.0,
    "keys": [{
        "key_id": "content-2026-b",
        "public_key_b64": "GQUQ40cMzanzEt2d1heNNVemsbN8Pv/DDVlFSbhTB/Q=",
        "not_before": 1788610000.0,
        "not_after": 1893456000.0,
    }],
    "revoked_key_ids": ["content-2026-a"],
}
SAFE_THREAT_KEYSET_2_SIGNATURE = "D+oJpjMWNtuSNCoNID+l2NRg1It8PxEUrdZDzwumYbhPFoEsqMW2+Nx7m7gygBINxa/eEXJII8RThmPvlq0RAw=="
