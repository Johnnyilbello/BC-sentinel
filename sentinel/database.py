from __future__ import annotations
import sqlite3
import os
import threading
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from .config import DB_PATH, ensure_dirs
from .path_security import canonical_path, is_within, is_reparse_point, secure_write_parent

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS detections(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 path TEXT NOT NULL,
 sha256 TEXT,
 score INTEGER NOT NULL,
 level TEXT NOT NULL,
 reasons_json TEXT NOT NULL,
 action TEXT NOT NULL DEFAULT 'logged'
);
CREATE INDEX IF NOT EXISTS idx_detections_hash_ts ON detections(sha256, ts);
CREATE INDEX IF NOT EXISTS idx_detections_score_ts ON detections(score, ts);

CREATE TABLE IF NOT EXISTS scan_history(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 started_ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 finished_ts TEXT,
 kind TEXT NOT NULL,
 files_scanned INTEGER NOT NULL DEFAULT 0,
 detections INTEGER NOT NULL DEFAULT 0,
 cancelled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS quarantine(
 id TEXT PRIMARY KEY,
 ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 original_path TEXT NOT NULL,
 stored_path TEXT NOT NULL,
 sha256 TEXT NOT NULL,
 score INTEGER NOT NULL,
 reason TEXT NOT NULL,
 restored INTEGER NOT NULL DEFAULT 0,
 deleted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS process_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 pid INTEGER,
 ppid INTEGER,
 name TEXT,
 path TEXT,
 cmdline TEXT,
 score INTEGER NOT NULL DEFAULT 0,
 reasons_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS behavior_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 category TEXT NOT NULL,
 source TEXT,
 detail_json TEXT NOT NULL,
 score INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings(
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS allowlist(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 kind TEXT NOT NULL,
 value TEXT NOT NULL,
 UNIQUE(kind, value)
);

CREATE TABLE IF NOT EXISTS firewall_expected_rules(
 rule_id TEXT PRIMARY KEY,
 remote_address TEXT NOT NULL,
 direction TEXT NOT NULL,
 protocol TEXT NOT NULL,
 remote_port INTEGER,
 application_path TEXT NOT NULL DEFAULT '',
 reason TEXT NOT NULL DEFAULT '',
 incident_id TEXT NOT NULL DEFAULT '',
 enabled INTEGER NOT NULL DEFAULT 1,
 created_at REAL NOT NULL DEFAULT 0,
 updated_ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ioc_feed_state(
 id INTEGER PRIMARY KEY CHECK(id=1),
 bundle_id TEXT NOT NULL,
 sequence INTEGER NOT NULL,
 issued_at REAL NOT NULL,
 expires_at REAL NOT NULL,
 payload_sha256 TEXT NOT NULL,
 signature_b64 TEXT NOT NULL,
 imported_ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ioc_indicators(
 kind TEXT NOT NULL,
 value TEXT NOT NULL,
 severity TEXT NOT NULL,
 label TEXT NOT NULL DEFAULT '',
 expires_at REAL NOT NULL,
 bundle_id TEXT NOT NULL,
 PRIMARY KEY(kind, value)
);
CREATE INDEX IF NOT EXISTS idx_ioc_indicators_kind_expiry ON ioc_indicators(kind, expires_at);

CREATE TABLE IF NOT EXISTS threat_package_ioc_state(
 id INTEGER PRIMARY KEY CHECK(id=1),
 package_id TEXT NOT NULL DEFAULT '',
 sequence INTEGER NOT NULL DEFAULT 0,
 payload_sha256 TEXT NOT NULL DEFAULT '',
 expires_at REAL NOT NULL DEFAULT 0,
 activated_at REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS threat_package_ioc_indicators(
 kind TEXT NOT NULL,
 value TEXT NOT NULL,
 severity TEXT NOT NULL,
 label TEXT NOT NULL DEFAULT '',
 expires_at REAL NOT NULL,
 package_id TEXT NOT NULL,
 package_sequence INTEGER NOT NULL,
 PRIMARY KEY(kind, value)
);
CREATE INDEX IF NOT EXISTS idx_threat_package_ioc_kind_expiry ON threat_package_ioc_indicators(kind, expires_at);

CREATE TABLE IF NOT EXISTS threat_package_reputation(
 kind TEXT NOT NULL,
 value TEXT NOT NULL,
 status TEXT NOT NULL,
 confidence INTEGER NOT NULL,
 label TEXT NOT NULL DEFAULT '',
 expires_at REAL NOT NULL,
 package_id TEXT NOT NULL,
 package_sequence INTEGER NOT NULL,
 PRIMARY KEY(kind, value)
);
CREATE INDEX IF NOT EXISTS idx_threat_package_reputation_kind_expiry ON threat_package_reputation(kind, expires_at);

CREATE TABLE IF NOT EXISTS containment_leases(
 lease_id TEXT PRIMARY KEY,
 rule_id TEXT NOT NULL UNIQUE,
 remote_address TEXT NOT NULL,
 incident_id TEXT NOT NULL DEFAULT '',
 reason TEXT NOT NULL DEFAULT '',
 created_at REAL NOT NULL,
 expires_at REAL NOT NULL,
 status TEXT NOT NULL DEFAULT 'active',
 released_at REAL NOT NULL DEFAULT 0,
 release_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_containment_leases_status_expiry ON containment_leases(status, expires_at);

CREATE TABLE IF NOT EXISTS web_findings(
 finding_id TEXT PRIMARY KEY,
 created_at REAL NOT NULL,
 updated_at REAL NOT NULL,
 domain TEXT NOT NULL,
 remote_address TEXT NOT NULL DEFAULT '',
 pid INTEGER,
 process_name TEXT NOT NULL DEFAULT '',
 process_path TEXT NOT NULL DEFAULT '',
 score INTEGER NOT NULL DEFAULT 0,
 level TEXT NOT NULL DEFAULT 'SAFE',
 source TEXT NOT NULL DEFAULT '',
 reasons_json TEXT NOT NULL DEFAULT '[]',
 evidence_json TEXT NOT NULL DEFAULT '{}',
 shared_ip INTEGER NOT NULL DEFAULT 0,
 block_recommended INTEGER NOT NULL DEFAULT 0,
 decision TEXT NOT NULL DEFAULT 'observe',
 status TEXT NOT NULL DEFAULT 'pending',
 lease_id TEXT NOT NULL DEFAULT '',
 resolved_at REAL NOT NULL DEFAULT 0,
 resolution TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_web_findings_status_created ON web_findings(status, created_at);
CREATE INDEX IF NOT EXISTS idx_web_findings_domain_address ON web_findings(domain, remote_address, created_at);

CREATE TABLE IF NOT EXISTS web_domain_trust(
 domain TEXT PRIMARY KEY,
 scope TEXT NOT NULL DEFAULT 'exact',
 reason TEXT NOT NULL DEFAULT '',
 source_finding_id TEXT NOT NULL DEFAULT '',
 created_at REAL NOT NULL,
 updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_web_domain_trust_updated ON web_domain_trust(updated_at);

CREATE TABLE IF NOT EXISTS web_domain_reputation(
 domain TEXT PRIMARY KEY,
 first_seen REAL NOT NULL,
 last_seen REAL NOT NULL,
 observations INTEGER NOT NULL DEFAULT 0,
 max_score INTEGER NOT NULL DEFAULT 0,
 malicious_observations INTEGER NOT NULL DEFAULT 0,
 suspicious_observations INTEGER NOT NULL DEFAULT 0,
 last_source TEXT NOT NULL DEFAULT '',
 last_status TEXT NOT NULL DEFAULT '',
 last_process_name TEXT NOT NULL DEFAULT '',
 last_process_path TEXT NOT NULL DEFAULT '',
 last_remote_address TEXT NOT NULL DEFAULT '',
 processes_json TEXT NOT NULL DEFAULT '[]',
 addresses_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_web_domain_reputation_last_seen ON web_domain_reputation(last_seen);

CREATE TABLE IF NOT EXISTS web_downloads(
 download_id TEXT PRIMARY KEY,
 created_at REAL NOT NULL,
 updated_at REAL NOT NULL,
 domain TEXT NOT NULL DEFAULT '',
 remote_address TEXT NOT NULL DEFAULT '',
 browser_pid INTEGER,
 browser_family TEXT NOT NULL DEFAULT '',
 browser_process_name TEXT NOT NULL DEFAULT '',
 browser_process_path TEXT NOT NULL DEFAULT '',
 file_path TEXT NOT NULL,
 stage TEXT NOT NULL DEFAULT 'materialized',
 origin_score INTEGER NOT NULL DEFAULT 0,
 origin_status TEXT NOT NULL DEFAULT 'unknown',
 origin_source TEXT NOT NULL DEFAULT '',
 origin_signed_ioc INTEGER NOT NULL DEFAULT 0,
 file_sha256 TEXT NOT NULL DEFAULT '',
 file_score INTEGER NOT NULL DEFAULT 0,
 file_level TEXT NOT NULL DEFAULT 'UNSCANNED',
 executed_pid INTEGER,
 executed_at REAL NOT NULL DEFAULT 0,
 incident_id TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'tracked',
 evidence_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_web_downloads_path_updated ON web_downloads(file_path, updated_at);
CREATE INDEX IF NOT EXISTS idx_web_downloads_domain_updated ON web_downloads(domain, updated_at);
CREATE INDEX IF NOT EXISTS idx_web_downloads_status_updated ON web_downloads(status, updated_at);

CREATE TABLE IF NOT EXISTS antispyware_findings(
 finding_id TEXT PRIMARY KEY,
 first_seen REAL NOT NULL,
 last_seen REAL NOT NULL,
 kind TEXT NOT NULL,
 location TEXT NOT NULL DEFAULT '',
 name TEXT NOT NULL DEFAULT '',
 command TEXT NOT NULL DEFAULT '',
 target_path TEXT NOT NULL DEFAULT '',
 target_exists INTEGER,
 user_writable INTEGER NOT NULL DEFAULT 0,
 signature_status TEXT NOT NULL DEFAULT '',
 signer TEXT NOT NULL DEFAULT '',
 score INTEGER NOT NULL DEFAULT 0,
 level TEXT NOT NULL DEFAULT 'SAFE',
 reasons_json TEXT NOT NULL DEFAULT '[]',
 evidence_json TEXT NOT NULL DEFAULT '{}',
 remediation TEXT NOT NULL DEFAULT 'observe',
 status TEXT NOT NULL DEFAULT 'observed'
);
CREATE INDEX IF NOT EXISTS idx_antispyware_findings_score ON antispyware_findings(score, last_seen);
CREATE INDEX IF NOT EXISTS idx_antispyware_findings_kind ON antispyware_findings(kind, last_seen);

CREATE TABLE IF NOT EXISTS antispyware_remediation_plans(
 plan_id TEXT PRIMARY KEY,
 finding_id TEXT NOT NULL,
 created_at REAL NOT NULL,
 updated_at REAL NOT NULL,
 kind TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'planned',
 snapshot_json TEXT NOT NULL DEFAULT '{}',
 snapshot_hmac TEXT NOT NULL DEFAULT '',
 result_json TEXT NOT NULL DEFAULT '{}',
 applied_at REAL NOT NULL DEFAULT 0,
 restored_at REAL NOT NULL DEFAULT 0,
 last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_antispyware_remediation_finding ON antispyware_remediation_plans(finding_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_antispyware_remediation_status ON antispyware_remediation_plans(status, updated_at);

CREATE TABLE IF NOT EXISTS advanced_antimalware_findings(
 finding_id TEXT PRIMARY KEY,
 first_seen REAL NOT NULL,
 last_seen REAL NOT NULL,
 category TEXT NOT NULL DEFAULT 'process',
 technique TEXT NOT NULL DEFAULT '',
 pid INTEGER,
 ppid INTEGER,
 process_name TEXT NOT NULL DEFAULT '',
 process_path TEXT NOT NULL DEFAULT '',
 cmdline TEXT NOT NULL DEFAULT '',
 score INTEGER NOT NULL DEFAULT 0,
 level TEXT NOT NULL DEFAULT 'SAFE',
 confidence REAL NOT NULL DEFAULT 0,
 reasons_json TEXT NOT NULL DEFAULT '[]',
 evidence_json TEXT NOT NULL DEFAULT '{}',
 status TEXT NOT NULL DEFAULT 'observed'
);
CREATE INDEX IF NOT EXISTS idx_advanced_antimalware_score ON advanced_antimalware_findings(score, last_seen);
CREATE INDEX IF NOT EXISTS idx_advanced_antimalware_pid ON advanced_antimalware_findings(pid, last_seen);

CREATE TABLE IF NOT EXISTS hash_cache(
 path TEXT PRIMARY KEY,
 mtime_ns INTEGER NOT NULL,
 size INTEGER NOT NULL,
 sha256 TEXT NOT NULL,
 sha1 TEXT NOT NULL DEFAULT '',
 score INTEGER NOT NULL,
 level TEXT NOT NULL,
 checked_ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 category TEXT NOT NULL,
 action TEXT NOT NULL,
 source TEXT NOT NULL,
 score INTEGER NOT NULL DEFAULT 0,
 path TEXT,
 pid INTEGER,
 ppid INTEGER,
 process_name TEXT,
 process_path TEXT,
 reasons_json TEXT NOT NULL DEFAULT '[]',
 data_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(ts);
CREATE INDEX IF NOT EXISTS idx_security_events_category ON security_events(category, ts);

CREATE TABLE IF NOT EXISTS correlation_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 category TEXT NOT NULL,
 source_event_category TEXT NOT NULL,
 source_event_action TEXT NOT NULL,
 pid INTEGER,
 process_name TEXT,
 score_delta INTEGER NOT NULL DEFAULT 0,
 confidence REAL NOT NULL DEFAULT 0,
 chain TEXT,
 reasons_json TEXT NOT NULL DEFAULT '[]',
 data_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_correlation_events_ts ON correlation_events(ts);
CREATE INDEX IF NOT EXISTS idx_correlation_events_pid ON correlation_events(pid, ts);

CREATE TABLE IF NOT EXISTS file_reputation(
 path TEXT PRIMARY KEY,
 mtime_ns INTEGER NOT NULL,
 size INTEGER NOT NULL,
 sha256 TEXT NOT NULL,
 signature_status TEXT NOT NULL DEFAULT '',
 publisher TEXT NOT NULL DEFAULT '',
 local_trust TEXT NOT NULL DEFAULT 'unknown',
 checked_ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_file_reputation_sha256 ON file_reputation(sha256);

CREATE TABLE IF NOT EXISTS network_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 pid INTEGER,
 process_name TEXT,
 process_path TEXT,
 local_addr TEXT,
 remote_addr TEXT,
 remote_port INTEGER,
 protocol TEXT,
 state TEXT,
 score INTEGER NOT NULL DEFAULT 0,
 reasons_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_network_events_ts ON network_events(ts);
CREATE INDEX IF NOT EXISTS idx_network_events_pid_ts ON network_events(pid, ts);

CREATE TABLE IF NOT EXISTS file_observations(
 sha256 TEXT NOT NULL,
 path TEXT NOT NULL,
 first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 observations INTEGER NOT NULL DEFAULT 1,
 publisher TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(sha256, path)
);
CREATE INDEX IF NOT EXISTS idx_file_observations_sha256 ON file_observations(sha256);

CREATE TABLE IF NOT EXISTS endpoint_reputation(
 indicator TEXT NOT NULL,
 kind TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'unknown',
 source TEXT NOT NULL DEFAULT 'local',
 confidence REAL NOT NULL DEFAULT 0,
 details_json TEXT NOT NULL DEFAULT '{}',
 checked_ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 expires_ts TEXT,
 PRIMARY KEY(indicator, kind)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_reputation_status ON endpoint_reputation(status, checked_ts);

CREATE TABLE IF NOT EXISTS network_endpoint_observations(
 indicator TEXT NOT NULL,
 process_key TEXT NOT NULL,
 first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 connections INTEGER NOT NULL DEFAULT 1,
 PRIMARY KEY(indicator, process_key)
);
CREATE INDEX IF NOT EXISTS idx_network_endpoint_observations_indicator ON network_endpoint_observations(indicator);

CREATE TABLE IF NOT EXISTS incidents(
 incident_id TEXT PRIMARY KEY,
 created_ts REAL NOT NULL,
 updated_ts REAL NOT NULL,
 status TEXT NOT NULL DEFAULT 'open',
 subject_key TEXT NOT NULL,
 pid INTEGER, ppid INTEGER, process_name TEXT, process_path TEXT,
 process_sha256 TEXT, signature_status TEXT, signer TEXT,
 score INTEGER NOT NULL DEFAULT 0,
 level TEXT NOT NULL DEFAULT 'SAFE',
 confidence REAL NOT NULL DEFAULT 0,
 categories_json TEXT NOT NULL DEFAULT '[]',
 reasons_json TEXT NOT NULL DEFAULT '[]',
 timeline_json TEXT NOT NULL DEFAULT '[]',
 recommended_actions_json TEXT NOT NULL DEFAULT '[]',
 suppressed INTEGER NOT NULL DEFAULT 0,
 data_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_ts);
CREATE INDEX IF NOT EXISTS idx_incidents_score ON incidents(score, updated_ts);
CREATE INDEX IF NOT EXISTS idx_incidents_subject ON incidents(subject_key, updated_ts);

CREATE TABLE IF NOT EXISTS incident_actions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 incident_id TEXT NOT NULL,
 ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 action TEXT NOT NULL,
 status TEXT NOT NULL,
 detail_json TEXT NOT NULL DEFAULT '{}',
 FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_incident_actions_incident ON incident_actions(incident_id, ts);

"""

class Database:
    def __init__(self, path: Path | str = DB_PATH):
        ensure_dirs()
        if is_reparse_point(path):
            raise ValueError("BC Sentinel database cannot be a symlink/reparse point.")
        secure_write_parent(path)
        self.path = str(path)
        self._lock = threading.RLock()
        self._allowlist_revision = 0
        self._ioc_revision = 0
        self._threat_package_revision = 0
        self._web_trust_revision = 0
        with self.connect() as con:
            con.executescript(SCHEMA)
            self._migrate_schema(con)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _migrate_schema(con):
        """Small additive migrations for databases created by earlier betas."""
        columns = {row[1] for row in con.execute("PRAGMA table_info(hash_cache)").fetchall()}
        if "sha1" not in columns:
            con.execute("ALTER TABLE hash_cache ADD COLUMN sha1 TEXT NOT NULL DEFAULT ''")
        if "checked_ts" not in columns:
            con.execute("ALTER TABLE hash_cache ADD COLUMN checked_ts TEXT NOT NULL DEFAULT ''")

        reputation_columns = {row[1] for row in con.execute("PRAGMA table_info(file_reputation)").fetchall()}
        for name, declaration in (
            ("issuer", "TEXT NOT NULL DEFAULT ''"),
            ("thumbprint", "TEXT NOT NULL DEFAULT ''"),
            ("valid_from", "TEXT NOT NULL DEFAULT ''"),
            ("valid_to", "TEXT NOT NULL DEFAULT ''"),
            ("timestamp_signer", "TEXT NOT NULL DEFAULT ''"),
            ("status_message", "TEXT NOT NULL DEFAULT ''"),
        ):
            if name not in reputation_columns:
                con.execute(f"ALTER TABLE file_reputation ADD COLUMN {name} {declaration}")

        network_columns = {row[1] for row in con.execute("PRAGMA table_info(network_events)").fetchall()}
        for name, declaration in (
            ("remote_domain", "TEXT NOT NULL DEFAULT ''"),
            ("endpoint_status", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("endpoint_confidence", "REAL NOT NULL DEFAULT 0"),
            ("endpoint_first_seen", "TEXT NOT NULL DEFAULT ''"),
            ("process_sha256", "TEXT NOT NULL DEFAULT ''"),
            ("signature_status", "TEXT NOT NULL DEFAULT ''"),
            ("signer", "TEXT NOT NULL DEFAULT ''"),
        ):
            if name not in network_columns:
                con.execute(f"ALTER TABLE network_events ADD COLUMN {name} {declaration}")

    def _validate_database_path(self):
        # Re-check on every connection. A same-user process could otherwise
        # replace the DB/WAL path with a symlink/reparse point after startup.
        secure_write_parent(self.path)
        for candidate in (self.path, self.path + "-wal", self.path + "-shm"):
            if os.path.lexists(candidate) and is_reparse_point(candidate):
                raise ValueError("BC Sentinel database path cannot use symlink/reparse-point objects.")

    @contextmanager
    def connect(self):
        self._validate_database_path()
        con = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        con.row_factory = sqlite3.Row
        try:
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA trusted_schema=OFF")
            con.execute("PRAGMA busy_timeout=10000")
            yield con
            con.commit()
        finally:
            con.close()

    def execute(self, sql: str, params: tuple = ()):
        with self._lock, self.connect() as con:
            return con.execute(sql, params).fetchall()

    @staticmethod
    def _normalize_allowlist(kind: str, value: str) -> tuple[str, str]:
        kind = str(kind or "").strip().casefold()
        if kind not in {"file", "directory", "hash", "publisher"}:
            raise ValueError(f"Unsupported allowlist kind: {kind}")
        raw = str(value or "").strip()
        if not raw:
            raise ValueError("Allowlist value cannot be empty.")
        if kind in {"file", "directory"}:
            return kind, canonical_path(raw)
        if kind == "hash":
            normalized = raw.casefold()
            if len(normalized) not in {40, 64} or any(c not in "0123456789abcdef" for c in normalized):
                raise ValueError("Allowlisted hash must be a SHA-1 or SHA-256 hex digest.")
            return kind, normalized
        return kind, raw.casefold()

    @property
    def allowlist_revision(self) -> int:
        return int(self._allowlist_revision)

    def add_allowlist(self, kind: str, value: str):
        kind, value = self._normalize_allowlist(kind, value)
        self.execute("INSERT OR IGNORE INTO allowlist(kind,value) VALUES(?,?)", (kind, value))
        self._allowlist_revision += 1

    def list_allowlist(self):
        return self.execute("SELECT id,kind,value FROM allowlist ORDER BY kind,value")

    def remove_allowlist(self, item_id: int):
        self.execute("DELETE FROM allowlist WHERE id=?", (int(item_id),))
        self._allowlist_revision += 1

    def upsert_firewall_expected_rule(self, rule) -> None:
        payload = rule.to_dict() if hasattr(rule, "to_dict") else dict(rule)
        self.execute(
            """INSERT INTO firewall_expected_rules(
                   rule_id,remote_address,direction,protocol,remote_port,application_path,
                   reason,incident_id,enabled,created_at,updated_ts
               ) VALUES(?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
               ON CONFLICT(rule_id) DO UPDATE SET
                   remote_address=excluded.remote_address,
                   direction=excluded.direction,
                   protocol=excluded.protocol,
                   remote_port=excluded.remote_port,
                   application_path=excluded.application_path,
                   reason=excluded.reason,
                   incident_id=excluded.incident_id,
                   enabled=excluded.enabled,
                   created_at=excluded.created_at,
                   updated_ts=CURRENT_TIMESTAMP""",
            (
                str(payload.get("rule_id") or ""),
                str(payload.get("remote_address") or ""),
                str(payload.get("direction") or "outbound"),
                str(payload.get("protocol") or "any"),
                payload.get("remote_port"),
                str(payload.get("application_path") or ""),
                str(payload.get("reason") or ""),
                str(payload.get("incident_id") or ""),
                1 if payload.get("enabled", True) else 0,
                float(payload.get("created_at") or 0.0),
            ),
        )

    def list_firewall_expected_rules(self):
        return self.execute(
            "SELECT * FROM firewall_expected_rules ORDER BY rule_id"
        )

    def delete_firewall_expected_rule(self, rule_id: str) -> None:
        self.execute("DELETE FROM firewall_expected_rules WHERE rule_id=?", (str(rule_id),))

    def set_firewall_expected_enabled(self, enabled: bool) -> None:
        self.execute(
            "UPDATE firewall_expected_rules SET enabled=?, updated_ts=CURRENT_TIMESTAMP",
            (1 if enabled else 0,),
        )

    def set_setting(self, key: str, value: str):
        self.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        rows = self.execute("SELECT value FROM settings WHERE key=?", (key,))
        return rows[0]["value"] if rows else default

    def allowlist_match(
        self,
        path: str,
        sha256: str | None = None,
        publisher: str | None = None,
    ) -> dict | None:
        """Return the matching allowlist record using boundary-safe comparisons."""
        p = canonical_path(path)
        digest = str(sha256 or "").casefold()
        pub = str(publisher or "").strip().casefold()
        rows = self.execute("SELECT id,kind,value FROM allowlist")
        for row in rows:
            kind = str(row["kind"] or "").casefold()
            value = str(row["value"] or "")
            try:
                if kind == "file" and p == canonical_path(value):
                    return dict(row)
                if kind == "directory" and is_within(p, value):
                    return dict(row)
            except (OSError, ValueError):
                continue
            if digest and kind == "hash" and digest == value.casefold():
                return dict(row)
            if pub and kind == "publisher" and pub == value.casefold():
                return dict(row)
        return None

    def is_path_allowlisted(self, path: str) -> bool:
        match = self.allowlist_match(path)
        return bool(match and match.get("kind") in {"file", "directory"})

    def is_allowlisted(
        self, path: str, sha256: str | None = None, publisher: str | None = None
    ) -> bool:
        return self.allowlist_match(path, sha256, publisher) is not None

    def recent_hash_cache(self, limit: int = 50000):
        return self.execute(
            """SELECT path,mtime_ns,size,sha256,sha1,score,level,checked_ts
               FROM hash_cache ORDER BY checked_ts DESC LIMIT ?""",
            (max(1, int(limit)),),
        )

    def get_hash_cache(self, path: str, mtime_ns: int, size: int):
        rows = self.execute(
            """SELECT path,mtime_ns,size,sha256,sha1,score,level,checked_ts
               FROM hash_cache WHERE path=? AND mtime_ns=? AND size=?""",
            (canonical_path(path), int(mtime_ns), int(size)),
        )
        return rows[0] if rows else None

    def upsert_hash_cache(
        self,
        *,
        path: str,
        mtime_ns: int,
        size: int,
        sha256: str,
        sha1: str = "",
        score: int = 0,
        level: str = "UNKNOWN",
    ):
        self.execute(
            """INSERT INTO hash_cache(path,mtime_ns,size,sha256,sha1,score,level,checked_ts)
               VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
               ON CONFLICT(path) DO UPDATE SET
                   mtime_ns=excluded.mtime_ns,
                   size=excluded.size,
                   sha256=excluded.sha256,
                   sha1=excluded.sha1,
                   score=excluded.score,
                   level=excluded.level,
                   checked_ts=CURRENT_TIMESTAMP""",
            (
                canonical_path(path), int(mtime_ns), int(size), str(sha256),
                str(sha1 or ""), int(score), str(level or "UNKNOWN"),
            ),
        )

    def upsert_hash_cache_batch(self, entries) -> int:
        rows = list(entries or [])
        if not rows:
            return 0
        payload = [
            (
                canonical_path(item["path"]), int(item["mtime_ns"]), int(item["size"]),
                str(item["sha256"]), str(item.get("sha1") or ""),
                int(item.get("score") or 0), str(item.get("level") or "UNKNOWN"),
            )
            for item in rows
        ]
        with self._lock, self.connect() as con:
            con.executemany(
                """INSERT INTO hash_cache(path,mtime_ns,size,sha256,sha1,score,level,checked_ts)
                   VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
                   ON CONFLICT(path) DO UPDATE SET
                       mtime_ns=excluded.mtime_ns,
                       size=excluded.size,
                       sha256=excluded.sha256,
                       sha1=excluded.sha1,
                       score=excluded.score,
                       level=excluded.level,
                       checked_ts=CURRENT_TIMESTAMP""",
                payload,
            )
        return len(payload)

    def prune_hash_cache(self, max_rows: int = 50000) -> int:
        max_rows = max(1000, int(max_rows))
        rows = self.execute("SELECT COUNT(*) AS c FROM hash_cache")
        count = int(rows[0]["c"] if rows else 0)
        excess = max(0, count - max_rows)
        if not excess:
            return 0
        self.execute(
            "DELETE FROM hash_cache WHERE path IN ("
            "SELECT path FROM hash_cache ORDER BY checked_ts ASC LIMIT ?)",
            (excess,),
        )
        return excess

    def add_detection(self, path: str, sha256: str, score: int, level: str,
                      reasons_json: str, action: str = "logged",
                      dedupe_minutes: int = 10) -> bool:
        """Persist only meaningful detections and suppress near-duplicates.

        Returns True when a new detection was inserted.
        SAFE / LOW telemetry is deliberately not stored in the detections table.
        """
        score = int(score)
        if score < 50:
            return False

        with self._lock, self.connect() as con:
            # SQLite CURRENT_TIMESTAMP is UTC in YYYY-MM-DD HH:MM:SS.
            row = con.execute(
                """
                SELECT id
                FROM detections
                WHERE sha256 = ?
                  AND score = ?
                  AND ts >= datetime('now', ?)
                ORDER BY id DESC
                LIMIT 1
                """,
                (sha256, score, f"-{int(dedupe_minutes)} minutes"),
            ).fetchone()
            if row:
                return False

            con.execute(
                """
                INSERT INTO detections(path,sha256,score,level,reasons_json,action)
                VALUES(?,?,?,?,?,?)
                """,
                (path, sha256, score, level, reasons_json, action),
            )
            return True

    def update_detection_action(self, sha256: str, action: str):
        """Update the latest detection state for a file hash."""
        self.execute(
            """
            UPDATE detections
               SET action=?
             WHERE id = (
                 SELECT id FROM detections
                 WHERE sha256=?
                 ORDER BY id DESC
                 LIMIT 1
             )
            """,
            (action, sha256),
        )

    def latest_detection_action(self, sha256: str) -> str | None:
        rows = self.execute(
            """
            SELECT action
              FROM detections
             WHERE sha256=?
             ORDER BY id DESC
             LIMIT 1
            """,
            (sha256,),
        )
        return rows[0]["action"] if rows else None


    @property
    def ioc_revision(self) -> int:
        return int(self._ioc_revision)

    def install_ioc_bundle(self, verified) -> dict:
        """Atomically install one verified signed IOC feed with anti-rollback."""
        payload = verified.to_dict() if hasattr(verified, "to_dict") else dict(verified)
        sequence = int(payload["sequence"])
        payload_sha256 = str(payload["payload_sha256"])
        with self._lock, self.connect() as con:
            current = con.execute("SELECT * FROM ioc_feed_state WHERE id=1").fetchone()
            if current is not None:
                current_seq = int(current["sequence"] or 0)
                current_digest = str(current["payload_sha256"] or "")
                if sequence < current_seq:
                    raise ValueError("IOC anti-rollback: signed bundle sequence is older than installed feed")
                if sequence == current_seq:
                    if payload_sha256 != current_digest:
                        raise ValueError("IOC anti-rollback: sequence reuse with different payload is forbidden")
                    return {
                        "installed": False, "idempotent": True,
                        "sequence": current_seq, "payload_sha256": current_digest,
                    }
            con.execute("DELETE FROM ioc_indicators")
            for entry in payload.get("entries") or []:
                con.execute(
                    """INSERT INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
                       VALUES(?,?,?,?,?,?)""",
                    (
                        str(entry.get("kind") or ""), str(entry.get("value") or ""),
                        str(entry.get("severity") or "high"), str(entry.get("label") or ""),
                        float(entry.get("expires_at") or payload["expires_at"]),
                        str(payload["bundle_id"]),
                    ),
                )
            con.execute(
                """INSERT INTO ioc_feed_state(
                       id,bundle_id,sequence,issued_at,expires_at,payload_sha256,signature_b64,imported_ts
                   ) VALUES(1,?,?,?,?,?,?,CURRENT_TIMESTAMP)
                   ON CONFLICT(id) DO UPDATE SET
                       bundle_id=excluded.bundle_id, sequence=excluded.sequence,
                       issued_at=excluded.issued_at, expires_at=excluded.expires_at,
                       payload_sha256=excluded.payload_sha256, signature_b64=excluded.signature_b64,
                       imported_ts=CURRENT_TIMESTAMP""",
                (
                    str(payload["bundle_id"]), sequence, float(payload["issued_at"]),
                    float(payload["expires_at"]), payload_sha256, str(payload["signature_b64"]),
                ),
            )
        self._ioc_revision += 1
        return {
            "installed": True, "idempotent": False, "sequence": sequence,
            "payload_sha256": payload_sha256, "entries": len(payload.get("entries") or []),
        }

    def ioc_status(self, *, now: float | None = None) -> dict:
        import time as _time
        current = float(_time.time() if now is None else now)
        state = self.execute("SELECT * FROM ioc_feed_state WHERE id=1")
        row = state[0] if state else None
        active_rows = self.execute("SELECT COUNT(*) AS n FROM ioc_indicators WHERE expires_at > ?", (current,))
        active = int(active_rows[0]["n"] or 0) if active_rows else 0
        if row is None:
            return {"installed": False, "active_entries": 0, "expired": False}
        return {
            "installed": True, "bundle_id": str(row["bundle_id"] or ""),
            "sequence": int(row["sequence"] or 0), "issued_at": float(row["issued_at"] or 0),
            "expires_at": float(row["expires_at"] or 0), "payload_sha256": str(row["payload_sha256"] or ""),
            "imported_ts": str(row["imported_ts"] or ""), "active_entries": active,
            "expired": float(row["expires_at"] or 0) <= current,
        }

    def ioc_kind_count(self, kind: str, *, now: float | None = None) -> int:
        import time as _time
        current = float(_time.time() if now is None else now)
        rows = self.execute(
            "SELECT COUNT(*) AS n FROM ioc_indicators WHERE kind=? AND expires_at > ?",
            (str(kind).strip().casefold(), current),
        )
        return int(rows[0]["n"] or 0) if rows else 0

    def recent_web_findings(self, limit: int = 100, *, min_score: int = 0, status: str | None = None):
        clauses = ["score >= ?"]
        params: list[object] = [max(0, min(int(min_score), 100))]
        if status:
            clauses.append("status=?")
            params.append(str(status))
        params.append(max(1, min(int(limit), 500)))
        return self.execute(
            f"""SELECT * FROM web_findings
                  WHERE {' AND '.join(clauses)}
                  ORDER BY created_at DESC LIMIT ?""",
            tuple(params),
        )

    def web_finding(self, finding_id: str):
        rows = self.execute("SELECT * FROM web_findings WHERE finding_id=?", (str(finding_id),))
        return rows[0] if rows else None

    def record_web_finding(
        self, *, finding_id: str, created_at: float, domain: str, remote_address: str = "",
        pid: int | None = None, process_name: str = "", process_path: str = "", score: int = 0,
        level: str = "SAFE", source: str = "", reasons_json: str = "[]", evidence_json: str = "{}",
        shared_ip: bool = False, block_recommended: bool = False, decision: str = "observe",
        dedupe_seconds: float = 300.0,
    ) -> dict:
        now = float(created_at)
        rows = self.execute(
            """SELECT * FROM web_findings
                 WHERE status='pending' AND domain=? AND remote_address=? AND COALESCE(pid,0)=?
                   AND created_at >= ?
                 ORDER BY created_at DESC LIMIT 1""",
            (str(domain), str(remote_address), int(pid or 0), now - max(1.0, float(dedupe_seconds))),
        )
        if rows:
            existing = rows[0]
            self.execute(
                """UPDATE web_findings SET updated_at=?, score=?, level=?, source=?, reasons_json=?, evidence_json=?,
                          shared_ip=?, block_recommended=?, decision=? WHERE finding_id=?""",
                (now, int(score), str(level), str(source), str(reasons_json), str(evidence_json), int(bool(shared_ip)),
                 int(bool(block_recommended)), str(decision), str(existing['finding_id'])),
            )
            return {"finding_id": str(existing["finding_id"]), "created": False}
        self.execute(
            """INSERT INTO web_findings(
                   finding_id,created_at,updated_at,domain,remote_address,pid,process_name,process_path,score,level,source,
                   reasons_json,evidence_json,shared_ip,block_recommended,decision,status
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending')""",
            (str(finding_id), now, now, str(domain), str(remote_address), int(pid) if pid else None,
             str(process_name), str(process_path), int(score), str(level), str(source), str(reasons_json),
             str(evidence_json), int(bool(shared_ip)), int(bool(block_recommended)), str(decision)),
        )
        return {"finding_id": str(finding_id), "created": True}

    def resolve_web_finding(self, finding_id: str, *, status: str, resolution: str, lease_id: str = "", resolved_at: float | None = None):
        import time as _time
        ts = float(_time.time() if resolved_at is None else resolved_at)
        self.execute(
            """UPDATE web_findings SET status=?, resolution=?, lease_id=?, resolved_at=?, updated_at=? WHERE finding_id=?""",
            (str(status), str(resolution), str(lease_id or ""), ts, ts, str(finding_id)),
        )

    def resolve_web_findings_by_lease(self, lease_id: str, *, status: str, resolution: str, resolved_at: float | None = None):
        import time as _time
        ts = float(_time.time() if resolved_at is None else resolved_at)
        self.execute(
            """UPDATE web_findings SET status=?, resolution=?, resolved_at=?, updated_at=? WHERE lease_id=?""",
            (str(status), str(resolution), ts, ts, str(lease_id)),
        )

    def resolve_pending_web_findings_by_domain(self, domain: str, *, status: str, resolution: str, resolved_at: float | None = None) -> int:
        import time as _time
        ts = float(_time.time() if resolved_at is None else resolved_at)
        with self._lock, self.connect() as con:
            cur = con.execute(
                """UPDATE web_findings SET status=?, resolution=?, resolved_at=?, updated_at=?
                     WHERE status='pending' AND domain=?""",
                (str(status), str(resolution), ts, ts, str(domain)),
            )
            return int(cur.rowcount or 0)

    @property
    def web_trust_revision(self) -> int:
        return int(self._web_trust_revision)

    def add_web_domain_trust(self, domain: str, *, reason: str = "", source_finding_id: str = "", now: float | None = None) -> dict:
        import time as _time
        normalized = str(domain or "").strip().rstrip(".").casefold()
        if not normalized or len(normalized) > 253 or "*" in normalized or "://" in normalized:
            raise ValueError("Trusted domain must be one exact normalized domain.")
        ts = float(_time.time() if now is None else now)
        self.execute(
            """INSERT INTO web_domain_trust(domain,scope,reason,source_finding_id,created_at,updated_at)
                 VALUES(?,'exact',?,?,?,?)
                 ON CONFLICT(domain) DO UPDATE SET reason=excluded.reason, source_finding_id=excluded.source_finding_id, updated_at=excluded.updated_at""",
            (normalized, str(reason or "")[:256], str(source_finding_id or "")[:64], ts, ts),
        )
        self._web_trust_revision += 1
        row = self.match_web_domain_trust(normalized)
        return dict(row or {})

    def remove_web_domain_trust(self, domain: str) -> bool:
        normalized = str(domain or "").strip().rstrip(".").casefold()
        with self._lock, self.connect() as con:
            cur = con.execute("DELETE FROM web_domain_trust WHERE domain=?", (normalized,))
            removed = int(cur.rowcount or 0) > 0
        if removed:
            self._web_trust_revision += 1
        return removed

    def match_web_domain_trust(self, domain: str):
        normalized = str(domain or "").strip().rstrip(".").casefold()
        rows = self.execute(
            """SELECT domain,scope,reason,source_finding_id,created_at,updated_at
                 FROM web_domain_trust WHERE domain=? LIMIT 1""",
            (normalized,),
        )
        return dict(rows[0]) if rows else None

    def list_web_domain_trust(self, limit: int = 500):
        return self.execute(
            """SELECT domain,scope,reason,source_finding_id,created_at,updated_at
                 FROM web_domain_trust ORDER BY updated_at DESC LIMIT ?""",
            (max(1, min(int(limit), 1000)),),
        )

    def web_domain_trust_count(self) -> int:
        rows = self.execute("SELECT COUNT(*) AS n FROM web_domain_trust")
        return int(rows[0]["n"] or 0) if rows else 0

    def web_domain_trust_conflicts(self, *, now: float | None = None, limit: int = 100) -> list[dict]:
        conflicts: list[dict] = []
        for row in self.list_web_domain_trust(limit=1000):
            domain = str(row["domain"] or "")
            match = self.match_ioc_endpoint(domain, now=now)
            if match is not None and str(match.get("kind") or "") == "domain":
                conflicts.append({
                    "domain": domain,
                    "trust": dict(row),
                    "ioc": dict(match),
                    "state": "overridden_by_signed_ioc",
                })
                if len(conflicts) >= max(1, min(int(limit), 500)):
                    break
        return conflicts

    def record_web_domain_observation(
        self, *, domain: str, score: int, status: str, source: str, process_name: str = "",
        process_path: str = "", remote_address: str = "", observed_at: float | None = None,
    ) -> dict:
        import json as _json
        import time as _time
        normalized = str(domain or "").strip().rstrip(".").casefold()
        if not normalized:
            return {}
        ts = float(_time.time() if observed_at is None else observed_at)
        score_i = max(0, min(int(score or 0), 100))
        with self._lock, self.connect() as con:
            row = con.execute("SELECT * FROM web_domain_reputation WHERE domain=?", (normalized,)).fetchone()
            if row is None:
                processes = []
                addresses = []
                observations = malicious = suspicious = max_score = 0
                first_seen = ts
            else:
                try: processes = list(_json.loads(str(row["processes_json"] or "[]")))
                except Exception: processes = []
                try: addresses = list(_json.loads(str(row["addresses_json"] or "[]")))
                except Exception: addresses = []
                observations = int(row["observations"] or 0)
                malicious = int(row["malicious_observations"] or 0)
                suspicious = int(row["suspicious_observations"] or 0)
                max_score = int(row["max_score"] or 0)
                first_seen = float(row["first_seen"] or ts)
            proc_key = str(process_name or process_path or "")[:128]
            addr = str(remote_address or "")[:128]
            if proc_key and proc_key not in processes:
                processes = (processes + [proc_key])[-16:]
            if addr and addr not in addresses:
                addresses = (addresses + [addr])[-16:]
            observations += 1
            status_cf = str(status or "").casefold()
            if status_cf == "malicious": malicious += 1
            if status_cf == "suspicious": suspicious += 1
            max_score = max(max_score, score_i)
            con.execute(
                """INSERT INTO web_domain_reputation(
                       domain,first_seen,last_seen,observations,max_score,malicious_observations,suspicious_observations,
                       last_source,last_status,last_process_name,last_process_path,last_remote_address,processes_json,addresses_json
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(domain) DO UPDATE SET
                       last_seen=excluded.last_seen, observations=excluded.observations, max_score=excluded.max_score,
                       malicious_observations=excluded.malicious_observations, suspicious_observations=excluded.suspicious_observations,
                       last_source=excluded.last_source, last_status=excluded.last_status, last_process_name=excluded.last_process_name,
                       last_process_path=excluded.last_process_path, last_remote_address=excluded.last_remote_address,
                       processes_json=excluded.processes_json, addresses_json=excluded.addresses_json""",
                (normalized, first_seen, ts, observations, max_score, malicious, suspicious, str(source or "")[:128],
                 str(status or "")[:32], str(process_name or "")[:128], str(process_path or "")[:1024], addr,
                 _json.dumps(processes, ensure_ascii=False), _json.dumps(addresses, ensure_ascii=False)),
            )
            # Bound local reputation state. Oldest aggregate rows are disposable
            # evidence; trust policy and signed IOC state live in separate tables.
            total = int(con.execute("SELECT COUNT(*) FROM web_domain_reputation").fetchone()[0] or 0)
            if total > 20000:
                excess = total - 20000
                con.execute(
                    "DELETE FROM web_domain_reputation WHERE domain IN (SELECT domain FROM web_domain_reputation ORDER BY last_seen ASC LIMIT ?)",
                    (excess,),
                )
        return self.web_domain_reputation(normalized)

    def web_domain_reputation(self, domain: str) -> dict:
        import json as _json
        normalized = str(domain or "").strip().rstrip(".").casefold()
        rows = self.execute("SELECT * FROM web_domain_reputation WHERE domain=?", (normalized,))
        if not rows:
            return {"domain": normalized, "observed": False, "observations": 0, "processes": [], "addresses": []}
        item = dict(rows[0])
        for field, target in (("processes_json", "processes"), ("addresses_json", "addresses")):
            try: item[target] = list(_json.loads(str(item.get(field) or "[]")))
            except Exception: item[target] = []
        item["observed"] = True
        item["process_count_sampled"] = len(item.get("processes") or [])
        item["address_count_sampled"] = len(item.get("addresses") or [])
        return item

    def web_domain_reputation_count(self) -> int:
        rows = self.execute("SELECT COUNT(*) AS n FROM web_domain_reputation")
        return int(rows[0]["n"] or 0) if rows else 0

    def record_web_download(
        self, *, download_id: str, created_at: float, domain: str, remote_address: str = "",
        browser_pid: int | None = None, browser_family: str = "", browser_process_name: str = "",
        browser_process_path: str = "", file_path: str, stage: str = "materialized",
        origin_score: int = 0, origin_status: str = "unknown", origin_source: str = "",
        origin_signed_ioc: bool = False, evidence_json: str = "{}", dedupe_seconds: float = 180.0,
    ) -> dict:
        now = float(created_at)
        canonical_path = str(file_path or "")
        if not canonical_path:
            raise ValueError("web download requires a file path")
        rows = self.execute(
            """SELECT * FROM web_downloads
                 WHERE file_path=? AND COALESCE(browser_pid,0)=? AND updated_at >= ?
                 ORDER BY updated_at DESC LIMIT 1""",
            (canonical_path, int(browser_pid or 0), now - max(1.0, float(dedupe_seconds))),
        )
        if rows:
            existing = rows[0]
            self.execute(
                """UPDATE web_downloads SET updated_at=?, domain=?, remote_address=?, browser_family=?,
                          browser_process_name=?, browser_process_path=?, stage=?, origin_score=?, origin_status=?,
                          origin_source=?, origin_signed_ioc=?, evidence_json=? WHERE download_id=?""",
                (now, str(domain), str(remote_address), str(browser_family), str(browser_process_name),
                 str(browser_process_path), str(stage), int(origin_score), str(origin_status), str(origin_source),
                 int(bool(origin_signed_ioc)), str(evidence_json), str(existing["download_id"])),
            )
            return {"download_id": str(existing["download_id"]), "created": False}
        self.execute(
            """INSERT INTO web_downloads(
                   download_id,created_at,updated_at,domain,remote_address,browser_pid,browser_family,
                   browser_process_name,browser_process_path,file_path,stage,origin_score,origin_status,
                   origin_source,origin_signed_ioc,evidence_json,status
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'tracked')""",
            (str(download_id), now, now, str(domain), str(remote_address), int(browser_pid) if browser_pid else None,
             str(browser_family), str(browser_process_name), str(browser_process_path), canonical_path, str(stage),
             int(origin_score), str(origin_status), str(origin_source), int(bool(origin_signed_ioc)), str(evidence_json)),
        )
        # Keep local download provenance bounded. Old rows are historical context,
        # not a permanent forensic archive in the endpoint database.
        rows = self.execute("SELECT COUNT(*) AS n FROM web_downloads")
        total = int(rows[0]["n"] or 0) if rows else 0
        if total > 5000:
            self.execute(
                "DELETE FROM web_downloads WHERE download_id IN (SELECT download_id FROM web_downloads ORDER BY updated_at ASC LIMIT ?)",
                (total - 5000,),
            )
        return {"download_id": str(download_id), "created": True}

    def web_download(self, download_id: str):
        rows = self.execute("SELECT * FROM web_downloads WHERE download_id=?", (str(download_id),))
        return rows[0] if rows else None

    def web_download_by_path(self, file_path: str, *, max_age_seconds: float | None = None, now: float | None = None):
        import time as _time
        params: list[object] = [str(file_path or "")]
        clause = "file_path=?"
        if max_age_seconds is not None:
            current = float(_time.time() if now is None else now)
            clause += " AND updated_at >= ?"
            params.append(current - max(1.0, float(max_age_seconds)))
        rows = self.execute(
            f"SELECT * FROM web_downloads WHERE {clause} ORDER BY updated_at DESC LIMIT 1", tuple(params)
        )
        if rows:
            return rows[0]
        # Windows path spelling may vary between ETW and watchdog/scanner
        # (slash direction/case). Fall back to a canonical textual comparison.
        canonical = str(file_path or "").replace("/", "\\").casefold()
        candidates = self.execute("SELECT * FROM web_downloads ORDER BY updated_at DESC LIMIT 500")
        for item in candidates:
            if str(item["file_path"] or "").replace("/", "\\").casefold() == canonical:
                if max_age_seconds is None or float(item["updated_at"] or 0) >= float((now if now is not None else _time.time())) - max(1.0, float(max_age_seconds)):
                    return item
        return None

    def recent_web_downloads(self, limit: int = 100, *, status: str | None = None):
        params: list[object] = []
        where = ""
        if status:
            where = "WHERE status=?"
            params.append(str(status))
        params.append(max(1, min(int(limit), 500)))
        return self.execute(
            f"SELECT * FROM web_downloads {where} ORDER BY updated_at DESC LIMIT ?", tuple(params)
        )

    def update_web_download_file_verdict(
        self, file_path: str, *, sha256: str = "", score: int = 0, level: str = "SAFE", now: float | None = None
    ) -> str:
        import time as _time
        ts = float(_time.time() if now is None else now)
        row = self.web_download_by_path(file_path)
        if row is None:
            return ""
        status = "file_risk" if int(score) >= 50 else str(row["status"] or "tracked")
        self.execute(
            """UPDATE web_downloads SET updated_at=?, file_sha256=?, file_score=?, file_level=?, status=?
                 WHERE download_id=?""",
            (ts, str(sha256 or "").casefold(), int(score), str(level or "SAFE").upper(), status, str(row["download_id"])),
        )
        return str(row["download_id"])

    def mark_web_download_executed(
        self, file_path: str, *, executed_pid: int | None = None, incident_id: str = "", now: float | None = None
    ) -> str:
        import time as _time
        ts = float(_time.time() if now is None else now)
        row = self.web_download_by_path(file_path)
        if row is None:
            return ""
        self.execute(
            """UPDATE web_downloads SET updated_at=?, executed_pid=?, executed_at=?, incident_id=?, status='executed'
                 WHERE download_id=?""",
            (ts, int(executed_pid) if executed_pid else None, ts, str(incident_id or ""), str(row["download_id"])),
        )
        return str(row["download_id"])

    def web_download_count(self) -> int:
        rows = self.execute("SELECT COUNT(*) AS n FROM web_downloads")
        return int(rows[0]["n"] or 0) if rows else 0

    @property
    def threat_package_revision(self) -> int:
        return int(self._threat_package_revision)

    def activate_threat_package_iocs(self, package, entries: list[dict]) -> dict:
        """Replace the active v0.8 signed-package IOC overlay atomically.

        Sequence anti-rollback is enforced by ThreatPackageManager; this DB
        layer intentionally supports LKG rollback to an older signed package.
        """
        payload = package.to_dict() if package is not None and hasattr(package, "to_dict") else (dict(package) if package else {})
        package_id = str(payload.get("package_id") or "")
        sequence = int(payload.get("sequence") or 0)
        digest = str(payload.get("payload_sha256") or "")
        expires_at = float(payload.get("expires_at") or 0)
        with self._lock, self.connect() as con:
            con.execute("DELETE FROM threat_package_ioc_indicators")
            for entry in entries or []:
                con.execute(
                    """INSERT INTO threat_package_ioc_indicators(
                           kind,value,severity,label,expires_at,package_id,package_sequence
                       ) VALUES(?,?,?,?,?,?,?)""",
                    (str(entry.get("kind") or ""), str(entry.get("value") or ""),
                     str(entry.get("severity") or "high"), str(entry.get("label") or ""),
                     float(entry.get("expires_at") or expires_at), package_id, sequence),
                )
            con.execute(
                """INSERT INTO threat_package_ioc_state(id,package_id,sequence,payload_sha256,expires_at,activated_at)
                     VALUES(1,?,?,?,?,?)
                     ON CONFLICT(id) DO UPDATE SET package_id=excluded.package_id,sequence=excluded.sequence,
                     payload_sha256=excluded.payload_sha256,expires_at=excluded.expires_at,activated_at=excluded.activated_at""",
                (package_id, sequence, digest, expires_at, __import__('time').time()),
            )
        self._ioc_revision += 1
        self._threat_package_revision += 1
        return {"package_id": package_id, "sequence": sequence, "entries": len(entries or [])}

    def threat_package_ioc_status(self, *, now: float | None = None) -> dict:
        import time as _time
        current = float(_time.time() if now is None else now)
        state = self.execute("SELECT * FROM threat_package_ioc_state WHERE id=1")
        row = state[0] if state else None
        active_rows = self.execute("SELECT COUNT(*) AS n FROM threat_package_ioc_indicators WHERE expires_at > ?", (current,))
        active = int(active_rows[0]["n"] or 0) if active_rows else 0
        if row is None or not str(row["package_id"] or ""):
            return {"installed": False, "active_entries": active}
        return {
            "installed": True, "package_id": str(row["package_id"] or ""),
            "sequence": int(row["sequence"] or 0), "payload_sha256": str(row["payload_sha256"] or ""),
            "expires_at": float(row["expires_at"] or 0), "activated_at": float(row["activated_at"] or 0),
            "active_entries": active, "expired": float(row["expires_at"] or 0) <= current,
        }

    def activate_threat_package_reputation(self, package, entries: list[dict]) -> dict:
        payload = package.to_dict() if package is not None and hasattr(package, "to_dict") else (dict(package) if package else {})
        package_id = str(payload.get("package_id") or "")
        sequence = int(payload.get("sequence") or 0)
        expires_at = float(payload.get("expires_at") or 0)
        with self._lock, self.connect() as con:
            con.execute("DELETE FROM threat_package_reputation")
            for entry in entries or []:
                con.execute(
                    """INSERT INTO threat_package_reputation(
                           kind,value,status,confidence,label,expires_at,package_id,package_sequence
                       ) VALUES(?,?,?,?,?,?,?,?)""",
                    (str(entry.get("kind") or ""), str(entry.get("value") or ""),
                     str(entry.get("status") or "suspicious"), int(entry.get("confidence") or 0),
                     str(entry.get("label") or ""), float(entry.get("expires_at") or expires_at),
                     package_id, sequence),
                )
        self._threat_package_revision += 1
        return {"package_id": package_id, "sequence": sequence, "entries": len(entries or [])}

    def match_signed_reputation(self, indicator: str, *, now: float | None = None):
        import ipaddress as _ipaddress
        import time as _time
        raw = str(indicator or "").strip().rstrip(".")
        if not raw:
            return None
        current = float(_time.time() if now is None else now)
        try:
            address = _ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            domain = raw.casefold()
            rows = self.execute(
                """SELECT kind,value,status,confidence,label,expires_at,package_id,package_sequence
                     FROM threat_package_reputation
                    WHERE kind='domain' AND expires_at > ?
                    ORDER BY confidence DESC, package_sequence DESC""", (current,)
            )
            for row in rows:
                value = str(row["value"] or "").casefold()
                if domain == value or domain.endswith("." + value):
                    out = dict(row); out["source"] = "signed_reputation"; return out
            return None
        rows = self.execute(
            """SELECT kind,value,status,confidence,label,expires_at,package_id,package_sequence
                 FROM threat_package_reputation
                WHERE kind='network' AND expires_at > ?
                ORDER BY confidence DESC, package_sequence DESC""", (current,)
        )
        for row in rows:
            try:
                if address in _ipaddress.ip_network(str(row["value"]), strict=False):
                    out = dict(row); out["source"] = "signed_reputation"; return out
            except ValueError:
                continue
        return None

    def threat_package_reputation_count(self, *, now: float | None = None) -> int:
        import time as _time
        current = float(_time.time() if now is None else now)
        rows = self.execute("SELECT COUNT(*) AS n FROM threat_package_reputation WHERE expires_at > ?", (current,))
        return int(rows[0]["n"] or 0) if rows else 0

    def list_ioc_entries(self, limit: int = 500, *, now: float | None = None):
        import time as _time
        current = float(_time.time() if now is None else now)
        bounded = max(1, min(int(limit), 6000))
        return self.execute(
            """SELECT kind,value,severity,label,expires_at,bundle_id,source FROM (
                   SELECT kind,value,severity,label,expires_at,bundle_id,'ioc_feed' AS source, 1 AS precedence
                     FROM ioc_indicators WHERE expires_at > ?
                   UNION ALL
                   SELECT kind,value,severity,label,expires_at,package_id AS bundle_id,'threat_package' AS source, 0 AS precedence
                     FROM threat_package_ioc_indicators WHERE expires_at > ?
               ) ORDER BY precedence ASC, severity DESC, kind, value LIMIT ?""",
            (current, current, bounded),
        )

    def match_ioc_hash(self, sha256: str, *, now: float | None = None):
        import time as _time
        digest = str(sha256 or "").strip().casefold()
        current = float(_time.time() if now is None else now)
        rows = self.execute(
            """SELECT kind,value,severity,label,expires_at,bundle_id,source FROM (
                   SELECT kind,value,severity,label,expires_at,package_id AS bundle_id,'threat_package' AS source,0 AS precedence
                     FROM threat_package_ioc_indicators WHERE kind='sha256' AND value=? AND expires_at > ?
                   UNION ALL
                   SELECT kind,value,severity,label,expires_at,bundle_id,'ioc_feed' AS source,1 AS precedence
                     FROM ioc_indicators WHERE kind='sha256' AND value=? AND expires_at > ?
               ) ORDER BY precedence ASC LIMIT 1""",
            (digest, current, digest, current),
        )
        return dict(rows[0]) if rows else None

    def match_ioc_endpoint(self, indicator: str, *, now: float | None = None):
        import ipaddress as _ipaddress
        import time as _time
        raw = str(indicator or "").strip().rstrip(".")
        if not raw:
            return None
        current = float(_time.time() if now is None else now)
        try:
            address = _ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            domain = raw.casefold()
            rows = self.execute(
                """SELECT kind,value,severity,label,expires_at,bundle_id,source,precedence FROM (
                       SELECT kind,value,severity,label,expires_at,package_id AS bundle_id,'threat_package' AS source,0 AS precedence
                         FROM threat_package_ioc_indicators WHERE kind='domain' AND expires_at > ?
                       UNION ALL
                       SELECT kind,value,severity,label,expires_at,bundle_id,'ioc_feed' AS source,1 AS precedence
                         FROM ioc_indicators WHERE kind='domain' AND expires_at > ?
                   ) ORDER BY precedence ASC""",
                (current, current),
            )
            for row in rows:
                value = str(row["value"] or "").casefold()
                if domain == value or domain.endswith("." + value):
                    return {k: row[k] for k in row.keys() if k != "precedence"}
            return None
        rows = self.execute(
            """SELECT kind,value,severity,label,expires_at,bundle_id,source,precedence FROM (
                   SELECT kind,value,severity,label,expires_at,package_id AS bundle_id,'threat_package' AS source,0 AS precedence
                     FROM threat_package_ioc_indicators WHERE kind='network' AND expires_at > ?
                   UNION ALL
                   SELECT kind,value,severity,label,expires_at,bundle_id,'ioc_feed' AS source,1 AS precedence
                     FROM ioc_indicators WHERE kind='network' AND expires_at > ?
               ) ORDER BY precedence ASC""",
            (current, current),
        )
        for row in rows:
            try:
                if address in _ipaddress.ip_network(str(row["value"]), strict=False):
                    return {k: row[k] for k in row.keys() if k != "precedence"}
            except ValueError:
                continue
        return None

    def add_containment_lease(self, *, lease_id: str, rule_id: str, remote_address: str, incident_id: str, reason: str, created_at: float, expires_at: float):
        self.execute(
            """INSERT INTO containment_leases(
                   lease_id,rule_id,remote_address,incident_id,reason,created_at,expires_at,status
               ) VALUES(?,?,?,?,?,?,?,'active')""",
            (str(lease_id), str(rule_id), str(remote_address), str(incident_id or ""), str(reason or ""), float(created_at), float(expires_at)),
        )

    def active_containment_leases(self, *, now: float | None = None):
        import time as _time
        current = float(_time.time() if now is None else now)
        return self.execute(
            """SELECT * FROM containment_leases
                WHERE status='active' ORDER BY expires_at ASC"""
        )

    def containment_lease(self, lease_id: str):
        rows = self.execute("SELECT * FROM containment_leases WHERE lease_id=?", (str(lease_id),))
        return rows[0] if rows else None

    def active_containment_lease_for_remote(self, remote_address: str):
        rows = self.execute(
            """SELECT * FROM containment_leases
                 WHERE status='active' AND remote_address=?
                 ORDER BY created_at ASC LIMIT 1""",
            (str(remote_address),),
        )
        return rows[0] if rows else None

    def mark_containment_lease_released(self, lease_id: str, *, reason: str, released_at: float):
        self.execute(
            """UPDATE containment_leases
                  SET status='released', released_at=?, release_reason=?
                WHERE lease_id=? AND status='active'""",
            (float(released_at), str(reason or ""), str(lease_id)),
        )

    def pending_threat_decisions(self, limit: int = 100):
        """Current HIGH/CRITICAL detections that still require an operator decision."""
        return self.execute(
            """SELECT d.*
                 FROM detections d
                 JOIN (
                       SELECT sha256, MAX(id) AS max_id
                         FROM detections
                        WHERE score >= 70 AND sha256 IS NOT NULL AND sha256 <> ''
                        GROUP BY sha256
                      ) latest ON latest.max_id=d.id
                WHERE d.action='logged'
                ORDER BY d.score DESC, d.id DESC
                LIMIT ?""",
            (max(1, min(int(limit), 500)),),
        )


    def get_last_completed_scan(self):
        rows = self.execute(
            """
            SELECT *
              FROM scan_history
             WHERE finished_ts IS NOT NULL
             ORDER BY id DESC
             LIMIT 1
            """
        )
        return rows[0] if rows else None

    def start_scan_record(self, kind: str) -> int:
        with self._lock, self.connect() as con:
            cur = con.execute(
                "INSERT INTO scan_history(kind) VALUES(?)",
                (str(kind),),
            )
            return int(cur.lastrowid)

    def finish_scan_record(
        self,
        scan_id: int,
        files_scanned: int,
        detections: int,
        cancelled: bool,
    ):
        self.execute(
            """
            UPDATE scan_history
               SET finished_ts=CURRENT_TIMESTAMP,
                   files_scanned=?,
                   detections=?,
                   cancelled=?
             WHERE id=?
            """,
            (
                int(files_scanned),
                int(detections),
                1 if cancelled else 0,
                int(scan_id),
            ),
        )

    def current_detection_history(self, limit: int = 500):
        """Return one current row per hash, using the newest database event."""
        return self.execute(
            """
            SELECT d.*
              FROM detections d
              JOIN (
                    SELECT sha256, MAX(id) AS max_id
                      FROM detections
                     WHERE score >= 50
                       AND sha256 IS NOT NULL
                       AND sha256 <> ''
                     GROUP BY sha256
                   ) latest
                ON latest.max_id = d.id
             ORDER BY d.id DESC
             LIMIT ?
            """,
            (int(limit),),
        )

    def record_security_event(self,event):
        import json
        p=event.to_dict() if hasattr(event,"to_dict") else dict(event)
        with self._lock,self.connect() as con:
            cur=con.execute("""INSERT INTO security_events(category,action,source,score,path,pid,ppid,process_name,process_path,reasons_json,data_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",(p.get("category","unknown"),p.get("action","event"),p.get("source","unknown"),int(p.get("score") or 0),p.get("path") or "",p.get("pid"),p.get("ppid"),p.get("process_name") or "",p.get("process_path") or "",json.dumps(p.get("reasons") or [],ensure_ascii=False),json.dumps(p.get("data") or {},ensure_ascii=False)))
            return int(cur.lastrowid)

    def record_correlation_event(
        self,
        *,
        category,
        source_event_category,
        source_event_action,
        pid=None,
        process_name="",
        score_delta=0,
        confidence=0.0,
        chain="",
        reasons=None,
        data=None,
    ):
        import json
        with self._lock,self.connect() as con:
            cur=con.execute(
                """INSERT INTO correlation_events(
                    category,
                    source_event_category,
                    source_event_action,
                    pid,
                    process_name,
                    score_delta,
                    confidence,
                    chain,
                    reasons_json,
                    data_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    category,
                    source_event_category,
                    source_event_action,
                    pid,
                    process_name or "",
                    int(score_delta or 0),
                    float(confidence or 0.0),
                    chain or "",
                    json.dumps(reasons or [],ensure_ascii=False),
                    json.dumps(data or {},ensure_ascii=False),
                ),
            )
            return int(cur.lastrowid)

    def recent_correlation_events(self,limit=250):
        return self.execute(
            "SELECT * FROM correlation_events ORDER BY id DESC LIMIT ?",
            (int(limit),),
        )

    def get_file_reputation(self,path,mtime_ns,size,sha256=None):
        if sha256:
            rows=self.execute(
                """SELECT * FROM file_reputation
                   WHERE path=? AND mtime_ns=? AND size=? AND sha256=?""",
                (str(path),int(mtime_ns),int(size),str(sha256)),
            )
        else:
            rows=self.execute(
                """SELECT * FROM file_reputation
                   WHERE path=? AND mtime_ns=? AND size=?""",
                (str(path),int(mtime_ns),int(size)),
            )
        return rows[0] if rows else None

    def upsert_file_reputation(
        self,
        *,
        path,
        mtime_ns,
        size,
        sha256,
        signature_status="",
        publisher="",
        local_trust="unknown",
        issuer="",
        thumbprint="",
        valid_from="",
        valid_to="",
        timestamp_signer="",
        status_message="",
    ):
        self.execute(
            """INSERT INTO file_reputation(
                   path,mtime_ns,size,sha256,signature_status,publisher,local_trust,
                   issuer,thumbprint,valid_from,valid_to,timestamp_signer,status_message
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(path) DO UPDATE SET
                   mtime_ns=excluded.mtime_ns,
                   size=excluded.size,
                   sha256=excluded.sha256,
                   signature_status=excluded.signature_status,
                   publisher=excluded.publisher,
                   local_trust=excluded.local_trust,
                   issuer=excluded.issuer, thumbprint=excluded.thumbprint,
                   valid_from=excluded.valid_from, valid_to=excluded.valid_to,
                   timestamp_signer=excluded.timestamp_signer,
                   status_message=excluded.status_message,
                   checked_ts=CURRENT_TIMESTAMP""",
            (
                str(path),int(mtime_ns),int(size),str(sha256),
                str(signature_status or ""),str(publisher or ""),
                str(local_trust or "unknown"),str(issuer or ""),
                str(thumbprint or ""),str(valid_from or ""),str(valid_to or ""),
                str(timestamp_signer or ""),str(status_message or ""),
            ),
        )

    def record_network_event(self,event):
        import json
        data=event.data or {}
        self.execute(
            """INSERT INTO network_events(
                   pid,process_name,process_path,local_addr,remote_addr,
                   remote_port,protocol,state,score,reasons_json,
                   remote_domain,endpoint_status,endpoint_confidence,
                   endpoint_first_seen,process_sha256,signature_status,signer
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event.pid,
                event.process_name or "",
                event.process_path or "",
                str(data.get("local_addr") or ""),
                str(data.get("remote_addr") or ""),
                int(data.get("remote_port") or 0),
                str(data.get("protocol") or ""),
                str(data.get("state") or ""),
                int(event.score or 0),
                json.dumps(event.reasons or [],ensure_ascii=False),
                str(data.get("remote_domain") or ""),
                str(data.get("endpoint_status") or "unknown"),
                float(data.get("endpoint_confidence") or 0.0),
                str(data.get("endpoint_first_seen") or ""),
                str(data.get("process_sha256") or ""),
                str(data.get("signature_status") or ""),
                str(data.get("signer") or ""),
            ),
        )

    def observe_file_reputation(self, sha256: str, path: str, publisher: str = "") -> dict:
        digest=str(sha256 or "").casefold()
        canonical=canonical_path(path)
        if not digest:
            return {"first_seen":"", "last_seen":"", "observations":0, "path_count":0}
        with self._lock,self.connect() as con:
            con.execute(
                """INSERT OR IGNORE INTO file_observations(sha256,path,publisher) VALUES(?,?,?)""",
                (digest,canonical,str(publisher or "")),
            )
            if publisher:
                con.execute(
                    """UPDATE file_observations SET publisher=?
                       WHERE sha256=? AND path=? AND publisher=''""",
                    (str(publisher),digest,canonical),
                )
            row=con.execute(
                """SELECT MIN(first_seen) first_seen, MAX(last_seen) last_seen,
                          SUM(observations) observations, COUNT(*) path_count
                   FROM file_observations WHERE sha256=?""",
                (digest,),
            ).fetchone()
            return dict(row) if row else {"first_seen":"", "last_seen":"", "observations":0, "path_count":0}

    def get_file_observation(self, sha256: str) -> dict:
        rows=self.execute(
            """SELECT MIN(first_seen) first_seen, MAX(last_seen) last_seen,
                      SUM(observations) observations, COUNT(*) path_count
               FROM file_observations WHERE sha256=?""",
            (str(sha256 or "").casefold(),),
        )
        return dict(rows[0]) if rows else {}

    def upsert_endpoint_reputation(self, *, indicator, kind, status="unknown", source="local", confidence=0.0, details=None, expires_ts=None):
        import json
        self.execute(
            """INSERT INTO endpoint_reputation(indicator,kind,status,source,confidence,details_json,expires_ts)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(indicator,kind) DO UPDATE SET
                 status=excluded.status, source=excluded.source, confidence=excluded.confidence,
                 details_json=excluded.details_json, expires_ts=excluded.expires_ts, checked_ts=CURRENT_TIMESTAMP""",
            (str(indicator),str(kind),str(status),str(source),float(confidence),json.dumps(details or {},ensure_ascii=False),expires_ts),
        )

    def get_endpoint_reputation(self, indicator: str, kind: str):
        rows=self.execute(
            """SELECT * FROM endpoint_reputation
               WHERE indicator=? AND kind=?
                 AND (expires_ts IS NULL OR expires_ts='' OR expires_ts>CURRENT_TIMESTAMP)""",
            (str(indicator),str(kind)),
        )
        return rows[0] if rows else None

    def observe_network_endpoint(self, indicator: str, process_key: str) -> dict:
        ind=str(indicator or "").strip()
        key=str(process_key or "unknown").strip() or "unknown"
        if not ind:
            return {"first_seen":"", "last_seen":"", "connection_count":0, "process_count":0}
        with self._lock,self.connect() as con:
            con.execute(
                """INSERT INTO network_endpoint_observations(indicator,process_key) VALUES(?,?)
                   ON CONFLICT(indicator,process_key) DO UPDATE SET
                     last_seen=CURRENT_TIMESTAMP,
                     connections=network_endpoint_observations.connections+1""",
                (ind,key),
            )
            row=con.execute(
                """SELECT MIN(first_seen) first_seen, MAX(last_seen) last_seen,
                          SUM(connections) connection_count, COUNT(*) process_count
                   FROM network_endpoint_observations WHERE indicator=?""",
                (ind,),
            ).fetchone()
            return dict(row) if row else {"first_seen":"", "last_seen":"", "connection_count":0, "process_count":0}

    def record_telemetry_batch(self, events, correlations=None) -> int:
        """Persist a service telemetry batch in one SQLite transaction.

        This keeps high-volume network/process bursts off the UI thread's
        transaction overhead while preserving the same normalized tables.
        """
        import json
        event_rows=list(events or [])
        correlation_rows=list(correlations or [])
        if not event_rows and not correlation_rows:
            return 0
        with self._lock,self.connect() as con:
            for event in event_rows:
                p=event.to_dict() if hasattr(event,"to_dict") else dict(event)
                con.execute(
                    """INSERT INTO security_events(category,action,source,score,path,pid,ppid,process_name,process_path,reasons_json,data_json)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (p.get("category","unknown"),p.get("action","event"),p.get("source","unknown"),int(p.get("score") or 0),p.get("path") or "",p.get("pid"),p.get("ppid"),p.get("process_name") or "",p.get("process_path") or "",json.dumps(p.get("reasons") or [],ensure_ascii=False),json.dumps(p.get("data") or {},ensure_ascii=False)),
                )
                if p.get("category")=="network":
                    data=p.get("data") or {}
                    con.execute(
                        """INSERT INTO network_events(
                               pid,process_name,process_path,local_addr,remote_addr,
                               remote_port,protocol,state,score,reasons_json,
                               remote_domain,endpoint_status,endpoint_confidence,
                               endpoint_first_seen,process_sha256,signature_status,signer
                           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (p.get("pid"),p.get("process_name") or "",p.get("process_path") or "",str(data.get("local_addr") or ""),str(data.get("remote_addr") or ""),int(data.get("remote_port") or 0),str(data.get("protocol") or ""),str(data.get("state") or ""),int(p.get("score") or 0),json.dumps(p.get("reasons") or [],ensure_ascii=False),str(data.get("remote_domain") or ""),str(data.get("endpoint_status") or "unknown"),float(data.get("endpoint_confidence") or 0.0),str(data.get("endpoint_first_seen") or ""),str(data.get("process_sha256") or ""),str(data.get("signature_status") or ""),str(data.get("signer") or "")),
                    )
            for row in correlation_rows:
                con.execute(
                    """INSERT INTO correlation_events(
                        category,source_event_category,source_event_action,pid,process_name,
                        score_delta,confidence,chain,reasons_json,data_json
                    ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (str(row.get("category") or "behavioral_correlation"),str(row.get("source_event_category") or "unknown"),str(row.get("source_event_action") or "event"),row.get("pid"),str(row.get("process_name") or ""),int(row.get("score_delta") or 0),float(row.get("confidence") or 0.0),str(row.get("chain") or ""),json.dumps(row.get("reasons") or [],ensure_ascii=False),json.dumps(row.get("data") or {},ensure_ascii=False)),
                )
        return len(event_rows)

    def recent_security_events(self,limit=250,category=None):
        if category:return self.execute("SELECT * FROM security_events WHERE category=? ORDER BY id DESC LIMIT ?",(category,int(limit)))
        return self.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?",(int(limit),))

    def upsert_incident(self, incident) -> None:
        import json
        p=incident.to_dict() if hasattr(incident,"to_dict") else dict(incident)
        self.execute(
            """INSERT INTO incidents(incident_id,created_ts,updated_ts,status,subject_key,pid,ppid,process_name,process_path,process_sha256,signature_status,signer,score,level,confidence,categories_json,reasons_json,timeline_json,recommended_actions_json,suppressed,data_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(incident_id) DO UPDATE SET
                 updated_ts=excluded.updated_ts,status=excluded.status,pid=excluded.pid,ppid=excluded.ppid,
                 process_name=excluded.process_name,process_path=excluded.process_path,process_sha256=excluded.process_sha256,
                 signature_status=excluded.signature_status,signer=excluded.signer,score=excluded.score,level=excluded.level,
                 confidence=excluded.confidence,categories_json=excluded.categories_json,reasons_json=excluded.reasons_json,
                 timeline_json=excluded.timeline_json,recommended_actions_json=excluded.recommended_actions_json,
                 suppressed=excluded.suppressed,data_json=excluded.data_json""",
            (str(p.get("incident_id") or ""),float(p.get("created_ts") or 0),float(p.get("updated_ts") or 0),str(p.get("status") or "open"),str(p.get("subject_key") or ""),p.get("pid"),p.get("ppid"),str(p.get("process_name") or ""),str(p.get("process_path") or ""),str(p.get("process_sha256") or ""),str(p.get("signature_status") or ""),str(p.get("signer") or ""),int(p.get("score") or 0),str(p.get("level") or "SAFE"),float(p.get("confidence") or 0),json.dumps(p.get("categories") or [],ensure_ascii=False),json.dumps(p.get("reasons") or [],ensure_ascii=False),json.dumps(p.get("timeline") or [],ensure_ascii=False),json.dumps(p.get("recommended_actions") or [],ensure_ascii=False),1 if p.get("suppressed") else 0,json.dumps(p.get("data") or {},ensure_ascii=False)),
        )

    def recent_incidents(self, limit=100, *, include_suppressed=True):
        if include_suppressed:
            return self.execute("SELECT * FROM incidents ORDER BY updated_ts DESC LIMIT ?",(int(limit),))
        return self.execute("SELECT * FROM incidents WHERE suppressed=0 ORDER BY updated_ts DESC LIMIT ?",(int(limit),))

    def get_incident(self, incident_id: str):
        rows=self.execute("SELECT * FROM incidents WHERE incident_id=?",(str(incident_id),))
        return rows[0] if rows else None

    def record_incident_action(self, *, incident_id: str, action: str, status: str, detail=None) -> int:
        import json
        with self._lock,self.connect() as con:
            cur=con.execute("INSERT INTO incident_actions(incident_id,action,status,detail_json) VALUES(?,?,?,?)",(str(incident_id),str(action),str(status),json.dumps(detail or {},ensure_ascii=False)))
            return int(cur.lastrowid)

    def incident_actions(self, incident_id: str, limit=100):
        return self.execute("SELECT * FROM incident_actions WHERE incident_id=? ORDER BY id DESC LIMIT ?",(str(incident_id),int(limit)))

    def record_antispyware_finding(self, assessment) -> dict:
        import json
        payload = assessment.to_dict() if hasattr(assessment, "to_dict") else dict(assessment)
        entry = payload.get("entry") or {}
        finding_id = str(entry.get("entry_id") or payload.get("finding_id") or "")
        if not finding_id:
            raise ValueError("antispyware finding_id is required")
        now = float(payload.get("observed_at") or __import__("time").time())
        exists = entry.get("target_exists")
        exists_db = None if exists is None else (1 if bool(exists) else 0)
        with self._lock, self.connect() as con:
            con.execute(
                """INSERT INTO antispyware_findings(
                     finding_id,first_seen,last_seen,kind,location,name,command,target_path,target_exists,user_writable,
                     signature_status,signer,score,level,reasons_json,evidence_json,remediation,status
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(finding_id) DO UPDATE SET
                     last_seen=excluded.last_seen,kind=excluded.kind,location=excluded.location,name=excluded.name,
                     command=excluded.command,target_path=excluded.target_path,target_exists=excluded.target_exists,
                     user_writable=excluded.user_writable,signature_status=excluded.signature_status,signer=excluded.signer,
                     score=excluded.score,level=excluded.level,reasons_json=excluded.reasons_json,
                     evidence_json=excluded.evidence_json,remediation=excluded.remediation,status='observed'""",
                (
                    finding_id, now, now, str(entry.get("kind") or "unknown"), str(entry.get("location") or ""),
                    str(entry.get("name") or ""), str(entry.get("command") or ""), str(entry.get("target_path") or ""),
                    exists_db, 1 if entry.get("user_writable") else 0, str(entry.get("signature_status") or ""),
                    str(entry.get("signer") or ""), int(payload.get("score") or 0), str(payload.get("level") or "SAFE"),
                    json.dumps(payload.get("reasons") or [], ensure_ascii=False),
                    json.dumps({
                        "confidence": float(payload.get("confidence") or 0),
                        "evidence_count": int(payload.get("evidence_count") or 0),
                        "signals": payload.get("signals") or [],
                        "metadata": entry.get("metadata") or {},
                        "automatic_destructive_action": False,
                    }, ensure_ascii=False, sort_keys=True),
                    str(payload.get("remediation") or "observe"), "observed",
                ),
            )
        rows = self.execute("SELECT * FROM antispyware_findings WHERE finding_id=?", (finding_id,))
        return dict(rows[0]) if rows else {}

    def recent_antispyware_findings(self, limit: int = 200, *, min_score: int = 0):
        limit = max(1, min(int(limit), 500))
        return self.execute(
            "SELECT * FROM antispyware_findings WHERE score>=? ORDER BY score DESC,last_seen DESC LIMIT ?",
            (max(0, min(int(min_score), 100)), limit),
        )

    def antispyware_summary(self) -> dict:
        rows = self.execute(
            "SELECT COUNT(*) AS total, SUM(CASE WHEN score>=50 THEN 1 ELSE 0 END) AS suspicious, "
            "SUM(CASE WHEN kind='wmi_subscription' THEN 1 ELSE 0 END) AS wmi, "
            "SUM(CASE WHEN kind='browser_policy' THEN 1 ELSE 0 END) AS browser_policy "
            "FROM antispyware_findings"
        )
        row = rows[0] if rows else None
        return {
            "total": int((row["total"] if row else 0) or 0),
            "suspicious": int((row["suspicious"] if row else 0) or 0),
            "wmi_subscriptions": int((row["wmi"] if row else 0) or 0),
            "browser_policies": int((row["browser_policy"] if row else 0) or 0),
        }

    def get_antispyware_finding(self, finding_id: str):
        rows = self.execute("SELECT * FROM antispyware_findings WHERE finding_id=?", (str(finding_id),))
        return rows[0] if rows else None

    def update_antispyware_finding_status(self, finding_id: str, status: str) -> bool:
        value = str(status or "observed")[:64]
        with self._lock, self.connect() as con:
            cur = con.execute(
                "UPDATE antispyware_findings SET status=?, last_seen=? WHERE finding_id=?",
                (value, __import__("time").time(), str(finding_id)),
            )
            return bool(cur.rowcount)

    def record_advanced_antimalware_finding(self, event, assessment) -> dict:
        import hashlib, json, time as _time
        payload = assessment.to_dict() if hasattr(assessment, "to_dict") else dict(assessment)
        data = dict(getattr(event, "data", {}) or {})
        raw = "|".join([
            str(getattr(event, "category", "")), str(getattr(event, "action", "")),
            str(getattr(event, "pid", "") or ""), str(getattr(event, "ppid", "") or ""),
            str(getattr(event, "process_name", "") or ""), str(data.get("cmdline") or data.get("command_line") or ""),
            ",".join(payload.get("techniques") or []),
        ]).encode("utf-8", errors="replace")
        finding_id = "BCM-" + hashlib.sha256(raw).hexdigest()[:20].upper()
        now = float(payload.get("observed_at") or _time.time())
        techniques = list(payload.get("techniques") or [])
        with self._lock, self.connect() as con:
            con.execute(
                """INSERT INTO advanced_antimalware_findings(
                     finding_id,first_seen,last_seen,category,technique,pid,ppid,process_name,process_path,cmdline,
                     score,level,confidence,reasons_json,evidence_json,status
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'observed')
                   ON CONFLICT(finding_id) DO UPDATE SET
                     last_seen=excluded.last_seen,score=excluded.score,level=excluded.level,confidence=excluded.confidence,
                     reasons_json=excluded.reasons_json,evidence_json=excluded.evidence_json,status='observed'""",
                (finding_id, now, now, str(getattr(event, "category", "") or "unknown"),
                 ",".join(techniques[:8]), getattr(event, "pid", None), getattr(event, "ppid", None),
                 str(getattr(event, "process_name", "") or ""), str(getattr(event, "process_path", "") or ""),
                 str(data.get("cmdline") or data.get("command_line") or ""), int(payload.get("score") or 0),
                 str(payload.get("level") or "SAFE"), float(payload.get("confidence") or 0),
                 json.dumps(payload.get("reasons") or [], ensure_ascii=False),
                 json.dumps({
                     "signals": payload.get("signals") or [], "techniques": techniques,
                     "evidence_families": payload.get("evidence_families") or [],
                     "qualified_high": bool(payload.get("qualified_high")),
                     "response_mode": payload.get("response_mode") or "observe",
                     "automatic_destructive_action": False,
                 }, ensure_ascii=False, sort_keys=True))
            )
        rows = self.execute("SELECT * FROM advanced_antimalware_findings WHERE finding_id=?", (finding_id,))
        return dict(rows[0]) if rows else {}

    def recent_advanced_antimalware_findings(self, limit: int = 200, *, min_score: int = 0):
        limit = max(1, min(int(limit), 500))
        return self.execute(
            "SELECT * FROM advanced_antimalware_findings WHERE score>=? ORDER BY score DESC,last_seen DESC LIMIT ?",
            (max(0, min(int(min_score), 100)), limit),
        )

    def advanced_antimalware_summary(self) -> dict:
        rows = self.execute(
            "SELECT COUNT(*) total, "
            "SUM(CASE WHEN score>=70 THEN 1 ELSE 0 END) high, "
            "SUM(CASE WHEN score>=85 THEN 1 ELSE 0 END) critical "
            "FROM advanced_antimalware_findings"
        )
        row = rows[0] if rows else None
        return {
            "total": int((row["total"] if row else 0) or 0),
            "high": int((row["high"] if row else 0) or 0),
            "critical": int((row["critical"] if row else 0) or 0),
        }

    def create_antispyware_remediation_plan(
        self, *, plan_id: str, finding_id: str, kind: str, created_at: float,
        snapshot: dict, snapshot_hmac: str,
    ) -> dict:
        import json
        now = float(created_at or __import__("time").time())
        with self._lock, self.connect() as con:
            con.execute(
                """INSERT INTO antispyware_remediation_plans(
                     plan_id,finding_id,created_at,updated_at,kind,status,snapshot_json,snapshot_hmac,result_json
                   ) VALUES(?,?,?,?,?,'planned',?,?, '{}')""",
                (
                    str(plan_id), str(finding_id), now, now, str(kind),
                    json.dumps(snapshot or {}, ensure_ascii=False, sort_keys=True), str(snapshot_hmac),
                ),
            )
        row = self.get_antispyware_remediation_plan(plan_id)
        return dict(row) if row is not None else {}

    def get_antispyware_remediation_plan(self, plan_id: str):
        rows = self.execute("SELECT * FROM antispyware_remediation_plans WHERE plan_id=?", (str(plan_id),))
        return rows[0] if rows else None

    def recent_antispyware_remediation_plans(self, limit: int = 100):
        return self.execute(
            "SELECT * FROM antispyware_remediation_plans ORDER BY updated_at DESC LIMIT ?",
            (max(1, min(int(limit), 500)),),
        )

    def update_antispyware_remediation_plan(
        self, plan_id: str, *, status: str, applied_at: float | None = None,
        restored_at: float | None = None, last_error: str = "", result: dict | None = None,
    ) -> bool:
        import json
        row = self.get_antispyware_remediation_plan(plan_id)
        if row is None:
            return False
        new_applied = float(row["applied_at"] or 0) if applied_at is None else float(applied_at or 0)
        new_restored = float(row["restored_at"] or 0) if restored_at is None else float(restored_at or 0)
        with self._lock, self.connect() as con:
            cur = con.execute(
                """UPDATE antispyware_remediation_plans
                   SET updated_at=?,status=?,applied_at=?,restored_at=?,last_error=?,result_json=?
                   WHERE plan_id=?""",
                (
                    __import__("time").time(), str(status)[:64], new_applied, new_restored,
                    str(last_error or "")[:1000], json.dumps(result or {}, ensure_ascii=False, sort_keys=True),
                    str(plan_id),
                ),
            )
            return bool(cur.rowcount)

    def antispyware_remediation_summary(self) -> dict:
        rows = self.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status='planned' THEN 1 ELSE 0 END) AS planned, "
            "SUM(CASE WHEN status='applied' THEN 1 ELSE 0 END) AS applied, "
            "SUM(CASE WHEN status='restored' THEN 1 ELSE 0 END) AS restored "
            "FROM antispyware_remediation_plans"
        )
        row = rows[0] if rows else None
        return {
            "total": int((row["total"] if row else 0) or 0),
            "planned": int((row["planned"] if row else 0) or 0),
            "applied": int((row["applied"] if row else 0) or 0),
            "restored": int((row["restored"] if row else 0) or 0),
        }

    def cleanup_detection_history(self) -> dict[str, int]:
        """Remove v0.1.x noise without deleting quarantine records.

        - removes scores below 50 from the detection list;
        - collapses duplicate hash+score rows, keeping the newest;
        - removes legacy self-project detections whose path contains BC_Sentinel/BC-Sentinel
          and are not currently quarantined.
        """
        stats = {"low_score": 0, "duplicates": 0, "legacy_self": 0}
        with self._lock, self.connect() as con:
            cur = con.execute("DELETE FROM detections WHERE score < 50")
            stats["low_score"] = cur.rowcount if cur.rowcount != -1 else 0

            # Keep newest event for each sha256 + score combination.
            cur = con.execute(
                """
                DELETE FROM detections
                 WHERE id NOT IN (
                     SELECT MAX(id)
                     FROM detections
                     WHERE sha256 IS NOT NULL AND sha256 <> ''
                     GROUP BY sha256, score
                 )
                   AND sha256 IS NOT NULL
                   AND sha256 <> ''
                """
            )
            stats["duplicates"] = cur.rowcount if cur.rowcount != -1 else 0

            cur = con.execute(
                """
                DELETE FROM detections
                 WHERE (
                       lower(path) LIKE '%bc_sentinel_v0_%'
                    OR lower(path) LIKE '%bc-sentinel%'
                 )
                   AND sha256 NOT IN (
                       SELECT sha256 FROM quarantine WHERE deleted=0 AND restored=0
                   )
                """
            )
            stats["legacy_self"] = cur.rowcount if cur.rowcount != -1 else 0
        return stats
