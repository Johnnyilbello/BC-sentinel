from __future__ import annotations

import sqlite3

import pytest

from sentinel.edr import EdrTelemetryStore


def test_edr_connection_context_closes_handle_on_exit(tmp_path):
    store = EdrTelemetryStore(tmp_path / "edr.sqlite3")
    with store._connect() as con:
        assert con.execute("SELECT 1").fetchone()[0] == 1

    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        con.execute("SELECT 1")


def test_edr_database_file_can_be_removed_after_operations(tmp_path):
    db = tmp_path / "removable.sqlite3"
    store = EdrTelemetryStore(db)
    store.query_events(limit=10)
    store.stats()

    db.unlink()
    assert not db.exists()
