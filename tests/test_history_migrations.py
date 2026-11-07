import sqlite3
from pathlib import Path

import pytest

from tool.engine import analyze_file
from tool.history import (
    DB_FILE,
    MIGRATIONS,
    SCHEMA_VERSION,
    History,
    HistoryError,
    Migration,
    migrate,
)

VALIDATION = Path(__file__).parent / "fixtures" / "validation"

# The table exactly as #21 created it, before versioning existed (user_version 0).
LEGACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    file        TEXT NOT NULL,
    scan_start  TEXT,
    added_at    TEXT NOT NULL,
    status      TEXT NOT NULL,
    score       INTEGER,
    digest      TEXT NOT NULL UNIQUE,
    result_json TEXT NOT NULL
)
"""


def version_of(path: Path) -> int:
    with sqlite3.connect(path) as db:
        return db.execute("PRAGMA user_version").fetchone()[0]


def indexes_of(path: Path) -> set[str]:
    with sqlite3.connect(path) as db:
        return {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='index'")}


def test_a_fresh_database_gets_the_newest_schema(tmp_path):
    h = History(tmp_path / "data")
    h.add(analyze_file(VALIDATION / "V1_home_basic.xml", salt=b"s"))
    assert h.schema_version() == SCHEMA_VERSION == len(MIGRATIONS)
    assert "scans_order" in indexes_of(h.path)


def test_a_database_from_before_versioning_upgrades_without_losing_rows(tmp_path):
    folder = tmp_path / "data"
    folder.mkdir()
    old = History(folder)
    # Build a v0 database the way #21 did: the table, rows, no user_version.
    with sqlite3.connect(folder / DB_FILE) as db:
        db.execute(LEGACY_SCHEMA)
        db.execute(
            "INSERT INTO scans (file, scan_start, added_at, status, score, digest, result_json)"
            " VALUES ('V6a_before.xml', '2026-11-02T08:24:01Z', 'x', 'ok', 60, 'd1', '{}')"
        )
    assert version_of(folder / DB_FILE) == 0

    assert [(s.file, s.score) for s in old.scans()] == [("V6a_before.xml", 60)]
    assert version_of(folder / DB_FILE) == SCHEMA_VERSION
    assert "scans_order" in indexes_of(folder / DB_FILE)


def test_reconnecting_is_a_no_op(tmp_path):
    h = History(tmp_path / "data")
    first = h.add(analyze_file(VALIDATION / "V2_smart_home.xml", salt=b"s"))
    for _ in range(3):
        assert h.schema_version() == SCHEMA_VERSION
    assert [s.id for s in h.scans()] == [first]


def test_a_database_from_a_newer_version_is_refused_untouched(tmp_path):
    folder = tmp_path / "data"
    folder.mkdir()
    with sqlite3.connect(folder / DB_FILE) as db:
        db.execute(LEGACY_SCHEMA)
        db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    before = (folder / DB_FILE).read_bytes()
    with pytest.raises(HistoryError, match="newer version"):
        History(folder).scans()
    assert (folder / DB_FILE).read_bytes() == before
    assert version_of(folder / DB_FILE) == SCHEMA_VERSION + 1


def test_a_failing_step_rolls_back_and_leaves_the_version(tmp_path):
    db = sqlite3.connect(tmp_path / "h.sqlite3")
    steps = (
        *MIGRATIONS,
        Migration("adds a table, then fails", ("CREATE TABLE extra (x)", "THIS IS NOT SQL")),
    )
    with pytest.raises(HistoryError, match=f"step {len(steps)}"):
        migrate(db, steps)
    assert db.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "extra" not in tables  # the half-done step was rolled back
    assert "scans" in tables  # the earlier, committed steps stay


def test_steps_are_applied_in_order_and_only_once(tmp_path):
    db = sqlite3.connect(tmp_path / "h.sqlite3")
    assert migrate(db) == SCHEMA_VERSION
    later = (*MIGRATIONS, Migration("a later column", ("ALTER TABLE scans ADD COLUMN note TEXT",)))
    assert migrate(db, later) == SCHEMA_VERSION + 1
    assert migrate(db, later) == SCHEMA_VERSION + 1  # running again changes nothing
    columns = [r[1] for r in db.execute("PRAGMA table_info(scans)")]
    assert columns.count("note") == 1


def test_two_processes_racing_never_repeat_a_step(tmp_path, monkeypatch):
    # agent-D's repro on #131: process A reads the version before B migrates, then gets the
    # lock after B is done. A must notice under the lock and skip, not re-run the steps.
    import tool.history as history

    path = tmp_path / "h.sqlite3"
    steps = (*MIGRATIONS, Migration("add a column", ("ALTER TABLE scans ADD COLUMN note TEXT",)))
    a, b = sqlite3.connect(path), sqlite3.connect(path)

    real = history._user_version
    calls = {"n": 0}

    def stale_first_read(db):
        calls["n"] += 1
        if db is a and calls["n"] == 1:
            assert migrate(b, steps) == len(steps)  # B runs everything in between
            return 0  # A's first read is from before B
        return real(db)

    monkeypatch.setattr(history, "_user_version", stale_first_read)
    assert migrate(a, steps) == len(steps)
    columns = [r[1] for r in a.execute("PRAGMA table_info(scans)")]
    assert columns.count("note") == 1


def test_rollback_is_skipped_when_sqlite_already_rolled_back(tmp_path):
    db = sqlite3.connect(tmp_path / "h.sqlite3")
    # ROLLBACK inside the step ends the transaction early, as SQLite does by itself on
    # SQLITE_FULL / IOERR; the next statement then fails outside a transaction.
    steps = (*MIGRATIONS, Migration("ends early", ("ROLLBACK", "CREATE TABLE t (x)", "BOGUS")))
    with pytest.raises(HistoryError, match="BOGUS|syntax"):  # the real error, not "no transaction"
        migrate(db, steps)
