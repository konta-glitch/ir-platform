"""
Tests that importing app modules has no filesystem side effects.

Regression test for the CI failures where `import app.main` raised
PermissionError / FileNotFoundError: several components created directories or
opened files at IMPORT time (module-level singletons), which works inside the
Docker container but fails on a bare CI runner (no /app, no root write).

Covered:
  - AuditLogger: directory created lazily on first record(), not at __init__.
  - Database: falls back to in-memory when the data dir can't be created.
  - ImageAnalyzer: tolerates an uncreatable images dir.
Construction must never raise just because the filesystem isn't writable.
"""
from pathlib import Path

from app.structured_logging import AuditLogger


def test_audit_construction_does_not_create_directory(tmp_path):
    target = tmp_path / "newdir" / "audit.jsonl"
    AuditLogger(target)
    assert not target.parent.exists()  # side-effect-free construction


def test_audit_directory_created_lazily_on_first_record(tmp_path):
    target = tmp_path / "newdir" / "audit.jsonl"
    a = AuditLogger(target)
    rid = a.record("test_event", foo="bar")
    assert rid
    assert target.parent.exists()
    assert target.exists()


def test_audit_unwritable_path_degrades_gracefully():
    a = AuditLogger(Path("/nonexistent_root_xyz123/data/audit.jsonl"))
    assert a.record("test_event", foo="bar")  # must not raise


def test_database_falls_back_to_memory_when_dir_unavailable():
    """Database init on an uncreatable path uses in-memory instead of raising."""
    from app.database import Database
    d = Database(Path("/nonexistent_root_xyz123/data/ir.db"))
    assert d._conn is not None
    cur = d._conn.execute("SELECT 1")
    assert cur.fetchone()[0] == 1


def test_importing_app_modules_does_not_raise():
    """The original CI failure: importing these must not touch /app."""
    import importlib
    for mod in ("app.structured_logging", "app.database", "app.image_analyzer"):
        importlib.import_module(mod)
