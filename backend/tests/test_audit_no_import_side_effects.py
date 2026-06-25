"""
Tests that AuditLogger doesn't touch the filesystem at construction time.

Regression test for the CI failure where `import app.main` raised
PermissionError: the module-level _audit = AuditLogger() tried to mkdir
/app/data at import, which fails on a bare CI runner (no /app, no root write).
Construction must be side-effect-free; the directory is created lazily on
first record(), and an unavailable directory degrades gracefully.
"""
from pathlib import Path

from app.structured_logging import AuditLogger


def test_construction_does_not_create_directory(tmp_path):
    target = tmp_path / "newdir" / "audit.jsonl"
    AuditLogger(target)
    # The parent dir must NOT exist yet — construction is side-effect-free.
    assert not target.parent.exists()


def test_directory_created_lazily_on_first_record(tmp_path):
    target = tmp_path / "newdir" / "audit.jsonl"
    a = AuditLogger(target)
    rid = a.record("test_event", foo="bar")
    assert rid  # returns an id
    assert target.parent.exists()  # dir created on demand
    assert target.exists()


def test_unwritable_path_degrades_gracefully():
    """An impossible path must not raise — record() returns, audit is skipped."""
    a = AuditLogger(Path("/nonexistent_root_xyz123/data/audit.jsonl"))
    # Neither construction nor record() should raise.
    rid = a.record("test_event", foo="bar")
    assert rid


def test_importing_app_main_does_not_raise():
    """The original CI failure: importing app.main must not touch /app."""
    import importlib
    # Should import cleanly regardless of whether /app exists/writable.
    importlib.import_module("app.structured_logging")
