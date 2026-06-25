"""
Tests for the hash/IOC reputation detector.

Cover: no-op when no feed is present, a clean match against a local feed,
hash-length validation, and de-duplication. Uses a tmp IOC file and points
the detector at it via the IOC_HASH_FILE env var.
"""
import os

import pytest

from app.detection import hash_reputation as hr


class _FakeEngine:
    """Minimal stand-in capturing _add_finding calls."""
    def __init__(self):
        self.findings = []

    def _add_finding(self, **kw):
        self.findings.append(kw)


@pytest.fixture(autouse=True)
def _clear_cache():
    # The IOC loader is lru_cached on path; clear between tests so each test's
    # tmp file is read fresh.
    hr._load_ioc_hashes.cache_clear()
    yield
    hr._load_ioc_hashes.cache_clear()


def test_no_feed_is_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("IOC_HASH_FILE", str(tmp_path / "does_not_exist.txt"))
    engine = _FakeEngine()
    hr.detect_hash_reputation(engine, "pslist", [{"sha256": "a" * 64}])
    assert engine.findings == []


def test_matches_known_bad_hash(tmp_path, monkeypatch):
    bad = "44d88612fea8a8f36de82e1278abb02f"  # 32-char md5
    feed = tmp_path / "ioc_hashes.txt"
    feed.write_text(f"# test feed\n{bad},Mimikatz\n")
    monkeypatch.setenv("IOC_HASH_FILE", str(feed))

    engine = _FakeEngine()
    hr.detect_hash_reputation(
        engine, "pslist",
        [{"Name": "evil.exe", "md5": bad.upper()}],  # upper to test case-insensitivity
    )
    assert len(engine.findings) == 1
    f = engine.findings[0]
    assert f["severity"] == "critical"
    assert f["category"] == "hash_reputation"
    assert "Mimikatz" in f["title"]
    assert f["evidence"]["hash"] == bad


def test_ignores_non_matching_and_malformed(tmp_path, monkeypatch):
    bad = "e" * 64
    feed = tmp_path / "ioc_hashes.txt"
    feed.write_text(f"{bad} Emotet\n")
    monkeypatch.setenv("IOC_HASH_FILE", str(feed))

    engine = _FakeEngine()
    hr.detect_hash_reputation(engine, "pslist", [
        {"sha256": "f" * 64},     # valid length, not in feed
        {"sha256": "tooshort"},   # malformed → ignored
        {"Name": "x"},            # no hash field
    ])
    assert engine.findings == []


def test_dedupes_repeated_hash(tmp_path, monkeypatch):
    bad = "a" * 64
    feed = tmp_path / "ioc_hashes.txt"
    feed.write_text(f"{bad},Dridex\n")
    monkeypatch.setenv("IOC_HASH_FILE", str(feed))

    engine = _FakeEngine()
    hr.detect_hash_reputation(engine, "pslist", [
        {"sha256": bad}, {"sha256": bad}, {"sha256": bad},
    ])
    # Same hash three times → one finding.
    assert len(engine.findings) == 1


def test_detector_is_registered():
    """The detector is wired into the engine's additional passes."""
    from app.detection.base import ADDITIONAL_PASSES
    fns = [fn.__name__ for _, fn in ADDITIONAL_PASSES]
    assert "detect_hash_reputation" in fns
