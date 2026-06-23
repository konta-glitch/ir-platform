"""
Tests for the detection engine's routing table.

The whole "add a detector = one register_route() call, touch nothing else"
design hinges on this registry being well-formed. These tests fail loudly
if a new detector is wired in wrong (e.g. registered with a non-callable,
or the package stops importing its detectors).
"""
from app.detection.base import ROUTES, ADDITIONAL_PASSES, register_route


def test_routes_are_registered():
    """Detectors are wired into the routing table on import."""
    assert len(ROUTES) > 0, "no detection routes registered — detection/__init__ broken?"


def test_every_route_maps_keywords_to_a_callable():
    """Each route is (list-of-keyword-strings, callable detector)."""
    for keywords, detector in ROUTES:
        assert isinstance(keywords, list) and keywords, f"bad keywords: {keywords!r}"
        assert all(isinstance(k, str) for k in keywords), f"non-str keyword in {keywords!r}"
        assert callable(detector), f"route {keywords!r} maps to non-callable {detector!r}"


def test_additional_passes_are_callable():
    """register_additional_pass entries are also well-formed."""
    for keywords, detector in ADDITIONAL_PASSES:
        assert isinstance(keywords, list) and keywords
        assert callable(detector)


def test_register_route_appends(monkeypatch):
    """register_route() adds to ROUTES without disturbing existing entries."""
    before = len(ROUTES)

    def _dummy(engine, key, rows):
        return None

    register_route(["__test_keyword__"], _dummy)
    try:
        assert len(ROUTES) == before + 1
        assert ROUTES[-1] == (["__test_keyword__"], _dummy)
    finally:
        # Keep global state clean for other tests.
        ROUTES.pop()
    assert len(ROUTES) == before
