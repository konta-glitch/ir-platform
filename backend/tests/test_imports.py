"""
Smoke tests: every backend module must import cleanly.

These catch the most common regression when the codebase grows — a syntax
error, a bad import, or a circular dependency introduced in one module that
silently breaks startup. They need no fixtures and no running services.
"""
import importlib
import pkgutil

import pytest

import app


def _all_submodules(package):
    """Yield the dotted names of every module under a package, recursively."""
    for info in pkgutil.walk_packages(package.__path__, prefix=package.__name__ + "."):
        yield info.name


@pytest.mark.parametrize("module_name", sorted(_all_submodules(app)))
def test_module_imports(module_name):
    """Each module under app/ imports without raising."""
    importlib.import_module(module_name)


def test_core_public_api_importable():
    """The handful of symbols other modules depend on are re-exported."""
    from app.detection import DetectionEngine, ENGINE_VERSION, build_llm_context

    assert DetectionEngine is not None
    assert isinstance(ENGINE_VERSION, str) and ENGINE_VERSION
    assert callable(build_llm_context)


def test_backward_compat_shim_still_works():
    """Old import path `from app.detection_engine import ...` must keep working."""
    from app.detection_engine import DetectionEngine, ENGINE_VERSION, build_llm_context

    assert DetectionEngine is not None
    assert callable(build_llm_context)
