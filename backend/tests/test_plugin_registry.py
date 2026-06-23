"""
Tests for the artifact-analyzer plugin registry.

Same idea as the detection registry: adding a parser should be a one-line
change in PluginRegistry.default(). These tests guard that contract — every
registered plugin must satisfy the AnalyzerPlugin interface, and the default
set must load.
"""
from app.plugins import PluginRegistry, AnalyzerPlugin


def test_default_registry_has_plugins():
    registry = PluginRegistry.default()
    assert len(registry.plugins) > 0, "default registry registered no plugins"


def test_all_default_plugins_implement_contract():
    """Every default plugin is an AnalyzerPlugin with the required methods."""
    registry = PluginRegistry.default()
    for plugin in registry.plugins:
        assert isinstance(plugin, AnalyzerPlugin)
        assert callable(getattr(plugin, "can_handle", None))
        assert callable(getattr(plugin, "analyze", None))


def test_register_returns_registry_for_chaining():
    """register() returns the registry so calls can be chained (fluent API)."""
    registry = PluginRegistry()
    result = registry.register(_NoopPlugin())
    assert result is registry
    assert len(registry.plugins) == 1


class _NoopPlugin(AnalyzerPlugin):
    """Minimal plugin used only to exercise registration."""

    def can_handle(self, raw):  # noqa: D102
        return False

    def analyze(self, raw):  # noqa: D102
        return []
