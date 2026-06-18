"""
Plugin system for artifact analyzers.

Every forensic parser (EVTX, MFT, Prefetch, Browser, Registry, Volatility …)
implements AnalyzerPlugin and registers itself here.  The orchestrator
discovers plugins via PluginRegistry — adding a new parser is a one-file
change with zero modifications to the pipeline.

Usage:
    from app.plugins.registry import PluginRegistry

    registry = PluginRegistry.default()
    artifacts = registry.run_all(raw_data)          # → list[Artifact]
"""

from __future__ import annotations
import logging
from abc import ABC, abstractmethod
from typing import Any

from app.models import Artifact, ArtifactType

logger = logging.getLogger(__name__)


# ── Base class ─────────────────────────────────────────────────────────────────

class AnalyzerPlugin(ABC):
    """
    Contract every forensic parser must satisfy.

    Implement `can_handle` to claim ownership of a data key, and `analyze`
    to convert raw rows into normalised Artifact objects.
    """

    #: Human-readable name shown in logs / UI
    name: str = "unnamed_plugin"

    #: Version stamp — recorded in Artifact.collector_version for audit trail
    version: str = "0.0.0"

    @abstractmethod
    def can_handle(self, key: str, data: Any) -> bool:
        """
        Return True if this plugin should process `data` (found under `key`
        in the structured collection dict).

        Example:
            def can_handle(self, key, data):
                return key in ("processes", "process_list") and isinstance(data, list)
        """

    @abstractmethod
    def analyze(self, key: str, data: Any) -> list[Artifact]:
        """
        Convert raw rows/objects under `key` into normalised Artifact objects.

        Rules:
          - Never raise — catch exceptions and return partial results.
          - Every returned Artifact must have `type` and `source` set.
          - `timestamp` should be ISO-8601 when available, empty string otherwise.
        """

    # Optional override — called once before a batch of analyze() calls
    def setup(self) -> None:  # noqa: B027
        pass

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} v{self.version}>"


# ── Registry ──────────────────────────────────────────────────────────────────

class PluginRegistry:
    """Discovers and dispatches to registered analyzer plugins."""

    def __init__(self) -> None:
        self._plugins: list[AnalyzerPlugin] = []

    def register(self, plugin: AnalyzerPlugin) -> "PluginRegistry":
        """Register a plugin.  Returns self for fluent chaining."""
        plugin.setup()
        self._plugins.append(plugin)
        logger.debug(f"Registered plugin: {plugin}")
        return self

    @property
    def plugins(self) -> list[AnalyzerPlugin]:
        return list(self._plugins)

    def run_all(self, structured_data: dict[str, Any]) -> list[Artifact]:
        """
        Run every registered plugin against the structured collection data.

        Each top-level key in `structured_data` is offered to all plugins;
        the first one that claims it (via `can_handle`) wins.  Keys not
        claimed by any plugin are silently skipped.

        Returns a flat list of all normalised Artifact objects.
        """
        artifacts: list[Artifact] = []
        claimed: set[str] = set()

        for key, value in structured_data.items():
            if key.startswith("_"):
                continue  # internal metadata keys
            for plugin in self._plugins:
                try:
                    if plugin.can_handle(key, value):
                        batch = plugin.analyze(key, value)
                        artifacts.extend(batch)
                        claimed.add(key)
                        logger.debug(
                            f"Plugin {plugin.name} → {len(batch)} artifacts from '{key}'"
                        )
                        break
                except Exception as exc:
                    logger.warning(
                        f"Plugin {plugin.name} failed on '{key}': {exc}", exc_info=True
                    )

        unclaimed = set(structured_data) - claimed - {k for k in structured_data if k.startswith("_")}
        if unclaimed:
            logger.debug(f"No plugin claimed keys: {unclaimed}")

        logger.info(
            f"PluginRegistry: {len(artifacts)} artifacts from "
            f"{len(claimed)}/{len(structured_data)} keys"
        )
        return artifacts

    @classmethod
    def default(cls) -> "PluginRegistry":
        """
        Build the default registry with all built-in plugins.

        Add new plugins here — one line per parser.
        """
        from app.plugins.process_plugin   import ProcessPlugin
        from app.plugins.network_plugin   import NetworkPlugin
        from app.plugins.event_plugin     import EventLogPlugin
        from app.plugins.persistence_plugin import PersistencePlugin
        from app.plugins.filesystem_plugin  import FileSystemPlugin

        registry = cls()
        registry.register(ProcessPlugin())
        registry.register(NetworkPlugin())
        registry.register(EventLogPlugin())
        registry.register(PersistencePlugin())
        registry.register(FileSystemPlugin())
        # Future: MFTPlugin, PrefetchPlugin, BrowserPlugin, RegistryPlugin, VolatilityPlugin
        return registry
