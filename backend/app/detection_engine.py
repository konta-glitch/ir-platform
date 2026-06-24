"""
app/detection_engine.py — backward-compatibility shim.

The detection engine was restructured from a single 1574-line file into
the app/detection/ package (one module per logical concern — processes,
network, eventlogs, defender, persistence, execution evidence, file
anomalies, DNS/DGA, auth patterns, behavior correlation, clustering).

This file exists only so old import paths keep working:
    from app.detection_engine import DetectionEngine, build_llm_context, ENGINE_VERSION

New code should import from app.detection directly:
    from app.detection import DetectionEngine, build_llm_context, ENGINE_VERSION

See app/detection/__init__.py for the actual package structure and the
route registration table.
"""

from app.detection import DetectionEngine, ENGINE_VERSION, build_llm_context
from app.detection.clustering import _cluster_findings_by_folder, _extract_tool_name_token

__all__ = [
    "DetectionEngine", "ENGINE_VERSION", "build_llm_context",
    "_cluster_findings_by_folder", "_extract_tool_name_token",
]
