"""
detection/thresholds.py — centralised tuning constants for the detection
engine.

Magic numbers (risk score thresholds, severity->score maps, beaconing windows)
were previously inlined across detector modules, so tuning meant hunting
through several files and hoping you found them all. They now live here, in
one place, named and commented. Detectors import from here instead of
hard-coding values.

Keep this file declarative — constants and small maps only, no logic.
"""
from __future__ import annotations

# ── Risk aggregation (detection/risk_scoring.py) ────────────────────────────
# Cumulative cross-category score at which an entity (process/IP/file) earns a
# "correlated_risk" summary finding. Deliberately above any single finding's
# score so one loud signal can't trip it alone — it requires corroboration.
RISK_SCORE_THRESHOLD = 130

# Minimum number of distinct finding categories an entity must span before its
# cumulative risk is treated as corroborated.
RISK_MIN_CATEGORIES = 2

# ── Sigma finding scores (app/sigma_engine.py) ──────────────────────────────
# Sigma matches are leads, not verdicts; severity is capped at HIGH elsewhere.
SIGMA_SCORE_BY_LEVEL = {
    "critical": 70,
    "high": 60,
    "medium": 45,
    "low": 25,
}

# Sigma severity is capped so a single uncorroborated rule can't go critical.
SIGMA_SEVERITY_CAP = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}

# ── Sampling safety valves ──────────────────────────────────────────────────
# Max sample findings kept per Sigma rule (avoids one noisy rule flooding the
# report). 0 would mean unlimited; this is a UX cap, not a correctness one.
MAX_MATCHES_PER_SIGMA_RULE = 20
