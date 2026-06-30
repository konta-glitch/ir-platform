"""
evidence_format.py — turn a finding's raw evidence dict into something an
analyst can read at a glance, and explain why the finding matters.

Two deterministic helpers (no LLM call, so they run for every finding):

  why_it_matters(finding)  -> one-sentence "so what" based on category/MITRE
  evidence_fields(finding) -> ordered [(label, value, is_raw)] for display,
                              pulling out the useful fields (path, command line,
                              registry key, matched strings, …) instead of only
                              the locator string.

Both the HTML and Markdown reports use these so the two stay consistent.
"""
from __future__ import annotations

# ── "Why it matters" by category ──────────────────────────────────────────
# Keyed by the finding's category; the first matching substring wins so we can
# be coarse ("malware") or specific ("malware_signature"). Phrased for an
# analyst triaging: what the detection implies and what it does NOT prove.
_CATEGORY_WHY = {
    "malware_signature": "A known-bad byte pattern was found inside the file "
        "itself — independent of where it sits or how it was launched. This is "
        "high-confidence: the file's content matched a malware rule.",
    "malware": "Content or behaviour matched a known malware indicator. Treat "
        "the file as suspect until a hash or sandbox check clears it.",
    "hash_reputation": "The file's hash matched a reputation list. The verdict "
        "is only as current as that list — re-check against live threat intel.",
    "correlated_risk": "The same entity tripped several independent detections. "
        "One alert can be noise; multiple categories on one process is the "
        "signal that something is genuinely off.",
    "process_anomaly": "A process behaved unusually for this host — unexpected "
        "location, parent, or arguments. Often the first visible sign of "
        "execution, but legitimate software can look the same, so corroborate.",
    "process_name": "A process name matched a watch pattern (RMM tool, known "
        "abuse). Legitimate use is common, so confirm whether it belongs here.",
    "persistence": "This is a mechanism that survives reboots (service, "
        "scheduled task, run key). Persistence is rarely accidental — it's how "
        "an attacker keeps access, so verify who created it and when.",
    "credential_access": "Activity consistent with reading or harvesting "
        "credentials. If unexpected, this is a priority — stolen credentials "
        "enable lateral movement and are hard to walk back.",
    "defense_evasion": "Activity that hides or disables defences (clearing "
        "logs, changing security settings, obfuscation). Attackers cover "
        "tracks; benign admin work can too, so check who and why.",
    "network_anomaly": "An unusual network connection or destination. Worth "
        "correlating with the process that opened it and known-bad IOCs.",
    "network": "Network activity flagged by the detection engine. Pair it with "
        "the owning process and timeline to judge intent.",
    "execution_evidence": "Artefacts (Prefetch/Amcache) showing a binary ran on "
        "this host — useful for proving execution even if the file is gone.",
    "execution": "Evidence of code execution. On its own it's expected on any "
        "live host; what matters is WHAT ran and whether it belongs.",
    "discovery": "Reconnaissance-style activity (enumerating files, processes, "
        "or users). Low-fidelity alone, but a common early attack phase when "
        "it clusters with other findings.",
    "sigma_detection": "A Sigma rule matched a log event. Sigma is broad by "
        "design — a lead to confirm against the raw event, not a verdict.",
    "suspicious_file": "A file in an unusual or user-writable location that's "
        "statistically rare for this host. Rare isn't malicious, but it's where "
        "staged payloads tend to hide.",
    "suspicious": "Flagged as suspicious by a heuristic. Calibrate against the "
        "evidence below before acting.",
    "anomaly": "Statistically unusual for this host. Rarity raises a flag; "
        "context decides whether it's a threat.",
}

_DEFAULT_WHY = ("Flagged by the detection engine. Review the evidence below to "
                "decide whether it reflects attacker activity or benign use.")


def why_it_matters(finding: dict) -> str:
    """One-sentence 'so what' for a finding, from its category."""
    cat = (finding.get("category") or "").lower()
    for key, text in _CATEGORY_WHY.items():
        if key in cat:
            return text
    return _DEFAULT_WHY


# ── Evidence field extraction ─────────────────────────────────────────────
# Raw evidence keys we know how to label, in the order we want to show them.
# Anything not listed is still shown (so we never hide data) but after these.
_FIELD_LABELS = [
    ("path", "Path"),
    ("source_file", "Source file"),
    ("name", "Name"),
    ("process", "Process"),
    ("image", "Image path"),
    ("command_line", "Command line"),
    ("args", "Arguments"),
    ("parent", "Parent process"),
    ("user", "User"),
    ("key", "Registry key"),
    ("value", "Value"),
    ("target", "Target"),
    ("domain", "Domain"),
    ("dest_ip", "Destination IP"),
    ("qtype", "DNS query type"),
    ("rule", "Matched rule"),
    ("event_id", "Event ID"),
    ("last_modified", "Last modified"),
    ("last_accessed", "Last accessed"),
    ("timestamp", "Timestamp"),
    ("row_index", "Row"),
]

# Keys we never surface as fields (internal / shown elsewhere / too noisy).
_SKIP = {"locator", "significance"}

# Keys whose values are long/binary and should be marked is_raw=True so the UI
# can put them behind a "show raw" toggle and the Markdown can fence them.
_RAW_KEYS = {"matched_strings", "raw", "raw_row", "hexdump"}


def evidence_fields(finding: dict) -> list[tuple[str, str, bool]]:
    """Return ordered (label, value, is_raw) tuples for a finding's evidence.

    Pulls out the meaningful fields (not just the path) and keeps long/binary
    values (matched_strings) flagged so the caller can collapse them.
    """
    ev = finding.get("evidence") or {}
    if not isinstance(ev, dict):
        return [("Evidence", str(ev), False)]

    out: list[tuple[str, str, bool]] = []
    seen: set[str] = set()

    # Known fields first, in defined order.
    for key, label in _FIELD_LABELS:
        if key in ev and key not in _SKIP:
            val = ev[key]
            if val in (None, "", []):
                continue
            out.append((label, _stringify(val), False))
            seen.add(key)

    # Raw/long fields, flagged.
    for key in _RAW_KEYS:
        if key in ev and ev[key] not in (None, "", []):
            out.append((_pretty_key(key), _stringify(ev[key]), True))
            seen.add(key)

    # Anything else we didn't anticipate — show it rather than drop it.
    for key, val in ev.items():
        if key in seen or key in _SKIP or val in (None, "", []):
            continue
        is_raw = len(str(val)) > 160
        out.append((_pretty_key(key), _stringify(val), is_raw))

    return out


def _stringify(val) -> str:
    if isinstance(val, (list, tuple)):
        return ", ".join(str(v) for v in val)
    if isinstance(val, dict):
        return ", ".join(f"{k}={v}" for k, v in val.items())
    return str(val)


def _pretty_key(key: str) -> str:
    return key.replace("_", " ").capitalize()
