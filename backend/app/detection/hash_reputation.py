"""
detection/hash_reputation.py — flag artifacts whose hashes match a local IOC
feed.

This closes the platform's biggest detection gap versus commercial tools
(Cyber Triage's ReversingLabs lookups, THOR's IOC sets): there was no way to
say "this exact file/process IS known-bad" by hash. Hash matching is the
highest-fidelity signal there is — unlike a path heuristic or a string YARA
rule, a SHA-256 match is a cryptographic identity, effectively zero false
positives.

LOCAL-FIRST by design (matching the rest of the platform): there is NO cloud
lookup here. Reputation comes from an offline IOC file the operator drops in,
so the tool stays air-gap friendly and leaks nothing. Sources that fit:
 - abuse.ch MalwareBazaar hash exports
 - a MISP instance's hash attribute export
 - a hand-maintained known-bad hash list from prior cases

IOC file format (data_dir/ioc_hashes.txt), one indicator per line:
    <hash>            # malware family / note (optional, after whitespace or comma)
    e3b0c442...855    # Emotet loader
    44d88612...example,Mimikatz
Lines starting with '#' are comments. md5 / sha1 / sha256 all supported
(detected by length). Matching is case-insensitive.

Wiring: registered as a route on hash-bearing artifacts (processes, file
listings, YARA matches). It reads whatever hash fields a row exposes and
checks them against the loaded set. If no IOC file is present, it is a silent
no-op — zero cost, no findings.
"""
from __future__ import annotations

import os
import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

# Hash field names that show up across the various artifact parsers. Matched
# case-insensitively against a row's keys.
HASH_FIELDS = (
    "md5", "sha1", "sha256", "sha-256", "sha_256",
    "hash", "filehash", "file_hash", "imphash",
)

# Hash lengths (hex chars) we recognise, to validate before lookup.
_HASH_LENS = {32, 40, 64}


@lru_cache(maxsize=1)
def _load_ioc_hashes(ioc_path: str) -> dict:
    """
    Load the offline IOC hash file into {hash_lower: note}. Cached so the file
    is read once per process, not per artifact. Returns {} when absent so the
    detector degrades to a no-op.
    """
    table: dict[str, str] = {}
    if not ioc_path or not os.path.exists(ioc_path):
        return table
    try:
        with open(ioc_path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Split hash from optional note (comma or whitespace separated).
                if "," in line:
                    h, _, note = line.partition(",")
                else:
                    parts = line.split(None, 1)
                    h = parts[0]
                    note = parts[1] if len(parts) > 1 else ""
                h = h.strip().lower()
                if len(h) in _HASH_LENS and all(c in "0123456789abcdef" for c in h):
                    table[h] = note.strip().lstrip("# ").strip()
    except Exception as e:  # pragma: no cover - defensive
        logger.debug(f"Could not read IOC hash file {ioc_path}: {e}")
    return table


def _ioc_path() -> str:
    """Resolve the IOC file path from settings/env, defaulting under data_dir."""
    # Prefer an explicit env override; else data_dir/ioc_hashes.txt.
    explicit = os.environ.get("IOC_HASH_FILE")
    if explicit:
        return explicit
    data_dir = os.environ.get("DATA_DIR", "/app/data")
    return os.path.join(data_dir, "ioc_hashes.txt")


def _row_hashes(row: dict):
    """Yield (field_name, hash_lower) for every recognised hash in the row."""
    for k, v in row.items():
        if not isinstance(v, str):
            continue
        if str(k).lower() in HASH_FIELDS:
            h = v.strip().lower()
            if len(h) in _HASH_LENS:
                yield k, h


def detect_hash_reputation(engine, key: str, rows: list[dict]) -> None:
    """
    Check each row's hashes against the local IOC feed. Emits a CRITICAL
    finding per matched hash — a hash match is identity-level evidence.
    """
    ioc = _load_ioc_hashes(_ioc_path())
    if not ioc:
        return  # no feed loaded → no-op, no cost

    seen: set[str] = set()
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        for field, h in _row_hashes(row):
            if h not in ioc or h in seen:
                continue
            seen.add(h)
            note = ioc[h] or "known-bad hash"
            # Try to name the offending object for the finding title.
            label = (row.get("Image") or row.get("Name") or row.get("Path")
                     or row.get("FileName") or row.get("file") or key)
            engine._add_finding(
                category="hash_reputation",
                severity="critical",
                title=f"Known-bad hash: {note}",
                description=(
                    f"{field}={h} matches a local IOC feed entry "
                    f"({note}). Hash matches are identity-level evidence — this "
                    f"object is the known-bad file, not merely similar to it."
                ),
                artifact=key,
                evidence={
                    "row_index": idx,
                    "hash_field": field,
                    "hash": h,
                    "ioc_note": note,
                    "object": str(label)[:200],
                    "matched_data": str(row)[:300],
                },
                score=95,
                mitre="",
            )

    if seen:
        logger.info(f"Hash reputation: {len(seen)} known-bad hash(es) in '{key}'")
