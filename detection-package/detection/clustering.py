"""
detection/clustering.py — group findings that belong to the same installed
tool/entity, even when split across different artifacts or subfolders.

Used by build_llm_context (in detection/__init__.py) to give the LLM an
explicit "these findings are one entity" signal — without it, a multi-file
tool installation (e.g. a JWrapper-packaged remote-access tool with 4
separate binaries) shows up as N isolated low-confidence findings instead
of one coherent signal. Confirmed in production: Mixtral-8x7B needed this
explicit grouping to connect findings that were individually low-signal but
collectively a clear installation.
"""

from __future__ import annotations
import re
from collections import defaultdict

def _extract_tool_name_token(path: str) -> str | None:
    """
    Extract a likely "tool/product name" token from a file path, for
    clustering findings that belong to the same installed application even
    when they live in DIFFERENT subfolders of that installation.

    Real-world gap this addresses: a JWrapper-packaged remote-access tool's
    components were observed split across two different parent folders —
    'JWrapper-Remote Access bundle-00118607124\\...-complete\\elev_win.exe'
    and 'JWrapper-Remote Access\\JWAppsSharedConfig\\restricted\\
    SimpleService.exe' — both clearly part of the same tool, but
    _cluster_findings_by_folder (exact-parent-folder matching) doesn't
    connect them since their immediate parent folders differ. This looks
    for a shared significant token instead.

    Heuristic: take path segments, keep ones that look like a
    product/vendor name (3+ alpha chars, not a generic Windows folder),
    return the first one found. Deliberately conservative — generic
    folder names (programdata, users, appdata, temp, etc.) are excluded so
    this doesn't cluster unrelated findings that merely share a common
    Windows directory.
    """
    GENERIC_SEGMENTS = {
        "programdata", "users", "appdata", "local", "roaming", "temp",
        "windows", "systemv", "syswowv", "program files",
        "program filesv", "public", "device", "harddiskvolume",
    }
    segments = [s.strip() for s in str(path).replace("/", "\\").split("\\") if s.strip()]
    for seg in segments:
        seg_lower = seg.lower()
        # Strip common bundle/version suffixes so e.g. "jwrapper-remote
        # access bundle-00118607124" and "jwrapper-remote access" both
        # reduce to a comparable token.
        normalized = re.sub(r"[-_]?(bundle|v\d+(\.\d+)*|version)[-_]?[\w.]*", "", seg_lower)
        normalized = re.sub(r"[^a-z]", "", normalized)  # letters only for comparison
        # Check the allowlist AFTER normalization — normalization strips
        # trailing digits (e.g. "harddiskvolume3" -> "harddiskvolume",
        # "system32" -> "system"), so the allowlist must match the
        # normalized form, not the raw segment, or generic Windows path
        # components leak through as false "tool name" tokens.
        if len(normalized) >= 5 and normalized not in GENERIC_SEGMENTS:
            # Skip pure-filename-looking segments (the last segment is
            # usually the file itself, e.g. "simpleservice.exe" — we want
            # directory-level product names, not the binary name, since
            # binary names are often generic (service.exe, monitor.exe).
            if seg == segments[-1]:
                continue
            return normalized
    return None


def _cluster_findings_by_folder(findings: list[dict]) -> list[dict]:
    """
    Detect groups of findings whose evidence paths share a common parent
    folder OR a common tool-name token — e.g. multiple binaries from the
    same install bundle (elev_win.exe, session_win.exe, SimpleService.exe
    all related to 'JWrapper-Remote Access', even when split across
    different subfolders of that installation).

    Without this, each binary shows up as an isolated "rare executable"
    finding and an LLM reviewing a flat list has no structural cue that
    they're part of ONE installation — it's left to infer that from reading
    near-identical long paths, which smaller/weaker local models routinely
    miss (confirmed: Mixtral-8x7B treated 4 same-folder JWrapper findings as
    unrelated noise rather than one coherent persistence-tool installation,
    and separately failed to connect a same-tool finding that lived in a
    sibling subfolder rather than the exact same folder).

    Returns a list of {"folder": str, "finding_ids": [...], "count": int}
    for any folder/token shared by 2+ findings, sorted by count descending.
    """
    from collections import defaultdict

    folder_groups: dict = defaultdict(list)
    token_groups: dict = defaultdict(list)

    for f in findings:
        ev = f.get("evidence", {})
        path = ev.get("path") or ev.get("locator") or ""
        if not path or "\\" not in str(path):
            continue

        # Pass 1: exact parent folder (original behavior)
        parent = str(path).rsplit("\\", 1)[0]
        if len(parent) >= 15:
            folder_groups[parent].append(f["id"])

        # Pass 2: shared tool-name token across different subfolders
        token = _extract_tool_name_token(path)
        if token:
            token_groups[token].append(f["id"])

    clusters = [
        {"folder": folder, "finding_ids": ids, "count": len(ids)}
        for folder, ids in folder_groups.items()
        if len(ids) >= 2
    ]

    # Token-based clusters only add value when they connect findings NOT
    # already grouped together by exact folder — otherwise every folder
    # cluster would also show up as a redundant token cluster (since
    # findings in the same folder obviously also share a tool-name token).
    already_grouped: set = set()
    for c in clusters:
        if len(c["finding_ids"]) >= 2:
            already_grouped.update(c["finding_ids"])

    for token, ids in token_groups.items():
        unique_ids = set(ids)
        if len(unique_ids) >= 2 and not unique_ids.issubset(already_grouped):
            clusters.append({
                "folder": f"(tool: {token})",
                "finding_ids": sorted(unique_ids),
                "count": len(unique_ids),
            })

    clusters.sort(key=lambda c: -c["count"])
    return clusters



