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


def _finding_entities(f: dict) -> set[str]:
    """Pull the concrete entities a finding touches — process name, IP, user,
    file — so two findings about the same artefact can be linked even when they
    sit in different folders or have different MITRE ids. Best-effort over the
    fields detections actually carry."""
    ents: set[str] = set()
    ev = f.get("evidence", {}) or {}
    for key in ("process", "process_name", "image", "user", "username",
                "src_ip", "dst_ip", "ip", "remote_ip", "hash", "sha256", "md5"):
        v = ev.get(key)
        if v and isinstance(v, str) and len(v) >= 3:
            ents.add(f"{key}:{v.lower()}")
    # The executable/file name out of a path is a strong linker.
    path = ev.get("path") or ev.get("locator") or ""
    if path and "\\" in str(path):
        ents.add("file:" + str(path).rsplit("\\", 1)[-1].lower())
    return ents


def group_findings_for_narrative(findings: list[dict],
                                 batch_size: int) -> list[list[dict]]:
    """
    Build narrative batches that keep RELATED findings together instead of
    slicing the flat list every `batch_size` items.

    Findings are linked when they share any of:
      - a folder / tool-name cluster (multi-file installs),
      - a MITRE technique (the same attack step),
      - a concrete entity (process, IP, user, file).

    Linked findings form connected components (union-find); each component is
    one coherent piece of the story. Components are then packed into batches no
    larger than `batch_size`, keeping a component whole whenever it fits. A
    component bigger than `batch_size` is split (rare; only huge installs), but
    its pieces stay adjacent so the per-batch cluster hints still connect them.

    Falls back to the naive fixed-size slicing if there's nothing to group.
    """
    if not findings:
        return []

    idx = {f["id"]: i for i, f in enumerate(findings)}
    parent = list(range(len(findings)))

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    # 1) folder / tool clusters
    for cluster in _cluster_findings_by_folder(findings):
        ids = [idx[i] for i in cluster["finding_ids"] if i in idx]
        for k in range(1, len(ids)):
            union(ids[0], ids[k])

    # 2) shared MITRE technique
    by_mitre: dict = {}
    by_entity: dict = {}
    for f in findings:
        i = idx[f["id"]]
        mitre = f.get("mitre")
        if mitre and mitre != "N/A":
            by_mitre.setdefault(mitre, []).append(i)
        for ent in _finding_entities(f):
            by_entity.setdefault(ent, []).append(i)

    for group in list(by_mitre.values()) + list(by_entity.values()):
        for k in range(1, len(group)):
            union(group[0], group[k])

    # Collect components, preserving each finding's original order within.
    components: dict = {}
    for i, f in enumerate(findings):
        components.setdefault(find(i), []).append(f)

    # Order components by severity weight (critical first) then size, so the
    # most important story leads and isn't buried in a late batch.
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    def comp_key(comp):
        best = min((sev_rank.get(str(x.get("severity", "")).lower(), 5) for x in comp), default=5)
        return (best, -len(comp))
    ordered = sorted(components.values(), key=comp_key)

    # Pack components into batches without exceeding batch_size. A component
    # larger than batch_size is chunked, but its chunks stay consecutive.
    batches: list[list[dict]] = []
    current: list[dict] = []
    for comp in ordered:
        if len(comp) > batch_size:
            if current:
                batches.append(current); current = []
            for j in range(0, len(comp), batch_size):
                batches.append(comp[j:j + batch_size])
            continue
        if len(current) + len(comp) > batch_size:
            batches.append(current); current = []
        current.extend(comp)
    if current:
        batches.append(current)

    return batches or [findings[i:i + batch_size]
                       for i in range(0, len(findings), batch_size)]



