"""
Correlation Engine — second-pass analysis that runs AFTER detection.

Where the detection engine looks at individual rows, the correlation engine
looks at relationships ACROSS the whole dataset:

  1. Timeline correlation — orders all timestamped events and findings,
     then surfaces tight clusters (e.g. logon → service install → C2 within
     minutes) that indicate a coordinated attack sequence.

  2. Process tree reconstruction — links PID/PPID across the entire process
     listing into ancestry chains, surfacing suspicious lineage like
     winword → powershell → rundll32 → cmd.

  3. Frequency analysis (stack counting) — the core threat-hunting technique:
     rare is suspicious. Counts occurrences of process names, paths, hashes,
     and command lines; flags statistical outliers that no single rule catches.

  + Allowlist filter — suppresses known-good signed Microsoft binaries from
    System32 to cut false-positive noise.
"""

import re
import logging
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


# Known-good system binaries that run from System32 — suppress as noise
# UNLESS they show suspicious args (handled separately by detection engine).
ALLOWLIST_PATHS = [
    r"c:\\windows\\system32\\",
    r"c:\\windows\\syswow64\\",
    r"c:\\windows\\winsxs\\",
    r"c:\\program files\\windows defender\\",
    r"c:\\program files\\common files\\microsoft shared\\",
]

# These names are benign ONLY from the expected path
KNOWN_GOOD_SYSTEM = {
    "svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "winlogon.exe",
    "wininit.exe", "smss.exe", "spoolsv.exe", "taskhostw.exe", "dwm.exe",
    "explorer.exe", "rundll32.exe", "conhost.exe", "fontdrvhost.exe",
    "sihost.exe", "ctfmon.exe", "searchindexer.exe", "runtimebroker.exe",
}

# Timestamp field name variations across artifacts
TIMESTAMP_FIELDS = [
    "TimeCreated", "timestamp", "Timestamp", "time", "Time",
    "CreateTime", "create_time", "creation_time", "CreationDate",
    "last_run", "LastRunTimes", "EventTime", "@timestamp",
    "Mtime", "modified", "last_execution",
]

# Timestamp parsing patterns
TS_PATTERNS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%m/%d/%Y %H:%M:%S",
]


def _parse_timestamp(value: Any) -> datetime | None:
    """Best-effort timestamp parsing."""
    if not value:
        return None
    s = str(value).strip()
    # Strip timezone colon for %z compatibility (2026-01-01T10:00:00+00:00)
    s_clean = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", s)
    for pattern in TS_PATTERNS:
        for candidate in (s, s_clean):
            try:
                dt = datetime.strptime(candidate, pattern)
                # Normalize to naive UTC for comparison
                if dt.tzinfo:
                    dt = dt.replace(tzinfo=None)
                return dt
            except (ValueError, TypeError):
                continue
    # Try ISO format fallback
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


def _get(d: dict, keys: list[str], default: str = "") -> str:
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d and d[k] is not None:
            return str(d[k])
    return default


class CorrelationEngine:
    """Cross-dataset correlation: timeline, process tree, frequency analysis."""

    def correlate(self, data: dict, findings: list[dict]) -> dict:
        """
        Run all correlation analyses.

        Returns a dict with:
            - timeline: ordered events with cluster annotations
            - timeline_clusters: tight bursts of activity
            - process_trees: reconstructed ancestry chains
            - suspicious_chains: process trees matching attack patterns
            - frequency_outliers: rare items worth investigating
            - new_findings: additional findings from correlation
        """
        result = {
            "timeline": [],
            "timeline_clusters": [],
            "process_trees": [],
            "suspicious_chains": [],
            "frequency_outliers": [],
            "new_findings": [],
            "allowlist_suppressed": 0,
        }

        try:
            result.update(self._build_timeline(data, findings))
        except Exception as e:
            logger.warning(f"Timeline correlation failed: {e}")

        try:
            result.update(self._build_process_trees(data))
        except Exception as e:
            logger.warning(f"Process tree reconstruction failed: {e}")

        try:
            result.update(self._frequency_analysis(data))
        except Exception as e:
            logger.warning(f"Frequency analysis failed: {e}")

        try:
            result["entity_graph"] = self._build_entity_graph(data, findings)
        except Exception as e:
            logger.warning(f"Entity graph build failed: {e}")
            result["entity_graph"] = {"nodes": [], "edges": []}

        return result

    def _build_entity_graph(self, data: dict, findings: list[dict]) -> dict:
        """
        Build a connectivity graph linking the entities seen in the case:
        processes, IP addresses, users, and files. Edges encode real
        relationships from the data (parent→child process, process→connection,
        user→process, finding→entity), so an analyst can see how the pieces
        relate instead of reading a flat list.

        Returns {"nodes": [...], "edges": [...]} ready for the frontend graph.
        Nodes are capped so the graph stays readable on large collections;
        entities tied to findings are always kept.
        """
        nodes: dict[str, dict] = {}
        edges: list[dict] = []

        def add_node(node_id: str, label: str, ntype: str, **extra):
            if not node_id:
                return None
            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id, "label": label[:60], "type": ntype,
                    "finding_count": 0, **extra,
                }
            return nodes[node_id]

        def add_edge(src: str, dst: str, rel: str):
            if src and dst and src != dst:
                edges.append({"source": src, "target": dst, "rel": rel})

        # ── Processes + parent/child edges ──
        procs = {}
        for key, rows in data.items():
            if key.startswith("_") or not isinstance(rows, list):
                continue
            if not any(t in key.lower() for t in ["pslist", "process", "pstree"]):
                continue
            for idx, row in enumerate(rows):
                if not isinstance(row, dict):
                    continue
                pid = _get(row, ["Pid", "pid", "ProcessId", "PID"])
                ppid = _get(row, ["Ppid", "ppid", "ParentProcessId", "PPID"])
                name = _get(row, ["Name", "name", "Image", "Exe"])
                user = _get(row, ["User", "Username", "user", "Owner", "SID"])
                if not pid:
                    continue
                pid = str(pid)
                pname = name.split("\\")[-1] if name else f"pid:{pid}"
                procs[pid] = {"name": pname, "ppid": str(ppid) if ppid else "",
                              "user": user}
                add_node(f"proc:{pid}", f"{pname} ({pid})", "process",
                         pid=pid, full_name=name)
                if user:
                    add_node(f"user:{user}", user, "user")
                    add_edge(f"user:{user}", f"proc:{pid}", "ran")

        # Parent → child edges
        for pid, info in procs.items():
            ppid = info["ppid"]
            if ppid and ppid in procs:
                add_edge(f"proc:{ppid}", f"proc:{pid}", "spawned")

        # ── Network connections: process → IP / domain ──
        ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        for key, rows in data.items():
            if key.startswith("_") or not isinstance(rows, list):
                continue
            if not any(t in key.lower() for t in ["netstat", "network", "conn", "dns"]):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                raddr = _get(row, ["Raddr", "RemoteAddress", "remote", "ForeignAddress", "DestAddr"])
                domain = _get(row, ["domain", "Domain", "QueryName", "query", "hostname"])
                pid = _get(row, ["Pid", "pid", "ProcessId", "PID"])

                m = ip_re.search(str(raddr))
                if m:
                    ip = m.group(1)
                    if not ip.startswith(("127.", "0.", "::")):
                        add_node(f"ip:{ip}", ip, "ip")
                        if pid and f"proc:{str(pid)}" in nodes:
                            add_edge(f"proc:{str(pid)}", f"ip:{ip}", "connected")

                # NEW: domain nodes — DNS queries / domain fields previously
                # had no representation in the graph at all, so "what domain
                # did this process resolve" was unanswerable from the graph.
                if domain and domain.lower() not in ("localhost", ""):
                    dnode = f"domain:{domain.lower()}"
                    add_node(dnode, domain.lower(), "domain")
                    if pid and f"proc:{str(pid)}" in nodes:
                        add_edge(f"proc:{str(pid)}", dnode, "resolved")

        # ── NEW: Persistence entities — registry run keys, scheduled tasks,
        #    services. Previously these only existed as text in findings;
        #    they had no graph representation at all, so "what process
        #    created this persistence mechanism" was unanswerable from the
        #    graph even though the underlying data usually has a PID/process
        #    name attached. This closes that gap. ──
        for key, rows in data.items():
            if key.startswith("_") or not isinstance(rows, list):
                continue
            key_lower = key.lower()
            is_registry = any(t in key_lower for t in ["registry", "run", "autorun", "startup"])
            is_task = any(t in key_lower for t in ["scheduledtask", "task"]) and "process" not in key_lower
            is_service = "service" in key_lower
            if not (is_registry or is_task or is_service):
                continue

            ptype = "registry_key" if is_registry else "task" if is_task else "service"
            for row in rows:
                if not isinstance(row, dict):
                    continue
                # Persistence entries vary widely in field naming across
                # collectors; try the common ones for each kind.
                if is_registry:
                    ident = _get(row, ["Key", "KeyPath", "path", "Path", "Name", "name"])
                elif is_task:
                    ident = _get(row, ["Name", "name", "TaskName", "Path"])
                else:
                    ident = _get(row, ["Name", "name", "DisplayName", "ServiceName"])
                if not ident:
                    continue

                label = ident.split("\\")[-1][:50]
                pnode = f"{ptype}:{label}"
                add_node(pnode, label, ptype)

                # Link to the creating/owning process when the row carries
                # a PID or executable path that matches a known process node.
                pid = _get(row, ["Pid", "pid", "ProcessId", "PID"])
                if pid and f"proc:{str(pid)}" in nodes:
                    add_edge(f"proc:{str(pid)}", pnode, "created")
                else:
                    # Fall back to matching by binary path referenced in the
                    # persistence entry (common for registry Run keys and
                    # service ImagePath, which name an exe but rarely a PID).
                    exe_ref = _get(row, ["Value", "ImagePath", "Command", "Action"])
                    if exe_ref:
                        exe_name = exe_ref.split("\\")[-1].split(" ")[0].lower()
                        for ppid, pinfo in procs.items():
                            if pinfo["name"] == exe_name:
                                add_edge(f"proc:{ppid}", pnode, "created")
                                break

        # ── Findings: link the finding's entity and flag involved nodes ──
        for f in findings:
            ev = f.get("evidence", {})
            sev = f.get("severity", "")
            # Process-based finding
            fpid = ev.get("leaf_pid") or ev.get("pid")
            if fpid and f"proc:{str(fpid)}" in nodes:
                nodes[f"proc:{str(fpid)}"]["finding_count"] += 1
                nodes[f"proc:{str(fpid)}"]["max_severity"] = sev
            # IP in the finding evidence
            for val in ev.values():
                m = ip_re.search(str(val))
                if m:
                    ip = m.group(1)
                    if not ip.startswith(("127.", "0.")):
                        n = add_node(f"ip:{ip}", ip, "ip")
                        if n:
                            n["finding_count"] += 1
                            n["max_severity"] = sev
            # File path in the finding
            path = ev.get("path") or ev.get("full_name") or ev.get("locator", "")
            if path and ("\\" in str(path) or "/" in str(path)):
                fname = str(path).replace("\\", "/").split("/")[-1][:40]
                if fname and "." in fname:
                    n = add_node(f"file:{fname}", fname, "file")
                    if n:
                        n["finding_count"] += 1
                        n["max_severity"] = sev

        # ── Trim for readability: keep finding-linked nodes + their neighbors,
        #    cap the rest. Large collections have thousands of processes; a
        #    graph of all of them is unreadable. ──
        MAX_NODES = 150
        if len(nodes) > MAX_NODES:
            # Priority order for keeping nodes:
            #   1. nodes tied to findings  2. non-process entities (ip/user/file)
            #   3. their immediate neighbors  4. highest-degree processes
            degree: dict = {}
            for e in edges:
                degree[e["source"]] = degree.get(e["source"], 0) + 1
                degree[e["target"]] = degree.get(e["target"], 0) + 1

            def priority(nid):
                n = nodes[nid]
                score = 0
                if n["finding_count"] > 0:
                    score += 1000
                # NEW: registry_key/task/service/domain get the same
                # priority boost as ip/user/file — they're high-signal,
                # low-volume entities that should survive trimming on
                # large collections just as readily as IPs do.
                if n["type"] in ("ip", "user", "file", "domain",
                                 "registry_key", "task", "service"):
                    score += 500
                score += degree.get(nid, 0)
                return score

            ranked = sorted(nodes.keys(), key=priority, reverse=True)
            keep = set(ranked[:MAX_NODES])
            nodes = {k: v for k, v in nodes.items() if k in keep}
            edges = [e for e in edges if e["source"] in nodes and e["target"] in nodes]

        return {
            "nodes": list(nodes.values()),
            "edges": edges,
            "truncated": len(nodes) >= MAX_NODES,
        }

    # ── 1. Timeline correlation ──

    def _build_timeline(self, data: dict, findings: list[dict]) -> dict:
        """Order all timestamped events and detect tight activity clusters."""
        events = []

        # Build a set of (artifact,row_index) that have an associated finding,
        # so we can tell "interesting" timeline events from background noise.
        finding_locations = set()
        for f in findings:
            ev = f.get("evidence", {})
            art = f.get("artifact", "")
            ri = ev.get("row_index")
            if art and ri is not None:
                finding_locations.add((art, ri))

        # Collect timestamped rows from all artifacts
        for key, rows in data.items():
            if key.startswith("_") or not isinstance(rows, list):
                continue
            for idx, row in enumerate(rows):
                if not isinstance(row, dict):
                    continue
                ts_raw = None
                for field in TIMESTAMP_FIELDS:
                    if field in row and row[field]:
                        ts_raw = row[field]
                        break
                if ts_raw:
                    dt = _parse_timestamp(ts_raw)
                    if dt:
                        desc = self._describe_event(key, row)
                        pname = _get(row, ["Name", "name", "Image", "Exe", "ProcessName"]).lower().split("\\")[-1]
                        events.append({
                            "timestamp": dt,
                            "timestamp_str": dt.isoformat(),
                            "artifact": key,
                            "row_index": idx,
                            "description": desc,
                            "is_finding": (key, idx) in finding_locations,
                            "is_boot_noise": self._is_boot_noise(key, row),
                            "is_suspicious_proc": pname in self.SUSPICIOUS_PROC_NAMES,
                        })

        # Sort chronologically
        events.sort(key=lambda e: e["timestamp"])

        # Detect clusters: 3+ events within a 5-minute window
        clusters = []
        window = timedelta(minutes=5)
        i = 0
        while i < len(events):
            cluster = [events[i]]
            j = i + 1
            while j < len(events) and (events[j]["timestamp"] - events[i]["timestamp"]) <= window:
                cluster.append(events[j])
                j += 1
            if len(cluster) >= 3:
                artifact_types = set(e["artifact"] for e in cluster)
                # A burst is only worth reporting if it is ANCHORED by something
                # genuinely suspicious — a detection finding or a known-bad
                # process in the window. Raw volume is NOT suspicious: system
                # boot and bulk service installs produce large clusters of
                # perfectly normal events. The old "non_boot >= 50%" rule still
                # flagged those (many uniquely-named services look 'non-boot').
                non_boot = [e for e in cluster if not e["is_boot_noise"]]
                has_finding = any(e["is_finding"] for e in cluster)
                has_suspicious_proc = any(e.get("is_suspicious_proc") for e in cluster)
                interesting = (
                    len(artifact_types) >= 2
                    and len(non_boot) >= 3
                    and (has_finding or has_suspicious_proc)
                )
                if interesting:
                    clusters.append({
                        "start": cluster[0]["timestamp_str"],
                        "end": cluster[-1]["timestamp_str"],
                        "event_count": len(cluster),
                        "artifacts_involved": list(artifact_types),
                        "has_finding": has_finding,
                        "events": [
                            {"time": e["timestamp_str"], "artifact": e["artifact"],
                             "description": e["description"], "is_finding": e["is_finding"]}
                            for e in cluster[:15] if not e["is_boot_noise"]
                        ],
                    })
                i = j
            else:
                i += 1

        new_findings = []
        for cluster in clusters:
            # Severity driven by whether real findings anchor the burst
            if cluster["has_finding"]:
                sev, score = "high", 70
            elif cluster["event_count"] >= 8:
                sev, score = "medium", 55
            else:
                sev, score = "low", 35
            new_findings.append({
                "id": f"C{len(new_findings)+1:04d}",
                "category": "temporal_correlation",
                "severity": sev,
                "title": f"Activity burst: {cluster['event_count']} events in <5min"
                         + (" (includes flagged activity)" if cluster["has_finding"] else ""),
                "description": (
                    f"{cluster['event_count']} events across "
                    f"{len(cluster['artifacts_involved'])} artifact types between "
                    f"{cluster['start']} and {cluster['end']}"
                    + (", anchored by at least one detection finding."
                       if cluster["has_finding"] else
                       ", clustered outside the normal boot sequence.")
                ),
                "artifact": "timeline",
                "evidence": {
                    "start": cluster["start"], "end": cluster["end"],
                    "artifacts": ", ".join(cluster["artifacts_involved"]),
                    "sample_events": "; ".join(
                        f"{e['time']} {e['description'][:60]}"
                        for e in cluster["events"][:5]
                    ),
                },
                "score": score,
                "mitre": "",
            })

        return {
            "timeline": [
                {"time": e["timestamp_str"], "artifact": e["artifact"],
                 "description": e["description"]}
                for e in events[:500]
            ],
            "timeline_clusters": clusters,
            "timeline_event_count": len(events),
            "new_findings": new_findings,
        }

    # Normal Windows boot/system processes that cluster at startup. A burst
    # made only of these is the OS booting, not an attack.
    BOOT_PROCESSES = {
        "registry", "system", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
        "fontdrvhost.exe", "dwm.exe", "spoolsv.exe", "lsm.exe",
        "memory compression", "secure system", "idle",
    }

    # Process names that make a timeline burst genuinely worth reporting
    SUSPICIOUS_PROC_NAMES = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "psexec.exe", "psexesvc.exe", "mimikatz.exe",
        "procdump.exe", "wmic.exe", "net.exe", "net1.exe", "at.exe",
        "schtasks.exe", "reg.exe", "vssadmin.exe", "ntdsutil.exe",
        "rubeus.exe", "sharphound.exe", "cobaltstrike", "ncat.exe",
    }

    def _is_boot_noise(self, artifact: str, row: dict) -> bool:
        """True if this row is a normal boot/system process or routine event."""
        name = _get(row, ["Name", "name", "Image", "Exe", "ProcessName"]).lower()
        name = name.split("\\")[-1]
        if name in self.BOOT_PROCESSES:
            return True
        # Routine system event log entries (boot, service control) are noise
        # unless tied to a finding
        eid = _get(row, ["EventID", "event_id", "Id"])
        if str(eid) in ("25", "12", "13", "6005", "6006", "6013"):
            return True
        return False

    def _describe_event(self, artifact: str, row: dict) -> str:
        """Build a short human description of a timeline event."""
        a = artifact.lower()
        if "event" in a or "evtx" in a:
            eid = _get(row, ["EventID", "event_id", "Id"])
            return f"Event {eid}" if eid else "Log event"
        if "process" in a or "pslist" in a:
            name = _get(row, ["Name", "name", "Image", "Exe"])
            return f"Process: {name.split(chr(92))[-1][:40]}"
        if "service" in a:
            return f"Service: {_get(row, ['Name', 'name', 'DisplayName'])[:40]}"
        if "task" in a:
            return f"Task: {_get(row, ['Name', 'name', 'TaskName'])[:40]}"
        if "netstat" in a or "network" in a:
            return f"Conn: {_get(row, ['Raddr', 'RemoteAddress', 'remote'])[:40]}"
        if "registry" in a or "run" in a or "autorun" in a or "startup" in a:
            key_path = _get(row, ["Key", "KeyPath", "path", "Path", "Name", "name"])
            return f"Registry: {key_path[-50:]}" if key_path else "Registry change"
        if "shimcache" in a or "appcompatcache" in a:
            path = _get(row, ["path", "Path"])
            return f"Shimcache exec: {path.split(chr(92))[-1][:40]}" if path else "Shimcache entry"
        if "userassist" in a:
            path = _get(row, ["path", "Path"])
            return f"GUI launch: {path.split(chr(92))[-1][:40]}" if path else "UserAssist entry"
        if "shellbag" in a:
            path = _get(row, ["path", "Path"])
            return f"Browsed: {path[-40:]}" if path else "Shellbag entry"
        return artifact[:30]

    # ── 2. Process tree reconstruction ──

    def _build_process_trees(self, data: dict) -> dict:
        """Reconstruct PID/PPID ancestry chains across all process artifacts."""
        # Find the process artifact
        procs = {}  # pid -> proc info
        for key, rows in data.items():
            if key.startswith("_") or not isinstance(rows, list):
                continue
            if not any(t in key.lower() for t in ["pslist", "process", "pstree"]):
                continue
            for idx, row in enumerate(rows):
                if not isinstance(row, dict):
                    continue
                pid = _get(row, ["Pid", "pid", "ProcessId", "PID"])
                ppid = _get(row, ["Ppid", "ppid", "ParentProcessId", "PPID"])
                name = _get(row, ["Name", "name", "Image", "Exe"])
                cmdline = _get(row, ["CommandLine", "cmdline", "Cmd"])
                if pid:
                    procs[str(pid)] = {
                        "pid": str(pid), "ppid": str(ppid),
                        "name": name.split("\\")[-1] if name else "",
                        "full_name": name,
                        "cmdline": cmdline[:200],
                        "row_index": idx, "artifact": key,
                    }

        if not procs:
            return {"process_trees": [], "suspicious_chains": []}

        # Build ancestry chains
        def get_chain(pid, depth=0, seen=None):
            if seen is None:
                seen = set()
            if pid in seen or depth > 12:  # cycle/depth guard
                return []
            seen.add(pid)
            proc = procs.get(pid)
            if not proc:
                return []
            chain = [proc]
            parent_chain = get_chain(proc["ppid"], depth + 1, seen)
            return parent_chain + chain

        # Suspicious lineage patterns — parent → (any) → descendant. These
        # encode real attack chains: office macros spawning shells, web servers
        # spawning commands (web shell), LOLBin abuse, etc.
        # HIGH-FIDELITY suspicious lineage patterns. Each parent→descendant
        # here is abnormal on its own — a real signal, not normal user activity.
        # We deliberately do NOT include explorer→powershell/cmd or
        # browser→cmd: those are everyday user actions (opening a terminal,
        # a browser launching a helper) and flagging them floods the report
        # with false positives.
        suspicious_ancestry = [
            # Office app spawning a script interpreter (macro / phishing)
            (["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
              "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe"],
             ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
              "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
              "certutil.exe", "bitsadmin.exe", "curl.exe"]),
            # Web/app server spawning a shell (web shell / RCE)
            (["w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe",
              "sqlservr.exe", "php-cgi.exe", "node.exe", "ManageEngine"],
             ["cmd.exe", "powershell.exe", "pwsh.exe", "net.exe", "net1.exe",
              "whoami.exe", "systeminfo.exe", "hostname.exe"]),
            # Script host spawning interpreters (staged execution)
            (["mshta.exe", "wscript.exe", "cscript.exe", "hh.exe"],
             ["powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe",
              "regsvr32.exe", "certutil.exe"]),
            # LOLBins spawning shells
            (["regsvr32.exe", "msbuild.exe", "installutil.exe",
              "mavinject.exe", "odbcconf.exe"],
             ["cmd.exe", "powershell.exe", "pwsh.exe"]),
            # services.exe spawning a shell directly (unusual — not explorer)
            (["services.exe"], ["cmd.exe", "powershell.exe", "pwsh.exe"]),
            # Interpreter spawning credential-dumping / recon tools
            (["powershell.exe", "pwsh.exe", "cmd.exe"],
             ["procdump.exe", "mimikatz.exe", "psexec.exe", "vssadmin.exe",
              "ntdsutil.exe", "rubeus.exe", "secretsdump"]),
            # WMI provider spawning shells (lateral movement / remote exec)
            (["wmiprvse.exe"], ["cmd.exe", "powershell.exe", "pwsh.exe"]),
            # Task scheduler spawning scripts
            (["taskeng.exe"],
             ["powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]),
        ]

        # Command-line context that makes a borderline chain genuinely suspicious
        SUSPICIOUS_CMDLINE_CONTEXT = re.compile(
            r"-enc\b|-e\s+[A-Za-z0-9+/]{20,}|frombase64|downloadstring|"
            r"downloadfile|invoke-expression|\biex\b|-w\s+hidden|-nop\b|"
            r"\\temp\\|\\appdata\\|\\programdata\\|hidden|bypass|"
            r"certutil.*-(?:decode|urlcache)|bitsadmin.*/transfer",
            re.IGNORECASE,
        )

        # Process names that are inherently suspicious wherever they appear
        INHERENTLY_SUSPICIOUS = {
            "mimikatz.exe", "psexec.exe", "psexesvc.exe", "procdump.exe",
            "wce.exe", "gsecdump.exe", "pwdump.exe", "lazagne.exe",
            "rubeus.exe", "sharphound.exe", "bloodhound.exe", "seatbelt.exe",
            "cobaltstrike", "beacon.exe", "meterpreter", "ncat.exe",
        }

        trees = []
        suspicious_chains = []
        new_findings = []

        for pid, proc in procs.items():
            chain = get_chain(pid)
            # Build trees for any chain with a parent (depth >= 2), so we catch
            # direct parent→child attacks (e.g. winword→powershell) that the
            # old depth>=3 threshold missed.
            if len(chain) >= 2:
                chain_names = [p["name"].lower() for p in chain]
                chain_str = " → ".join(p["name"] for p in chain if p["name"])

                # Check for suspicious ancestry anywhere in the chain
                is_suspicious = False
                matched_pattern = ""
                for ancestors, descendants in suspicious_ancestry:
                    for i in range(len(chain_names) - 1):
                        if chain_names[i] in ancestors:
                            for later in chain_names[i+1:]:
                                if later in descendants:
                                    is_suspicious = True
                                    matched_pattern = f"{chain_names[i]} → ... → {later}"
                                    break
                        if is_suspicious:
                            break
                    if is_suspicious:
                        break

                # Inherently suspicious tool anywhere in the chain
                hacktool = next((n for n in chain_names
                                 if any(h in n for h in INHERENTLY_SUSPICIOUS)), None)

                tree_entry = {
                    "leaf_pid": pid,
                    "depth": len(chain),
                    "chain": chain_str,
                    "suspicious": is_suspicious or bool(hacktool),
                }
                if len(chain) >= 3 or tree_entry["suspicious"]:
                    trees.append(tree_entry)

                if is_suspicious:
                    suspicious_chains.append(tree_entry)
                    new_findings.append({
                        "id": f"P{len(new_findings)+1:04d}",
                        "category": "process_anomaly",
                        "severity": "high",
                        "title": f"Suspicious process lineage: {matched_pattern}",
                        "description": (
                            f"Process ancestry chain matches a known attack pattern: "
                            f"{chain_str}. This lineage is characteristic of "
                            f"macro/exploit-driven execution, LOLBin abuse, or web shell activity."
                        ),
                        "artifact": proc["artifact"],
                        "evidence": {
                            "row_index": proc["row_index"],
                            "chain": chain_str,
                            "leaf_pid": pid,
                            "leaf_cmdline": proc["cmdline"],
                        },
                        "score": 85,
                        "mitre": "T1059",
                    })
                elif hacktool:
                    suspicious_chains.append(tree_entry)
                    new_findings.append({
                        "id": f"P{len(new_findings)+1:04d}",
                        "category": "process_anomaly",
                        "severity": "high",
                        "title": f"Known offensive tool in process tree: {hacktool}",
                        "description": (
                            f"The process '{hacktool}' appears in the ancestry chain "
                            f"{chain_str}. This tool is commonly used by attackers for "
                            f"credential theft, lateral movement, or C2."
                        ),
                        "artifact": proc["artifact"],
                        "evidence": {
                            "row_index": proc["row_index"],
                            "chain": chain_str,
                            "leaf_pid": pid,
                            "leaf_cmdline": proc["cmdline"],
                        },
                        "score": 88,
                        "mitre": "T1059",
                    })

        # Keep only deepest/most interesting trees for display
        trees.sort(key=lambda t: (-t["suspicious"], -t["depth"]))

        return {
            "process_trees": trees[:50],
            "suspicious_chains": suspicious_chains,
            "process_count": len(procs),
            "new_findings": new_findings,
        }

    # ── 3. Frequency analysis (stack counting) ──

    def _frequency_analysis(self, data: dict) -> dict:
        """Stack counting — rare items are suspicious. The core hunt technique."""
        # Counters across the whole dataset
        proc_names = Counter()
        proc_paths = Counter()
        proc_hashes = Counter()
        cmdline_patterns = Counter()
        remote_endpoints = Counter()  # NEW: IPs/domains, same stack-counting logic

        # Track which row each rare item came from
        name_rows = defaultdict(list)
        path_rows = defaultdict(list)
        hash_rows = defaultdict(list)
        endpoint_rows = defaultdict(list)  # NEW

        for key, rows in data.items():
            if key.startswith("_") or not isinstance(rows, list):
                continue
            if not any(t in key.lower() for t in
                       ["pslist", "process", "prefetch", "amcache", "executable", "service"]):
                continue
            for idx, row in enumerate(rows):
                if not isinstance(row, dict):
                    continue
                name = _get(row, ["Name", "name", "Image", "Exe", "Executable"]).split("\\")[-1].lower()
                path = _get(row, ["Exe", "Path", "path", "ExecutablePath", "FullPath"]).lower()
                h = _get(row, ["Hash", "sha256", "SHA256", "sha1", "MD5"])

                if name:
                    proc_names[name] += 1
                    if len(name_rows[name]) < 5:
                        name_rows[name].append({"artifact": key, "row_index": idx, "path": path})
                if path:
                    proc_paths[path] += 1
                    if len(path_rows[path]) < 5:
                        path_rows[path].append({"artifact": key, "row_index": idx})
                if h and len(h) > 8:
                    proc_hashes[h] += 1
                    if len(hash_rows[h]) < 5:
                        hash_rows[h].append({"artifact": key, "row_index": idx, "name": name})

        # NEW: separate pass over network artifacts for endpoint stack counting.
        # A remote IP/domain contacted only once across the whole collection is
        # the same "rare = suspicious" signal as a rare file path — classic
        # C2 beaconing indicator that the original version of this function
        # never looked for, since it only scanned process-family artifacts.
        ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        for key, rows in data.items():
            if key.startswith("_") or not isinstance(rows, list):
                continue
            if not any(t in key.lower() for t in ["netstat", "network", "conn", "dns"]):
                continue
            for idx, row in enumerate(rows):
                if not isinstance(row, dict):
                    continue
                raddr = _get(row, ["Raddr", "RemoteAddress", "remote", "ForeignAddress", "DestAddr"])
                domain = _get(row, ["domain", "Domain", "QueryName", "query", "hostname"])

                m = ip_re.search(str(raddr))
                if m:
                    ip = m.group(1)
                    if not ip.startswith(("127.", "0.", "10.", "192.168.", "::")):
                        remote_endpoints[ip] += 1
                        if len(endpoint_rows[ip]) < 5:
                            endpoint_rows[ip].append({"artifact": key, "row_index": idx, "type": "ip"})

                if domain and domain not in ("localhost", ""):
                    remote_endpoints[domain.lower()] += 1
                    if len(endpoint_rows[domain.lower()]) < 5:
                        endpoint_rows[domain.lower()].append({"artifact": key, "row_index": idx, "type": "domain"})

        outliers = []
        new_findings = []

        # Rare paths (appearing once) that are NOT in standard locations
        rare_paths = [(p, c) for p, c in proc_paths.items() if c == 1]
        suspicious_rare = []
        for path, count in rare_paths:
            # Skip allowlisted paths
            if any(re.search(allow, path) for allow in ALLOWLIST_PATHS):
                continue
            # Rare + suspicious location = high interest
            if any(loc in path for loc in
                   ["\\temp\\", "\\appdata\\", "\\users\\public\\", "\\programdata\\",
                    "\\downloads\\", "\\$recycle", "\\perflogs\\"]):
                suspicious_rare.append({"path": path, "count": count,
                                        "rows": path_rows[path]})

        for item in suspicious_rare[:30]:
            outliers.append({
                "type": "rare_path",
                "value": item["path"],
                "occurrences": item["count"],
            })
            new_findings.append({
                "id": f"FQ{len(new_findings)+1:04d}",
                "category": "frequency_outlier",
                "severity": "medium",
                "title": "Rare executable in suspicious location",
                "description": (
                    f"Executable appears only once in the dataset and runs from a "
                    f"user-writable location: {item['path']}. Rare + suspicious path "
                    f"is a classic malware staging indicator (stack counting)."
                ),
                "artifact": item["rows"][0]["artifact"] if item["rows"] else "frequency",
                "evidence": {
                    "row_index": item["rows"][0]["row_index"] if item["rows"] else None,
                    "path": item["path"],
                    "occurrences": item["count"],
                },
                "score": 50,
                "mitre": "T1036",
            })

        # NEW: rare remote endpoints (contacted exactly once) — beaconing/C2
        # detection works the opposite way (many connections to the SAME IP),
        # but a single, never-repeated connection to an unfamiliar endpoint is
        # its own signal: staged exfil, one-time payload download, or a C2
        # check-in that only fired once before the host was contained.
        rare_endpoints = [(e, c) for e, c in remote_endpoints.items() if c == 1]
        for endpoint, count in rare_endpoints[:30]:
            rows = endpoint_rows[endpoint]
            etype = rows[0]["type"] if rows else "ip"
            outliers.append({
                "type": "rare_remote_endpoint",
                "value": endpoint,
                "occurrences": count,
            })
            new_findings.append({
                "id": f"FQ{len(new_findings)+1:04d}",
                "category": "frequency_outlier",
                "severity": "low",
                "title": f"Rare remote endpoint contacted once: {endpoint}",
                "description": (
                    f"{'IP address' if etype == 'ip' else 'Domain'} '{endpoint}' appears "
                    f"exactly once across all network activity in this collection. A "
                    f"single, non-repeated connection to an unfamiliar endpoint can "
                    f"indicate a one-time payload download or C2 check-in — corroborate "
                    f"with the process that made the connection before treating this as "
                    f"a true positive, since one-off connections are also common for "
                    f"normal software (update checks, telemetry, etc.)."
                ),
                "artifact": rows[0]["artifact"] if rows else "frequency",
                "evidence": {
                    "row_index": rows[0]["row_index"] if rows else None,
                    "endpoint": endpoint,
                    "endpoint_type": etype,
                    "occurrences": count,
                },
                "score": 35,  # deliberately low — see corroboration note above
                "mitre": "T1071",  # Application Layer Protocol (generic C2 channel)
            })

        # Hash collision: same hash, different names (possible masquerading)
        # or same name, different hashes (possible trojanized binary)
        name_to_hashes = defaultdict(set)
        for key, rows in data.items():
            if key.startswith("_") or not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                name = _get(row, ["Name", "name", "Image", "Exe"]).split("\\")[-1].lower()
                h = _get(row, ["Hash", "sha256", "SHA256"])
                if name and h and len(h) > 8:
                    name_to_hashes[name].add(h)

        for name, hashes in name_to_hashes.items():
            if len(hashes) > 1 and name in KNOWN_GOOD_SYSTEM:
                # System binary with multiple hashes = possible trojanized/masqueraded
                outliers.append({
                    "type": "hash_mismatch",
                    "value": name,
                    "distinct_hashes": len(hashes),
                })
                new_findings.append({
                    "id": f"FQ{len(new_findings)+1:04d}",
                    "category": "frequency_outlier",
                    "severity": "high",
                    "title": f"System binary with multiple hashes: {name}",
                    "description": (
                        f"'{name}' appears with {len(hashes)} different file hashes. "
                        f"A core system binary should have a consistent hash — multiple "
                        f"hashes suggest a trojanized or masqueraded copy."
                    ),
                    "artifact": "frequency",
                    "evidence": {"name": name, "distinct_hashes": len(hashes)},
                    "score": 75,
                    "mitre": "T1036.005",
                })

        # Summary of frequency distribution
        return {
            "frequency_outliers": outliers,
            "frequency_summary": {
                "unique_process_names": len(proc_names),
                "unique_paths": len(proc_paths),
                "unique_hashes": len(proc_hashes),
                "unique_remote_endpoints": len(remote_endpoints),  # NEW
                "rare_suspicious_paths": len(suspicious_rare),
                "rare_remote_endpoints": len(rare_endpoints),  # NEW
                "most_common_processes": dict(proc_names.most_common(10)),
                "most_common_endpoints": dict(remote_endpoints.most_common(10)),  # NEW
            },
            "new_findings": new_findings,
        }


def apply_allowlist(findings: list[dict]) -> tuple[list[dict], int]:
    """
    Filter out low-value findings for known-good signed system binaries.
    Returns (filtered_findings, suppressed_count).

    A finding is suppressed ONLY if:
      - it's low or medium severity, AND
      - its evidence path is in an allowlisted location, AND
      - it doesn't involve suspicious command-line content
    """
    kept = []
    suppressed = 0

    for f in findings:
        # Never suppress critical/high findings
        if f.get("severity") in ("critical", "high"):
            kept.append(f)
            continue

        ev = f.get("evidence", {})
        path = str(ev.get("path", "") or ev.get("cmdline", "")).lower()

        # Check if path is allowlisted
        is_allowlisted = any(re.search(allow, path) for allow in ALLOWLIST_PATHS)

        # Don't suppress if there's suspicious content even in allowlisted path
        has_suspicious_args = any(
            ind in path for ind in
            ["-enc", "hidden", "downloadstring", "frombase64", "iex",
             "bypass", "-nop", "comsvcs", "minidump"]
        )

        if is_allowlisted and not has_suspicious_args and f.get("category") in (
            "suspicious_file", "process_anomaly", "execution"
        ):
            suppressed += 1
            continue

        kept.append(f)

    return kept, suppressed