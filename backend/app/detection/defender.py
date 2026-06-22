"""
detection/defender.py — ALL Windows Defender detection in one place.

Two distinct data sources feed this module, unified here so "everything
about whether Defender caught something or was tampered with" lives in one
file instead of being split across the general eventlog handler and a
separate MPLog method:

  1. EVTX Operational log events (try_detect_defender_event) — called by
     eventlogs.py for any event ID it doesn't otherwise handle, scoped to
     the actual Defender channel. CHANNEL SCOPING IS REQUIRED: these event
     IDs are not globally unique to Defender — e.g. Event 3002 also exists
     in the unrelated MUI (Multilingual User Interface) channel. A real
     production run produced exactly this false positive (22 "Defender
     real-time protection error" findings that were actually generic MUI
     errors) before channel scoping was added here.

  2. MPLog (Microsoft Protection Log) parsed events (detect_mplog_events) —
     plain-text troubleshooting logs with richer detail than EVTX: file
     paths, hashes, PIDs already extracted, plus event types EVTX doesn't
     carry at all (EMS memory-scan detections, per-process file-access
     evidence that survives even after the file itself is deleted).
"""

from __future__ import annotations
import re

# Event IDs this module owns — used by eventlogs.py to know which
# unhandled event IDs to offer to try_detect_defender_event.
DEFENDER_EVENT_IDS = {1116, 1117, 5001, 5004, 5007, 5008, 5010, 5012, 3002}


def try_detect_defender_event(
    engine, key: str, channel: str, eid: int | None,
    timestamp: str, data_str: str, evidence: dict,
) -> None:
    """
    Called by eventlogs.py for any event ID it didn't already handle.
    Only produces a finding if BOTH the event ID matches a known Defender
    event AND the channel is actually the Defender Operational channel —
    see module docstring for why the channel check is non-negotiable.
    """
    if eid not in DEFENDER_EVENT_IDS:
        return

    is_defender_channel = (
        "windows defender" in channel
        or "windows defender" in key.lower()
    )
    if not is_defender_channel:
        return  # wrong channel — e.g. Event 3002 in the MUI channel

    if eid == 1116:  # Malware/threat detected by Defender
        # 1116 alone says "Defender SAW something" — doesn't say whether it
        # was removed. The paired 1117 event carries the action taken,
        # including the dangerous case where the configured action was
        # "Allow" (detected but NOT remediated).
        threat_match = re.search(
            r"(?:threat\s*name|Threat Name)[:\s]+([A-Za-z0-9:/_.\-]{3,100})",
            data_str, re.IGNORECASE,
        )
        threat_name = threat_match.group(1).strip() if threat_match else "unknown threat"
        engine._add_finding(
            "execution", "critical",
            f"Windows Defender detected: {threat_name}",
            f"Event 1116 at {timestamp} — Defender flagged '{threat_name}'. "
            f"Check the paired Event 1117 to confirm whether it was actually "
            f"removed/quarantined or merely logged.",
            key, evidence,
            score=95, mitre="T1204",
        )

    elif eid == 1117:  # Defender action taken on a detected threat
        allowed = re.search(r"\bAllow\b", data_str, re.IGNORECASE) is not None
        engine._add_finding(
            "execution",
            "critical" if allowed else "high",
            "Defender action taken on detected threat"
            + (" — threat was ALLOWED, not removed" if allowed else ""),
            f"Event 1117 at {timestamp} — "
            + (
                "the configured action for this threat was 'Allow', meaning "
                "Defender detected it but the threat REMAINS on the system. "
                "This is not a resolved detection."
                if allowed else
                "Defender took remediation action on a previously detected threat."
            ),
            key, evidence,
            score=95 if allowed else 80, mitre="T1204",
        )

    elif eid == 5001:  # Real-time protection disabled
        engine._add_finding(
            "defense_evasion", "critical",
            "Windows Defender real-time protection disabled",
            f"Event 5001 at {timestamp} — real-time protection was turned off. "
            f"Classic defense-evasion step immediately preceding malware execution.",
            key, evidence,
            score=90, mitre="T1562.001",  # Impair Defenses: Disable Tools
        )

    elif eid in (5010, 5012):  # Spyware/virus scanning disabled
        what = "spyware/PUA" if eid == 5010 else "virus"
        engine._add_finding(
            "defense_evasion", "critical",
            f"Windows Defender {what} scanning disabled",
            f"Event {eid} at {timestamp} — {what} scanning was disabled.",
            key, evidence,
            score=88, mitre="T1562.001",
        )

    elif eid in (5004, 5008):  # Antimalware engine error/failure
        engine._add_finding(
            "defense_evasion", "medium",
            "Windows Defender engine error or failure",
            f"Event {eid} at {timestamp} — the antimalware engine encountered "
            f"an error. Could be benign (update glitch) or deliberate tampering "
            f"— check timing against other findings.",
            key, evidence,
            score=50, mitre="T1562.001",
        )

    elif eid == 5007:  # Defender configuration changed
        engine._add_finding(
            "defense_evasion", "medium",
            "Windows Defender configuration changed",
            f"Event 5007 at {timestamp} — a Defender setting changed. Review "
            f"to confirm this was an authorized administrative change.",
            key, evidence,
            score=45, mitre="T1562.001",
        )

    elif eid == 3002:  # Real-time protection error
        engine._add_finding(
            "defense_evasion", "medium",
            "Windows Defender real-time protection error",
            f"Event 3002 at {timestamp} — real-time protection encountered an "
            f"error and failed. Worth correlating with nearby execution events.",
            key, evidence,
            score=50, mitre="T1562.001",
        )


def detect_mplog_events(engine, key: str, rows: list[dict]) -> None:
    """
    Process parsed MPLog events (see collector._parse_mplog_lines).

    Unlike the Defender Operational EVTX events (try_detect_defender_event
    above), MPLog events come with file paths, hashes, and PIDs already
    extracted, and include event types EVTX doesn't carry at all — EMS
    (memory-scan) detections and per-process file-access evidence
    (Estimated Impact) that can survive even after the offending process
    and file are both gone from disk.
    """
    for idx, event in enumerate(rows):
        etype = event.get("event_type", "")
        evidence = {"row_index": idx, **{k: v for k, v in event.items() if k != "raw"}}

        if etype == "detection":
            threat = event.get("threat_name", "unknown threat")
            target = event.get("file") or f"PID {event.get('pid', '?')}"
            engine._add_finding(
                "execution", "critical",
                f"MPLog: Defender detected {threat}",
                f"MPLog DETECTION_ADD event at {event.get('timestamp', 'unknown time')} — "
                f"'{threat}' identified at {target}. This is a direct AV verdict, "
                f"not a heuristic — Defender's engine already classified this as malicious.",
                key, evidence,
                score=95, mitre="T1204",
            )

        elif etype == "ems_detection":
            threat = event.get("threat_name", "unknown threat")
            pid = event.get("pid", "?")
            engine._add_finding(
                "defense_evasion", "critical",
                f"MPLog: EMS memory-scan detected {threat}",
                f"MPLog EMS (memory scan) detection — '{threat}' found in the memory "
                f"of PID {pid}. EMS detections specifically indicate in-memory "
                f"injection or fileless techniques — there may be no file on disk "
                f"to find, making this evidence often unavailable anywhere else.",
                key, evidence,
                score=92, mitre="T1055",  # Process Injection
            )

        elif etype == "sdn":
            # SDN events are file-existence + hash evidence from Defender's
            # cloud-lookup telemetry — present regardless of whether a
            # detection verdict was reached. Lower severity than an actual
            # detection, but valuable IOC material: confirms a specific
            # file (with hash) existed on the host.
            engine._add_finding(
                "suspicious_file", "low",
                "MPLog: file observed by Defender cloud telemetry",
                f"MPLog SDN event — '{event.get('file', 'unknown')}' was queried "
                f"against Defender's cloud reputation service "
                f"(SHA1: {event.get('sha1', '')[:16]}..., "
                f"SHA256: {event.get('sha256', '')[:16]}...). No detection verdict "
                f"on its own, but provides hash-backed file existence even if the "
                f"file has since been deleted.",
                key, evidence,
                score=30, mitre="T1204",
            )

        elif etype == "estimated_impact":
            # Execution + file-access evidence. The MaxTimeFile field is
            # particularly valuable: it's the file that took longest to
            # scan among everything this process accessed — frequently
            # the most "interesting" (largest/most complex) file that
            # process touched.
            proc = event.get("process", "unknown")
            max_file = event.get("max_time_file", "")
            try:
                files_accessed = int(event.get("files_accessed", "0"))
            except (ValueError, TypeError):
                files_accessed = 0

            max_file_lower = max_file.lower()
            is_suspicious_local_path = any(
                loc in max_file_lower
                for loc in ["\\temp\\", "\\appdata\\", "\\programdata\\",
                            "\\users\\public\\", "\\downloads\\"]
            )
            # Network share access — \\Device\\Mup\\ (multiple UNC
            # provider) or a literal UNC-style \\server\share path. This
            # is the RClone/mass-exfiltration pattern: a process reading
            # a huge number of files from a network share is one of the
            # strongest single signals MPLog can offer for data staging
            # or exfiltration, independent of any local suspicious path.
            is_network_share = (
                "\\device\\mup\\" in max_file_lower
                or re.match(r"\\\\[^\\]+\\[^\\]+", max_file)
            )
            # High file count on its own (regardless of path) — a process
            # touching tens of thousands of files in one scan window is
            # anomalous for almost anything except backup/AV/indexing
            # software, and worth surfacing for the analyst to corroborate
            # against what the process actually is.
            is_high_volume = files_accessed >= 1000

            if is_suspicious_local_path or is_network_share or is_high_volume:
                reason = (
                    "accessed a large network share file set — classic mass-exfiltration "
                    "staging pattern (e.g. rclone/robocopy-style bulk file access)"
                    if is_network_share else
                    f"accessed an unusually high number of files ({files_accessed:,}) in "
                    f"one scan window"
                    if is_high_volume and not is_suspicious_local_path else
                    "accessed a file in a suspicious location"
                )
                sev = "high" if (is_network_share or is_high_volume) else "low"
                score = 70 if (is_network_share or is_high_volume) else 40
                engine._add_finding(
                    "execution", sev,
                    f"MPLog: {proc} {reason}",
                    f"MPLog Estimated Impact event — '{proc}' accessed {files_accessed:,} "
                    f"file(s), including '{max_file}'. This is execution+file-access "
                    f"evidence independent of Prefetch/Amcache — useful corroboration "
                    f"even if those artifacts were tampered with, and for network-share "
                    f"access in particular, MPLog may be the ONLY artifact that captures "
                    f"this at all (file-server-side access doesn't appear in local EVTX).",
                    key, evidence,
                    score=score,
                    mitre="T1567" if is_network_share else "T1204",  # Exfil over Web Service / User Execution
                )
