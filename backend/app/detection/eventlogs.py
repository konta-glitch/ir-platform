"""
detection/eventlogs.py — core Windows Event Log detection.

Covers the general-purpose Security/System event IDs: log clearing (1102,
104), account changes (4720, 4728/4732/4756), service/task creation
(4697/7045, 4698/4702), failed/brute-force logons (4625), and
PowerShell/process-creation script-block checks (4104, 4688).

Windows Defender's own event stream (1116, 1117, 5001, 5004, 5007, 5008,
5010, 5012, 3002) is handled separately in detection/defender.py —
channel-scoped detection that's substantial enough (and specific enough)
to warrant its own module rather than living inside this general handler.
"""

from __future__ import annotations
import re
from collections import defaultdict, Counter

from app.detection.base import SUSPICIOUS_CMDLINE

BRUTE_FORCE_THRESHOLD = 5  # failed logons from same source


def detect_eventlogs(engine, key: str, rows: list[dict]) -> None:
    failed_logons = defaultdict(list)
    event_id_counts = Counter()

    for idx, event in enumerate(rows):
        eid = engine._get(event, ["EventID", "event_id", "Id", "ID"])
        try:
            eid = int(eid) if eid else None
        except (ValueError, TypeError):
            eid = None

        if eid is None:
            continue

        event_id_counts[eid] += 1
        data_str = str(event)[:500]
        timestamp = engine._get(event, ["TimeCreated", "timestamp", "Timestamp", "time"])

        evidence = {
            "row_index": idx, "event_id": eid, "timestamp": timestamp,
            "data": data_str,
        }

        # Log-clearing events — but ONLY in the channels where they mean
        # "audit log cleared". Event 104 in particular is overloaded:
        #   - System/Security channel 104/1102 = real log clear (critical)
        #   - Diagnosis-Scripted, PowerShell, and many app channels emit
        #     Event 104 for benign reasons (scenario completion, etc.)
        # Flagging 104 everywhere produced hundreds of false positives.
        channel = str(engine._get(event, ["Channel", "channel", "LogName"]) or "").lower()
        source = str(engine._get(event, ["provider", "Provider", "SourceName"]) or "").lower()
        is_security_channel = (
            "security" in channel or "system" in channel
            or "eventlog" in source or "eventlog" in channel
            or key.lower().endswith("security") or key.lower().endswith("system")
            or "evtx_security" in key.lower() or "evtx_system" in key.lower()
        )

        if eid == 1102 and ("security" in channel or "evtx_security" in key.lower()
                            or key.lower().endswith("security") or not channel):
            cleared_logs_finding = True
            engine._add_finding(
                "defense_evasion", "critical",
                "Security audit log cleared",
                f"Event 1102 — the Security audit log was cleared at {timestamp}. "
                f"Strong indicator of anti-forensic activity.",
                key, evidence,
                score=95, mitre="T1070.001",
            )
        elif eid == 104 and is_security_channel:
            engine._add_finding(
                "defense_evasion", "high",
                "Event log cleared",
                f"Event 104 in {channel or key} — an event log was cleared at "
                f"{timestamp}. Possible anti-forensic activity.",
                key, evidence,
                score=75, mitre="T1070.001",
            )
        # Event 104 in any other channel (Diagnosis-Scripted, etc.) is
        # routine and intentionally NOT flagged.

        elif eid == 4720:  # New account
            engine._add_finding(
                "persistence", "high",
                "New user account created",
                f"Event 4720 — a user account was created at {timestamp}",
                key, evidence,
                score=70, mitre="T1136.001",  # Create Account
            )

        elif eid in (4728, 4732, 4756):  # Added to privileged group
            engine._add_finding(
                "privilege_escalation", "high",
                "Account added to privileged group",
                f"Event {eid} — a member was added to a security group at {timestamp}",
                key, evidence,
                score=70, mitre="T1098",  # Account Manipulation
            )

        elif eid in (4697, 7045):  # Service installed
            # Service installs are routine on Windows (updates, drivers,
            # software). Default to medium; only escalate to high if the
            # service binary/command looks suspicious.
            svc_sev, svc_score = "medium", 50
            if re.search(r"-enc\b|frombase64|downloadstring|\biex\b|"
                         r"\\temp\\|\\appdata\\|powershell.*-w\s+hidden",
                         data_str, re.IGNORECASE):
                svc_sev, svc_score = "high", 75
            engine._add_finding(
                "persistence", svc_sev,
                "New service installed",
                f"Event {eid} — a new service was installed at {timestamp}. Data: {data_str[:200]}",
                key, evidence,
                score=svc_score, mitre="T1543.003",
            )

        elif eid in (4698, 4702):  # Scheduled task
            engine._add_finding(
                "persistence", "medium",
                "Scheduled task created/modified",
                f"Event {eid} — scheduled task activity at {timestamp}",
                key, evidence,
                score=55, mitre="T1053.005",
            )

        elif eid == 4625:  # Failed logon
            src = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", data_str)
            src_ip = src.group(1) if src else "unknown"
            failed_logons[src_ip].append(evidence)

        elif eid == 4104:  # PowerShell script block
            for pattern, desc, sev in SUSPICIOUS_CMDLINE:
                if re.search(pattern, data_str, re.IGNORECASE):
                    engine._add_finding(
                        "execution", sev,
                        f"Suspicious PowerShell script block: {desc}",
                        f"Event 4104 at {timestamp} — script block contains {desc}",
                        key, evidence,
                        score=75, mitre="T1059.001",
                    )
                    break

        elif eid == 4688:  # Process creation
            for pattern, desc, sev in SUSPICIOUS_CMDLINE:
                if re.search(pattern, data_str, re.IGNORECASE):
                    engine._add_finding(
                        "execution", sev,
                        f"Suspicious process creation: {desc}",
                        f"Event 4688 at {timestamp} — process with {desc}",
                        key, evidence,
                        score=70, mitre="T1059",
                    )
                    break

        else:
            # Not handled here — give detection/defender.py a chance to
            # claim it if it's a Defender-channel event.
            from app.detection.defender import try_detect_defender_event
            try_detect_defender_event(engine, key, channel, eid, timestamp, data_str, evidence)

    # Brute force detection
    for src_ip, attempts in failed_logons.items():
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            engine._add_finding(
                "credential_access", "high",
                f"Possible brute-force from {src_ip}",
                f"{len(attempts)} failed logon attempts (Event 4625) from {src_ip}",
                key, {"source": src_ip, "attempt_count": len(attempts),
                      "samples": attempts[:5]},
                score=65, mitre="T1110",  # Brute Force
            )

    # Store event distribution
    engine.stats[f"{key}_event_distribution"] = dict(event_id_counts.most_common(20))
