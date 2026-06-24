"""
detection/auth_patterns.py — advanced authentication pattern analysis.

The original engine only had a brute-force threshold (N failed logons from
one source). This adds patterns a simple threshold misses:
  - successful logon following a burst of failures (credential-stuffing
    success)
  - same account authenticating from multiple distinct sources (password
    spraying / compromised credential reuse)
  - privileged logons outside normal business hours

Runs as an ADDITIONAL pass alongside the primary eventlog detector (see
detection/base.py ADDITIONAL_PASSES) — not a replacement for the existing
per-event-ID brute-force counting in eventlogs.py.
"""

from __future__ import annotations
import re
from collections import defaultdict
from datetime import datetime
from typing import Any

# Off-hours window for flagging privileged logons — configurable
# heuristic, not a hard rule (legitimate on-call/global-team activity
# happens at all hours, so this is a lead not a verdict).
OFF_HOURS_START = 22  # 10pm
OFF_HOURS_END = 5     # 5am

PRIVILEGED_LOGON_TYPES = {"2", "10"}  # interactive, remote interactive (RDP)

def _parse_event_timestamp(value: Any) -> datetime | None:
    """Best-effort timestamp parsing — mirrors correlation_engine's approach."""
    if not value:
        return None
    s = str(value).strip()
    s_clean = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", s)
    patterns = [
        "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
    ]
    for pattern in patterns:
        for candidate in (s, s_clean):
            try:
                return datetime.strptime(candidate, pattern)
            except ValueError:
                continue
    return None


def detect_auth_patterns(engine, key: str, rows: list[dict]) -> None:
    """
    Analyze authentication events (4624 success, 4625 failure) for patterns
    beyond simple brute-force volume:

      - successful logon immediately following a burst of failures for the
        SAME account (credential-stuffing success / password-guess hit)
      - same account authenticating from multiple distinct source IPs in a
        short window (password spraying success, or compromised-credential
        reuse from multiple attacker-controlled hosts)
      - privileged-looking logons outside normal business hours
    """
    # account -> list of (timestamp, event_id, source_ip)
    account_events: dict = defaultdict(list)

    for idx, row in enumerate(rows):
        eid = row.get("EventID") or row.get("event_id") or row.get("Id")
        try:
            eid = int(eid) if eid else None
        except (ValueError, TypeError):
            eid = None
        if eid not in (4624, 4625):
            continue

        account = (row.get("TargetUserName") or row.get("account") or
                   row.get("User") or row.get("Username") or "unknown")
        if str(account).endswith("$"):
            continue  # machine accounts — not user auth, skip

        ts_raw = (row.get("TimeCreated") or row.get("timestamp") or
                  row.get("Timestamp") or row.get("time"))
        ts = _parse_event_timestamp(ts_raw)
        if not ts:
            continue

        src_ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", str(row))
        src_ip = src_ip_match.group(1) if src_ip_match else "unknown"
        logon_type = str(row.get("LogonType") or "")

        account_events[str(account)].append({
            "row_index": idx, "timestamp": ts, "event_id": eid,
            "source_ip": src_ip, "logon_type": logon_type,
        })

    for account, events in account_events.items():
        events.sort(key=lambda e: e["timestamp"])

        # ── Success-after-failure-burst ──
        failure_streak = 0
        for i, ev in enumerate(events):
            if ev["event_id"] == 4625:
                failure_streak += 1
                continue
            if ev["event_id"] == 4624 and failure_streak >= 5:
                engine._add_finding(
                    "credential_access", "high",
                    f"Successful logon for '{account}' after {failure_streak} failed attempts",
                    f"Account '{account}' had {failure_streak} consecutive failed logons "
                    f"immediately followed by a SUCCESSFUL logon from {ev['source_ip']} at "
                    f"{ev['timestamp'].isoformat()}. Classic credential-guessing or "
                    f"credential-stuffing success pattern.",
                    key, {"row_index": ev["row_index"], "account": account,
                          "failed_attempts": failure_streak, "source_ip": ev["source_ip"]},
                    score=85, mitre="T1110",
                )
            failure_streak = 0

        # ── Multiple distinct sources for the same account ──
        successful = [e for e in events if e["event_id"] == 4624]
        distinct_sources = {e["source_ip"] for e in successful if e["source_ip"] != "unknown"}
        if len(distinct_sources) >= 3:
            engine._add_finding(
                "credential_access", "medium",
                f"Account '{account}' logged on from {len(distinct_sources)} distinct sources",
                f"Account '{account}' had successful logons from {len(distinct_sources)} "
                f"different source IPs ({', '.join(list(distinct_sources)[:5])}) in this "
                f"collection window. Could indicate compromised-credential reuse across "
                f"multiple attacker-controlled hosts, or legitimate multi-device/VPN use — "
                f"corroborate with geolocation/timing before escalating.",
                key, {"account": account, "distinct_sources": list(distinct_sources)},
                score=50, mitre="T1078",  # Valid Accounts
            )

        # ── Off-hours privileged logon ──
        for ev in successful:
            if ev["logon_type"] in PRIVILEGED_LOGON_TYPES:
                hour = ev["timestamp"].hour
                is_off_hours = hour >= OFF_HOURS_START or hour < OFF_HOURS_END
                if is_off_hours:
                    engine._add_finding(
                        "credential_access", "low",
                        f"Off-hours privileged logon for '{account}'",
                        f"Account '{account}' logged on (type {ev['logon_type']}) at "
                        f"{ev['timestamp'].isoformat()} ({hour:02d}:00 local) — outside "
                        f"typical business hours. May be legitimate (on-call, different "
                        f"timezone) — flagged for analyst context, not a standalone verdict.",
                        key, {"row_index": ev["row_index"], "account": account,
                              "hour": hour, "logon_type": ev["logon_type"]},
                        score=30, mitre="T1078",
                    )
