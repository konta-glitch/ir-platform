"""
Extended detection rules — DNS/DGA anomalies and advanced authentication
pattern analysis.

These two areas were genuine gaps (correctly identified in external review):

  - DNS analysis: the original detection_engine had no domain-specific
    rules at all — only IP-based C2 port/beaconing checks. Malware
    increasingly uses Domain Generation Algorithms (DGA) and DNS tunneling,
    neither of which involves a "suspicious port" an IP-based rule would
    catch.

  - Auth pattern analysis: the original engine only had a brute-force
    threshold (N failed logons from one source). It had no notion of a
    SUCCESSFUL logon following a burst of failures (classic credential-
    stuffing success), logons from multiple distinct sources for the same
    account (password spraying / compromised credential reuse), or
    off-hours privileged logons.

Design: kept as a separate module (same pattern as detection_extended.py)
so these can be unit-tested independently and extended without touching
the core DetectionEngine class.
"""

from __future__ import annotations
import math
import re
import logging
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════
# DNS / DGA detection
# ══════════════════════════════════════════════════

# DGA heuristic thresholds, based on published feature sets (length,
# Shannon entropy, vowel ratio, consecutive-consonant ratio, digit ratio —
# see e.g. "A Detection Scheme for DGA Domain Names Based on SVM" and
# Splunk's DGA detection writeups). This is a heuristic first pass, not a
# trained classifier — it will have false positives on legitimately
# random-looking subdomains (CDNs, cloud storage) and false negatives on
# dictionary-based/combo-squatting DGAs, which are known weak spots for
# string-heuristic approaches generally. Flag findings here as "low"
# confidence accordingly; they're leads, not verdicts.
DGA_MIN_LABEL_LENGTH = 12          # only score labels at least this long
DGA_ENTROPY_THRESHOLD = 3.6        # bits/char; random strings trend higher
DGA_MAX_VOWEL_RATIO = 0.25         # DGA strings are vowel-poor
DGA_MIN_CONSONANT_RUN = 5          # 5+ consecutive consonants is unusual

VOWELS = set("aeiou")

# Common legitimate high-entropy subdomain patterns to avoid flagging —
# CDN/cloud edge nodes, mail/tracking pixels, etc. routinely use random-
# looking subdomains. Allowlisting domains (not just patterns) cuts the
# single biggest source of DGA-heuristic false positives.
DGA_ALLOWLIST_DOMAINS = {
    "amazonaws.com", "cloudfront.net", "akamai.net", "akamaiedge.net",
    "windowsupdate.com", "microsoft.com", "office.com", "office365.com",
    "googleusercontent.com", "googleapis.com", "gstatic.com",
    "cloudflare.com", "fastly.net", "azureedge.net", "azure.com",
    "doubleclick.net", "google-analytics.com",
}


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char — higher means more 'random-looking'."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _max_consonant_run(s: str) -> int:
    """Longest run of consecutive consonant characters."""
    s = s.lower()
    best = run = 0
    for ch in s:
        if ch.isalpha() and ch not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _looks_like_dga(label: str) -> tuple[bool, dict]:
    """
    Score a single domain label (the part before the first dot — DGA
    domains are generated, not their TLD) against the heuristic feature
    set. Returns (is_suspicious, feature_dict) so callers can include the
    actual numbers in the finding for analyst review.
    """
    if len(label) < DGA_MIN_LABEL_LENGTH:
        return False, {}

    alpha_chars = [c for c in label.lower() if c.isalpha()]
    if len(alpha_chars) < DGA_MIN_LABEL_LENGTH * 0.6:
        # Mostly digits/hyphens — not the alphabetic-string pattern DGA
        # heuristics target; skip rather than produce a meaningless score.
        return False, {}

    entropy = _shannon_entropy(label.lower())
    vowel_ratio = sum(1 for c in alpha_chars if c in VOWELS) / len(alpha_chars)
    consonant_run = _max_consonant_run(label)
    digit_ratio = sum(1 for c in label if c.isdigit()) / len(label)

    features = {
        "length": len(label),
        "entropy": round(entropy, 2),
        "vowel_ratio": round(vowel_ratio, 2),
        "max_consonant_run": consonant_run,
        "digit_ratio": round(digit_ratio, 2),
    }

    # Require at least 2 of 3 independent signals to agree — single-signal
    # triggers (e.g. just high entropy) are too noisy on their own given
    # how common legitimately random subdomains are in practice.
    signals = [
        entropy >= DGA_ENTROPY_THRESHOLD,
        vowel_ratio <= DGA_MAX_VOWEL_RATIO,
        consonant_run >= DGA_MIN_CONSONANT_RUN,
    ]
    is_suspicious = sum(signals) >= 2
    return is_suspicious, features


def _registered_domain(fqdn: str) -> str:
    """
    Best-effort extraction of the registrable domain (e.g.
    'evil.sub.example.com' -> 'example.com') for allowlist matching.
    Not PSL-aware (doesn't know about co.uk-style multi-part TLDs) —
    good enough for allowlist checks, not for anything security-critical.
    """
    parts = fqdn.lower().strip(".").split(".")
    if len(parts) < 2:
        return fqdn.lower()
    return ".".join(parts[-2:])


def detect_dns_anomalies(add_finding, key: str, rows: list[dict]) -> None:
    """
    Analyze DNS query rows for DGA-pattern domains, NXDOMAIN bursts, and
    excessively long subdomains (a common DNS-tunneling indicator — exfil
    data encoded into subdomain labels pushes length well past normal use).
    """
    nxdomain_counter: Counter = Counter()
    query_counter: Counter = Counter()

    for idx, row in enumerate(rows):
        domain = (row.get("domain") or row.get("Domain") or
                  row.get("QueryName") or row.get("query") or
                  row.get("hostname") or "")
        domain = str(domain).strip().rstrip(".")
        if not domain or "." not in domain:
            continue

        rcode = str(row.get("rcode") or row.get("ResponseCode") or
                     row.get("status") or "").upper()
        qtype = str(row.get("type") or row.get("QueryType") or "").upper()

        evidence = {"row_index": idx, "domain": domain, "qtype": qtype, "rcode": rcode}

        registered = _registered_domain(domain)
        if registered in DGA_ALLOWLIST_DOMAINS:
            continue

        # DGA pattern check — score the leftmost label, which is where
        # generated content lives (e.g. 'xj3kf9z.evil-tld.com').
        first_label = domain.split(".")[0]
        is_dga, features = _looks_like_dga(first_label)
        if is_dga:
            add_finding(
                "command_and_control", "low",  # heuristic, not a verdict — see module docstring
                "DNS: domain resembles DGA pattern",
                f"Queried domain '{domain}' has DGA-like string characteristics: "
                f"entropy={features['entropy']}, vowel_ratio={features['vowel_ratio']}, "
                f"max_consonant_run={features['max_consonant_run']}. Heuristic flag — "
                f"corroborate with the requesting process and connection outcome before "
                f"treating as confirmed C2.",
                key, {**evidence, **features},
                score=35, mitre="T1568.002",  # Dynamic Resolution: DGA
            )

        # DNS tunneling indicator — abnormally long subdomain label, often
        # from encoding exfiltrated data into the query itself.
        if len(first_label) > 50:
            add_finding(
                "exfiltration", "medium",
                "DNS: abnormally long subdomain label",
                f"Domain '{domain}' has a {len(first_label)}-character first label — "
                f"unusually long for a legitimate hostname. Long subdomain labels are "
                f"a common DNS-tunneling pattern (data encoded into the query).",
                key, evidence,
                score=55, mitre="T1071.004",  # DNS as C2 channel
            )

        # TXT record queries are disproportionately used for DNS tunneling
        # and C2 (vs. the much more common A/AAAA queries for normal
        # browsing) — not inherently malicious, but worth surfacing as a
        # frequency signal rather than per-query noise.
        if qtype == "TXT":
            query_counter[("TXT", registered)] += 1

        if "NXDOMAIN" in rcode or rcode in ("3", "NAME_ERROR"):
            nxdomain_counter[registered] += 1

    # Burst of NXDOMAIN for the same registered domain — classic of a DGA
    # client cycling through generated candidates until one resolves.
    for domain, count in nxdomain_counter.most_common(10):
        if count >= 10:
            add_finding(
                "command_and_control", "medium",
                f"DNS: NXDOMAIN burst for {domain}",
                f"{count} NXDOMAIN responses for subdomains of '{domain}' — consistent "
                f"with a DGA client cycling through generated candidate domains until "
                f"one resolves to an active C2 server.",
                key, {"domain": domain, "nxdomain_count": count},
                score=60, mitre="T1568.002",
            )

    # High volume of TXT queries to the same domain — tunneling/exfil signal
    for (qtype, domain), count in query_counter.most_common(10):
        if count >= 20:
            add_finding(
                "exfiltration", "medium",
                f"DNS: high volume of TXT queries to {domain}",
                f"{count} TXT-type DNS queries to '{domain}' — TXT queries are "
                f"disproportionately used for DNS tunneling/C2 compared to normal "
                f"browsing traffic (which is dominated by A/AAAA queries).",
                key, {"domain": domain, "txt_query_count": count},
                score=55, mitre="T1071.004",
            )


# ══════════════════════════════════════════════════
# Advanced authentication pattern analysis
# ══════════════════════════════════════════════════

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


def detect_auth_patterns(add_finding, key: str, rows: list[dict]) -> None:
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
                add_finding(
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
            add_finding(
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
                    add_finding(
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
