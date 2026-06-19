"""
detection/dns_dga.py — DNS query analysis: DGA pattern detection, NXDOMAIN
bursts, DNS tunneling indicators.

The original detection_engine had no domain-specific rules at all — only
IP-based C2 port/beaconing checks. Malware increasingly uses Domain
Generation Algorithms (DGA) and DNS tunneling, neither of which involves a
"suspicious port" an IP-based rule would catch.
"""

from __future__ import annotations
import math
import re
import logging
from collections import Counter

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


def detect_dns_anomalies(engine, key: str, rows: list[dict]) -> None:
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
            engine._add_finding(
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
            engine._add_finding(
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
            engine._add_finding(
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
            engine._add_finding(
                "exfiltration", "medium",
                f"DNS: high volume of TXT queries to {domain}",
                f"{count} TXT-type DNS queries to '{domain}' — TXT queries are "
                f"disproportionately used for DNS tunneling/C2 compared to normal "
                f"browsing traffic (which is dominated by A/AAAA queries).",
                key, {"domain": domain, "txt_query_count": count},
                score=55, mitre="T1071.004",
            )
