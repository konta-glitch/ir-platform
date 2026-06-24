"""
detection/textlogs.py — detection for generic text-based log formats.

Handles artifacts ingested from:
  - Linux syslog / auth.log / kern.log
  - Apache / Nginx / IIS access logs (Combined Log Format)
  - Suricata EVE JSON (alerts)
  - Zeek conn.log / dns.log / http.log (TSV)
  - CSV exports from SIEMs (Splunk, Elastic, QRadar)
  - Generic firewall logs (key=value or space-delimited)
  - Any raw .log / .txt file

The approach: run a fast keyword/regex scan to generate structured findings
comparable to what Sigma or sysmon.py produce for EVTX. Results flow into
the same finding pipeline, so Sigma scoring, correlation, narrative pass,
and the report all work unchanged.

Add new log types by adding an entry to LOG_PARSERS — the dispatch loop
auto-picks the best parser based on content sniffing.
"""

from __future__ import annotations

import re
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Severity helpers ────────────────────────────────────────────────────────

def _sev(keyword: str) -> str:
    k = keyword.lower()
    if any(w in k for w in ("critical", "emerg", "alert", "crit")):
        return "critical"
    if any(w in k for w in ("error", "err", "fail", "denied", "refused",
                             "attack", "exploit", "malware", "trojan",
                             "rootkit", "injection", "shell", "exec")):
        return "high"
    if any(w in k for w in ("warn", "warning", "notice", "suspicious",
                             "invalid", "blocked", "drop", "reject")):
        return "medium"
    return "low"


# ── Suricata EVE JSON parser ────────────────────────────────────────────────

_SURICATA_CATEGORIES = {
    "ET EXPLOIT": ("high",  "T1190"),
    "ET MALWARE": ("high",  "T1059"),
    "ET SCAN":    ("medium","T1046"),
    "ET POLICY":  ("medium","T1071"),
    "ET TROJAN":  ("high",  "T1105"),
    "ET INFO":    ("low",   "T1071"),
}

def _parse_suricata_eve(rows: list[dict]) -> list[dict]:
    findings = []
    for row in rows:
        raw = row.get("raw", "")
        try:
            evt = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            continue

        if evt.get("event_type") != "alert":
            continue

        alert = evt.get("alert", {})
        sig   = alert.get("signature", "Unknown Suricata alert")
        cat   = alert.get("category", "")
        src   = evt.get("src_ip", "")
        dst   = evt.get("dest_ip", "")
        dport = evt.get("dest_port", "")
        proto = evt.get("proto", "")
        ts    = evt.get("timestamp", "")

        sev, mitre = "medium", "T1071"
        for prefix, (s, m) in _SURICATA_CATEGORIES.items():
            if sig.startswith(prefix):
                sev, mitre = s, m
                break

        findings.append({
            "category":    "network_anomaly",
            "severity":    sev,
            "mitre":       mitre,
            "name":        sig,
            "description": (
                f"Suricata alert: {sig} | "
                f"{src} → {dst}:{dport} ({proto})"
            ),
            "timestamp":   ts,
            "evidence": {
                "source_ip":   src,
                "dest_ip":     dst,
                "dest_port":   str(dport),
                "protocol":    proto,
                "signature":   sig,
                "category":    cat,
                "severity_id": alert.get("severity", ""),
            },
        })
    return findings


# ── Apache / Nginx Combined Log Format parser ───────────────────────────────

# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
_APACHE_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

_SUSPICIOUS_PATHS = re.compile(
    r'(\.\./|%2e%2e|%00|/etc/passwd|/etc/shadow|cmd\.exe|/bin/sh'
    r'|phpinfo|eval\(|base64_decode|union.*select|<script'
    r'|\.php\?.*=http|/wp-admin|/xmlrpc\.php|/shell\.|/webshell)',
    re.IGNORECASE
)

def _parse_apache(rows: list[dict]) -> list[dict]:
    findings = []
    for row in rows:
        line = row.get("raw", "")
        m = _APACHE_RE.match(line)
        if not m:
            continue

        status = m.group("status")
        path   = m.group("path")
        ip     = m.group("ip")
        method = m.group("method")
        ts     = m.group("ts")

        # Only flag anomalous requests
        if status.startswith("4") or status.startswith("5") or _SUSPICIOUS_PATHS.search(path):
            sev = "high" if (_SUSPICIOUS_PATHS.search(path) or status == "500") else "medium"
            findings.append({
                "category":    "network_anomaly",
                "severity":    sev,
                "mitre":       "T1190",
                "name":        f"HTTP {status} — {method} {path[:80]}",
                "description": (
                    f"Web server {status} response: {method} {path} from {ip}"
                ),
                "timestamp":   ts,
                "evidence": {
                    "source_ip":  ip,
                    "method":     method,
                    "path":       path,
                    "status":     status,
                },
            })
    return findings


# ── Zeek TSV log parser (conn.log, dns.log, http.log) ──────────────────────

def _parse_zeek(rows: list[dict], log_type: str) -> list[dict]:
    """
    Zeek logs have a #fields header line. We parse that once and use it
    as the column mapping. rows already have raw line strings.
    """
    findings = []
    fields: list[str] = []

    for row in rows:
        line = row.get("raw", "")
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not fields:
            continue

        parts = line.split("\t")
        rec = dict(zip(fields, parts))

        if log_type == "conn":
            # Flag large transfers, unusual protocols, long durations
            try:
                orig_bytes = int(rec.get("orig_bytes", 0) or 0)
                resp_bytes = int(rec.get("resp_bytes", 0) or 0)
                duration   = float(rec.get("duration", 0) or 0)
            except (ValueError, TypeError):
                orig_bytes = resp_bytes = 0
                duration = 0.0

            proto    = rec.get("proto", "")
            dst_port = rec.get("id.resp_p", "")
            src_ip   = rec.get("id.orig_h", "")
            dst_ip   = rec.get("id.resp_h", "")
            state    = rec.get("conn_state", "")

            suspicious = (
                orig_bytes > 50_000_000
                or resp_bytes > 50_000_000
                or (proto == "tcp" and dst_port in ("4444", "1337", "31337", "9001", "8888"))
                or (duration > 3600 and orig_bytes > 1_000_000)
            )
            if suspicious:
                findings.append({
                    "category":    "network_anomaly",
                    "severity":    "high" if dst_port in ("4444", "1337", "31337") else "medium",
                    "mitre":       "T1041" if orig_bytes > 50_000_000 else "T1071",
                    "name":        f"Zeek: suspicious connection {src_ip}→{dst_ip}:{dst_port}",
                    "description": (
                        f"Zeek conn.log: {src_ip}→{dst_ip}:{dst_port} ({proto}) "
                        f"sent {orig_bytes:,}B recv {resp_bytes:,}B state={state}"
                    ),
                    "timestamp":   rec.get("ts", ""),
                    "evidence":    rec,
                })

        elif log_type == "dns":
            query  = rec.get("query", "")
            qtype  = rec.get("qtype_name", "")
            answer = rec.get("answers", "")
            src_ip = rec.get("id.orig_h", "")

            # Flag long domains (DGA), TXT queries (C2/exfil), non-standard qtypes
            dga_signal = len(query) > 50 or query.count(".") > 5
            if dga_signal or qtype in ("TXT", "NULL", "ANY"):
                findings.append({
                    "category":    "network_anomaly",
                    "severity":    "medium",
                    "mitre":       "T1568" if dga_signal else "T1071.004",
                    "name":        f"Zeek DNS: suspicious query {query[:60]}",
                    "description": (
                        f"DNS {qtype} query for '{query}' from {src_ip} "
                        f"→ {answer[:80]}"
                    ),
                    "timestamp":   rec.get("ts", ""),
                    "evidence":    {"query": query, "qtype": qtype,
                                    "answer": answer, "src": src_ip},
                })

        elif log_type == "http":
            uri    = rec.get("uri", "")
            method = rec.get("method", "")
            host   = rec.get("host", "")
            ua     = rec.get("user_agent", "")
            status = rec.get("status_code", "")
            src_ip = rec.get("id.orig_h", "")

            if _SUSPICIOUS_PATHS.search(uri) or (method in ("PUT", "DELETE") and not host):
                findings.append({
                    "category":    "network_anomaly",
                    "severity":    "high",
                    "mitre":       "T1190",
                    "name":        f"Zeek HTTP: suspicious {method} {uri[:60]}",
                    "description": (
                        f"Zeek http.log: {method} http://{host}{uri} from {src_ip} "
                        f"status={status} UA={ua[:40]}"
                    ),
                    "timestamp":   rec.get("ts", ""),
                    "evidence":    {"uri": uri, "method": method, "host": host,
                                    "status": status, "user_agent": ua, "src": src_ip},
                })

    return findings


# ── Generic syslog / auth.log parser ───────────────────────────────────────

_AUTH_PATTERNS = [
    (re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)',    re.I), "high",   "T1110.001", "SSH brute-force / failed password"),
    (re.compile(r'Accepted (?:password|publickey) for (\S+) from (\S+)',      re.I), "low",    "T1078",     "SSH successful login"),
    (re.compile(r'Invalid user (\S+) from (\S+)',                             re.I), "medium", "T1110.003", "SSH invalid user enumeration"),
    (re.compile(r'sudo:\s+(\S+) : .*COMMAND=(.*)',                            re.I), "medium", "T1548.003", "Sudo command execution"),
    (re.compile(r'useradd|groupadd|usermod|passwd (?!:)',                     re.I), "high",   "T1136.001", "User/group modification"),
    (re.compile(r'crontab|at\.allow|/etc/cron',                              re.I), "medium", "T1053.003", "Cron persistence"),
    (re.compile(r'segfault|kernel BUG|Oops|panic',                           re.I), "medium", "T1499",     "Kernel error / crash"),
    (re.compile(r'iptables|ufw|firewalld',                                   re.I), "low",    "T1562.004", "Firewall rule change"),
    (re.compile(r'insmod|modprobe|rmmod',                                    re.I), "high",   "T1547.006", "Kernel module load/unload"),
    (re.compile(r'(chmod|chown)\s+[0-9]*7[0-9]*\s',                        re.I), "medium", "T1222",     "Permissive file permission change"),
]

def _parse_syslog(rows: list[dict]) -> list[dict]:
    findings = []
    for row in rows:
        line = row.get("raw", "")
        ts   = row.get("timestamp", "")

        for pattern, sev, mitre, label in _AUTH_PATTERNS:
            m = pattern.search(line)
            if m:
                groups = m.groups()
                user = groups[0] if groups else ""
                src  = groups[1] if len(groups) > 1 else ""
                findings.append({
                    "category":    "process_anomaly" if "sudo" in label.lower() else "credential_access",
                    "severity":    sev,
                    "mitre":       mitre,
                    "name":        label,
                    "description": line[:200].strip(),
                    "timestamp":   ts,
                    "evidence":    {"user": user, "source": src, "raw": line[:300]},
                })
                break  # one match per line is enough

    return findings


# ── CSV / SIEM export parser ────────────────────────────────────────────────

_CSV_SECURITY_KEYWORDS = re.compile(
    r'fail|error|deny|block|attack|malware|exploit|trojan|shell|inject'
    r'|privilege|escalat|lateral|mimikatz|credential|dump|ransomware'
    r'|suspicious|alert|critical|high.sever',
    re.IGNORECASE
)

def _parse_csv_rows(rows: list[dict]) -> list[dict]:
    """
    Generic CSV: treat each row as a structured record and look for
    security-relevant fields. Works with Splunk exports, QRadar exports,
    custom SIEM CSVs, etc.
    """
    findings = []
    for row in rows:
        # Skip rows that are themselves the raw string
        if not isinstance(row, dict):
            continue
        # Build a flat searchable string from all values
        flat = " ".join(str(v) for v in row.values() if v)
        if not _CSV_SECURITY_KEYWORDS.search(flat):
            continue

        # Try to extract standard fields by common column names
        ts       = (row.get("timestamp") or row.get("time") or
                    row.get("EventTime") or row.get("_time") or "")
        severity = (row.get("severity") or row.get("Severity") or
                    row.get("priority") or "")
        message  = (row.get("message") or row.get("Message") or
                    row.get("description") or row.get("EventData") or flat[:200])
        src_ip   = (row.get("src_ip") or row.get("SourceIP") or
                    row.get("src") or "")

        sev = _sev(severity or message)
        findings.append({
            "category":    "sigma_detection",
            "severity":    sev,
            "mitre":       "",
            "name":        message[:80],
            "description": message[:300],
            "timestamp":   str(ts),
            "evidence":    {k: str(v)[:100] for k, v in row.items()},
        })
    return findings


# ── Content sniffer — auto-detect log type ─────────────────────────────────

def _sniff_log_type(rows: list[dict], artifact_key: str) -> str:
    """Detect log format from content or artifact key name."""
    key = artifact_key.lower()

    # Key name hints
    if "suricata" in key or "eve" in key:
        return "suricata"
    if "zeek" in key or "bro" in key:
        if "conn" in key:    return "zeek_conn"
        if "dns" in key:     return "zeek_dns"
        if "http" in key:    return "zeek_http"
        return "zeek_conn"
    if "apache" in key or "nginx" in key or "iis" in key or "access" in key:
        return "apache"
    if "auth" in key or "secure" in key or "syslog" in key:
        return "syslog"
    if "csv" in key or "siem" in key or "splunk" in key or "elastic" in key:
        return "csv"

    # Content sniff — look at first few rows
    sample = [r.get("raw", "") for r in rows[:20] if isinstance(r, dict)]
    sample_str = "\n".join(sample)

    if '"event_type":"alert"' in sample_str or '"alert":{' in sample_str:
        return "suricata"
    if "#fields\tts\t" in sample_str:
        if "id.orig_h" in sample_str and "id.resp_h" in sample_str:
            if "query" in sample_str:   return "zeek_dns"
            if "uri" in sample_str:     return "zeek_http"
            return "zeek_conn"
    if _APACHE_RE.search(sample_str):
        return "apache"
    if re.search(r'(Failed password|Accepted password|Invalid user|sudo:)', sample_str):
        return "syslog"
    if rows and isinstance(rows[0], dict) and "raw" not in rows[0]:
        return "csv"

    return "syslog"  # safe default for unknown text logs


# ── Main entry point called by detection routing ───────────────────────────

def detect_textlogs(engine: Any, key: str, rows: list[dict]) -> list[dict]:
    """
    Entry point registered in detection/__init__.py for text-based log formats.
    Called automatically whenever an artifact key matches the route patterns.
    """
    if not rows:
        return []

    log_type = _sniff_log_type(rows, key)
    logger.info(f"detect_textlogs: key={key!r} → detected type={log_type} ({len(rows)} rows)")

    if log_type == "suricata":
        raw_findings = _parse_suricata_eve(rows)
    elif log_type == "apache":
        raw_findings = _parse_apache(rows)
    elif log_type.startswith("zeek_"):
        raw_findings = _parse_zeek(rows, log_type.split("_")[1])
    elif log_type == "syslog":
        raw_findings = _parse_syslog(rows)
    elif log_type == "csv":
        raw_findings = _parse_csv_rows(rows)
    else:
        raw_findings = _parse_syslog(rows)

    if not raw_findings:
        logger.info(f"detect_textlogs: no findings from {key!r}")
        return []

    logger.info(f"detect_textlogs: {len(raw_findings)} findings from {key!r} ({log_type})")

    # Normalise to the Finding schema the engine expects
    findings = []
    for i, f in enumerate(raw_findings):
        findings.append({
            "id":          f"TL{i:04d}",
            "category":    f.get("category", "sigma_detection"),
            "severity":    f.get("severity", "medium"),
            "mitre":       f.get("mitre", ""),
            "name":        f.get("name", "Log finding"),
            "description": f.get("description", ""),
            "timestamp":   f.get("timestamp", ""),
            "source":      key,
            "evidence":    f.get("evidence", {}),
            "count":       1,
        })

    return findings
