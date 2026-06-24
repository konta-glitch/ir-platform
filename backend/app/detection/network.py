"""
detection/network.py — network connection detection: suspicious ports,
beaconing patterns.

DNS-specific analysis (DGA, NXDOMAIN bursts, tunneling) lives in
detection/dns_dga.py — kept separate because DNS query rows have a
completely different shape than connection rows (domain/rcode/qtype vs.
local/remote addr + state), even though both are "network" in a broad
sense.
"""

from __future__ import annotations
import re
from collections import Counter

# Known suspicious ports (C2, common malware)
SUSPICIOUS_PORTS = {
    4444: "Metasploit default", 5555: "Common backdoor",
    1337: "Common backdoor", 31337: "Back Orifice",
    6666: "Common IRC bot", 6667: "IRC",
    8080: "Common HTTP proxy/C2", 8443: "Alt HTTPS/C2",
    9001: "Tor", 9050: "Tor SOCKS",
    1080: "SOCKS proxy", 3389: "RDP (lateral movement)",
    5985: "WinRM HTTP", 5986: "WinRM HTTPS",
}


def detect_network(engine, key: str, rows: list[dict]) -> None:
    remote_counter = Counter()
    for idx, conn in enumerate(rows):
        raddr = engine._get(conn, ["Raddr", "RemoteAddress", "remote", "remote_address", "ForeignAddress"])
        laddr = engine._get(conn, ["Laddr", "LocalAddress", "local", "local_address"])
        state = engine._get(conn, ["Status", "State", "state"])
        pid = engine._get(conn, ["Pid", "pid", "OwningProcess"])
        proc = engine._get(conn, ["Name", "Process", "process_name"])

        # Extract remote port
        rport = None
        port_match = re.search(r":(\d+)$", str(raddr))
        if port_match:
            rport = int(port_match.group(1))

        evidence = {
            "row_index": idx, "local": laddr, "remote": raddr,
            "state": state, "pid": pid, "process": proc,
        }

        if rport in SUSPICIOUS_PORTS:
            engine._add_finding(
                "network_anomaly", "high",
                f"Connection to suspicious port {rport}",
                f"Process '{proc}' (PID {pid}) connected to {raddr} — {SUSPICIOUS_PORTS[rport]}",
                key, evidence,
                score=70, mitre="T1571",  # Non-Standard Port
            )

        # Track remote addresses for beaconing detection
        if raddr and "ESTABLISHED" in str(state).upper():
            ip_only = re.sub(r":\d+$", "", str(raddr))
            if ip_only and not ip_only.startswith(("127.", "0.0", "::", "[::")):
                remote_counter[ip_only] += 1

    # Beaconing: many connections to same remote
    for ip, count in remote_counter.most_common(10):
        if count >= 5:
            engine._add_finding(
                "network_anomaly", "medium",
                f"Potential beaconing to {ip}",
                f"{count} connections to the same remote host {ip} — possible C2 beaconing",
                key, {"remote": ip, "connection_count": count},
                score=55, mitre="T1071",  # Application Layer Protocol
            )
