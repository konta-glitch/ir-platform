"""
app/yara_scanner.py — YARA content scanning for collected files.

This fills the single biggest detection gap identified in the DFIR tool
comparison: every serious DFIR tool (Cyber Triage, THOR, Loki,
Velociraptor) scans the CONTENT of collected files against malware
patterns, but our engine previously only looked at file METADATA (path,
name, hash collisions). A planted binary that doesn't trip any heuristic
path/cmdline rule was invisible to us; a YARA hit on the file's bytes
catches known-bad patterns inside it.

Design:
  - Compiles every .yar/.yara file in the rules directory once at startup
    (compilation is the expensive part; scanning is cheap).
  - scan_bytes() works directly on in-memory bytes, so it can scan ZIP
    members without extracting them to disk — matches how the collector
    already reads EVTX/registry files straight from the archive.
  - Each rule's meta.severity / meta.mitre flow straight into the finding,
    so a hit maps to a detection finding without guessing.

100% offline — no API keys, no network. Consistent with the platform's
local-first design. To expand coverage, drop a public ruleset (YARA-Forge,
signature-base) into the rules directory; no code change needed.
"""

from __future__ import annotations
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Files larger than this are skipped — YARA scanning multi-hundred-MB files
# is slow and rarely useful for the string/byte patterns these rules target
# (malware payloads are typically small). Tunable.
MAX_SCAN_SIZE = 50 * 1024 * 1024  # 50 MB

# Path fragments for known security/EDR/AV/forensic software. These products
# legitimately CONTAIN malware-pattern strings (PowerShell-attack signatures,
# Mimikatz indicators, etc.) because detecting those patterns is their whole
# job — so YARA string rules fire on them constantly as false positives.
# Skipping them at the path level is standard DFIR practice (THOR/Loki ship
# extensive allowlists for exactly this). Matched case-insensitively as a
# substring of the full file path.
#
# NOTE: this is deliberately a SKIP-SCAN allowlist, not a "trust everything
# here" rule — if an attacker plants malware OUTSIDE these vendor folders,
# it's still scanned. The risk of a planted binary INSIDE a genuine
# SentinelOne/Defender install folder is low (those dirs are protected), and
# is far outweighed by the false-positive noise of scanning EDR binaries.
SECURITY_SOFTWARE_PATH_ALLOWLIST = (
    "\\sentinelone\\", "/sentinelone/", "sentinel agent",
    "\\windows defender\\", "/windows defender/",
    "\\microsoft\\windows defender", "/microsoft/windows defender",
    "\\crowdstrike\\", "/crowdstrike/",
    "\\carbon black\\", "/carbon black/", "\\carbonblack\\",
    "\\cylance\\", "/cylance/",
    "\\cortex xdr\\", "/cortex xdr/", "\\palo alto networks\\",
    "\\sophos\\", "/sophos/",
    "\\eset\\", "/eset/",
    "\\bitdefender\\", "/bitdefender/",
    "\\malwarebytes\\", "/malwarebytes/",
    "\\trend micro\\", "/trend micro/",
    "\\mcafee\\", "/mcafee/",
    "\\symantec\\", "/symantec/",
    "\\kaspersky\\", "/kaspersky/",
    "\\huntress\\", "/huntress/",
    "\\wazuh\\", "/wazuh/",
    "\\velociraptor\\", "/velociraptor/",
)

# File extensions worth scanning. We scan executables, scripts, and
# documents that can carry payloads — not media/data files where a YARA
# string hit would almost always be a false positive.
SCANNABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".ocx",
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".bat", ".cmd", ".hta", ".jar", ".msi", ".lnk",
    ".php", ".asp", ".aspx", ".jsp", ".jspx",  # webshells
    ".dat", ".bin", ".tmp",  # generic payload containers
}


class YaraScanner:
    """Compiles YARA rules once and scans file content against them."""

    def __init__(self, rules_dir: str = "/app/yara_rules"):
        self.rules_dir = Path(rules_dir)
        self.rules = None
        self.rule_count = 0
        self._compile_rules()

    def _compile_rules(self) -> None:
        """Compile all .yar/.yara files in the rules directory."""
        try:
            import yara
        except ImportError:
            logger.warning("yara-python not installed — YARA scanning disabled")
            return

        if not self.rules_dir.exists():
            logger.warning(f"YARA rules dir not found: {self.rules_dir} — scanning disabled")
            return

        rule_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))
        if not rule_files:
            logger.warning(f"No .yar/.yara files in {self.rules_dir} — scanning disabled")
            return

        # Many real-world rulesets (YARA-Forge, signature-base) reference
        # external variables that the scanning host is expected to provide
        # — most commonly filename/filepath/extension/filetype. Declaring
        # them at compile time (with placeholder values) lets those rules
        # COMPILE; we then pass the real per-file values at scan time. Without
        # this, every rule using these variables fails to compile and gets
        # skipped, which would silently drop a large fraction of a real
        # ruleset.
        self._externals = {
            "filename": "", "filepath": "", "extension": "",
            "filetype": "", "owner": "", "md5": "",
        }

        # yara.compile with filepaths={} compiles multiple rule files into
        # one ruleset. Namespacing by filename keeps rule-name collisions
        # across different rulesets from clobbering each other.
        filepaths = {f.stem: str(f) for f in rule_files}
        try:
            self.rules = yara.compile(filepaths=filepaths, externals=self._externals)
            # Count rules for logging (iterate the compiled set once)
            self.rule_count = sum(1 for _ in self.rules)
            logger.info(f"YARA: compiled {len(rule_files)} rule file(s) from {self.rules_dir}")
        except yara.Error as e:
            # A single malformed ruleset shouldn't take down the whole
            # scanner — try compiling files one at a time, skipping bad ones.
            logger.warning(f"YARA: bulk compile failed ({e}); trying files individually")
            self._compile_individually(rule_files)

    def _compile_individually(self, rule_files: list) -> None:
        """Fallback: compile each rule file alone so one bad file doesn't disable all."""
        import yara
        good = {}
        for f in rule_files:
            try:
                yara.compile(filepath=str(f), externals=self._externals)  # test it compiles
                good[f.stem] = str(f)
            except yara.Error as e:
                logger.warning(f"YARA: skipping un-compilable rule file {f.name}: {e}")
        if good:
            try:
                self.rules = yara.compile(filepaths=good, externals=self._externals)
                self.rule_count = sum(1 for _ in self.rules)
                logger.info(f"YARA: compiled {len(good)} of {len(rule_files)} rule file(s)")
            except yara.Error as e:
                logger.error(f"YARA: compilation failed entirely: {e}")

    @property
    def available(self) -> bool:
        return self.rules is not None

    def should_scan(self, filename: str, size: int) -> bool:
        """Decide whether a file is worth scanning (extension + size + allowlist)."""
        if not self.available:
            return False
        if size <= 0 or size > MAX_SCAN_SIZE:
            return False
        # Skip known security-software install paths — their binaries
        # legitimately contain malware-pattern strings (see allowlist
        # comment) and produce only false positives.
        fl = filename.lower()
        if any(frag in fl for frag in SECURITY_SOFTWARE_PATH_ALLOWLIST):
            return False
        ext = Path(filename).suffix.lower()
        return ext in SCANNABLE_EXTENSIONS

    def scan_bytes(self, data: bytes, filename: str = "") -> list[dict]:
        """
        Scan raw bytes against the compiled ruleset. Returns a list of
        finding-shaped dicts (one per matched rule), empty if no match or
        scanning unavailable.
        """
        if not self.available or not data:
            return []

        # Provide real per-file values for the external variables declared
        # at compile time, so rules that gate on filename/extension/etc.
        # evaluate correctly instead of always seeing empty strings.
        base = filename.replace("\\", "/").split("/")[-1]
        ext = Path(base).suffix.lower().lstrip(".")
        scan_externals = {
            "filename": base,
            "filepath": filename,
            "extension": ext,
            "filetype": "",
            "owner": "",
            "md5": "",
        }

        try:
            matches = self.rules.match(data=data, externals=scan_externals)
        except Exception as e:
            logger.debug(f"YARA scan error on {filename}: {e}")
            return []

        results = []
        for m in matches:
            meta = m.meta or {}
            # Pull a few matched strings as evidence (capped, decoded safely)
            sample_strings = []
            for s in getattr(m, "strings", [])[:3]:
                try:
                    # yara-python 4.3+ StringMatch object
                    ident = s.identifier
                    for inst in s.instances[:1]:
                        snippet = bytes(inst.matched_data[:40]).decode("utf-8", errors="replace")
                        sample_strings.append(f"{ident}={snippet!r}")
                except AttributeError:
                    # Older yara-python tuple format (offset, identifier, data)
                    try:
                        _, ident, matched = s
                        snippet = bytes(matched[:40]).decode("utf-8", errors="replace")
                        sample_strings.append(f"{ident}={snippet!r}")
                    except Exception:
                        pass

            results.append({
                "rule": m.rule,
                "severity": meta.get("severity", "medium"),
                "mitre": meta.get("mitre", ""),
                "description": meta.get("description", m.rule),
                "filename": filename,
                "matched_strings": sample_strings,
                "tags": list(m.tags) if m.tags else [],
            })
        return results
