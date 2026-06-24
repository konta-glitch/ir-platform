"""
Comprehensive Company Data Anonymizer

Strips ALL identifiers that could reveal company infrastructure:
  - Private/internal IP addresses (10.x, 172.16-31.x, 192.168.x)
  - Public IP addresses
  - Computer/hostnames (NetBIOS, FQDN)
  - Windows identities (DOMAIN\\user, user@domain, SIDs)
  - UNC paths (\\\\server\\share)
  - File paths with usernames
  - Active Directory objects (DN, OU, GPO, groups)
  - MAC addresses
  - Internal email addresses
  - Internal URLs and domain names
  - Certificate subjects, service names, share names

Two-pass approach:
  1. Regex: catches structural patterns
  2. Local LLM: catches contextual identifiers regex missed
"""

import re
import json
import logging
from typing import Any

from app.config import get_settings
from app.lm_client import get_lm_client
from app.models import AnonymizationMapping, AnonymizationResult

logger = logging.getLogger(__name__)

# ═════════════════════════════════════════════
# Exclusion lists
# ═════════════════════════════════════════════

SAFE_IPS = {"127.0.0.1", "0.0.0.0", "::1", "255.255.255.255"}

SYSTEM_ACCOUNTS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "NT AUTHORITY",
    "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE",
    "NT AUTHORITY\\NETWORK SERVICE", "BUILTIN",
    "Everyone", "Authenticated Users", "INTERACTIVE", "SERVICE",
    "ANONYMOUS LOGON", "IUSR", "DefaultAccount", "Guest",
    "root", "nobody", "daemon", "www-data", "sshd",
}

SYSTEM_SID_PREFIXES = {
    "S-1-0", "S-1-1", "S-1-2", "S-1-3", "S-1-5-1", "S-1-5-2",
    "S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-5-7", "S-1-5-8",
    "S-1-5-9", "S-1-5-10", "S-1-5-11", "S-1-5-12", "S-1-5-13",
    "S-1-5-14", "S-1-5-15", "S-1-5-17", "S-1-5-18", "S-1-5-19",
    "S-1-5-20", "S-1-5-32", "S-1-5-64", "S-1-5-80", "S-1-5-83",
    "S-1-5-90", "S-1-5-113", "S-1-5-114",
}

KNOWN_EXTERNAL_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com",
    "google.com", "googleapis.com", "apple.com", "icloud.com",
    "amazon.com", "amazonaws.com", "cloudflare.com",
    "github.com", "githubusercontent.com",
    "ubuntu.com", "debian.org", "office.com", "outlook.com",
    "virustotal.com", "abuse.ch", "verisign.com", "digicert.com",
}

SYSTEM_PROCESSES = {
    "system", "idle", "svchost.exe", "services.exe", "lsass.exe",
    "csrss.exe", "wininit.exe", "winlogon.exe", "smss.exe",
    "explorer.exe", "dwm.exe", "taskhostw.exe", "spoolsv.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe",
    "systemd", "init", "kthreadd", "cron", "sshd", "bash", "sh",
}


# ═════════════════════════════════════════════
# Regex patterns — ordered by specificity
# ═════════════════════════════════════════════

PATTERNS = [
    # ── Windows identity ──
    ("ad_identity",
     r"(?<![A-Za-z\\])([A-Z][A-Z0-9_-]{1,15})\\([a-zA-Z][a-zA-Z0-9._-]{0,30})", 0),
    ("upn_identity",
     r"\b([a-zA-Z][a-zA-Z0-9._-]{0,30})@([a-zA-Z0-9-]+\.(?:local|internal|corp|lan|ad|intra|pri|domain)(?:\.[a-zA-Z]{2,})?)\b", 0),
    ("sid",
     r"\bS-1-5-21-\d{8,12}-\d{8,12}-\d{8,12}(?:-\d{1,10})?\b", 0),

    # ── Private IPs ──
    ("private_ip",
     r"\b10\.(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){2}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", 0),
    ("private_ip",
     r"\b172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.\d{1,3})\b", 0),
    ("private_ip",
     r"\b192\.168\.\d{1,3}\.\d{1,3}\b", 0),
    ("private_ip",
     r"\b169\.254\.\d{1,3}\.\d{1,3}\b", 0),

    # ── Public IPs ──
    ("public_ip",
     r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", 0),

    # ── IPv6 ──
    ("ipv6", r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b", 0),
    ("private_ipv6", r"\bfd[0-9a-fA-F]{2}(?::[0-9a-fA-F]{1,4}){1,7}\b", 0),

    # MAC
    ("mac_address", r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", 0),

    # Subnets in CIDR
    ("subnet",
     r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}/\d{1,2}\b", 0),

    # ── Paths ──
    ("unc_path", r"\\\\[A-Za-z0-9._-]+(?:\\[A-Za-z0-9$._\\ -]+)+", 0),
    ("user_path_win", r"[Cc]:\\[Uu]sers\\([A-Za-z0-9._-]+)", 0),
    ("user_path_linux", r"/home/([a-z_][a-z0-9_-]{0,30})", 0),
    ("registry_user",
     r"(?:HKEY_USERS|HKU)\\(?:S-1-5-21-[\d-]+|[A-Za-z0-9._-]+)", 0),

    # ── AD / LDAP ──
    ("ldap_dn",
     r"(?:CN|OU|DC)=[^,;\n]+(?:,\s*(?:CN|OU|DC)=[^,;\n]+){1,}", re.IGNORECASE),
    ("gpo_guid",
     r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}", 0),

    # ── Email & domains ──
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 0),
    ("internal_fqdn",
     r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]+)*\.(?:local|internal|corp|lan|ad|intra|pri|domain)\b",
     re.IGNORECASE),
    ("external_fqdn",
     r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]+)*\.(?:com|org|net|io|gov|edu|co|info|biz|us|uk|de|fr|ru|cn|jp|au)\b",
     re.IGNORECASE),

    # ── Computer names ──
    ("computer_name",
     r"\b(?:DESKTOP|LAPTOP|SRV|SERVER|PC|WS|WORKSTATION|DC|VM|VDI|NB|HOST|NODE|WIN|APP|WEB|DB|FS|PS|TS|RDP|PRINT|EXCH|SQL|MAIL|DNS|DHCP|AD|CA|PKI|SCCM|WSUS|HV|ESX|NAS|SAN)[-_][A-Z0-9]{2,15}\b", 0),
    ("hostname",
     r"\b(?=[A-Z0-9-]{4,15}\b)(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*[0-9])[A-Z][A-Z0-9-]{3,14}\b", 0),
]


class Anonymizer:
    """Comprehensive anonymizer for all company identifiers."""

    def __init__(self):
        self.settings = get_settings()
        self._mappings: dict[str, AnonymizationMapping] = {}
        self._counter: dict[str, int] = {}

    def _make_placeholder(self, category: str, original: str) -> str:
        key = f"{category}:{original}"
        if key in self._mappings:
            return self._mappings[key].anonymized
        self._counter.setdefault(category, 0)
        self._counter[category] += 1
        idx = self._counter[category]
        placeholders = {
            "private_ip": f"10.0.{idx}.{idx}",
            "public_ip": f"203.0.113.{idx}",
            "ipv6": f"2001:db8::{idx}",
            "private_ipv6": f"fd00:db8::{idx}",
            "mac_address": f"00:00:5E:00:53:{idx:02X}",
            "subnet": f"10.0.{idx}.0/24",
            "ad_identity": f"YOURDOM\\user_{idx}",
            "upn_identity": f"user_{idx}@yourdom.local",
            "sid": f"S-1-5-21-0000000000-0000000000-0000000000-{1000+idx}",
            "email": f"user{idx}@redacted.example",
            "computer_name": f"HOST-YOURCO{idx:02d}",
            "hostname": f"YOURHOST{idx:02d}",
            "internal_fqdn": f"host{idx}.yourdom.local",
            "external_fqdn": f"redacted{idx}.example.com",
            "unc_path": f"\\\\YOURSERVER{idx}\\share$",
            "user_path_win": f"C:\\Users\\youruser{idx}",
            "user_path_linux": f"/home/youruser{idx}",
            "registry_user": f"HKU\\S-1-5-21-REDACTED-{1000+idx}",
            "ldap_dn": f"CN=Redacted{idx},OU=YourOU,DC=yourdom,DC=local",
            "gpo_guid": f"{{00000000-0000-0000-0000-{idx:012d}}}",
            "organization": f"YOURORG{idx}",
            "department": f"YOURDEPT{idx}",
            "project_name": f"YOURPROJECT{idx}",
            "app_name": f"YOURAPP{idx}",
            "location": f"YOURLOCATION{idx}",
            "person_name": f"Person{idx}",
            "phone": f"+1-555-000-{idx:04d}",
            "wifi_ssid": f"YOURWIFI{idx}",
            "printer": f"YOURPRINTER{idx}",
            "service_name": f"YourService{idx}",
            "share_name": f"YourShare{idx}$",
            "group_name": f"YourGroup{idx}",
        }
        placeholder = placeholders.get(category, f"[REDACTED_{category.upper()}_{idx}]")
        self._mappings[key] = AnonymizationMapping(
            original=original, anonymized=placeholder, category=category,
        )
        return placeholder

    def _should_skip(self, category: str, value: str) -> bool:
        if category in ("private_ip", "public_ip") and value in SAFE_IPS:
            return True
        if category in ("ad_identity", "upn_identity"):
            parts = re.split(r'[\\@]', value)
            for part in parts:
                if part.upper() in {a.upper() for a in SYSTEM_ACCOUNTS}:
                    return True
        if category == "sid":
            for prefix in SYSTEM_SID_PREFIXES:
                if value.startswith(prefix) and (
                    len(value) == len(prefix) or value[len(prefix)] == '-'):
                    return True
        if category == "external_fqdn":
            val_lower = value.lower()
            for domain in KNOWN_EXTERNAL_DOMAINS:
                if val_lower == domain or val_lower.endswith(f".{domain}"):
                    return True
        if category == "hostname":
            if value.lower() in SYSTEM_PROCESSES or len(value) < 4:
                return True
        if category == "user_path_win":
            # Extract username from match
            m = re.search(r'[Cc]:\\[Uu]sers\\([A-Za-z0-9._-]+)', value)
            if m and m.group(1).upper() in {"PUBLIC", "DEFAULT", "ALL USERS", "DEFAULTAPPPOOL"}:
                return True
        if category == "user_path_linux":
            m = re.search(r'/home/([a-z_][a-z0-9_-]*)', value)
            if m and m.group(1) in {"root", "nobody", "daemon", "www-data", "sshd"}:
                return True
        return False

    def _regex_pass(self, text: str) -> str:
        """Pass 1: structural patterns."""
        for category, pattern, flags in PATTERNS:
            regex_flags = flags if flags else 0
            for match in re.finditer(pattern, text, regex_flags):
                value = match.group()
                if self._should_skip(category, value):
                    continue
                if "REDACTED" in value or "YOURDOM" in value or "yourdom" in value:
                    continue
                placeholder = self._make_placeholder(category, value)
                text = text.replace(value, placeholder)
        return text

    async def _llm_pass(self, text: str) -> str:
        """Pass 2: contextual identifiers via local LLM."""
        prompt = f"""You are a data anonymization specialist for cybersecurity IR.
The data below has already had IPs, SIDs, emails, paths, and hostnames removed by regex.
Find REMAINING company identifiers:

1. Organization/company names, subsidiary names, brand names
2. Department/team names ("Finance", "SOC", "DevOps")
3. Real person names (not system accounts)
4. Internal project names, codenames, product names
5. Custom internal application names, LOB apps
6. Physical locations, office names, building names
7. Phone numbers
8. Wi-Fi SSIDs, printer names
9. AD group names, distribution lists
10. Custom service/daemon names
11. Internal DNS suffixes, search domains
12. Any other company-specific identifier

Do NOT flag: system accounts, standard processes, already-redacted values
(YOURDOM, REDACTED, YOURORG, etc.), standard Windows/Linux terms.

Respond ONLY with a JSON array:
[{{"original": "exact text", "category": "category_name"}}]
If nothing found: []

Data:
---
{text[:6000]}
---"""

        try:
            lm = get_lm_client()
            content = await lm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0, max_tokens=3000, timeout=180.0,
            )
            if content.startswith("```"):
                content = re.sub(r"^```(?:json)?\s*", "", content)
                content = re.sub(r"\s*```$", "", content)
            findings = json.loads(content)
            logger.info(f"LLM pass: {len(findings)} additional items found")
            for f in findings:
                orig = f.get("original", "")
                cat = f.get("category", "other").lower().replace(" ", "_")
                if orig and len(orig) > 1 and orig in text:
                    if "REDACTED" in orig or "YOURDOM" in orig or "YOURORG" in orig:
                        continue
                    text = text.replace(orig, self._make_placeholder(cat, orig))
        except json.JSONDecodeError as e:
            logger.warning(f"LLM anonymization parse error: {e}")
        except Exception as e:
            logger.warning(f"LLM anonymization failed: {e}")
        return text

    async def anonymize(self, text: str, use_llm: bool = True) -> AnonymizationResult:
        self._mappings = {}
        self._counter = {}
        anonymized = self._regex_pass(text)
        regex_count = len(self._mappings)
        logger.info(f"Regex pass: {regex_count} items redacted")
        if use_llm:
            anonymized = await self._llm_pass(anonymized)
            logger.info(f"LLM pass: {len(self._mappings) - regex_count} additional items")
        logger.info(f"Total: {len(self._mappings)} items anonymized")
        return AnonymizationResult(
            original_text=text, anonymized_text=anonymized,
            mappings=list(self._mappings.values()),
            model_used=self.settings.lm_studio_model if use_llm else "regex-only",
        )

    async def health_check(self) -> bool:
        return await get_lm_client().health_check()

    def deanonymize(self, text: str, mappings: list[AnonymizationMapping]) -> str:
        for m in mappings:
            text = text.replace(m.anonymized, m.original)
        return text

    def get_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for m in self._mappings.values():
            summary[m.category] = summary.get(m.category, 0) + 1
        return summary
