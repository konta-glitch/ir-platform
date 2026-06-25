"""
Sigma Rule Engine — loads and applies Sigma detection rules.

Sigma is the open standard for SIEM detection rules (https://github.com/SigmaHQ/sigma).
This module loads Sigma YAML rules and matches them against parsed artifact rows,
giving the platform access to thousands of community-maintained detections.

Drop any .yml Sigma rules into ./sigma_rules/ and they're loaded automatically.

Sigma rule structure (simplified):
    title: Suspicious PowerShell Download
    level: high
    tags: [attack.execution, attack.t1059.001]
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            Image|endswith: powershell.exe
            CommandLine|contains:
                - DownloadString
                - Net.WebClient
        condition: selection

We implement a practical subset of the Sigma spec that covers the vast
majority of process/file/registry/network rules:
  - field modifiers: contains, startswith, endswith, all, re, (none = equals)
  - selections with lists (OR) and dicts (AND)
  - conditions: selection, sel1 and sel2, sel1 or sel2,
    not filter, selection and not filter, 1 of selection*, all of selection*
"""

import re
import logging
from pathlib import Path
from typing import Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger(__name__)


# Map Sigma logsource categories to our artifact key patterns
LOGSOURCE_TO_ARTIFACT = {
    "process_creation": ["pslist", "process", "pstree", "4688", "sysmon"],
    "network_connection": ["netstat", "network", "connection", "sysmon"],
    "registry_set": ["registry", "run", "autorun"],
    "registry_event": ["registry", "run", "autorun"],
    "registry_add": ["registry", "run", "autorun"],
    "file_event": ["file", "matches", "searchglobs", "upload", "lnk"],
    "image_load": ["sysmon", "dll"],
    "scheduled_task": ["task", "scheduledtask", "schtasks"],
    "service_creation": ["service", "7045", "executable"],
    "ps_script": ["powershell", "4104", "scriptblock"],
    "ps_module": ["powershell", "4103"],
    "security": ["eventlog", "security", "evtx"],
    "system": ["eventlog", "system", "evtx"],
}

# Common Sigma field → our parsed field name variations
FIELD_ALIASES = {
    "Image": ["Image", "Exe", "Path", "ExecutablePath", "NewProcessName", "path", "name", "Name"],
    "CommandLine": ["CommandLine", "cmdline", "Cmd", "ProcessCommandLine", "Arguments"],
    "ParentImage": ["ParentImage", "ParentProcessName", "parent_path"],
    "ParentCommandLine": ["ParentCommandLine", "parent_cmdline"],
    "TargetFilename": ["TargetFilename", "FullPath", "path", "Path", "OSPath", "FileName"],
    "Image|endswith": ["Image", "Exe", "Path", "name", "Name"],
    "DestinationPort": ["DestinationPort", "RemotePort", "remote_port", "Raddr"],
    "DestinationIp": ["DestinationIp", "RemoteAddress", "remote", "Raddr"],
    "SourceIp": ["SourceIp", "LocalAddress", "local", "Laddr"],
    "User": ["User", "Username", "user", "account", "SubjectUserName", "TargetUserName"],
    "ServiceName": ["ServiceName", "Name", "name"],
    "ServiceFileName": ["ServiceFileName", "PathName", "ImagePath", "image_path", "path", "ImagePath"],
    "TargetObject": ["TargetObject", "key", "Key", "FullPath"],
    "Details": ["Details", "value", "Value", "Data"],
    "EventID": ["EventID", "event_id", "Id", "ID", "EventId"],
    "Channel": ["Channel", "channel", "LogName", "log_name", "artifact"],
    "Provider": ["Provider", "Provider_Name", "ProviderName", "provider", "SourceName"],
    "ScriptBlockText": ["ScriptBlockText", "data", "Message", "message", "Path"],
    "TaskName": ["TaskName", "Name", "name"],
    "CommandName": ["Command", "command", "Action"],
    "ParentProcessName": ["ParentProcessName", "ParentImage", "parent_path"],
    "NewProcessName": ["NewProcessName", "Image", "Exe", "path"],
    "OriginalFileName": ["OriginalFileName", "original_filename"],
    "Hashes": ["Hashes", "Hash", "sha256", "SHA256", "md5", "MD5"],
    "IntegrityLevel": ["IntegrityLevel", "integrity_level"],
    "LogonType": ["LogonType", "logon_type"],
    "TargetImage": ["TargetImage", "target_image"],
    "SourceImage": ["SourceImage", "source_image"],
    "QueryName": ["QueryName", "query_name", "query"],
    "DestinationHostname": ["DestinationHostname", "dest_hostname", "remote"],
}


class SigmaRule:
    """A parsed Sigma rule ready for matching."""

    def __init__(self, raw: dict, source_file: str = ""):
        self.raw = raw
        self.source_file = source_file
        self.title = raw.get("title", "Untitled Sigma rule")
        self.id = raw.get("id", "")
        self.level = raw.get("level", "medium")
        self.description = raw.get("description", "")
        self.tags = raw.get("tags") or []
        self.status = raw.get("status", "")

        logsource = raw.get("logsource") or {}
        if not isinstance(logsource, dict):
            logsource = {}
        self.category = logsource.get("category", "")
        self.product = logsource.get("product", "")
        self.service = logsource.get("service", "")

        self.detection = raw.get("detection") or {}
        if not isinstance(self.detection, dict):
            self.detection = {}
        self.condition = self.detection.get("condition", "")
        self._required_fields = None  # lazily computed + cached

        # Aggregation rules (Sigma "near"/correlation syntax) use a pipe to a
        # count/sum/etc. over a GROUP, e.g.
        #   "selection | count() by ServiceName < 5"
        #   "selection | near other within 30s"
        # These can't be evaluated per-row — they need grouping/correlation
        # across the whole dataset — so this row-based engine can't support
        # them. We flag them once here and skip at load time, rather than
        # failing closed on every single row (which floods the logs). Any
        # condition containing an aggregation pipe ("| count", "| near", etc.)
        # qualifies.
        self.is_aggregation = bool(
            re.search(r"\|\s*(count|sum|avg|min|max|near|values|base64)",
                      self.condition, re.IGNORECASE)
        )

        # Extract MITRE technique from tags
        self.mitre = ""
        for tag in self.tags:
            m = re.match(r"attack\.t(\d+(?:\.\d+)?)", str(tag), re.IGNORECASE)
            if m:
                self.mitre = f"T{m.group(1)}"
                break

    def applies_to_artifact(self, artifact_key: str) -> bool:
        """Check if this rule's logsource matches the artifact type."""
        artifact_lower = artifact_key.lower()
        patterns = LOGSOURCE_TO_ARTIFACT.get(self.category, [])
        if patterns:
            return any(p in artifact_lower for p in patterns)
        # No category mapping. Only consider it applicable if the rule has a
        # service that names a specific channel matching the artifact. We do
        # NOT blanket-match every windows rule to every artifact — that made
        # thousands of process rules scan every event log (massive slowdown
        # and false positives).
        if self.service:
            return self.service.lower().replace("-", "") in artifact_lower.replace("-", "")
        # Category-less, service-less rules are too generic to apply safely.
        return False

    def required_fields(self) -> set:
        """The set of field names this rule actually inspects (cached)."""
        if self._required_fields is not None:
            return self._required_fields
        fields = set()
        def walk(sel):
            if isinstance(sel, dict):
                for k in sel:
                    if k != "condition":
                        fields.add(k.split("|")[0].lower())
            elif isinstance(sel, list):
                for item in sel:
                    walk(item)
        for name, val in self.detection.items():
            if name != "condition":
                walk(val)
        self._required_fields = fields
        return fields

    # Fields that carry the actual malicious signal in a process rule.
    # If a rule keys on any of these, the row must HAVE at least one of them —
    # otherwise we'd match a state-snapshot row (PsList: Name/Image only, no
    # command line or parent) on the image name alone, which fires Ryuk/Mint
    # Sandstorm/etc. on benign svchost.exe & lsass.exe. (Major false positives.)
    DISCRIMINATOR_FIELDS = {
        "commandline", "parentimage", "parentcommandline",
        "originalfilename", "targetfilename", "imageloaded",
        "scriptblocktext", "parentprocessname", "processcommandline",
    }
    DISCRIMINATOR_ALIASES = {
        "commandline", "cmdline", "processcommandline",
        "parentimage", "parentprocessname", "parentcommandline",
        "originalfilename", "targetfilename", "imageloaded",
        "scriptblocktext",
    }

    def could_match_fields(self, row_fields: set) -> bool:
        """
        Cheap field-presence pre-check, given a row's lowercased field-name set.

        Returns False when this rule provably cannot match the row (no shared
        inspected field, or a missing discriminator field). The caller computes
        `row_fields` ONCE per row and reuses it across all rules, avoiding the
        per-rule recomputation that match_row() would otherwise do on every
        (row x rule) pair. This is a pure performance gate — it never turns a
        non-match into a match, so detection results are identical.
        """
        req = self.required_fields()
        if req:
            if not (req & row_fields) and not self._has_aliased_field(req, row_fields):
                return False
        rule_discriminators = req & self.DISCRIMINATOR_FIELDS
        if rule_discriminators:
            if not (self.DISCRIMINATOR_ALIASES & row_fields):
                return False
        return True

    def match_row(self, row: dict) -> bool:
        """Evaluate this rule's detection logic against a single row."""
        if not isinstance(row, dict):
            return False

        row_fields = {str(k).lower() for k in row.keys()}

        # Fast pre-filter (shared with the engine's per-row gate): if the row
        # can't possibly satisfy this rule's field requirements, skip the
        # expensive selection/condition evaluation.
        if not self.could_match_fields(row_fields):
            return False

        # Evaluate each named selection block
        selection_results = {}
        for sel_name, sel_value in self.detection.items():
            if sel_name == "condition":
                continue
            selection_results[sel_name] = self._eval_selection(sel_value, row)

        # Evaluate the condition expression
        return self._eval_condition(self.condition, selection_results)

    @staticmethod
    def _has_aliased_field(req: set, row_fields: set) -> bool:
        """Check if any required field maps to a present field via aliases."""
        ALIASES = {
            "image": {"newprocessname", "processname", "exe", "path", "image"},
            "commandline": {"commandline", "cmdline", "processcommandline"},
            "parentimage": {"parentprocessname", "parentimage"},
            "targetfilename": {"targetfilename", "filename", "ospath", "path"},
            "eventid": {"eventid", "event_id", "id"},
        }
        for r in req:
            aliases = ALIASES.get(r, set())
            if aliases & row_fields:
                return True
        return False

    def _eval_selection(self, selection: Any, row: dict) -> bool:
        """Evaluate a single selection block against a row."""
        if isinstance(selection, list):
            # List of dicts/values = OR
            return any(self._eval_selection(item, row) for item in selection)

        if isinstance(selection, dict):
            # Dict = AND across all field matches
            for field_spec, expected in selection.items():
                if not self._match_field(field_spec, expected, row):
                    return False
            return True

        return False

    def _match_field(self, field_spec: str, expected: Any, row: dict) -> bool:
        """Match a single field spec (with modifiers) against the row."""
        # Parse field|modifier syntax
        parts = field_spec.split("|")
        field_name = parts[0]
        modifiers = parts[1:] if len(parts) > 1 else []

        # Get actual value from row (try aliases)
        actual = self._get_field_value(field_name, field_spec, row)

        # Null check: "Field: null" means field should be absent/empty
        if expected is None:
            return actual is None or actual == ""

        if actual is None:
            return False
        actual_str = str(actual)

        # Handle list of expected values (OR, unless 'all' modifier)
        if isinstance(expected, list):
            if "all" in modifiers:
                return all(self._apply_modifier(actual_str, str(e), modifiers) for e in expected)
            return any(self._apply_modifier(actual_str, str(e), modifiers) for e in expected)

        return self._apply_modifier(actual_str, str(expected), modifiers)

    @staticmethod
    def _path_norm(s: str) -> str:
        """Normalize backslashes to forward slashes for path matching."""
        return s.replace("\\", "/")

    def _apply_modifier(self, actual: str, expected: str, modifiers: list) -> bool:
        """Apply Sigma field modifiers."""
        actual_l = actual.lower()
        expected_l = expected.lower()

        if "contains" in modifiers:
            if "windash" in modifiers:
                # windash: treat - / – as interchangeable dash variants
                norm_actual = re.sub(r"[/–—]", "-", actual_l)
                norm_expected = re.sub(r"[/–—]", "-", expected_l)
                return norm_expected in norm_actual
            # Normalize path separators so \ and / both match
            return self._path_norm(expected_l) in self._path_norm(actual_l)
        if "startswith" in modifiers:
            return self._path_norm(actual_l).startswith(self._path_norm(expected_l))
        if "endswith" in modifiers:
            return self._path_norm(actual_l).endswith(self._path_norm(expected_l))
        if "re" in modifiers:
            try:
                return bool(re.search(expected, actual, re.IGNORECASE))
            except re.error:
                return False
        if "cidr" in modifiers:
            # Basic CIDR — just check IP prefix match
            prefix = expected.split("/")[0].rsplit(".", 1)[0]
            return actual.startswith(prefix)
        # Default: equals (case-insensitive). Handle numeric comparison.
        if actual_l == expected_l:
            return True
        # Numeric equality (EventID: 4688 matches "4688")
        try:
            return float(actual) == float(expected)
        except (ValueError, TypeError):
            return False

    def _get_field_value(self, field_name: str, full_spec: str, row: dict):
        """Get a field value from the row, trying known aliases."""
        # Direct match
        if field_name in row:
            return row[field_name]

        # Try aliases
        aliases = FIELD_ALIASES.get(field_name, [])
        for alias in aliases:
            if alias in row:
                return row[alias]

        # Case-insensitive search
        field_lower = field_name.lower()
        for k, v in row.items():
            if k.lower() == field_lower:
                return v

        # For process rules, fall back to searching the whole row string
        # for CommandLine/Image style fields
        if field_name in ("CommandLine", "Image", "ScriptBlockText"):
            return str(row)

        return None

    def _eval_condition(self, condition: str, results: dict) -> bool:
        """Evaluate a Sigma condition expression.

        Handles 'X of pattern*' both as a whole condition AND as a
        sub-expression inside a larger boolean (e.g.
        'selection_parent and ( all of selection_child_* )'). Earlier this
        only handled the whole-condition case; a compound condition fell
        through to a permissive 'any selection matched' fallback, which
        produced false positives (Mint Sandstorm matching lsass, etc.).
        """
        if not condition:
            return False

        cond = condition.strip().lower()

        # Replace every "N of pattern*" / "all of them" quantifier with its
        # concrete True/False BEFORE building the boolean expression, so they
        # work inside parentheses and alongside and/or/not.
        def resolve_quantifier(match):
            qty = match.group(1)           # '1', 'any', or 'all'
            pattern = match.group(2).strip().rstrip("*")
            if pattern == "them":
                vals = list(results.values())
            else:
                vals = [v for k, v in results.items() if k.startswith(pattern)]
            if not vals:
                return "False"
            if qty in ("1", "any"):
                return str(any(vals))
            return str(all(vals))  # 'all'

        # e.g. "all of selection_special_child_*" or "1 of selection*"
        cond = re.sub(r"\b(1|any|all)\s+of\s+([a-z0-9_*]+)",
                      resolve_quantifier, cond)

        # Replace remaining selection names with their boolean results
        # (longest first to avoid partial-name clobbering).
        expr = cond
        for name in sorted(results.keys(), key=len, reverse=True):
            expr = re.sub(rf"\b{re.escape(name.lower())}\b",
                         str(results[name]), expr)

        # Safety: only allow boolean tokens now. If anything else remains
        # (an unresolved selection name, an unknown construct), FAIL CLOSED
        # (return False) rather than the old permissive any()-match, which
        # turned unparseable conditions into false positives.
        allowed = re.compile(r"^[\s()TrueFalsenotandor]+$")
        if not allowed.match(expr):
            logger.debug(f"Sigma condition not fully resolved, failing closed: "
                         f"{condition!r} -> {expr!r}")
            return False

        try:
            return bool(eval(expr, {"__builtins__": {}}, {"True": True, "False": False}))
        except Exception:
            return False


class SigmaEngine:
    """Loads Sigma rules and applies them to collected data."""

    def __init__(self, rules_dir: str = "/app/sigma_rules"):
        self.rules_dir = Path(rules_dir)
        self.rules: list[SigmaRule] = []
        self._loaded = False

    # Rules that fire on an event TYPE alone (every process creation, every
    # DLL load, etc.) without any suspicious indicator. These aren't threat
    # detections — they're "an event happened" alerts and flood the report
    # with hundreds of meaningless high-severity findings. The most reliable
    # signal is the source filename: these come from a generic Sysmon
    # event-mirroring rule pack (Sysmon_N_*_RuleAlert.yml etc.), not from
    # curated threat-detection rules.
    NOISE_SOURCE_MARKERS = (
        "_rulealert", "rulealert.yml",
        "sysmon_1_high_procexec", "sysmon_1_high_proc",
        "_nonexeprocexec", "_sysmonalert",
    )
    # Exact generic descriptions that mean "this event type occurred".
    NOISE_DESC_EXACT = (
        "sysmon process creation", "sysmon file create", "sysmon dll load",
        "sysmon network connection", "sysmon registry event",
        "sysmon process access", "sysmon raw access read",
        "sysmon pipe created", "sysmon image loaded",
    )

    def _is_noise_rule(self, rule: "SigmaRule") -> bool:
        """True for generic 'an event occurred' rules with no real signal."""
        src = (rule.source_file or "").lower()
        if any(m in src for m in self.NOISE_SOURCE_MARKERS):
            return True
        desc = (rule.description or "").lower().strip()
        if desc in self.NOISE_DESC_EXACT:
            return True
        return False

    def load_rules(self) -> int:
        """Load all Sigma YAML rules from the rules directory."""
        if not HAS_YAML:
            logger.warning("PyYAML not available — Sigma rules disabled")
            return 0

        self.rules = []
        if not self.rules_dir.exists():
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created Sigma rules dir: {self.rules_dir}")
            return 0

        yml_files = list(self.rules_dir.rglob("*.yml")) + list(self.rules_dir.rglob("*.yaml"))
        skipped = 0
        noise_skipped = 0
        agg_skipped = 0
        for yml in yml_files:
            try:
                with open(yml) as f:
                    for doc in yaml.safe_load_all(f):
                        if not (doc and isinstance(doc, dict) and doc.get("detection")):
                            continue
                        rule = SigmaRule(doc, str(yml.name))
                        # Only keep rules with a usable detection block and condition
                        if not (rule.detection and rule.condition):
                            skipped += 1
                            continue
                        # Aggregation/correlation rules ("| count() by ...")
                        # need cross-dataset grouping this row-based engine
                        # can't do. Skip once here instead of failing closed on
                        # every row (which floods the logs).
                        if rule.is_aggregation:
                            agg_skipped += 1
                            continue
                        # Drop generic event-type "alert" rules — they fire on
                        # every Sysmon event and produce pure noise.
                        if self._is_noise_rule(rule):
                            noise_skipped += 1
                            continue
                        self.rules.append(rule)
            except Exception as e:
                skipped += 1
                logger.debug(f"Skipped Sigma rule {yml.name}: {e}")

        self._loaded = True
        logger.info(f"Loaded {len(self.rules)} Sigma rules from {self.rules_dir} "
                    f"({skipped} skipped — unsupported/empty, "
                    f"{noise_skipped} skipped — generic event-type noise, "
                    f"{agg_skipped} skipped — aggregation/correlation rules)")
        return len(self.rules)

    def analyze(self, data: dict, max_matches_per_rule: int = 20,
                progress_cb=None, max_rows_per_artifact: int = 0) -> list[dict]:
        """
        Apply all Sigma rules to the collected data.

        IR REQUIREMENT: every applicable row is scanned — no row caps.
        max_rows_per_artifact=0 means unlimited (default). A non-zero value
        is only a last-resort safety valve.

        Performance: we still skip applying Sigma rules to bulk FILE-METADATA
        artifacts (raw file listings), because Sigma rules target Windows
        event/process records by logsource — a process_creation rule cannot
        match a file-listing row by construction. Those bulk artifacts ARE
        fully scanned by the detection engine's file-anomaly rules instead,
        so no row goes unexamined across the platform.
        """
        if not self._loaded:
            self.load_rules()
        if not self.rules:
            return []

        findings = []
        # Sigma matches are lower-fidelity leads: a rule firing means "this
        # COULD be malicious", not "this IS an attack". We cap Sigma severity
        # at HIGH (never auto-critical) so a single uncorroborated rule can't
        # dominate the report, and tag findings as needing corroboration.
        from app.detection.thresholds import SIGMA_SEVERITY_CAP, SIGMA_SCORE_BY_LEVEL
        sev_map = SIGMA_SEVERITY_CAP
        score_map = SIGMA_SCORE_BY_LEVEL

        # Bulk file-metadata artifacts: scanned by detection_engine, not Sigma
        # (Sigma event/process rules cannot match file-listing rows).
        BULK_SKIP = ["matches", "searchglobs", "upload", "metadata"]

        artifacts = [(k, v) for k, v in data.items()
                     if not k.startswith("_") and isinstance(v, list)]

        for key, rows in artifacts:
            key_lower = key.lower()

            # Skip bulk metadata artifacts (covered by detection engine)
            if any(b in key_lower for b in BULK_SKIP):
                logger.info(f"Sigma: {key} ({len(rows)} rows) scanned by detection engine, not Sigma")
                continue

            applicable = [r for r in self.rules if r.applies_to_artifact(key)]
            if not applicable:
                continue

            # Scan ALL rows — no sampling. Safety valve only if explicitly set.
            scan_rows = rows
            if max_rows_per_artifact and len(rows) > max_rows_per_artifact:
                logger.warning(f"Sigma: {key} hit safety cap {max_rows_per_artifact} of {len(rows)} rows")
                scan_rows = rows[:max_rows_per_artifact]

            if progress_cb:
                progress_cb(key, len(applicable), len(scan_rows))

            # Iterate rows in outer loop (each row tested against all rules),
            # so we touch each row once and can early-exit per rule via counts.
            # PERF: compute the row's field-name set ONCE here and reuse it for
            # every rule's cheap pre-filter, instead of recomputing it inside
            # each match_row() call. At ~3k rules x thousands of rows this turns
            # millions of redundant set-builds into one per row. Logic is
            # unchanged: could_match_fields() is the same gate match_row() uses.
            rule_match_counts = {}
            for idx, row in enumerate(scan_rows):
                if not isinstance(row, dict):
                    continue
                row_fields = {str(k).lower() for k in row.keys()}
                for rule in applicable:
                    rid = id(rule)
                    count = rule_match_counts.get(rid, 0)
                    if count > max_matches_per_rule:
                        continue  # already have enough samples from this rule
                    # Cheap field-presence gate before the expensive eval.
                    if not rule.could_match_fields(row_fields):
                        continue
                    if rule.match_row(row):
                        rule_match_counts[rid] = count + 1
                        if count < max_matches_per_rule:
                            findings.append({
                                "category": "sigma_detection",
                                "severity": sev_map.get(rule.level, "medium"),
                                "title": f"Sigma: {rule.title}",
                                "description": (rule.description or rule.title)[:300],
                                "artifact": key,
                                "evidence": {
                                    "row_index": idx,
                                    "rule_id": rule.id,
                                    "rule_source": rule.source_file,
                                    "matched_data": str(row)[:300],
                                },
                                "score": score_map.get(rule.level, 50),
                                "mitre": rule.mitre,
                            })

        logger.info(f"Sigma engine: {len(findings)} findings from {len(self.rules)} rules")
        return findings

    def rule_count(self) -> int:
        if not self._loaded:
            self.load_rules()
        return len(self.rules)
