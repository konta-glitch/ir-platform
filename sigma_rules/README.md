# Sigma Rules

This folder holds [Sigma](https://github.com/SigmaHQ/sigma) detection rules.
Any `.yml` / `.yaml` file dropped here is loaded automatically and applied to
every collection/image analyzed by the platform.

## Quick start — install curated rules

The platform ships with `builtin_rules.yml` (12 high-value detections). To add
thousands more, use the installer script:

```bash
# From the project root
./scripts/install-sigma-rules.sh hayabusa    # recommended (curated, ~4000 rules)
./scripts/install-sigma-rules.sh sigmahq     # full upstream community set
./scripts/install-sigma-rules.sh both        # everything

# Then reload into the running platform
curl -X POST http://localhost:8080/api/sigma/reload
```

## Why Hayabusa rules (recommended)

[Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)
is the same curated ruleset used by Hayabusa and Velociraptor's built-in Sigma
detection. Advantages over raw upstream SigmaHQ for our use case:

- **Lower false-positives** — logsource is de-abstracted with explicit Channel/EventID
- **Works on built-in Windows logs** — not just Sysmon (matches what our collectors gather)
- **Pre-filtered for parseability** — only rules that Sigma-native tools can handle,
  which lines up exactly with our engine's supported feature set

Both Hayabusa and our engine share the same limitation: aggregation expressions
(other than simple `count`) and `|near` temporal rules are not supported and are
skipped gracefully.

## Manual install

```bash
cd sigma_rules
git clone --depth 1 https://github.com/Yamato-Security/hayabusa-rules.git _hr
find _hr/sigma -name '*.yml' -exec cp {} . \;
curl -X POST http://localhost:8080/api/sigma/reload
```

## Supported Sigma features

- Field modifiers: `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`,
  `windash`, equals (incl. numeric EventID matching)
- Null checks: `Field: null` (field absence)
- Selections with lists (OR) and dicts (AND)
- Conditions: `selection`, `a and b`, `a or b`, `not filter`,
  `selection and not filter`, `1 of selection*`, `all of selection*`, `all of them`

## Logsource → artifact mapping

Rules match artifacts by their `logsource.category`:

| Sigma category | Matches artifacts containing |
|----------------|------------------------------|
| process_creation | pslist, process, 4688, sysmon |
| network_connection | netstat, network, connection |
| registry_set/event | registry, run, autorun |
| file_event | file, matches, searchglobs, lnk |
| scheduled_task | task, schtasks |
| service_creation | service, 7045 |
| ps_script | powershell, 4104 |
| security/system | eventlog, evtx |
