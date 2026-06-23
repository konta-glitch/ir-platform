# Validation Playbook — 60GB Velociraptor Collection (Account Takeover Case)

How to be confident the detection is working on a real collection where you
DON'T know the ground truth in advance.

---

## Phase 0 — Before you trust any finding

The case is **business Gmail/Workspace account takeover via the victim's
Windows machine**. The likely on-host evidence is *credential/session theft*,
not classic ransomware. So the questions you're really asking the data:

1. Did malware read the browser's saved passwords / cookies / session tokens?
2. Was there an infostealer (RedLine, Raccoon, Lumma, Vidar, etc.)?
3. How did it get in (phishing attachment, fake installer, malicious script)?
4. Did it persist, and did it exfiltrate?

Keep these four questions open the whole time. Every finding either helps
answer one of them or is noise.

---

## Phase 1 — Prove completeness (no skipped data)

A detection result is meaningless if half the data wasn't scanned. Before
reading findings, open the **Data Coverage** section of the report and check:

- [ ] `rows_scanned` in the pipeline trace is in the millions (a 60GB
      collection has a LOT of rows). If it's small, parsing failed somewhere.
- [ ] Every artifact shows `fully_scanned = True`.
- [ ] The artifacts you EXPECT are present. For a Velociraptor Windows
      triage, you should see things like:
      - `evtx_*` (Security, System, Sysmon, PowerShell-Operational)
      - `registry_*` (SYSTEM, SOFTWARE, NTUSER, USRCLASS)
      - process listing (PsList/Pstree)
      - `Windows.Forensics.*` outputs (Prefetch, SRUM, Amcache, ShimCache)
- [ ] No expected artifact shows 0 rows.

If anything's missing, the collection didn't include it OR the collector
didn't parse it — fix that before trusting the verdict.

---

## Phase 2 — Positive control (does it catch a KNOWN attack?)

You can't validate recall on unknown data. So inject a known-bad sample and
confirm the tool flags it.

1. From EVTX-ATTACK-SAMPLES, pick a file in the **Credential Access** folder
   (closest to your case), e.g. an LSASS-dump or credential-theft sample.
2. Add it into the collection folder (or analyze it alongside).
3. Confirm the tool produces the expected finding.

If it catches the planted attack buried in 60GB, you have evidence it isn't
silently missing things. If it doesn't — the detection has a gap worth fixing
before you rely on the verdict.

---

## Phase 3 — Hunt the account-takeover indicators specifically

Use the **investigation agent chat** (Ask the agent) with targeted questions.
These map directly to your four case questions:

**Browser credential / session theft:**
- "Search for any access to Chrome or Edge Login Data, Cookies, or Web Data files"
- "Were any browser credential databases copied, read, or moved?"
- "Search for 'Local State' or DPAPI master key access"

**Infostealer presence:**
- "Are there any findings for known infostealer malware?"
- "Search for processes running from Temp, AppData, or Downloads"
- "Check frequency of any executable running from a user-writable path"

**Initial access (how it got in):**
- "Show me the timeline around the earliest suspicious finding"
- "Were any Office apps or email clients spawning scripts or shells?"
- "Search for recently downloaded executables or script files"

**Persistence & exfil:**
- "List any persistence findings — run keys, services, scheduled tasks"
- "Were there outbound network connections to unusual destinations?"
- "Search for any data being uploaded, posted, or archived"

The agent grounds each answer in the actual data, so you can follow leads
without manually grepping 60GB.

---

## Phase 4 — Negative control (measure your noise floor)

If you can get a **clean** reference Windows machine from the same
environment, analyze it too. Anything it flags is, by definition, a false
positive for your environment. That tells you which findings on the victim
machine are just normal corporate-software behavior vs. real signal.

No clean reference? Then judge each finding by corroboration: a single
medium-severity Sigma hit with nothing around it is weak; a credential-store
access + infostealer process + outbound connection in the same time window is
a real chain.

---

## Phase 5 — Correlate with the Gmail side (outside this tool)

This tool analyzes the **Windows host**. The account-takeover proof usually
lives in **Google Workspace logs**, which you pull separately from the Admin
console (admin.google.com → Reporting → Audit):

- **Login audit log** — logins from new IPs/countries/devices, especially
  around the time of the on-host compromise.
- **Email log search** — auto-forwarding rules, mass deletions, filters the
  attacker created to hide activity.
- **Admin audit log** — any settings/delegation changes.
- **OAuth / token grants** — third-party app access the attacker may have
  authorized to keep access even after a password reset.

**The key correlation:** match the timestamp of on-host credential/cookie
theft (from this tool) against the timestamp of the first anomalous Gmail
login (from Workspace logs). If they line up, you've established the chain:
*host compromise → credential/session theft → account takeover.*

---

## What "working well" looks like

You can be confident the detection is solid when:
- Completeness is proven (Phase 1 all checked).
- The planted known attack was caught (Phase 2).
- Findings cluster into a coherent story answering the four case questions,
  rather than a flat list of hundreds of unrelated alerts.
- The few high/critical findings, when inspected, point to real artifacts you
  can open and verify — not generic "an event occurred" noise.
