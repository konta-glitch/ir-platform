"""
Investigation Agent — an LLM-driven analyst that investigates interactively.

Instead of a single pass over pre-computed findings, this agent runs a
reasoning loop: the LLM is given a set of TOOLS to query the actual collected
data, and it decides what to look at next — pivoting on IOCs, pulling specific
rows, checking process ancestry, searching event logs — just like a human
analyst chasing a lead.

The loop:
  1. Agent receives the case context (findings summary + available artifacts).
  2. LLM picks a tool + arguments (as JSON) to investigate a hypothesis.
  3. We execute the tool against the real data and return the result.
  4. LLM reasons over the result and either pivots (another tool) or concludes.
  5. Repeat until the LLM emits a final verdict or max_steps is hit.

This keeps the LLM grounded — every claim is backed by a tool result over the
actual data, never a guess. The full transcript of tool calls is recorded so
the investigation is auditable and reproducible.
"""

import json
import logging
import re
from typing import Any, Callable

logger = logging.getLogger(__name__)


class InvestigationTools:
    """
    The tools the agent can call. Each operates over the structured data
    (the parsed artifacts) and returns a compact, factual result.

    Every tool is read-only and deterministic — it queries data, never guesses.
    """

    def __init__(self, structured_data: dict, detection_result: dict,
                 correlation_result: dict):
        self.data = structured_data
        self.detection = detection_result
        self.correlation = correlation_result
        # Flatten artifacts for quick access (skip private keys)
        self.artifacts = {
            k: v for k, v in structured_data.items()
            if not k.startswith("_") and isinstance(v, list)
        }

    # ── Tool: list available artifacts ──
    def list_artifacts(self) -> dict:
        """Return the artifacts available and their row counts."""
        return {
            "artifacts": [
                {"name": k, "rows": len(v)}
                for k, v in sorted(self.artifacts.items(), key=lambda x: -len(x[1]))
            ]
        }

    # ── Tool: search all artifacts for a string ──
    def search(self, query: str, max_results: int = 20) -> dict:
        """Case-insensitive substring search across every row of every artifact."""
        if not query:
            return {"error": "empty query"}
        q = query.lower()
        hits = []
        for artifact, rows in self.artifacts.items():
            for idx, row in enumerate(rows):
                if q in str(row).lower():
                    hits.append({
                        "artifact": artifact,
                        "row_index": idx,
                        "data": str(row)[:300],
                    })
                    if len(hits) >= max_results:
                        return {"query": query, "total_hits": len(hits),
                                "results": hits, "truncated": True}
        return {"query": query, "total_hits": len(hits), "results": hits}

    # ── Tool: get specific rows from an artifact ──
    def get_rows(self, artifact: str, start: int = 0, count: int = 10) -> dict:
        """Return a slice of rows from a named artifact."""
        if artifact not in self.artifacts:
            close = [a for a in self.artifacts if artifact.lower() in a.lower()]
            return {"error": f"artifact '{artifact}' not found",
                    "did_you_mean": close[:5]}
        rows = self.artifacts[artifact]
        count = min(count, 50)
        slice_ = rows[start:start + count]
        return {
            "artifact": artifact, "total_rows": len(rows),
            "start": start, "returned": len(slice_),
            "rows": [{"row_index": start + i, "data": r} for i, r in enumerate(slice_)],
        }

    # ── Tool: get findings, optionally filtered ──
    def get_findings(self, severity: str = "", category: str = "",
                     limit: int = 20) -> dict:
        """Return detection findings, optionally filtered by severity/category."""
        findings = self.detection.get("findings", [])
        filtered = []
        for f in findings:
            if severity and f.get("severity") != severity.lower():
                continue
            if category and category.lower() not in f.get("category", "").lower():
                continue
            filtered.append({
                "id": f.get("id"), "severity": f.get("severity"),
                "title": f.get("title"), "category": f.get("category"),
                "mitre": f.get("mitre"),
                "locator": f.get("evidence", {}).get("locator", ""),
                "description": f.get("description", "")[:200],
            })
            if len(filtered) >= limit:
                break
        return {"total_matching": len(filtered), "findings": filtered}

    # ── Tool: inspect one finding in full detail ──
    def inspect_finding(self, finding_id: str) -> dict:
        """Return the full detail + evidence for a specific finding."""
        for f in self.detection.get("findings", []):
            if f.get("id") == finding_id:
                return {
                    "id": f["id"], "severity": f["severity"],
                    "title": f["title"], "category": f["category"],
                    "mitre": f.get("mitre"), "description": f["description"],
                    "evidence": f.get("evidence", {}),
                    "score": f.get("score"),
                }
        return {"error": f"finding '{finding_id}' not found"}

    # ── Tool: look at process ancestry ──
    def get_process_tree(self, pid: str = "") -> dict:
        """Return reconstructed process trees, optionally for a specific PID."""
        trees = self.correlation.get("process_trees", [])
        if pid:
            for t in trees:
                if str(t.get("pid")) == str(pid) or str(t.get("ppid")) == str(pid):
                    return {"tree": t}
            return {"error": f"no process tree for PID {pid}",
                    "available_pids": [t.get("pid") for t in trees[:20]]}
        return {"process_trees": trees[:15], "total": len(trees)}

    # ── Tool: timeline around a timestamp ──
    def get_timeline(self, around: str = "", window_events: int = 20) -> dict:
        """Return timeline events, optionally centered on a timestamp substring."""
        timeline = self.correlation.get("timeline", [])
        if around:
            for i, ev in enumerate(timeline):
                if around in str(ev.get("timestamp", "")):
                    lo = max(0, i - window_events // 2)
                    hi = min(len(timeline), i + window_events // 2)
                    return {"center_index": i, "events": timeline[lo:hi]}
            return {"error": f"no timeline event matching '{around}'"}
        return {"events": timeline[:window_events], "total": len(timeline)}

    # ── Tool: frequency / rarity check ──
    def check_frequency(self, value: str) -> dict:
        """How often does a value (path, hash, name) appear across the dataset?"""
        if not value:
            return {"error": "empty value"}
        v = value.lower()
        count = 0
        artifacts_seen = set()
        for artifact, rows in self.artifacts.items():
            for row in rows:
                if v in str(row).lower():
                    count += 1
                    artifacts_seen.add(artifact)
        return {
            "value": value, "occurrences": count,
            "artifacts": sorted(artifacts_seen),
            "rarity": "rare" if count <= 3 else "common" if count > 20 else "uncommon",
        }


# Tool schema presented to the LLM
TOOL_SCHEMA = """Available tools (call ONE per step, as JSON):

- list_artifacts: see what data is available. Args: none.
- search: substring search across ALL rows of ALL artifacts. Args: {"query": "mimikatz", "max_results": 20}
- get_rows: read specific rows of an artifact. Args: {"artifact": "PsList_From_Pslist", "start": 0, "count": 10}
- get_findings: list detections. Args: {"severity": "critical", "category": "credential", "limit": 20} (all optional)
- inspect_finding: full detail of one finding. Args: {"finding_id": "F0001"}
- get_process_tree: process ancestry. Args: {"pid": "1234"} (pid optional)
- get_timeline: events over time. Args: {"around": "2026-06-07T10:00", "window_events": 20} (around optional)
- check_frequency: how rare is a value. Args: {"value": "C:/Users/Public/x.exe"}
"""

# Native function-calling schema (OpenAI/LM Studio format). Used when the
# loaded model supports tool calling (e.g. Qwen3) — far more reliable than
# parsing JSON out of free text. Falls back to the text protocol otherwise.
NATIVE_TOOLS = [
    {"type": "function", "function": {
        "name": "list_artifacts",
        "description": "List the available forensic artifacts and their row counts.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "search",
        "description": "Case-insensitive substring search across every row of every artifact.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "Text to search for, e.g. an IOC, path, or process name"},
            "max_results": {"type": "integer", "description": "Max hits to return (default 20)"},
        }, "required": ["query"]},
    }},
    {"type": "function", "function": {
        "name": "get_rows",
        "description": "Read a slice of rows from a named artifact.",
        "parameters": {"type": "object", "properties": {
            "artifact": {"type": "string", "description": "Artifact name, e.g. PsList_From_Pslist"},
            "start": {"type": "integer", "description": "First row index (default 0)"},
            "count": {"type": "integer", "description": "How many rows (default 10, max 50)"},
        }, "required": ["artifact"]},
    }},
    {"type": "function", "function": {
        "name": "get_findings",
        "description": "List detection findings, optionally filtered by severity or category.",
        "parameters": {"type": "object", "properties": {
            "severity": {"type": "string", "description": "critical|high|medium|low (optional)"},
            "category": {"type": "string", "description": "e.g. credential, execution (optional)"},
            "limit": {"type": "integer", "description": "Max findings (default 20)"},
        }},
    }},
    {"type": "function", "function": {
        "name": "inspect_finding",
        "description": "Get the full detail and evidence for one finding by ID.",
        "parameters": {"type": "object", "properties": {
            "finding_id": {"type": "string", "description": "Finding ID, e.g. F0001 or S0054"},
        }, "required": ["finding_id"]},
    }},
    {"type": "function", "function": {
        "name": "get_process_tree",
        "description": "Get reconstructed process ancestry, optionally for one PID.",
        "parameters": {"type": "object", "properties": {
            "pid": {"type": "string", "description": "Process ID to focus on (optional)"},
        }},
    }},
    {"type": "function", "function": {
        "name": "get_timeline",
        "description": "Get timeline events, optionally centered on a timestamp.",
        "parameters": {"type": "object", "properties": {
            "around": {"type": "string", "description": "Timestamp substring to center on (optional)"},
            "window_events": {"type": "integer", "description": "How many events (default 20)"},
        }},
    }},
    {"type": "function", "function": {
        "name": "check_frequency",
        "description": "Check how often a value (path, hash, name) appears across the dataset.",
        "parameters": {"type": "object", "properties": {
            "value": {"type": "string", "description": "The value to count occurrences of"},
        }, "required": ["value"]},
    }},
]

SYSTEM_PROMPT = """You are an expert incident-response analyst investigating a compromised host.
You work by calling tools to query the ACTUAL collected forensic data — never guess or invent facts.

""" + TOOL_SCHEMA + """

On each step respond with ONLY a JSON object, no other text:

To investigate further:
{"thought": "why you're checking this", "action": "tool_name", "args": {...}}

When you have enough evidence to conclude:
{"thought": "summary of reasoning", "action": "conclude", "verdict": {
  "compromised": true/false,
  "confidence": 0.0-1.0,
  "summary": "what happened, 2-4 sentences",
  "attack_chain": ["step 1", "step 2"],
  "key_evidence": [{"finding_id": "F0001", "why": "..."}],
  "recommended_actions": ["action 1", "action 2"]
}}

Investigate methodically: start broad (list_artifacts, get_findings), then pivot on
the most suspicious leads (search for IOCs, inspect findings, check process trees,
verify rarity). Corroborate before concluding. Be specific and cite finding IDs.

/no_think"""


CHAT_SYSTEM_PROMPT = """You are an expert incident-response analyst in an interactive session.
An analyst will ask you questions about a compromised host. You answer by calling tools to
query the ACTUAL collected forensic data — never guess or invent facts.

""" + TOOL_SCHEMA + """

For each analyst question, respond with ONLY a JSON object, no other text.

To query data before answering:
{"thought": "what you're checking and why", "action": "tool_name", "args": {...}}

When ready to answer the analyst:
{"thought": "brief reasoning", "action": "answer", "answer": "your natural-language answer, citing finding IDs and evidence locations"}

Guidelines:
- Use tools to ground every claim. If asked about an IOC, search for it. If asked about a
  process, check the process tree. If asked how rare something is, check frequency.
- Keep answers concise and factual. Cite finding IDs (F0001) and source locations.
- Remember the conversation — the analyst may refer back to earlier answers ("that IP",
  "the second finding"). Use context from previous turns.
- If the data doesn't contain the answer, say so plainly rather than guessing.

/no_think"""


class InvestigationAgent:
    """Runs the LLM-driven investigation loop."""

    def __init__(self, llm_call: Callable, tools: InvestigationTools,
                 use_native_tools: bool = True):
        # llm_call(messages, tools=...) -> str | message-dict  (async)
        self.llm_call = llm_call
        self.tools = tools
        self.transcript: list[dict] = []
        # Try native function-calling first; auto-disable on failure so we
        # gracefully fall back to the text-JSON protocol for models that
        # don't support tools.
        self.use_native_tools = use_native_tools
        self._native_failed = False

    async def _call_native(self, history: list[dict]):
        """
        One native function-calling turn. Returns a normalized decision dict
        compatible with the text path: {"action","args"} or {"action":"answer"/
        "conclude", ...}. Returns None if native calling isn't usable.
        """
        if not self.use_native_tools or self._native_failed:
            return None
        try:
            msg = await self.llm_call(history, tools=NATIVE_TOOLS)
        except TypeError:
            # llm_call doesn't accept tools — disable native path
            self._native_failed = True
            return None
        except Exception as e:
            logger.info(f"Native tool call failed, falling back to text: {e}")
            self._native_failed = True
            return None

        # If the adapter returned plain text, native isn't in effect
        if isinstance(msg, str):
            self._native_failed = True
            return None

        tool_calls = msg.get("tool_calls") if isinstance(msg, dict) else None
        if tool_calls:
            call = tool_calls[0]
            fn = call.get("function", {})
            name = fn.get("name", "")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except (json.JSONDecodeError, TypeError):
                args = {}
            return {"action": name, "args": args,
                    "thought": (msg.get("content") or "").strip()[:200],
                    "_assistant_msg": msg, "_tool_call_id": call.get("id")}
        # No tool call — the model answered in text. Treat content as a
        # natural-language answer/conclusion. If the content is empty (e.g. a
        # reasoning model burned the whole budget on <think>), signal a retry
        # rather than returning a blank answer to the user.
        content = (msg.get("content") or "").strip()
        if not content:
            self._native_failed = True
            return None
        return {"action": "answer", "answer": content,
                "_assistant_msg": msg}

    def _dispatch(self, action: str, args: dict) -> dict:
        """Execute a tool call against the data."""
        tool_map = {
            "list_artifacts": lambda a: self.tools.list_artifacts(),
            "search": lambda a: self.tools.search(a.get("query", ""), a.get("max_results", 20)),
            "get_rows": lambda a: self.tools.get_rows(a.get("artifact", ""), a.get("start", 0), a.get("count", 10)),
            "get_findings": lambda a: self.tools.get_findings(a.get("severity", ""), a.get("category", ""), a.get("limit", 20)),
            "inspect_finding": lambda a: self.tools.inspect_finding(a.get("finding_id", "")),
            "get_process_tree": lambda a: self.tools.get_process_tree(a.get("pid", "")),
            "get_timeline": lambda a: self.tools.get_timeline(a.get("around", ""), a.get("window_events", 20)),
            "check_frequency": lambda a: self.tools.check_frequency(a.get("value", "")),
        }
        fn = tool_map.get(action)
        if not fn:
            return {"error": f"unknown tool '{action}'"}
        try:
            return fn(args or {})
        except Exception as e:
            return {"error": f"tool '{action}' failed: {e}"}

    @staticmethod
    def _parse_json(text: str) -> dict | None:
        """Extract a JSON object from the LLM response.

        Reasoning models sometimes emit JSON with the spaces stripped
        ("TofindIP...") or minor structural slips, so after strict json we fall
        back to json-repair before giving up.
        """
        if not text:
            return None
        # Strip code fences
        text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        # First balanced object
        match = re.search(r"\{.*\}", text, re.DOTALL)
        candidate = match.group(0) if match else text
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
        # Last resort: json-repair on both the candidate and the full text,
        # take whichever yields a dict with an "action".
        try:
            from json_repair import repair_json
            for src in (candidate, text):
                try:
                    obj = repair_json(src, return_objects=True)
                    if isinstance(obj, dict) and obj.get("action"):
                        return obj
                except Exception:
                    continue
        except Exception:
            pass
        return None

    async def ask(self, question: str, history: list[dict] | None = None,
                  case_summary: str = "", max_steps: int = 6,
                  progress_cb: Callable | None = None) -> dict:
        """
        Answer a single analyst question conversationally.

        Unlike investigate() which runs to a verdict, ask() answers one
        question — running tool calls as needed — and returns the answer plus
        the updated conversation history so the next question keeps context.
        """
        if not history:
            history = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}]
            if case_summary:
                history.append({"role": "user", "content":
                    f"Here is the case context for the host under investigation:\n{case_summary}"})
                history.append({"role": "assistant", "content":
                    "Understood. I have the case context and can query the forensic "
                    "data with tools. What would you like me to investigate?"})

        history.append({"role": "user", "content":
            f"{question}\n\n(Investigate using tools as needed, then give your answer. "
            f"Respond with a single JSON object.)"})

        steps_this_turn = []
        answer = None

        for step in range(max_steps):
            # Try native function calling first; fall back to text-JSON.
            decision = await self._call_native(history)
            used_native = decision is not None

            if not used_native:
                try:
                    raw = await self.llm_call(history)
                except Exception as e:
                    logger.warning(f"Agent chat LLM call failed: {e}")
                    answer = f"I hit an error querying the model: {e}"
                    break
                decision = self._parse_json(raw)
                if not decision:
                    # Parsing failed. If the raw text is clearly the internal
                    # tool-call protocol leaking (starts with '{' / mentions
                    # "action"), don't dump that JSON at the analyst — retry the
                    # turn with a nudge instead. Only surface genuine prose.
                    stripped = raw.strip()
                    looks_like_protocol = stripped.startswith("{") or '"action"' in stripped
                    if looks_like_protocol and step < max_steps - 1:
                        history.append({"role": "assistant", "content": stripped[:400]})
                        history.append({"role": "user", "content":
                            "That wasn't valid JSON. Reply with ONLY a single JSON "
                            "object per the protocol — either an action call or "
                            "an \"answer\"."})
                        continue
                    answer = stripped[:1500] if not looks_like_protocol else (
                        "I had trouble forming a structured answer. Please rephrase "
                        "the question or ask about a specific finding.")
                    history.append({"role": "assistant", "content": raw[:800]})
                    break

            action = decision.get("action", "")
            thought = decision.get("thought", "")

            if action == "answer":
                answer = decision.get("answer", "")
                if used_native and decision.get("_assistant_msg"):
                    history.append(decision["_assistant_msg"])
                else:
                    history.append({"role": "assistant", "content": json.dumps(
                        {k: v for k, v in decision.items() if not k.startswith("_")})})
                if progress_cb:
                    progress_cb(step, "answer", thought)
                break

            args = decision.get("args", {})
            result = self._dispatch(action, args)
            steps_this_turn.append({
                "step": step, "thought": thought, "action": action,
                "args": args, "result_summary": self._summarize_result(result),
            })
            if progress_cb:
                progress_cb(step, action, thought)

            if used_native and decision.get("_assistant_msg"):
                # Native protocol: append assistant msg + tool result message
                history.append(decision["_assistant_msg"])
                history.append({
                    "role": "tool",
                    "tool_call_id": decision.get("_tool_call_id"),
                    "content": json.dumps(result)[:2500],
                })
            else:
                # Text protocol
                history.append({"role": "assistant", "content": json.dumps(
                    {k: v for k, v in decision.items() if not k.startswith("_")})})
                history.append({"role": "user", "content":
                    f"Tool '{action}' result:\n{json.dumps(result)[:2500]}\n\n"
                    f"Answer the question now, or use another tool. Single JSON object."})

        if answer is None:
            answer = ("I gathered some data but couldn't form a complete answer "
                      "within the step limit. Try narrowing the question.")

        # Trim history if it grows long (keep system + recent turns)
        if len(history) > 40:
            history = [history[0]] + history[-30:]

        return {"answer": answer, "steps": steps_this_turn, "history": history}

    async def investigate(self, case_summary: str, max_steps: int = 12,
                          progress_cb: Callable | None = None) -> dict:
        """
        Run the investigation loop.

        Returns {
          "verdict": {...},          # final conclusion
          "steps": [...],            # full transcript of tool calls + results
          "completed": bool,         # whether the agent concluded on its own
        }
        """
        history = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content":
                f"Case summary:\n{case_summary}\n\n"
                f"Begin your investigation. Respond with a single JSON action."},
        ]

        verdict = None
        for step in range(max_steps):
            # Ask the LLM for the next action
            try:
                raw = await self.llm_call(history)
            except Exception as e:
                logger.warning(f"Agent LLM call failed at step {step}: {e}")
                self.transcript.append({"step": step, "error": str(e)})
                break

            decision = self._parse_json(raw)
            if not decision:
                # LLM didn't return valid JSON — nudge it once, else stop
                logger.debug(f"Agent step {step}: non-JSON response")
                self.transcript.append({"step": step, "raw": raw[:300],
                                        "note": "could not parse action"})
                history.append({"role": "assistant", "content": raw[:500]})
                history.append({"role": "user", "content":
                    "Respond with ONLY a single JSON object as instructed."})
                continue

            thought = decision.get("thought", "")
            action = decision.get("action", "")

            if action == "conclude":
                verdict = decision.get("verdict", {})
                self.transcript.append({
                    "step": step, "thought": thought, "action": "conclude",
                    "verdict": verdict,
                })
                if progress_cb:
                    progress_cb(step, "conclude", thought)
                break

            # Execute the tool
            args = decision.get("args", {})
            result = self._dispatch(action, args)
            step_record = {
                "step": step, "thought": thought,
                "action": action, "args": args,
                "result_summary": self._summarize_result(result),
            }
            self.transcript.append(step_record)
            if progress_cb:
                progress_cb(step, action, thought)

            # Feed the result back to the LLM
            history.append({"role": "assistant", "content": json.dumps(decision)})
            history.append({"role": "user", "content":
                f"Tool '{action}' result:\n{json.dumps(result)[:2500]}\n\n"
                f"Continue investigating or conclude. Respond with a single JSON action."})

        return {
            "verdict": verdict or {
                "compromised": None, "confidence": 0.0,
                "summary": "Investigation did not reach a conclusion within step limit.",
                "attack_chain": [], "key_evidence": [], "recommended_actions": [],
            },
            "steps": self.transcript,
            "completed": verdict is not None,
            "step_count": len(self.transcript),
        }

    @staticmethod
    def _summarize_result(result: dict) -> str:
        """Compact summary of a tool result for the transcript."""
        if "error" in result:
            return f"error: {result['error']}"
        if "total_hits" in result:
            return f"{result['total_hits']} hits"
        if "artifacts" in result and isinstance(result["artifacts"], list):
            return f"{len(result['artifacts'])} artifacts"
        if "total_matching" in result:
            return f"{result['total_matching']} findings"
        if "rows" in result:
            return f"{result.get('returned', 0)} rows"
        if "occurrences" in result:
            return f"{result['occurrences']} occurrences ({result.get('rarity','')})"
        return "ok"
