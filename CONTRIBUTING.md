# Contributing

This codebase is built to grow by **adding files, not editing core ones**.
Three extension points cover almost everything. Each is a single-file change.

---

## 1. Add a new artifact parser (plugin)

When you have a new data source (MFT, Prefetch, Browser history, Registry…).

1. Create `backend/app/plugins/<name>_plugin.py`.
2. Subclass `AnalyzerPlugin` and implement the contract (see
   `plugins/__init__.py` for the abstract base):
   - `can_handle(raw)` → bool
   - `analyze(raw)` → `list[Artifact]`
3. Register it in `PluginRegistry.default()`.

Emit the unified `Artifact` model (`app/models.py`) — that's what lets
detection, correlation, and Sigma stay source-agnostic. Do **not** add
special cases downstream.

## 2. Add a new detector

When you want a new detection over already-parsed artifacts.

1. Create `backend/app/detection/<concern>.py` with:
   ```python
   def detect_<concern>(engine, key, rows):
       # append findings via engine's helpers
       ...
   ```
2. In `detection/__init__.py`, import it and add **one** line:
   ```python
   register_route("<artifact_key>", detect_<concern>)
   ```

`base.py`'s dispatch loop is routing-table driven on purpose — it never
needs editing as detectors are added. For a cross-cutting pass that runs
after all per-artifact detection (e.g. correlation), use
`register_additional_pass(...)` instead.

## 3. Add a new API route

1. Add the endpoint in `main.py` — keep it **thin**. No business logic here.
2. Delegate to a service in `services.py` (or a new one).
3. The orchestrator sequences services; it doesn't hold logic either.

The layering is deliberate: `main.py` (HTTP) → `orchestrator.py` (sequencing)
→ `services.py` + engines (logic). If you find yourself writing logic in
`main.py` or `orchestrator.py`, push it down.

---

## Detection rules

Rules are **fetched, not committed** (the curated sets are large and
auto-updated upstream):

```bash
./scripts/install-yara-rules.sh core
./scripts/install-sigma-rules.sh hayabusa
```

Only hand-written rules are committed: `backend/yara_rules/starter_rules.yar`
and `sigma_rules/builtin_rules.yml`. Add your own custom rules there.

## Tests

Tests live in `backend/tests/` and run with pytest:

```bash
cd backend
pip install -r requirements.txt pytest
pytest
```

CI runs the same suite on every push and PR (`.github/workflows/ci.yml`).
The current tests are intentionally lightweight smoke + registry checks:
every module must import, and the detection/plugin registries must stay
well-formed. When you add a detector or plugin, the registry tests already
assert it's wired correctly — add a focused behaviour test for the new
detection logic itself.

## Before opening a PR

- [ ] `pytest` passes (from `backend/`)
- [ ] `./scripts/verify-build.sh` passes
- [ ] New parser/detector/route is a single-file addition where possible
- [ ] No business logic leaked into `main.py` or `orchestrator.py`
- [ ] No large downloaded rulesets, data dumps, or secrets committed
      (check `git status` against `.gitignore`)
- [ ] README updated if you changed the architecture

## Branch & commit conventions

- Branches: `feat/…`, `fix/…`, `chore/…`, `docs/…`
- Keep commits scoped and described in the imperative ("add MFT plugin").
