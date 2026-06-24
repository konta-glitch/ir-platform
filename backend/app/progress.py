"""
Progress tracker — tracks the state of long-running analysis jobs
so the frontend can show a live progress bar with descriptions.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional


# Pipeline stages with descriptions and weight (% of total)
STAGES = [
    ("upload", "Reading collection file", 5),
    ("extract", "Extracting & parsing artifacts", 20),
    ("binary_parse", "Parsing binary files (EVTX, registry)", 15),
    ("detection", "Running forensic detection engine over all rows", 30),
    ("anonymize", "Anonymizing sensitive identifiers", 10),
    ("llm_analysis", "Local LLM analyzing findings", 15),
    ("report", "Generating report", 5),
]


@dataclass
class JobProgress:
    job_id: str
    stage: str = "queued"
    stage_label: str = "Queued"
    percent: int = 0
    detail: str = ""
    done: bool = False
    error: Optional[str] = None
    result: Optional[dict] = None
    started_at: float = field(default_factory=time.time)
    # sub-counters for detailed reporting
    rows_processed: int = 0
    total_rows: int = 0
    findings_count: int = 0


class ProgressTracker:
    """In-memory progress store for active analysis jobs."""

    def __init__(self):
        self._jobs: dict[str, JobProgress] = {}

    def create(self, job_id: str) -> JobProgress:
        job = JobProgress(job_id=job_id)
        self._jobs[job_id] = job
        return job

    def get(self, job_id: str) -> Optional[JobProgress]:
        return self._jobs.get(job_id)

    def update(self, job_id: str, stage: str = None, detail: str = None,
               rows_processed: int = None, total_rows: int = None,
               findings_count: int = None):
        job = self._jobs.get(job_id)
        if not job:
            return

        if stage:
            job.stage = stage
            # Find stage label and compute cumulative percent
            cumulative = 0
            for s_key, s_label, s_weight in STAGES:
                if s_key == stage:
                    job.stage_label = s_label
                    job.percent = min(cumulative + s_weight, 99)
                    break
                cumulative += s_weight
        if detail is not None:
            job.detail = detail
        if rows_processed is not None:
            job.rows_processed = rows_processed
        if total_rows is not None:
            job.total_rows = total_rows
        if findings_count is not None:
            job.findings_count = findings_count

    def complete(self, job_id: str, result: dict):
        job = self._jobs.get(job_id)
        if job:
            job.done = True
            job.percent = 100
            job.stage = "complete"
            job.stage_label = "Analysis complete"
            job.result = result

    def fail(self, job_id: str, error: str):
        job = self._jobs.get(job_id)
        if job:
            job.done = True
            job.error = error
            job.stage = "error"
            job.stage_label = "Analysis failed"

    def cleanup(self, job_id: str):
        """Remove a finished job after the client has retrieved the result."""
        self._jobs.pop(job_id, None)


# Global singleton
_tracker = ProgressTracker()


def get_tracker() -> ProgressTracker:
    return _tracker
