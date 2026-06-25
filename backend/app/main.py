"""
IR Platform — Local-first incident response.

Stack: LM Studio (local LLM) + Claude (standby) + standalone collectors.
No Velociraptor dependency.
"""

import json
import logging
import shutil
import uuid
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.models import AnalyzeRequest, HealthResponse, IncidentStatus
from app.orchestrator import Orchestrator
from app.collector import CollectorManager
from app.image_analyzer import ImageAnalyzer
from app.report_generator import generate_report, generate_markdown
from app.html_report import generate_html
from app.progress import get_tracker, STAGES
from app.structured_logging import setup_logging, get_audit_logger
from app.config import get_settings as _gs

setup_logging(log_level=_gs().log_level)
logger = logging.getLogger(__name__)
audit = get_audit_logger()

orchestrator = Orchestrator()
collector = CollectorManager()
image_analyzer = ImageAnalyzer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("IR Platform starting (local-first, no Velociraptor)")
    model = await orchestrator.local.get_loaded_model()
    if model:
        logger.info(f"LM Studio model: {model}")
    else:
        logger.warning("LM Studio not reachable — start it before using")

    # Load Sigma rules (Hayabusa + built-in). The entrypoint may still be
    # updating them in the background; we load what's present now and the
    # /api/sigma/reload endpoint can refresh once the download completes.
    try:
        rule_count = orchestrator.sigma.load_rules()
        logger.info(f"Sigma engine: {rule_count} rules loaded")
    except Exception as e:
        logger.warning(f"Could not load Sigma rules at startup: {e}")

    yield
    logger.info("IR Platform shut down")


app = FastAPI(
    title="IR Platform",
    description="Local-first Incident Response with standalone collectors",
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════
# Health
# ══════════════════════════════════════════════════

@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    model = await orchestrator.local.get_loaded_model()
    return HealthResponse(
        status="ok",
        lm_studio_reachable=await orchestrator.local.health_check(),
        lm_studio_model=model,
        claude_api_configured=orchestrator.cloud.health_check(),
    )


@app.get("/api/stats")
async def platform_stats():
    """Platform statistics including persisted incident count."""
    try:
        incident_count = orchestrator.db.count_incidents()
    except Exception:
        incident_count = len(orchestrator.incidents)
    return {
        "incidents_stored": incident_count,
        "sigma_rules": orchestrator.sigma.rule_count(),
        "persistence": "sqlite",
    }


# ══════════════════════════════════════════════════
# Analysis
# ══════════════════════════════════════════════════

@app.post("/api/analyze")
async def analyze_data(request: AnalyzeRequest):
    """Anonymize + analyze raw forensic data (from collector upload or manual paste)."""
    try:
        incident, stats = await orchestrator.analyze(request)
        return {
            "incident_id": incident.id,
            "analysis": incident.analysis.model_dump() if incident.analysis else None,
            "escalation": incident.escalation.model_dump() if incident.escalation else None,
            "stats": stats.model_dump(),
        }
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(500, f"Analysis error: {e}")


@app.post("/api/anonymize")
async def anonymize_only(raw_data: str, use_llm: bool = True):
    """Anonymize raw text (without analysis)."""
    result = await orchestrator.anonymizer.anonymize(raw_data, use_llm=use_llm)
    return {
        "anonymized_text": result.anonymized_text,
        "mappings_count": len(result.mappings),
        "mappings": [m.model_dump() for m in result.mappings],
        "model_used": result.model_used,
    }


# ══════════════════════════════════════════════════
# Collector — download scripts, upload results
# ══════════════════════════════════════════════════

@app.get("/api/collector/download/windows")
async def download_windows_collector():
    """Download the Windows PowerShell IR collector."""
    path = Path("/app/collectors/ir_collect.ps1")
    if not path.exists():
        raise HTTPException(404, "Windows collector not found")
    return FileResponse(path, media_type="application/octet-stream", filename="ir_collect.ps1")


@app.get("/api/collector/download/linux")
async def download_linux_collector():
    """Download the Linux/Mac bash IR collector."""
    path = Path("/app/collectors/ir_collect.sh")
    if not path.exists():
        raise HTTPException(404, "Linux collector not found")
    return FileResponse(path, media_type="application/octet-stream", filename="ir_collect.sh")


@app.post("/api/collector/upload")
async def upload_collector_results(
    file: UploadFile = File(...),
    title: str = Form("Uploaded collection"),
    context: str = Form(""),
    allow_cloud: bool = Form(True),
):
    """Upload collector results (ZIP/JSON) for automated analysis."""
    upload_dir = Path(get_settings().data_dir) / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    file_path = upload_dir / file.filename

    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    logger.info(f"Uploaded: {file.filename} ({file_path.stat().st_size} bytes)")

    try:
        upload_result = await collector.process_upload(str(file_path), title)

        if "error" in upload_result.get("data", {}):
            return {
                "status": "error",
                "message": upload_result["data"]["error"],
                "filename": file.filename,
            }

        request = AnalyzeRequest(
            title=title or f"Upload: {file.filename}",
            raw_data="",  # structured path doesn't use raw_data
            data_type="mixed",
            context=context or f"Uploaded from collector: {file.filename}",
            allow_cloud=allow_cloud,
        )
        incident, stats = await orchestrator.analyze_structured(
            upload_result["data"], request
        )

        return {
            "status": "analyzed",
            "filename": file.filename,
            "upload_summary": {
                "size_bytes": upload_result["size_bytes"],
                "source_type": upload_result.get("source_type", "unknown"),
                "data_types": upload_result["data_types"],
                "total_items": upload_result["total_items"],
            },
            "incident_id": incident.id,
            "analysis": incident.analysis.model_dump() if incident.analysis else None,
            "stats": stats.model_dump(),
        }
    except Exception as e:
        logger.error(f"Upload analysis failed: {e}", exc_info=True)
        raise HTTPException(500, f"Analysis failed: {e}")
    finally:
        try:
            file_path.unlink()
        except Exception:
            pass


# ══════════════════════════════════════════════════
# Large Collections (path-based, for 60GB+ files)
# ══════════════════════════════════════════════════

@app.get("/api/collections")
async def list_collections():
    """List collection files in the ./collections/ folder."""
    collections_dir = Path("/app/collections")
    collections_dir.mkdir(parents=True, exist_ok=True)
    files = []
    for f in sorted(collections_dir.iterdir()):
        if f.is_file() and f.suffix.lower() in ('.zip', '.tar', '.gz', '.json', '.jsonl'):
            files.append({
                "filename": f.name,
                "path": str(f),
                "size_gb": round(f.stat().st_size / (1024**3), 2),
                "size_mb": round(f.stat().st_size / (1024**2), 1),
                "format": f.suffix.lower().lstrip('.'),
            })
        elif f.is_dir():
            # Velociraptor collections are sometimes extracted folders
            total = sum(
                ff.stat().st_size for ff in f.rglob("*") if ff.is_file()
            )
            files.append({
                "filename": f.name,
                "path": str(f),
                "size_gb": round(total / (1024**3), 2),
                "size_mb": round(total / (1024**2), 1),
                "format": "folder",
            })
    return {"collections": files}


@app.post("/api/collections/analyze")
async def analyze_collection_from_path(
    collection_path: str = Form(...),
    title: str = Form("Collection analysis"),
    allow_cloud: bool = Form(True),
):
    """Start async analysis of a collection. Returns a job_id for progress tracking."""
    path = Path(collection_path)
    if not path.exists():
        raise HTTPException(404, f"Collection not found: {collection_path}")

    job_id = str(uuid.uuid4())[:8]
    tracker = get_tracker()
    tracker.create(job_id)

    # Run analysis in background
    asyncio.create_task(_run_collection_analysis(
        job_id, str(path), title, allow_cloud
    ))

    return {"job_id": job_id, "status": "started"}


async def _run_collection_analysis(job_id: str, collection_path: str,
                                    title: str, allow_cloud: bool):
    """Background task: parse + analyze a collection with progress updates."""
    tracker = get_tracker()
    path = Path(collection_path)
    try:
        tracker.update(job_id, stage="upload", detail=f"Reading {path.name}")
        logger.info(f"[{job_id}] Analyzing collection: {path.name} ({path.stat().st_size / 1e9:.1f}GB)")

        tracker.update(job_id, stage="extract", detail="Extracting and parsing artifacts")
        if path.is_dir():
            upload_result = await collector.process_upload_dir(str(path))
        else:
            upload_result = await collector.process_upload(str(path), title)

        if "error" in upload_result.get("data", {}):
            tracker.fail(job_id, upload_result["data"]["error"])
            return

        request = AnalyzeRequest(
            title=title or f"Collection: {path.name}",
            raw_data="",
            data_type="mixed",
            context=f"Collection from path: {path.name}, "
                    f"source: {upload_result.get('source_type', 'unknown')}",
            allow_cloud=allow_cloud,
        )
        incident, stats = await orchestrator.analyze_structured(
            upload_result["data"], request, job_id=job_id
        )

        tracker.complete(job_id, {
            "status": "analyzed",
            "filename": path.name,
            "upload_summary": {
                "size_bytes": upload_result.get("size_bytes", 0),
                "source_type": upload_result.get("source_type", "unknown"),
                "data_types": upload_result.get("data_types", []),
                "total_items": upload_result.get("total_items", 0),
            },
            "incident_id": incident.id,
            "analysis": incident.analysis.model_dump() if incident.analysis else None,
            "stats": stats.model_dump(),
        })
        logger.info(f"[{job_id}] Analysis complete: incident {incident.id}")
    except Exception as e:
        logger.error(f"[{job_id}] Collection analysis failed: {e}", exc_info=True)
        tracker.fail(job_id, str(e))


@app.get("/api/jobs/{job_id}/progress")
async def stream_job_progress(job_id: str):
    """Server-Sent Events stream of analysis progress."""
    async def event_generator():
        tracker = get_tracker()
        # Grace period: the job may not be registered the instant the client
        # connects. Don't give up immediately if it's missing.
        missing_ticks = 0
        last_heartbeat = asyncio.get_event_loop().time()

        while True:
            job = tracker.get(job_id)

            if not job:
                missing_ticks += 1
                # Allow ~10s for the job to appear before declaring it gone
                if missing_ticks > 20:
                    yield f"data: {json.dumps({'error': 'Job not found'})}\n\n"
                    break
                # Send a heartbeat comment so the connection stays alive
                yield ": waiting for job\n\n"
                await asyncio.sleep(0.5)
                continue

            missing_ticks = 0
            payload = {
                "stage": job.stage,
                "stage_label": job.stage_label,
                "percent": job.percent,
                "detail": job.detail,
                "done": job.done,
                "error": job.error,
                "rows_processed": job.rows_processed,
                "total_rows": job.total_rows,
                "findings_count": job.findings_count,
            }
            if job.done and job.result:
                payload["result"] = job.result

            yield f"data: {json.dumps(payload)}\n\n"

            if job.done:
                break

            # Heartbeat every ~5s even if nothing changed, so proxies and
            # browsers don't drop the connection during long blocking stages
            # (e.g. parsing every EVTX event, scanning 850K rows).
            now = asyncio.get_event_loop().time()
            if now - last_heartbeat > 5:
                yield ": heartbeat\n\n"
                last_heartbeat = now

            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive",
                 "X-Accel-Buffering": "no"},
    )


@app.get("/api/jobs/{job_id}/status")
async def get_job_status(job_id: str):
    """Plain JSON job status — polling fallback when SSE drops."""
    tracker = get_tracker()
    job = tracker.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    payload = {
        "stage": job.stage,
        "stage_label": job.stage_label,
        "percent": job.percent,
        "detail": job.detail,
        "done": job.done,
        "error": job.error,
        "rows_processed": job.rows_processed,
        "total_rows": job.total_rows,
        "findings_count": job.findings_count,
    }
    if job.done and job.result:
        payload["result"] = job.result
    return payload


@app.get("/api/pipeline/stages")
async def get_pipeline_stages():
    """Return the pipeline stage definitions for the UI."""
    return {"stages": [{"key": k, "label": l, "weight": w} for k, l, w in STAGES]}


# ══════════════════════════════════════════════════
# Investigation Agent — LLM-driven interactive analysis
# ══════════════════════════════════════════════════

_agent_jobs: dict = {}


@app.post("/api/incidents/{incident_id}/investigate")
async def start_investigation(incident_id: str,
                              question: str = Form(""),
                              max_steps: int = Form(12)):
    """Launch the LLM investigation agent. Returns a job_id to stream progress."""
    incident = orchestrator.get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")

    job_id = str(uuid.uuid4())[:8]
    _agent_jobs[job_id] = {"steps": [], "done": False, "result": None, "error": None}

    async def _run():
        def progress_cb(step, action, thought):
            _agent_jobs[job_id]["steps"].append({
                "step": step, "action": action, "thought": thought,
            })
        try:
            result = await orchestrator.run_investigation(
                incident_id, max_steps=max_steps,
                question=question, progress_cb=progress_cb,
            )
            _agent_jobs[job_id]["result"] = result
            _agent_jobs[job_id]["done"] = True
        except Exception as e:
            logger.error(f"Investigation failed: {e}", exc_info=True)
            _agent_jobs[job_id]["error"] = str(e)
            _agent_jobs[job_id]["done"] = True

    asyncio.create_task(_run())
    return {"job_id": job_id, "status": "started"}


@app.get("/api/investigations/{job_id}")
async def get_investigation_status(job_id: str):
    """Poll investigation progress + result."""
    job = _agent_jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Investigation job not found")
    return job


@app.get("/api/incidents/{incident_id}/graph")
async def get_incident_graph(incident_id: str):
    """Return the entity connectivity graph (processes, IPs, users, files)."""
    incident = orchestrator.get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    graph = incident.raw_artifacts.get("entity_graph", {"nodes": [], "edges": []})
    return graph


@app.get("/api/incidents/{incident_id}/investigation")
async def get_incident_investigation(incident_id: str):
    """Return the stored investigation for an incident, if any."""
    incident = orchestrator.get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    inv = incident.raw_artifacts.get("investigation")
    if not inv:
        raise HTTPException(404, "No investigation has been run for this incident")
    return inv


@app.post("/api/incidents/{incident_id}/chat")
async def chat_with_agent(incident_id: str, question: str = Form(...)):
    """
    Ask the investigation agent a question. The agent queries the real data
    with tools and answers, keeping conversation context for follow-ups.
    """
    incident = orchestrator.get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    try:
        steps_seen = []
        def progress_cb(step, action, thought):
            steps_seen.append({"step": step, "action": action, "thought": thought})
        result = await orchestrator.ask_agent(incident_id, question, progress_cb=progress_cb)
        return {
            "answer": result["answer"],
            "steps": result["steps"],
        }
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.error(f"Agent chat failed: {e}", exc_info=True)
        raise HTTPException(500, f"Agent chat failed: {e}")


@app.post("/api/incidents/{incident_id}/chat/clear")
async def clear_agent_chat(incident_id: str):
    """Reset the conversation history with the agent for this incident."""
    orchestrator.clear_chat(incident_id)
    return {"status": "cleared"}


@app.get("/api/sigma/rules")
async def list_sigma_rules():
    """List loaded Sigma detection rules."""
    count = orchestrator.sigma.rule_count()
    return {
        "rule_count": count,
        "rules": [
            {
                "title": r.title,
                "level": r.level,
                "mitre": r.mitre,
                "category": r.category,
                "source": r.source_file,
            }
            for r in orchestrator.sigma.rules
        ],
    }


@app.post("/api/sigma/reload")
async def reload_sigma_rules():
    """Reload Sigma rules from the ./sigma_rules/ folder."""
    count = orchestrator.sigma.load_rules()
    return {"status": "reloaded", "rule_count": count}


# ══════════════════════════════════════════════════
# Audit log + diagnostics
# ══════════════════════════════════════════════════

@app.get("/api/audit")
async def get_audit_log(limit: int = 100, event: str | None = None):
    """Read recent audit log records (newest first)."""
    from app.structured_logging import get_audit_logger
    a = get_audit_logger()
    return {
        "records": a.read_recent(limit=limit, event_filter=event),
        "stats": a.stats(),
    }


@app.get("/api/incidents/{incident_id}/trace")
async def get_incident_trace(incident_id: str):
    """Get the detailed pipeline execution trace for an incident."""
    incident = orchestrator.get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    trace = incident.raw_artifacts.get("pipeline_trace")
    if not trace:
        raise HTTPException(404, "No trace recorded for this incident")
    return trace


# ══════════════════════════════════════════════════
# Disk Image Analysis (FTK Imager, E01, raw, VMDK)
# ══════════════════════════════════════════════════

@app.get("/api/images")
async def list_images():
    """List disk images available in the /app/images volume."""
    return {"images": image_analyzer.list_available_images()}


@app.post("/api/images/analyze")
async def analyze_disk_image(
    image_path: str = Form(...),
    title: str = Form("Disk image analysis"),
    artifacts: str = Form(""),
    allow_cloud: bool = Form(True),
):
    """
    Analyze a forensic disk image (E01, raw, VMDK, VHD).
    Place images in the ./images/ folder (mapped to /app/images).
    """
    artifact_list = [a.strip() for a in artifacts.split(",") if a.strip()] or None

    try:
        logger.info(f"Starting image analysis: {image_path}")
        extracted = await image_analyzer.analyze_image(image_path, artifact_list)

        if "error" in extracted:
            raise HTTPException(400, extracted["error"])

        # Feed extracted artifacts into the analysis pipeline
        request = AnalyzeRequest(
            title=title or f"Image: {Path(image_path).name}",
            raw_data="",
            data_type="mixed",
            context=f"Forensic disk image: {Path(image_path).name}. "
                    f"Extracted {extracted.get('image_info', {}).get('total_artifacts_extracted', 0)} artifacts.",
            allow_cloud=allow_cloud,
        )
        incident, stats = await orchestrator.analyze_structured(extracted, request)

        return {
            "status": "analyzed",
            "image_info": extracted.get("image_info"),
            "system_info": extracted.get("system_info"),
            "incident_id": incident.id,
            "analysis": incident.analysis.model_dump() if incident.analysis else None,
            "stats": stats.model_dump(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Image analysis failed: {e}", exc_info=True)
        raise HTTPException(500, f"Image analysis failed: {e}")


@app.post("/api/images/upload")
async def upload_disk_image(file: UploadFile = File(...)):
    """Upload a disk image file to the images volume."""
    images_dir = Path("/app/images")
    images_dir.mkdir(parents=True, exist_ok=True)
    dest = images_dir / file.filename

    logger.info(f"Receiving image upload: {file.filename}")
    with open(dest, "wb") as f:
        while chunk := await file.read(8 * 1024 * 1024):  # 8MB chunks
            f.write(chunk)

    size_gb = round(dest.stat().st_size / (1024**3), 2)
    logger.info(f"Image saved: {dest} ({size_gb}GB)")

    return {
        "status": "uploaded",
        "filename": file.filename,
        "path": str(dest),
        "size_gb": size_gb,
    }


# ══════════════════════════════════════════════════
# Incidents
# ══════════════════════════════════════════════════

@app.get("/api/incidents")
async def list_incidents():
    incs = orchestrator.list_incidents()
    return {"incidents": [i.model_dump() for i in incs], "count": len(incs)}


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    incident = orchestrator.get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident.model_dump()


@app.delete("/api/incidents/{incident_id}")
async def delete_incident(incident_id: str):
    """Permanently delete an incident and its investigation data."""
    existed = orchestrator.delete_incident(incident_id)
    if not existed:
        raise HTTPException(404, "Incident not found")
    return {"status": "deleted", "incident_id": incident_id}


@app.patch("/api/incidents/{incident_id}")
async def update_incident(
    incident_id: str,
    status: IncidentStatus | None = None,
    analyst_notes: str | None = None,
):
    incident = orchestrator.update_incident(
        incident_id, status=status, analyst_notes=analyst_notes,
    )
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident.model_dump()


@app.post("/api/incidents/{incident_id}/findings/{finding_id}/triage")
async def triage_finding(
    incident_id: str,
    finding_id: str,
    verdict: str | None = Form(None),
    note: str | None = Form(None),
):
    """Set a finding's analyst verdict and/or note.

    verdict ∈ {true_positive, false_positive, benign, needs_review, clear}.
    "clear" removes the triage entry. Either field may be sent on its own, so
    the UI can update a verdict and a note independently.
    """
    valid = {"true_positive", "false_positive", "benign", "needs_review", "clear", None}
    if verdict not in valid:
        raise HTTPException(400, f"Invalid verdict: {verdict}")
    incident = orchestrator.triage_finding(
        incident_id, finding_id, verdict=verdict, note=note,
    )
    if not incident:
        raise HTTPException(404, "Incident not found")
    return {"finding_id": finding_id, "triage": incident.finding_triage.get(finding_id, {})}


@app.post("/api/incidents/{incident_id}/deanonymize")
async def deanonymize_report(incident_id: str):
    result = orchestrator.deanonymize_report(incident_id)
    if not result:
        raise HTTPException(404, "Incident not found or no analysis")
    return result


@app.post("/api/incidents/{incident_id}/escalation/approve")
async def approve_escalation(incident_id: str):
    """Send unresolved knowledge gaps to Claude for answers.

    Data is anonymized right before sending to Claude and de-anonymized on
    return (handled inside escalate_incident_gaps).
    """
    incident = orchestrator.get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")

    try:
        from app.structured_logging import get_audit_logger
        unresolved_count = len([
            i for i in (incident.escalation.items if incident.escalation else [])
            if not i.resolved_by_cloud and not i.resolved_locally
        ])
        get_audit_logger().record(
            "cloud_escalation_approved",
            incident_id=incident_id,
            questions=unresolved_count,
        )
        return await orchestrator.escalate_incident_gaps(incident_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.error(f"Cloud escalation failed: {e}", exc_info=True)
        raise HTTPException(500, f"Cloud escalation failed: {e}")


# ══════════════════════════════════════════════════
# Reports
# ══════════════════════════════════════════════════

@app.get("/api/incidents/{incident_id}/report")
async def get_incident_report(incident_id: str):
    """Generate a structured report for an incident."""
    incident = orchestrator.get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return generate_report(incident)


@app.get("/api/incidents/{incident_id}/report/download")
async def download_incident_report(incident_id: str):
    """Download incident report as Markdown."""
    incident = orchestrator.get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")

    md = generate_markdown(incident)
    filename = f"IR-{incident_id}-report.md"

    from fastapi.responses import Response
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/incidents/{incident_id}/report/html")
async def get_incident_report_html(incident_id: str, download: bool = False):
    """Render the incident report as a styled, self-contained HTML document.

    Same data as the Markdown/JSON report, but as a single shareable file with
    an executive/technical toggle and client-side finding filters. Pass
    ?download=true to get it as an attachment instead of inline.
    """
    incident = orchestrator.get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")

    from fastapi.responses import HTMLResponse, Response
    report = generate_report(incident)
    page = generate_html(report)
    if download:
        return Response(
            content=page,
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="IR-{incident_id}-report.html"'},
        )
    return HTMLResponse(content=page)
@app.get("/api/incidents/{incident_id}/search")
async def rag_search(incident_id: str, q: str, top_k: int = 15):
    """Semantic search over incident findings."""
    from app.rag_engine import get_engine
    engine = get_engine(incident_id)
    if not engine.is_indexed:
        raise HTTPException(404, "Findings not indexed yet — run analysis first")
    results = engine.search(q, top_k=top_k)
    return {"query": q, "results": results, "total": len(results)}


@app.post("/api/incidents/{incident_id}/ask")
async def rag_ask(incident_id: str, body: dict):
    """RAG: answer a natural-language question grounded in incident findings."""
    from app.rag_engine import get_engine
    from app.lm_client import get_lm_client
    question = body.get("question", "")
    if not question:
        raise HTTPException(400, "question field required")
    engine = get_engine(incident_id)
    if not engine.is_indexed:
        raise HTTPException(404, "Findings not indexed yet — run analysis first")
    lm = get_lm_client()
    answer = await engine.query_llm(question, lm)
    return {"question": question, "answer": answer}