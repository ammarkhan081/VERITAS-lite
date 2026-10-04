"""FastAPI application for the VERITAS-lite backend."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.routes import campaigns, health, reports
from backend.memory.db import init_db

logger = logging.getLogger("veritas.api")


@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db()
    logger.info("VERITAS-lite API started")
    yield


app = FastAPI(
    title="VERITAS-lite API",
    description="Closed-loop multi-agent security hardening system for AI agents",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
from pathlib import Path

app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(campaigns.router, prefix="/api/campaigns", tags=["Campaigns"])
app.include_router(reports.router, prefix="/api/campaigns", tags=["Reports"])
app.include_router(reports.metrics_router, prefix="/api", tags=["Metrics"])

# Serve frontend build if available
frontend_dir = Path(__file__).parent.parent.parent / "frontend" / "dist"
if frontend_dir.exists():
    from fastapi.responses import FileResponse
    
    # Custom catch-all for SPA routing (React Router)
    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        resolved_frontend = frontend_dir.resolve()
        file_path = (frontend_dir / full_path).resolve()
        if (
            full_path
            and file_path.is_relative_to(resolved_frontend)
            and file_path.exists()
            and file_path.is_file()
        ):
            return FileResponse(file_path)
        return FileResponse(frontend_dir / "index.html")
else:
    logger.warning("Frontend build not found at %s. UI will not be served.", frontend_dir)


@app.exception_handler(Exception)
async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled API error for %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
