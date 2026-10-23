"""Spork-IDS FastAPI Application Entry Point."""
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.core.config import settings
from app.core.logging import logger
from app.db.session import init_db, SessionLocal
from app.db.seed import seed_initial_data
from app.api.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes database schema and default records on startup."""
    logger.info("Initializing Spork-IDS database tables...")
    init_db()
    with SessionLocal() as db:
        seed_initial_data(db)
    logger.info("Spork-IDS engine initialized and ready.")
    yield
    logger.info("Spork-IDS engine shutting down.")


app = FastAPI(
    title="Spork-IDS API",
    version="1.0.0",
    description="Python-based Intrusion Detection System and Security Operations Platform inspired by CrowdSec.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.SPORK_CORS_ORIGINS if settings.SPORK_CORS_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Router
app.include_router(api_router)

# Mount Frontend Static Assets if built
FRONTEND_DIST_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")

if os.path.isdir(FRONTEND_DIST_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST_DIR, "assets")), name="static-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(full_path: str):
        # If specific static file exists in dist, serve it
        possible_file = os.path.join(FRONTEND_DIST_DIR, full_path)
        if full_path and os.path.isfile(possible_file):
            return FileResponse(possible_file)
        # Otherwise fallback to index.html for client-side routing
        return FileResponse(os.path.join(FRONTEND_DIST_DIR, "index.html"))
else:
    @app.get("/", include_in_schema=False)
    async def index_placeholder():
        return {
            "name": "Spork-IDS API",
            "version": "1.0.0",
            "status": "online",
            "docs": "/docs",
            "dashboard": "Run frontend build (`cd frontend && npm run build`) or Vite dev server (`npm run dev`)",
        }
