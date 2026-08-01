from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app import __version__
from app.config import get_settings
from app.db import SessionLocal, init_db
from app.routers import audit, auth, lab
from app.seed import seed_demo_admin

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        seed_demo_admin(db)
    finally:
        db.close()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version=__version__,
        lifespan=lifespan,
    )

    static_dir = BASE_DIR / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    application.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    application.include_router(auth.router)
    application.include_router(audit.router)
    application.include_router(lab.router)

    @application.get("/health")
    def health() -> dict[str, str | bool]:
        return {
            "status": "ok",
            "service": settings.app_name,
            "version": __version__,
            "env": settings.app_env,
            "simulation_mode": settings.simulation_mode,
        }

    @application.get("/", response_class=HTMLResponse)
    def home(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "app_name": settings.app_name,
                "version": __version__,
                "simulation_mode": settings.simulation_mode,
            },
        )

    return application


app = create_app()
