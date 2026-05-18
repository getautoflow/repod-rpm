import logging
import os
from contextlib import asynccontextmanager

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from auth.router import router as auth_router
from routers.artifacts import router as artifacts_router
from routers.downloads_router import router as downloads_router
from routers.sbom_router import router as sbom_router
from routers.dashboard_router import router as dashboard_router
from routers.distributions_router import router as distributions_router
from routers.import_router import router as import_router
from routers.packages import router as packages_router
from routers.security_router import router as security_router
from routers.settings_router import router as settings_router
from routers.upload import router as upload_router
from routers.health_router import router as health_router
from services import scheduler_state
from services.security_sync import run_security_sync
from services.sla_alerts import run_sla_check
from services.retention import run_retention
from services.settings import get_settings
from routers.distributions_router import auto_init_distributions

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

_JWT_SECRET = os.getenv("JWT_SECRET_KEY", "")
if not _JWT_SECRET or _JWT_SECRET == "change-me-in-production":
    if os.getenv("ENV", "development") == "production":
        raise RuntimeError(
            "ERREUR CRITIQUE : JWT_SECRET_KEY n'est pas défini ou utilise la valeur par défaut. "
            "Générez une valeur aléatoire avec : openssl rand -hex 32"
        )
    else:
        logger.warning(
            "[security] JWT_SECRET_KEY utilise la valeur par défaut. "
            "Définissez une vraie valeur avant de passer en production."
        )

from limiter import limiter

_IS_PROD = os.getenv("ENV", "development") == "production"
_docs_url    = None if _IS_PROD else "/docs"
_redoc_url   = None if _IS_PROD else "/redoc"
_openapi_url = None if _IS_PROD else "/openapi.json"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Init automatique des distributions RPM (première installation)
    auto_init_distributions()

    settings = get_settings()
    sync_cfg = settings.get("sync", {})

    hour    = int(sync_cfg.get("hour", 3))
    minute  = int(sync_cfg.get("minute", 0))
    enabled = sync_cfg.get("enabled", True)

    sched = BackgroundScheduler(timezone="Europe/Paris")
    sched.add_job(
        run_security_sync,
        trigger=CronTrigger(hour=hour, minute=minute),
        id="security_sync_daily",
        name="Sync quotidienne des sources RPM sécurité",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    sched.add_job(
        run_sla_check,
        trigger=CronTrigger(hour=8, minute=0),
        id="sla_check_daily",
        name="Vérification SLA décisions CVE",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    sched.add_job(
        run_retention,
        trigger=CronTrigger(hour=2, minute=0),
        id="retention_daily",
        name="Politique de rétention (audit + paquets)",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    sched.start()

    scheduler_state.scheduler = sched

    if enabled:
        logger.info(
            f"[scheduler] Sync sécurité RPM planifiée chaque jour à "
            f"{hour:02d}:{minute:02d} (Europe/Paris)"
        )
    else:
        sched.pause_job("security_sync_daily")
        logger.info("[scheduler] Sync sécurité désactivée dans les paramètres.")

    yield

    sched.shutdown(wait=False)
    scheduler_state.scheduler = None
    logger.info("[scheduler] Scheduler arrêté proprement.")


app = FastAPI(
    title="RPM Repo Manager",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    openapi_url=_openapi_url,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

allowed_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:3003").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(packages_router)
app.include_router(upload_router)
app.include_router(artifacts_router)
app.include_router(import_router)
app.include_router(security_router)
app.include_router(dashboard_router)
app.include_router(distributions_router)
app.include_router(settings_router)
app.include_router(downloads_router)
app.include_router(sbom_router)
