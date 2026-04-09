from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
import httpx
import secrets

from database import init_db
from api.routes import accounts, alerts, webhooks, stats
from api.routes import websocket as ws_routes
from config import get_settings
from utils.logger import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)
settings = get_settings()
security = HTTPBasic()


_SOC_HEALTH_URL = "http://soc:8001/health"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("startup_initializing_database")
    await init_db()

    # ── SOC health check (non-blocking) ───────────────────────────────────────
    # Verify the SOC service is reachable at startup. Failure is a warning
    # only — SFD operates independently of the SOC service.
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(_SOC_HEALTH_URL)
            if resp.status_code == 200:
                logger.info("soc_service_reachable", url=_SOC_HEALTH_URL)
            else:
                logger.warning("soc_service_unhealthy", status=resp.status_code)
    except Exception as exc:
        logger.warning("soc_service_unreachable", error=str(exc))

    logger.info("startup_complete")
    yield
    logger.info("shutdown")


app = FastAPI(
    title="Social Fraud Detector API",
    version="1.0.0",
    description="Real-time fraud and unauthorized access detection for social media accounts.",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://frontend:80"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    """HTTP Basic Auth guard for all protected API routes."""
    correct_user = secrets.compare_digest(credentials.username, settings.dashboard_username)
    correct_pass = secrets.compare_digest(credentials.password, settings.dashboard_password)
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


# Public webhook routes (verified by platform-specific signatures)
app.include_router(webhooks.router, prefix="/api")

# Protected routes
app.include_router(accounts.router, prefix="/api", dependencies=[Depends(verify_credentials)])
app.include_router(alerts.router, prefix="/api", dependencies=[Depends(verify_credentials)])
app.include_router(stats.router, prefix="/api", dependencies=[Depends(verify_credentials)])

# WebSocket routes (auth via ?token= query param, handled inside the router)
app.include_router(ws_routes.router)

# Static files — serves the WS test console at /static/ws_test.html
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "social-fraud-detector"}
