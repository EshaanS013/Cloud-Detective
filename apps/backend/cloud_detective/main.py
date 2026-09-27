from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from cloud_detective import __version__
from cloud_detective.config import get_settings

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description="AWS control-plane security monitoring and incident response API",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/api/v1/health", tags=["system"])
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "cloud-detective-api",
        "version": __version__,
        "environment": settings.environment,
        "response_mode": settings.response_mode,
    }
