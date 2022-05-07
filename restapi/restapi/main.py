from loguru import logger
from fastapi import FastAPI

from .config import AppConfig
from .exceptions import install_handlers
from .routes import reports_router, scans_router, status_router

# Setup app and add routers
app = FastAPI()
install_handlers(app)
app.include_router(reports_router)
app.include_router(scans_router)
app.include_router(status_router)


@app.on_event("startup")
async def startup():
    logger.info("Starting up")
    # Instantiate config to check for missing fields
    AppConfig()
