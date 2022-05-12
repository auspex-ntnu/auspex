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

# @app.exception_handler(Exception)
# async def handle_exception(request, exc):
#     logger.error("An exception occured", exc)
#     return JSONResponse(status_code=500, content=exc.args)


@app.on_event("startup")
async def startup():
    logger.info("Starting up")
    # Instantiate config to check for missing fields
    AppConfig()
