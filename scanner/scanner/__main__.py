import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from .scan import scan_container
from scanner.exceptions import APIError

from pydantic import BaseModel
from core.models.scan import ScanIn, ScanOut

app = FastAPI()


class ScanRequest(BaseModel):
    images: list[str]
    backend: str = "snyk"
    pdf: bool = False


@app.exception_handler(APIError)
async def handle_api_error(request: Request, exc: APIError):
    # logging here
    return JSONResponse(status_code=500, content="lol")


@app.post("/scan", response_model=ScanOut)
async def scan_endpoint(scan_request: ScanIn) -> dict:
    for image in scan_request.images:
        scan = await scan_container(
            image=image,
            backend=scan_request.backend,
        )
        # use scan
    return ScanOut(
        status="Ok",
        logs=[],
        pdf=[],
    )
