import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from scanner import scan_container
import scanner
from scanner.exceptions import APIError
from http import HTTPStatus

from pydantic import BaseModel

app = FastAPI()


class ScanRequest(BaseModel):
    image: str
    backend: str = "snyk"


@app.exception_handler(APIError)
async def handle_api_error(request: Request, exc: APIError):
    # logging here
    return JSONResponse(status_code=500, content="lol")


@app.post("/scan")
async def scan_endpoint(scanr: ScanRequest) -> dict:
    scan = scan_container(
        image_name=scanr.image,
        backend=scanr.backend,
    )
    return scan.dict()
    # return json.loads(scan.get_results())
