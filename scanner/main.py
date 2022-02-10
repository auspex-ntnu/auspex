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
    images: list[str]
    backend: str = "snyk"
    pdf: bool = False


@app.exception_handler(APIError)
async def handle_api_error(request: Request, exc: APIError):
    # logging here
    return JSONResponse(status_code=500, content="lol")


@app.post("/scan")
async def scan_endpoint(request: ScanRequest) -> dict:
    scan = scan_container(
        image_name=request.image,
        backend=request.backend,
    )
    return scan.dict()
    # return json.loads(scan.get_results())
