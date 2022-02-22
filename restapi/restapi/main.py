from typing import cast
from fastapi import FastAPI, File, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import os

from .workflows.base import WorkflowRunner
from .workflows import get_runner
from .workflows.gcp import start_pdf_workflow, run_workflow
from auspex_core.models.scan import ScanIn, ScanOut
from auspex_core.models.pdf import PDFRequestIn


app = FastAPI()
runner: WorkflowRunner = get_runner()


@app.get("/logs", response_class=RedirectResponse)
async def logs():
    return "http://pdfurl.com"


@app.post("/pdf/generate")
async def generate_pdf_report(body: PDFRequestIn):
    return await start_pdf_workflow()


@app.post("/scan", response_model=ScanOut)
async def generate(scan_in: ScanIn):
    return os.getenv("SCAN_URL")


@app.get("/")
async def root():
    return "Hello World!"


@app.get("/countries/{country}")
async def countries(country: str):
    return await run_workflow("test", country=country, lol="lmao")
