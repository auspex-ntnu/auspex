from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from pydantic import BaseModel


app = FastAPI()


@app.get("/logs", response_class=RedirectResponse)
async def logs():
    return "http://pdfurl.com"


@app.post("/pdf/generate", response_class=RedirectResponse)
async def generate_pdf_report():
    return "https://pdfurl.com"


@app.post("/scan", response_class=RedirectResponse)
async def generate():
    return "https://scanurl.com"


@app.get("/")
async def root():
    return "Hello World!"
