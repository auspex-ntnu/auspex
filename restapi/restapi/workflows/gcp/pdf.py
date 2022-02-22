from .utils import run_workflow
from proto import Field


async def start_pdf_workflow() -> str:
    return await run_workflow("generate-pdf")
