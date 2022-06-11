from proto import Field

from .utils import run_workflow


async def start_pdf_workflow() -> str:
    return await run_workflow("generate-pdf")
