from proto import Field

from ..base import WorkflowRunner
from .utils import run_workflow


class GCPRunner(WorkflowRunner):
    async def start_pdf(self) -> dict:
        r = await run_workflow("generate-pdf")
        return {}

    async def start_scan(self) -> dict:
        r = await run_workflow("generate-pdf")
        return {}
