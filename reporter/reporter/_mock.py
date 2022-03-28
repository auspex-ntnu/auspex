import io
from pathlib import Path

import fastapi
from fastapi.exceptions import HTTPException
from fastapi.responses import StreamingResponse

from .backends.snyk.model import SnykContainerScan
from .backends.snyk.aggregate import AggregateScan
from .frontends.latex import create_document
from .models import ReportSingleIn

mockrouter = fastapi.APIRouter()


@mockrouter.post("/reportmock")
async def generate_report_mock(r: ReportSingleIn) -> StreamingResponse:
    import json
    import time

    json_start = time.perf_counter()
    with open("../_scans/mariadbscan.json", "r") as jsonfile:
        d = json.load(jsonfile)
    print(f"Loading json: {time.perf_counter() - json_start}s")

    # Parse scan log and create report
    pydantic_start = time.perf_counter()
    scan = SnykContainerScan(**d)
    from .backends.cve import CVSSTimeType

    vulns = scan.vulnerabilities.get_vulns_by_date(CVSSTimeType.PUBLICATION_TIME)
    print(f"Pydantic model instantization: {time.perf_counter() - pydantic_start}s")

    latex_start = time.perf_counter()
    latex_document = await create_document(scan)
    print(f"Latex document creation: {time.perf_counter() - latex_start}s")

    document_path = Path(f"{latex_document.default_filepath}.pdf")
    if not document_path.exists():
        raise HTTPException(500, "Failed to generate report.")

    # Send report file back as a streaming response
    with open(document_path, "rb") as f:
        return StreamingResponse(io.BytesIO(f.read()), media_type="application/pdf")


@mockrouter.post("/aggregatemock")
async def generate_aggregate_mock() -> None:
    import json

    files = ["phpscan.json", "mongoscan.json", "mariadbscan.json"]
    scans = []
    for filename in files:
        with open(f"../_scans/{filename}", "r") as jsonfile:
            d = json.load(jsonfile)
        # Parse scan log and create report
        scan = SnykContainerScan(**d)
        scans.append(scan)
    ag = AggregateScan(scans=scans)
    print(ag)
