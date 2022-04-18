from datetime import datetime, timedelta
import io
from pathlib import Path
import random
from auspex_core.models.cve import CVSS
from auspex_core.models.gcr import ImageInfo
from auspex_core.models.scan import CVSSv3Distribution, ReportData

import fastapi
from fastapi.exceptions import HTTPException
from fastapi.responses import StreamingResponse

from reporter.utils.firestore import get_firestore_document

from .backends.snyk.aggregate import AggregateScan
from .backends.snyk.model import SnykContainerScan
from .config import AppConfig
from .frontends.latex import create_document
from .models import ReportRequestIn
from .utils.firestore import get_firestore_document
from .db import get_prev_scans

mockrouter = fastapi.APIRouter()


def get_mock_reportdata(report: ReportData, n: int = 100) -> list[ReportData]:
    return [
        ReportData(
            id="mock",
            image=report.image,
            timestamp=datetime(
                year=2022, month=random.randint(1, 6), day=random.randint(1, 28)
            ),
            cvss=CVSS(
                mean=random.uniform(3.0, 7.0),
                median=random.uniform(3.0, 7.0),
                stdev=random.uniform(0.0, 1.0),
                min=random.uniform(0.0, 2.0),
                max=random.uniform(2.0, 10.0),
            ),
            vulnerabilities=CVSSv3Distribution(
                critical=random.randint(0, 10),
                high=random.randint(0, 10),
                medium=random.randint(0, 10),
                low=random.randint(0, 10),
            ),
            report_url=None,
            aggregate=False,
            schema_version="1",
            historical=False,
            updated=datetime.utcnow(),
            upgrade_paths=[],
            dockerfile_instructions=[],
        )
        for _ in range(n)
    ]


@mockrouter.post("/reportmock")
async def generate_report_mock(r: ReportRequestIn) -> StreamingResponse:
    import json
    import time

    doc = await get_firestore_document(r.document_id[0], AppConfig().collection_reports)
    d = doc.to_dict()
    if not d:
        raise HTTPException(status_code=404, detail="Document not found")
    scan = ReportData(**d)

    prev_scans = await get_prev_scans(
        scan,
        collection=AppConfig().collection_reports,
        max_age=timedelta(weeks=24),
        ignore_self=True,
        skip_historical=False,  # FIXME: set to True & should be envvar
    )

    outdoc = await create_document(scan, prev_scans)
    if not outdoc.path.exists():
        raise HTTPException(500, "Failed to generate report.")

    # Send report file back as a streaming response
    with open(outdoc.path, "rb") as f:
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
