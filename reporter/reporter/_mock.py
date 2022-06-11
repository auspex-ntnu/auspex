import io
import pickle
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import fastapi
from auspex_core.docker.models import ImageInfo
from auspex_core.models.api.report import ReportRequestIn
from auspex_core.models.cve import CVSS
from auspex_core.models.scan import CVSSv3Distribution, ReportData
from fastapi.exceptions import HTTPException
from fastapi.responses import StreamingResponse

from reporter.utils.firestore import get_firestore_document

from .backends.aggregate import AggregateReport
from .backends.snyk.model import SnykContainerScan
from .config import AppConfig
from .db import get_prev_scans
from .frontends.latex import create_document
from .types.protocols import ScanType
from .utils.firestore import get_firestore_document

mockrouter = fastapi.APIRouter()


@mockrouter.post("/reportmock")
async def generate_report_mock(r: ReportRequestIn) -> StreamingResponse:
    scan = await get_mock_report(r.scan_ids[0])
    prev_scans = get_mock_reportdata(scan.image, n=100)

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
    ag = AggregateReport(reports=scans)
    print(ag)


def get_mock_reportdata(
    image: Optional[ImageInfo] = None, n: int = 100
) -> list[ReportData]:
    def get_image(image: Optional[ImageInfo]) -> ImageInfo:
        return ImageInfo(
            imageSizeBytes=image.image_size_bytes if image else "123",
            layerId=image.layer_id if image else "123",
            mediaType=image.media_type if image else "123",
            tag=[
                random.choice(
                    ["1.0.0", "2.0.0", "3.0.0", "latest", "test", "latest-test"]
                )
            ],
            timeCreatedMs=datetime(
                year=2022, month=random.randint(1, 6), day=random.randint(1, 28)
            ),
            timeUploadedMs=datetime(
                year=2022, month=random.randint(1, 6), day=random.randint(1, 28)
            ),
            image=image.image if image else "telenor/mock-img",
        )

    return [
        ReportData(
            id="mock",
            image=get_image(image),
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


async def get_mock_report(docid: str) -> ScanType:
    from .main import scan_from_docid

    try:
        with open(f"{docid}.pkl", "rb") as f:
            return pickle.load(f)
    except:
        scan = await scan_from_docid(docid, "auspex-logs")
        with open(f"{docid}.pkl", "wb") as f:
            pickle.dump(scan, f)
        return scan
