from datetime import datetime

import aiohttp
from auspex_core.models.api.scan import ScanRequest
import backoff
from auspex_core.docker.models import ImageInfo
from auspex_core.gcp.firestore import add_document
from auspex_core.gcp.storage import upload_json_blob_from_memory
from auspex_core.models.scan import ScanLog
from google.api_core.exceptions import ServerError

from .config import AppConfig
from .types import ScanResultsType


@backoff.on_exception(
    backoff.expo,
    exception=(aiohttp.ClientResponseError, ServerError),
    max_tries=5,
    jitter=backoff.full_jitter,
)
async def log_scan(
    scan: ScanResultsType, image: ImageInfo, options: ScanRequest
) -> ScanLog:
    # Generate log filename
    timestamp = datetime.utcnow()
    filename = f"{image.image}_{str(timestamp).replace('.', '_')}"

    # Upload JSON log blob to bucket
    obj = await upload_json_blob_from_memory(
        scan.scan, filename, AppConfig().bucket_scans
    )

    scanlog = ScanLog(
        image=image,
        backend=scan.backend,
        id="",  # injected after firestore document is created
        timestamp=timestamp,
        url=obj.selfLink,
        blob=obj.name,
        bucket=obj.bucket,
        base_vulns=options.base_vulns,
    )

    # Add firestore document
    doc = await add_document(AppConfig().collection_scans, scanlog.dict(exclude={"id"}))

    scanlog.id = doc.id

    return scanlog
