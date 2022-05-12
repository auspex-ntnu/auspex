from datetime import datetime

from auspex_core.gcp.firestore import add_document
from auspex_core.gcp.storage import upload_json_blob_from_memory
from auspex_core.docker.models import ImageInfo
from auspex_core.models.scan import ScanLog

from .config import AppConfig
from .types import ScanResultsType


async def log_scan(scan: ScanResultsType, image: ImageInfo) -> ScanLog:
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
    )

    # Add firestore document
    doc = await add_document(AppConfig().collection_scans, scanlog.dict(exclude={"id"}))

    scanlog.id = doc.id

    return scanlog
