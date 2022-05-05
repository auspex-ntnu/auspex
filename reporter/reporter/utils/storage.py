from pathlib import Path
from auspex_core.gcp.storage import ObjectStatus, upload_file_to_bucket


async def upload_report_to_bucket(
    path: Path, bucket: str, delete_after: bool = True
) -> ObjectStatus:
    """Uploads a report to the given bucket.

    Parameters
    ----------
    path : `Path`
        Path to the report to upload.
    bucket : `str`
        Cloud storage bucket to upload to
    delete_after : `bool`, optional
        Whether to delete the report after uploading, by default True.

    Returns
    -------
    `ObjectStatus`
        Status of the upload.
        See: `auspex_core.gcp.storage.ObjectStatus`

    Raises
    ------
    `HTTPException`
        FastAPI HTTPException that is propagated to the user in the event
        of a failure.
    """
    status = await upload_file_to_bucket(path, bucket)
    if delete_after:
        # Ignore if the file doesn't exist somehow (it should)
        path.unlink(missing_ok=True)
    return status
