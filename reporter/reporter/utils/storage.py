from auspex_core.gcp.env import SCANS_BUCKET_NAME
from auspex_core.gcp.storage import StorageObject, fetch_json_blob
from fastapi.exceptions import HTTPException
from google.cloud.firestore_v1 import DocumentSnapshot
from loguru import logger


async def get_object_from_document(
    doc: DocumentSnapshot, bucket: str = SCANS_BUCKET_NAME
) -> StorageObject:
    """Wrapper around `auspex_core.gcp.storage.fetch_json_blob`
    that handles exceptions and logging for the service.

    Parameters
    ----------
    doc : `DocumentSnapshot`
        Firestore document to retrieve Cloud Storage blob name from.
    bucket : `str`, optional
        Cloud storage bucket to fetch from, by default bucket given by env var.

    Returns
    -------
    `StorageObject`
        An object containing the contents of the blob as well
        as the blob itself.
        See: `auspex_core.gcp.storage.StorageObject`

    Raises
    ------
    `HTTPException`
        FastAPI HTTPException that is propagated to the user in the event
        of a failure.
    """
    # Get scan file from bucket
    blobname = doc.get("blob")
    bucket = doc.get("bucket") or bucket
    if not blobname:
        raise HTTPException(
            # Maybe not a 422?
            422,
            f"Document {doc.id} is not associated with a scan file.",
        )
    try:
        obj = await fetch_json_blob(bucket, blobname)
    except Exception as e:
        msg = f"Failed to retrieve JSON blob for document with ID {doc.id}"
        logger.exception(msg)
        raise HTTPException(500, msg)
    return obj
