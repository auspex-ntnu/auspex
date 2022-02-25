from datetime import datetime
import time
import os

from typing import TYPE_CHECKING, Optional, Tuple, Union

if TYPE_CHECKING:
    import flask
    from google.cloud.firestore import Client as FirestoreClient

import functions_framework
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud import storage
from google.cloud.firestore import DocumentReference
from sanitize_filename import sanitize
from pydantic import BaseModel, ValidationError, Field


# TODO: remove defaults??
BUCKET_NAME = os.getenv("BUCKET_NAME", "auspex-scans")
LOGS_COLLECTION_NAME = os.getenv("LOGS_COLLECTION_NAME", "auspex-logs")
PROJECT_NAME = os.getenv("GCP_PROJECT", "ntnu-student-project")

# We get automatically authenticated with firebase with default credentials
firebase_admin.initialize_app(
    credentials.ApplicationDefault(),
    {
        "projectId": PROJECT_NAME,
    },
)


class Scan(BaseModel):
    """Model for incoming scans."""

    image: str  # Name of scanned image
    scan: str = Field(..., exclude=True)  # Output of scanning software (not dumped)
    id: Optional[str] = None  #  (set by function) Firestore document ID
    timestamp: Optional[float] = None  # (set by function) Timestamp of scan
    url: Optional[str] = None  # (set by function) URL to scan results
    blob: Optional[str] = None  # (set by function) Name of uploaded blob

    class Config:
        extra = "allow"  # we account for future additions to schema
        validate_assignment = True


def log_results(scan: Scan) -> Scan:
    # Generate log filename
    scan.timestamp = time.time()
    filename = f"{scan.image}_{str(scan.timestamp).replace('.', '_')}"

    # Upload JSON log blob to bucket
    blob = upload_json_blob_from_memory(scan.scan, filename)
    scan.url = blob.public_url
    scan.blob = blob.name

    # Add firestore document
    doc = add_firestore_document(scan)
    scan.id = doc.id

    return scan


def add_firestore_document(scan: Scan) -> DocumentReference:
    """Adds a firestore document."""
    # Use the application default credentials
    db = firestore.client()  # type: FirestoreClient
    doc = db.collection(LOGS_COLLECTION_NAME).document()
    doc.set(scan.dict(exclude={"id"}))
    return doc


def upload_json_blob_from_memory(scan_contents: str, filename: str) -> storage.Blob:
    """Uploads a file to the bucket."""
    # Get client and bucket
    storage_client = storage.Client()
    bucket = storage_client.bucket(BUCKET_NAME)

    # Upload file with .json suffix
    if not filename.endswith(".json"):
        filename = f"{filename}.json"
    filename = sanitize(filename)

    blob = bucket.blob(filename)
    blob.upload_from_string(scan_contents, content_type="application/json")
    print("{} uploaded to {}.".format(filename, BUCKET_NAME))
    return blob


@functions_framework.http
def handle_request(
    request: "flask.Request",
) -> Tuple[Union[dict, str], int]:  # msg, status code
    """Responds to any HTTP request.
    Args:
        request (flask.Request): HTTP request object.
    Returns:
        The response text or any set of values that can be turned into a
        Response object using
        `make_response <http://flask.pocoo.org/docs/1.0/api/#flask.Flask.make_response>`.
    """

    if not request.method == "POST":
        return "Method Not Allowed", 405

    request_json = request.json
    if not request_json:
        return "Request must contain a JSON payload", 422

    # Parse request body
    try:
        scan = Scan(**request_json)
    except ValidationError as e:
        return e.json(), 422

    scan = log_results(scan)
    return scan.json(), 201
