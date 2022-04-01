"""
This cloud function requires permissions to create buckets and write files.

Required environment variables:
    BUCKET_SCANS: name of the bucket to upload to
    COLLECTION_LOGS: Firestore collection name for scan logs
    GCP_PROJECT: Google Cloud Project ID (automatically set by GCP)
"""

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
from pydantic import BaseModel, BaseSettings, ValidationError, Field


# Get from environment variables and ensure they are defined
BUCKET_SCANS = ""
COLLECTION_LOGS = ""
GCP_PROJECT = ""
for var in ("BUCKET_SCANS", "COLLECTION_LOGS", "GCP_PROJECT"):
    v = os.getenv(var)
    if not v:
        raise ValueError(f"Environment variable '{var}' is not defined.")
    globals()[var] = v


class AppSettings(BaseSettings):
    """Settings for the application."""

    BUCKET_SCANS: str = Field(str, env="BUCKET_SCANS")
    COLLECTION_LOGS: str = Field(str, env="COLLECTION_LOGS")
    GCP_PROJECT: str = Field(str, env="GCP_PROJECT")


# We get automatically authenticated with firebase with default credentials
firebase_admin.initialize_app(
    credentials.ApplicationDefault(),
    {
        "projectId": GCP_PROJECT,
    },
)

# Duplicate definition of ImageInfo from /scanner/containerregistry.py
class ImageInfo(BaseModel):
    image_size_bytes: str
    layer_id: str
    mediaType: str
    tag: list[str]
    created: datetime
    uploaded: datetime
    digest: Optional[str]  # injected by ImageManifest (see its root_validator)
    image: Optional[str]  # injected by get_image_info()


class Scan(BaseModel):
    """
    Model for incoming scans.

    Represents structure of firestore document.
    """

    image: ImageInfo
    backend: str  # Scanner backend tool used
    scan: str = Field(
        ..., exclude=True
    )  # Output of scanning software (not stored in DB)
    id: Optional[str] = None  #  Firestore document ID (set by function)
    timestamp: Optional[datetime] = None  # Timestamp of scan (set by function)
    url: Optional[str] = None  # URL to scan results (set by function)
    blob: Optional[str] = None  # Name of uploaded blob (set by function)
    bucket: Optional[str] = None  # Bucket blob is stored in (set by function)

    class Config:
        extra = "allow"  # we account for future additions to schema
        validate_assignment = True


def log_results(scan: Scan) -> Scan:
    # Generate log filename
    scan.timestamp = datetime.utcnow()
    filename = f"{scan.image.image}_{str(scan.timestamp).replace('.', '_')}"

    # Upload JSON log blob to bucket
    blob = upload_json_blob_from_memory(scan.scan, filename)
    scan.url = blob.public_url
    scan.blob = blob.name
    scan.bucket = blob.bucket.name

    # Add firestore document
    doc = add_firestore_document(scan)
    scan.id = doc.id

    return scan


def add_firestore_document(scan: Scan) -> DocumentReference:
    """Adds a firestore document."""
    # Use the application default credentials
    db = firestore.client()  # type: FirestoreClient
    doc = db.collection(COLLECTION_LOGS).document()
    doc.set(scan.dict(exclude={"id"}))
    return doc


def upload_json_blob_from_memory(scan_contents: str, filename: str) -> storage.Blob:
    """Uploads a file to the bucket."""
    # Get client and bucket
    storage_client = storage.Client()
    bucket = storage_client.bucket(BUCKET_SCANS)
    if not bucket.exists():
        print(f"Creating bucket {BUCKET_SCANS}")
        storage_client.create_bucket(BUCKET_SCANS)
        # Make sure bucket exists after it has been created
        assert (
            bucket.exists()
        ), "Bucket does not exist. Bucket creation failed or is pending."

    # Upload file with .json suffix
    if not filename.endswith(".json"):
        filename = f"{filename}.json"
    filename = sanitize(filename)

    blob = bucket.blob(filename)
    blob.upload_from_string(
        scan_contents,
        # Explicitly set content-type charset to UTF-8 for faster parsing
        # by google-aio-storage
        # See: https://pypi.org/project/gcloud-aio-storage/#:~:text=the%20session%20explicitly-,file%20encodings,-In%20some%20cases
        content_type="application/json; charset=UTF-8",
    )
    print(f"{filename} uploaded to {BUCKET_SCANS}.")
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
