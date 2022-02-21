from datetime import datetime
import time
import os

from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:
    import flask
    from werkzeug.datastructures import FileStorage
    from google.cloud.firestore import Client as FirestoreClient

import functions_framework
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud import storage
from google.cloud.firestore_v1.types.write import WriteResult
from sanitize_filename import sanitize
from pydantic import BaseModel, ValidationError


# TODO: remove defaults??
BUCKET_NAME = os.getenv("BUCKET_NAME", "auspex-scans")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "auspex-logs")
PROJECT_NAME = os.getenv("GCP_PROJECT", "ntnu-student-project")

firebase_admin.initialize_app(
    credentials.ApplicationDefault(),
    {
        "projectId": PROJECT_NAME,
    },
)


class Scan(BaseModel):
    image: str
    backend: str
    started: int
    finished: Optional[int] = None  # set by function
    status: str
    stderr: str
    score: float
    url: Optional[str] = None  # set by function


def log_results(scan: Scan, scan_file: "FileStorage") -> Scan:
    scan.finished = int(time.time())
    docname = f"{scan.image}_{scan.started}"

    # Upload JSON blob to bucket
    blob = upload_json_blob_from_memory(scan_file, docname)
    scan.url = blob.public_url

    # Add firestore document
    add_firestore_document(scan)

    return scan


def add_firestore_document(scan: Scan) -> WriteResult:
    """Adds a firestore document."""
    # Use the application default credentials
    db = firestore.client()  # type: FirestoreClient
    ref = db.collection(COLLECTION_NAME).document().set(scan.dict())
    return ref


def upload_json_blob_from_memory(
    scan_file: "FileStorage", filename: str
) -> storage.Blob:
    """Uploads a file to the bucket."""
    # Get client and bucket
    storage_client = storage.Client()
    bucket = storage_client.bucket(BUCKET_NAME)

    # Upload file with .json suffix
    if not filename.endswith(".json"):
        filename = f"{filename}.json"
    filename = sanitize(filename)

    blob = bucket.blob(f"{filename}.json")
    blob.upload_from_file(scan_file)
    print("{} uploaded to {}.".format(filename, BUCKET_NAME))
    return blob


@functions_framework.http
def handle_request(request: "flask.Request") -> Tuple[str, int]:  # msg, status code
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

    # Parse request body
    try:
        form = Scan(**request.form)
    except ValidationError as e:
        return str(e), 422

    if not (f := request.files["scan"]):
        return "Unprocessable entity", 422

    scan = log_results(form, f)
    return scan.dict(), 201
