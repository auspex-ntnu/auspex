from typing import TYPE_CHECKING, Any, Tuple

if TYPE_CHECKING:
    import flask
    from google.cloud.firestore_v1.types.write import WriteResult


import os

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from google.cloud import storage

# TODO: remove defaults??
BUCKET_NAME = os.getenv("BUCKET_NAME", "auspex-scans")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "auspex-logs")


def log_results(data: dict):
    image = data["image"]
    started = data["started"]
    results = data.pop("results")  # pop large JSON blob
    docname = f"{image}_{started}"

    # Upload JSON blob to bucket
    blob = upload_json_blob_from_memory(results, docname)
    data["url"] = blob.public_url

    # Add firestore document
    add_firestore_document(docname, data)

    return data


def add_firestore_document(docname: str, content: dict) -> WriteResult:
    """Adds a firestore document."""
    # Use the application default credentials
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(
        cred,
        {
            "projectId": "ntnu-student-project",
        },
    )
    db = firestore.client()  # type: firestore.Client
    ref = db.collection(COLLECTION_NAME).document(docname).set(content)
    return ref


def upload_json_blob_from_memory(contents: str, filename: str) -> storage.Blob:
    """Uploads a file to the bucket."""
    storage_client = storage.Client()
    bucket = storage_client.bucket(BUCKET_NAME)

    if not filename.endswith(".json"):
        filename = f"{filename}.json"
    blob = bucket.blob(f"{filename}.json")
    blob.upload_from_string(contents)
    print("{} with contents {} uploaded to {}.".format(filename, contents, BUCKET_NAME))
    return blob


def handle_request(request: flask.Request) -> Tuple[str, int]:  # msg, status code
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
    request_json = request.get_json()
    if not request_json:
        return "Unprocessable entity", 422

    data = log_results(request_json)
    return data, 201
