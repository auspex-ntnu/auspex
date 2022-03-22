import os

_ERR_MSG = "Environment variable {VAR_NAME} is not defined."

# Google Cloud Project Name
GCP_PROJECT = os.getenv("GCP_PROJECT")
if not GCP_PROJECT:
    raise ValueError(_ERR_MSG.format(VAR_NAME="GCP_PROJECT"))

# Firestore collection of completed scan logs
LOGS_COLLECTION_NAME = os.getenv("LOGS_COLLECTION_NAME")
if not LOGS_COLLECTION_NAME:
    raise ValueError(_ERR_MSG.format(VAR_NAME="LOGS_COLLECTION_NAME"))

# Firestore collection of parsed scan data overviews
PARSED_COLLECTION_NAME = os.getenv("PARSED_COLLECTION_NAME")
if not PARSED_COLLECTION_NAME:
    raise ValueError(_ERR_MSG.format(VAR_NAME="PARSED_COLLECTION_NAME"))

# Firestore collection of generated reports
REPORTS_COLLECTION_NAME = os.getenv("REPORTS_COLLECTION_NAME")
if not PARSED_COLLECTION_NAME:
    raise ValueError(_ERR_MSG.format(VAR_NAME="REPORTS_COLLECTION_NAME"))

# Cloud Storage Bucket of raw scan files
SCANS_BUCKET_NAME = os.getenv("SCANS_BUCKET_NAME")
if not SCANS_BUCKET_NAME:
    raise ValueError(_ERR_MSG.format(VAR_NAME="SCANS_BUCKET_NAME"))

SERVICE_ACCOUNT_KEYFILE = os.getenv("SERVICE_ACCOUNT_KEYFILE")
# We allow this to be undefined
