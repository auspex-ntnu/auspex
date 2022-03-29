import os

from pydantic import BaseSettings, Field

_ERR_MSG = "Environment variable {VAR_NAME} is not defined."

# Google Cloud Project Name
GCP_PROJECT = os.getenv("GCP_PROJECT")
if not GCP_PROJECT:
    raise ValueError(_ERR_MSG.format(VAR_NAME="GCP_PROJECT"))

# Firestore collection of completed scan logs
COLLECTION_LOGS = os.getenv("COLLECTION_LOGS")
if not COLLECTION_LOGS:
    raise ValueError(_ERR_MSG.format(VAR_NAME="COLLECTION_LOGS"))

# Firestore collection of reports
COLLECTION_REPORTS = os.getenv("COLLECTION_REPORTS")
if not COLLECTION_REPORTS:
    raise ValueError(_ERR_MSG.format(VAR_NAME="COLLECTION_REPORTS"))


# Cloud Storage Bucket of raw scan files
BUCKET_SCANS = os.getenv("BUCKET_SCANS")
if not BUCKET_SCANS:
    raise ValueError(_ERR_MSG.format(VAR_NAME="BUCKET_SCANS"))

GOOGLE_APPLICATION_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

# We allow this to be undefined


# URLS

# class AppSettings(BaseSettings):
#     bucket_scans: str = Field(..., env="BUCKET_SCANS")
#     bucket_reports: str = Field(..., env="REPORTS_BUCKET_NAME")
#     bucket_aggregate: str = Field(..., env="AGGREGATE_BUCKET_NAME")
#     project_id: str = Field(..., env="GCP_PROJECT")
#     collection_logs: str = Field(..., env="COLLECTION_LOGS")
#     collection_parsed: str = Field(..., env="COLLECTION_REPORTS")
#     collection_reports: str = Field(..., env="COLLECTION_REPORTS")
#     google_application_credentials: str = Field(..., env="GOOGLE_APPLICATION_CREDENTIALS")
