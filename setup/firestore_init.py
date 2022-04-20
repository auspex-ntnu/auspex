"""
Creates all the required composite indexes for the application.

Required environment variables:
- COLLECTION_REPORTS: The name of the collection to store reports in
- GOOGLE_CLOUD_PROJECT: The name of the project to use
- GOOGLE_APPLICATION_CREDENTIALS: The path to the credentials file
"""

from google.api_core.exceptions import AlreadyExists
from google.cloud.firestore_admin_v1 import CreateIndexRequest, Index
from google.cloud.firestore_admin_v1.services.firestore_admin.async_client import (
    FirestoreAdminClient,
)
from google.cloud.firestore_admin_v1.types import GetDatabaseRequest
from google.oauth2 import service_account
from loguru import logger
from pydantic import BaseSettings, Field


class Config(BaseSettings):
    collection_reports: str = Field(..., env="COLLECTION_REPORTS")
    project_id: str = Field(..., env="GOOGLE_CLOUD_PROJECT")
    credentials: str = Field(..., env="GOOGLE_APPLICATION_CREDENTIALS")


config = Config()

credentials = service_account.Credentials.from_service_account_file(config.credentials)
client = FirestoreAdminClient(credentials=credentials)

# Ensure database exists and is in native mode?
# https://stackoverflow.com/a/70564716


DBPATH = f"projects/{config.project_id}/databases/(default)"
COLPATH = f"{DBPATH}/collectionGroups/{config.collection_reports}"

# TODO: create collections before we can create index?
db = client.get_database(name=DBPATH)
logger.debug(f"Using database: {db}")


IF = Index.IndexField
ASC = Index.IndexField.Order.ASCENDING
DESC = Index.IndexField.Order.DESCENDING
indexes: list[list[Index.IndexField]] = [
    [
        IF(field_path="image.image", order=ASC),
        IF(field_path="timestamp", order=DESC),
    ],
    [
        IF(field_path="image.image", order=ASC),
        IF(field_path="timestamp", order=ASC),
    ],
    [
        IF(field_path="image.image", order=ASC),
        IF(field_path="historical", order=DESC),
    ],
    [
        IF(field_path="image.image", order=ASC),
        IF(field_path="cvss.mean", order=DESC),
    ],
    [
        IF(field_path="image.image", order=ASC),
        IF(field_path="cvss.median", order=DESC),
    ],
    [
        IF(field_path="image.image", order=ASC),
        IF(field_path="cvss.stdev", order=DESC),
    ],
    [
        IF(field_path="image.image", order=ASC),
        IF(field_path="cvss.min", order=DESC),
    ],
    [
        IF(field_path="image.image", order=ASC),
        IF(field_path="cvss.max", order=DESC),
    ],
    [
        IF(field_path="aggregate", order=ASC),
        IF(field_path="cvss.mean", order=DESC),
    ],
]

for index in indexes:
    try:
        client.create_index(
            # https://firebase.google.com/docs/firestore/reference/rpc/google.firestore.admin.v1beta2#google.firestore.admin.v1beta2.CreateIndexRequest
            CreateIndexRequest(
                parent=COLPATH,
                index=Index(
                    fields=index,
                    query_scope=Index.QueryScope.COLLECTION,
                ),
            )
        )
    except AlreadyExists:
        logger.info(f"Index already exists: {index}")
    else:
        logger.info(f"Created index: {index}")
