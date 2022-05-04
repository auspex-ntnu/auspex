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

from .config import AppConfig
from .utils import get_project_id


def init():
    config = AppConfig()
    project_id = get_project_id()

    if config.credentials:
        credentials = service_account.Credentials.from_service_account_file(
            config.credentials
        )
        client = FirestoreAdminClient(credentials=credentials)
    else:
        client = FirestoreAdminClient()

    # Ensure database exists and is in native mode?
    # https://stackoverflow.com/a/70564716

    DBPATH = f"projects/{project_id}/databases/(default)"
    COLPATH = f"{DBPATH}/collectionGroups/{config.collection_reports}"

    # TODO: create collections before we can create index?
    db = client.get_database(name=DBPATH)
    logger.debug(f"Using database: {db}")

    indexes = get_indexes()
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


def get_indexes() -> list[list[Index.IndexField]]:
    # Aliases for brevity
    IF = Index.IndexField
    ASC = Index.IndexField.Order.ASCENDING
    DESC = Index.IndexField.Order.DESCENDING

    indexes: list[list[Index.IndexField]] = []
    # CVSS metrics + image indexes
    for field in ["cvss.mean", "cvss.median", "cvss.stdev", "cvss.min", "cvss.max"]:
        for order in [ASC, DESC]:
            indexes.append(
                [
                    IF(field_path="image.image", order=ASC),
                    IF(field_path=field, order=order),
                ]
            )

    # Aggregate + CVSS mean indexes
    for order in [ASC, DESC]:
        indexes.append(
            [
                IF(field_path="aggregate", order=ASC),
                IF(field_path="cvss.mean", order=order),
            ]
        )

    # Image + Timestamp indexes
    for order in [ASC, DESC]:
        indexes.append(
            [
                IF(field_path="image.image", order=ASC),
                IF(field_path="timestamp", order=order),
            ]
        )

    # Image + Historical indexes
    indexes.append(
        [
            IF(field_path="image.image", order=ASC),
            IF(field_path="historical", order=DESC),
        ]
    )
    return indexes


if __name__ == "__main__":
    init()
