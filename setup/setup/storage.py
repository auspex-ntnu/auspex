"""
Required environment variables:
- BUCKET_SCANS: The name of the bucket to store scans in
- BUCKET_REPORTS: The name of the bucket to store reports in

Optional environment variables:
- EXIT_ON_MISSING: If set, the script will exit if any of the required environment variables are not set
"""

import os
from typing import Any
from google.cloud import storage
import backoff
from loguru import logger
from .config import AppConfig


def on_giveup(details: dict[str, Any]) -> None:
    logger.error(
        "Gave up after {tries} tries calling function {target} with args {args} and kwargs {kwargs}".format(
            **details
        ),
        exc=Exception,
    )


@backoff.on_exception(
    backoff.expo,
    Exception,  # TODO: make this more specific
    max_tries=5,
    jitter=backoff.full_jitter,
    on_giveup=on_giveup,
)
def create_bucket(client: storage.Client, bucketname: str) -> None:
    bucket = client.bucket(bucketname)
    if bucket.exists():
        logger.debug(f"Bucket {bucketname} already exists")
        return
    client.create_bucket(bucketname, location=AppConfig().service_region)
    logger.info("Created bucket {}", bucketname)


def init() -> None:
    client = storage.Client()
    config = AppConfig()
    buckets = [config.bucket_scans, config.bucket_reports]
    for bucket_name in buckets:
        create_bucket(client, bucket_name)


if __name__ == "__main__":
    init()
