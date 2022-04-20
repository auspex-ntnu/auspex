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

# By default we don't quit on missing name, but it can be enabled
EXIT_ON_MISSING = os.environ.get("EXIT_ON_MISSING", "") != ""


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
    client.create_bucket(bucketname)
    logger.info("Created bucket {}", bucketname)


def main() -> None:
    client = storage.Client()

    buckets = {b: os.getenv(b) for b in ("BUCKET_SCANS", "BUCKET_REPORTS")}

    for envvar, bucket_name in buckets.items():
        if bucket_name is None:
            logger.warning(f"{envvar} is not set")
            if EXIT_ON_MISSING:
                logger.error("Exiting due to EXIT_ON_MISSING")
                exit(1)
            continue
        create_bucket(client, bucket_name)


if __name__ == "__main__":
    main()
