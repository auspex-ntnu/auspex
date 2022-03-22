from datetime import datetime

from typing import TYPE_CHECKING

from loguru import logger


if TYPE_CHECKING:
    from google.cloud.firestore_v1.collection import CollectionReference

from auspex_core.gcp.firestore import get_firestore_client
from auspex_core.gcp.env import PARSED_COLLECTION_NAME
from auspex_core.models.scan import ParsedScan, ParsedVulnerabilities
from google.cloud.firestore_v1.types.write import WriteResult
from google.api_core.exceptions import InvalidArgument
from google.cloud import firestore

from .backends.cve import SEVERITIES
from .backends.snyk.model import SnykContainerScan


# TODO: replace arg with protocol type to support multiple backends
async def log_scan(scan: SnykContainerScan) -> WriteResult:
    """Store results of parsed container scan in the database."""
    p = ParsedScan(
        image=scan.image,
        id=scan.id,
        cvss_min=scan.cvss_min,
        cvss_max=scan.cvss_max,
        cvss_mean=scan.cvss_mean,
        cvss_median=scan.cvss_median,
        cvss_stdev=scan.cvss_stdev,
        vulnerabilities=dict(scan.get_distribution_by_severity()),
        # most_common_cve=scan.most_common_cve(max_n=None),
        # critical=scan.critical,
        report_url=None,
    )

    client = get_firestore_client()
    doc = client.collection(PARSED_COLLECTION_NAME).document()

    # TODO: handle exceptions

    # Create document
    result = await doc.create(p.dict())

    # Create subcollections for vulnerabilities
    collection = doc.collection("vulnerabilities")  # type: CollectionReference
    for severity in SEVERITIES:
        try:
            data = ParsedVulnerabilities(
                vulnerabilities=getattr(scan, severity),
                ok=True,
            )
            await collection.document(severity).set(data.dict())
        except InvalidArgument as e:
            if e.args and "exceeds the maximum allowed size" in e.args[0]:
                logger.error(
                    f"Unable to log vulnerabilities with severity '{severity}' for scan with ID '{scan.id}' (image: '{scan.image}'). "
                    "Number of severities are too large to be stored in a firestore collection. Consult raw log."
                )
                data.vulnerabilities = []  # empty list
                data.ok = False
                # TODO: try to cut down size of list until it fits?
                #
                # Realistically no production image should have so many vulnerabilities
                # they can't be stored in a firestore document, but known vulnerable
                # images like "vulhub/php:5.4.1-cgi" do trigger this exception,
                # hence we have to account for it happening and handle it + log it.
                await collection.document(severity).set(data.dict())
            else:
                raise

    return result
