from datetime import datetime

from typing import TYPE_CHECKING

from loguru import logger


if TYPE_CHECKING:
    from google.cloud.firestore_v1.collection import CollectionReference

from auspex_core.gcp.firestore import get_firestore_client
from .config import AppConfig
from auspex_core.models.scan import ReportData, ParsedVulnerabilities
from google.cloud.firestore_v1.types.write import WriteResult
from google.api_core.exceptions import InvalidArgument
from google.cloud import firestore  # type: ignore # mypy doesn't understand this import


from auspex_core.models.cve import SEVERITIES
from .types import ScanTypeSingle


# TODO: replace arg with protocol type to support multiple backends
async def log_scan(scan: ScanTypeSingle) -> WriteResult:
    """Store results of parsed container scan in the database."""
    r = ReportData(
        image=scan.image.dict(),
        id=scan.id,
        cvss=scan.cvss,  # TODO: use dedicated type
        vulnerabilities=scan.get_distribution_by_severity(),
        report_url=None,
    )

    client = get_firestore_client()
    doc = client.collection(AppConfig().collection_reports).document()

    # TODO: Delete or update existing documents with the same image digest
    # TODO: handle exceptions
    # TODO: perform this as a transaction

    # Create document
    result = await doc.create(r.dict())

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

                # This is a limitation of the firestore maximum document size.
                # It could be mitigated by creating subcollections of N size,
                # where N is a known safe number of vulnerabilities to store that
                # does not exceed the maximum document size.
                await collection.document(severity).set(data.dict())
            else:
                raise

    return result
