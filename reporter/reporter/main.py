# NOTE: ONLY SUPPORTS GCP RIGHT NOW


import asyncio
import os

from datetime import timedelta
from functools import partial
from typing import Optional

from auspex_core.gcp.firestore import check_db_exists
from auspex_core.models.api.report import ReportOut, ReportQuery, ReportRequest
from auspex_core.models.scan import ReportData
from auspex_core.models.status import ServiceStatus, ServiceStatusCode
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import HTTPException
from loguru import logger


from .config import AppConfig
from .db import get_prev_scans, get_reports_filtered, log_report
from .exceptions import combine_exception_messages
from .frontends.latex import create_document
from .models import ReportRequestIn
from .report import parse_scan
from .backends.aggregate import AggregateReport
from .types.protocols import ScanTypeSingle
from .utils.storage import upload_report_to_bucket

if os.getenv("DEBUG") == "1":
    import debugpy

    DEBUG_PORT = 5678
    debugpy.listen(("0.0.0.0", DEBUG_PORT))
    logger.debug(f"Debugger is listening on port {DEBUG_PORT}")
    # debugpy.wait_for_client()
    # debugpy.breakpoint()

app = FastAPI()

# Add mock routes for internal development
from contextlib import suppress

with suppress(ImportError):
    from ._mock import mockrouter

    app.include_router(mockrouter)


@app.on_event("startup")
async def on_app_startup():
    # instantiate config to check that all envvars are defined
    AppConfig()


@app.post("/reports", response_model=ReportOut)
async def generate_report(r: ReportRequestIn):
    # Create reports for all reports in the request
    reports = await asyncio.gather(
        *[create_single_report(scan_id, r) for scan_id in r.scan_ids],
        return_exceptions=True,
    )

    # Filter out any exceptions (and log them)
    failed = [r for r in reports if isinstance(r, Exception)]
    for f in failed:
        reports.remove(f)
    if failed:
        exc_msg = combine_exception_messages(failed)
        msg = f"One or more scans failed to be parsed: {exc_msg}"

        if not r.ignore_failed:
            raise HTTPException(status_code=500, detail=msg)
        else:
            logger.warning(msg)

    # Create aggregate report if specified and there are multiple reports
    aggregate: Optional[AggregateReport] = None
    msg = ""
    if r.aggregate:
        if len(reports) > 1:
            aggregate = await create_aggregate_report(reports)
        else:
            msg = "Aggregate report requested but only one scan was provided."
            logger.warning(msg)
    # TODO: determine failed scans and return them in the response
    return ReportOut(reports=reports, aggregate=aggregate, message=msg, failed=[])


async def create_single_report(scan_id: str, settings: ReportRequest) -> ReportData:
    report = await parse_scan(scan_id)
    prev_scans = await get_prev_scans(
        report,
        collection=AppConfig().collection_reports,
        max_age=timedelta(weeks=AppConfig().trend_weeks),
        ignore_self=True,
        skip_historical=False,  # FIXME: set to True & should be envvar
    )

    doc = await create_document(report, prev_scans)
    if not doc.path.exists():
        raise HTTPException(500, "Failed to generate report.")
    status = await upload_report_to_bucket(doc.path, AppConfig().bucket_reports)

    # FIXME: we don't mark the previous scans historical until here
    #    because we create the report, THEN log and mark the previous scans

    try:
        report_data = await log_report(report, status.mediaLink)
    except Exception as e:
        logger.error(f"Failed to log scan: {e}")
        raise HTTPException(500, f"Failed to log scan: {e}")
    return report_data


async def create_aggregate_report(reports: list[ScanTypeSingle]) -> ReportData:
    report = AggregateReport(reports=reports)
    prev_scans = await get_prev_scans(
        report,
        collection=AppConfig().collection_reports,
        max_age=timedelta(weeks=AppConfig().trend_weeks),
        ignore_self=True,
        skip_historical=False,  # NOTE: MUST be True for aggregate reports
        aggregate=True,
    )

    doc = await create_document(report, prev_scans)
    if not doc.path.exists():
        raise HTTPException(500, "Failed to generate report.")
    status = await upload_report_to_bucket(doc.path, AppConfig().bucket_reports)
    await log_report(report, status.mediaLink)
    return report


@app.get("/reports")  # name TBD
async def get_reports(
    params: ReportQuery = Depends(),
) -> list[ReportData]:
    try:
        return await get_reports_filtered(params)
    except Exception as e:
        logger.exception("Failed to retrieve reports", e)
        raise HTTPException(500, "Failed to retrieve reports")


@app.get("/status", response_model=ServiceStatus)
async def get_status(request: Request) -> ServiceStatus:
    status = partial(ServiceStatus, url=request.url)
    if await check_db_exists(AppConfig().collection_reports):
        return status(
            status=ServiceStatusCode.OK,
        )
    else:
        return status(
            status=ServiceStatusCode.ERROR,
            message="Database unreachable",
        )
