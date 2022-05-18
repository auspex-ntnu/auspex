# NOTE: ONLY SUPPORTS GCP RIGHT NOW
import asyncio
from dataclasses import dataclass
from datetime import timedelta
from functools import partial
from typing import Optional

from auspex_core.gcp.firestore import check_db_exists
from auspex_core.models.api.report import (
    ReportOut,
    ReportQuery,
    ReportRequestIn,
)
from auspex_core.models.scan import ReportData
from auspex_core.models.status import ServiceStatus, ServiceStatusCode
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import HTTPException
from loguru import logger


from .config import AppConfig
from .db import get_reports_filtered
from .report import SingleReportResult, create_single_report, create_aggregate_report
from .backends.aggregate import AggregateReport
from .types.protocols import ScanType
from .exceptions import install_handlers


app = FastAPI()
install_handlers(app)

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
    """Create one or more reports. Optionally aggregate the results."""
    # Create single reports in parallel
    # See frontends/latex/latex.py for limitations
    # TODO: use multiprocessing instead
    results = await asyncio.gather(
        *[create_single_report(scan_id, r) for scan_id in r.scan_ids],
        # We don't need to do return_exceptions=True
        # because we're already catching exceptions
    )

    failed = [r for r in results if r.error]  # type: list[SingleReportResult]
    if failed:
        detail = {
            "message": f"One or more scans failed to be parsed.",
            "scans": [r.scan_id for r in failed],
        }
        # TODO: fix this message
        if not r.ignore_failed:
            raise HTTPException(status_code=500, detail=detail)

    # TODO: check if any reports contain the same image
    # if so, select the newest one

    reports = [r.report for r in results if r.report]  # type: list[ScanType]
    reports_out = [
        r.report_data for r in results if r.report_data
    ]  # type: list[ReportData]

    # Create aggregate report if specified and there are multiple reports
    aggregate: Optional[AggregateReport] = None
    msg = ""
    if r.aggregate:
        if len(reports) > 1:
            aggregate = await create_aggregate_report(reports, r)
        else:
            msg = "Aggregate report requested but only one scan was provided."
            logger.warning(msg)
    # TODO: determine failed scans and return them in the response
    return ReportOut(reports=reports_out, aggregate=aggregate, message=msg, failed=[])


@app.get("/reports")  # name TBD
async def get_reports(
    params: ReportQuery = Depends(),
) -> list[ReportData]:
    """Fetch reports from the database."""
    try:
        return await get_reports_filtered(params)
    except Exception as e:
        logger.exception("Failed to retrieve reports", e)
        raise HTTPException(500, "Failed to retrieve reports")


@app.get("/status", response_model=ServiceStatus)
async def get_status(request: Request) -> ServiceStatus:
    """Get the status of the service."""
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
