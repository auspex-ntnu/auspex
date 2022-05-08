# NOTE: ONLY SUPPORTS GCP RIGHT NOW
from datetime import timedelta
from functools import partial
from typing import Optional

from auspex_core.gcp.firestore import check_db_exists
from auspex_core.models.api.report import (
    FailedReport,
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
from .db import get_prev_scans, get_reports_filtered
from .report import create_and_upload_report, get_report
from .backends.aggregate import AggregateReport
from .types.protocols import ScanType


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
    reports: list[ReportData] = []
    failed: list[FailedReport] = []
    for scan_id in r.scan_ids:
        try:
            # We don't create in parallel here due to thread safety
            # See: frontends/latex/latex.py
            report = await create_single_report(scan_id, r)
            reports.append(report)
        except Exception as e:
            logger.warning(e)
            failed.append((scan_id, str(e)))

    if failed:
        detail = {
            "message": f"One or more scans failed to be parsed.",
            "reports": [f.dict() for f in failed],
        }
        if not r.ignore_failed:
            raise HTTPException(status_code=500, detail=detail)

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
    return ReportOut(reports=reports, aggregate=aggregate, message=msg, failed=[])


async def create_single_report(scan_id: str, settings: ReportRequestIn) -> ReportData:
    report = await get_report(scan_id)
    prev_scans = await get_prev_scans(
        report,
        collection=AppConfig().collection_reports,
        max_age=timedelta(weeks=AppConfig().trend_weeks),
        ignore_self=True,
        skip_historical=False,  # FIXME: set to True & should be envvar
    )
    # TODO: add support for multiple frontends
    # Right not we just assume it's latex

    # Create and upload the LaTeX document
    return await create_and_upload_report(report, prev_scans, settings)


async def create_aggregate_report(
    reports: list[ScanType], settings: ReportRequestIn
) -> ReportData:
    """Creates an aggregate report from a list of reports.

    Parameters
    ----------
    reports : `list[ScanType]`
        A list of reports to aggregate.
    settings : `ReportRequestIn`
        The settings to use for the aggregate report.

    Returns
    -------
    `ReportData`
        The aggregate report as represented in the database.

    Raises
    ------
    HTTPException
        If the aggregate report fails to be created.
    """
    report = AggregateReport(reports=reports)
    prev_scans = await get_prev_scans(
        report,
        collection=AppConfig().collection_reports,
        max_age=timedelta(weeks=AppConfig().trend_weeks),
        ignore_self=True,
        skip_historical=False,  # NOTE: MUST be False for aggregate reports. Aggregates can't be historical.
        aggregate=True,
    )
    return await create_and_upload_report(report, prev_scans, settings)


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
