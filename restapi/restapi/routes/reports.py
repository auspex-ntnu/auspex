from typing import Any
from auspex_core.models.api.scan import ScanRequest
from auspex_core.models.scan import ScanLog
import backoff
import httpx
from httpx import Response, RequestError
from auspex_core.models.api.report import (
    ReportData,
    ReportOut,
    ReportQuery,
    ReportRequestIn,
)
from fastapi import APIRouter, Depends, Request
from fastapi.exceptions import HTTPException
from auspex_core.utils.backoff import on_backoff, on_giveup
from loguru import logger

from .scans import do_request_scans
from ..models import ScanReportRequest

from ..config import AppConfig

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("", response_model=ReportOut)
async def create_report(req: ScanReportRequest) -> ReportOut:
    """Create reports from a list of scans."""
    scanreq = ScanRequest(**req.dict())
    scans = await do_request_scans(scanreq)
    return await _create_reports(scans, req)


@backoff.on_exception(
    backoff.expo, RequestError, max_tries=5, on_backoff=on_backoff, on_giveup=on_giveup
)
async def _create_reports(scans: list[ScanLog], req: ScanReportRequest) -> ReportOut:
    request = ReportRequestIn(
        scan_ids=[scan.id for scan in scans],
        **req.dict(),
    )
    async with httpx.AsyncClient(timeout=AppConfig().timeout_reporter) as client:
        res = await client.post(
            f"{AppConfig().url_reporter}/reports", json=request.dict()
        )
        if res.status_code != 200:
            raise HTTPException(status_code=res.status_code, detail=res.text)
        try:
            return ReportOut(**res.json())
        except Exception as e:
            logger.error(f"Could not parse response: {e}")
            logger.exception(e)
            raise HTTPException(
                status_code=500,
                detail="Unable to create report. Unable to parse response from reporter.",
            )


@router.get("", response_model=list[ReportData])
async def get_reports(
    request: Request,
    params: ReportQuery = Depends(),  # can we only include this in the schema somehow?
) -> list[ReportData]:
    """Retrieve reports based on a range of parameters."""
    res = await _get_reports(request, params)
    try:
        return res.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to parse response.")


@backoff.on_exception(
    backoff.expo, RequestError, max_tries=5, on_backoff=on_backoff, on_giveup=on_giveup
)
async def _get_reports(request: Request, params: ReportQuery = Depends()) -> Response:
    """Retrieves reports for the given query parameters from the Reporter service."""
    async with httpx.AsyncClient(timeout=AppConfig().timeout_reporter) as client:
        res = await client.get(
            f"{AppConfig().url_reporter}/reports",
            params=request.query_params,
        )
        res.raise_for_status()  # Is this a bad idea
        return res
    # TODO: handle error from reporter


@router.get("/{report_id}", response_model=ReportData)
async def get_report(report_id: str) -> ReportData:
    """Get a report by its ID."""
    res = await _get_report(report_id)
    try:
        return res.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to parse response.")


@backoff.on_exception(
    backoff.expo, RequestError, max_tries=5, on_backoff=on_backoff, on_giveup=on_giveup
)
async def _get_report(report_id: str) -> Response:
    """Fetches a report from the reporter service."""
    async with httpx.AsyncClient(timeout=30) as client:
        res = await client.get(f"{AppConfig().url_reporter}/reports/{report_id}")
        return res
