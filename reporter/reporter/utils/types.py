from typing import Optional

from auspex_core.models.scan import ReportData

from ..backends.aggregate import AggregateReport
from ..types.protocols import ScanType


def get_reportdata(report: ScanType, report_url: Optional[str] = None) -> ReportData:
    """Constructs a ReportData object from a ScanType object."""
    return ReportData(
        image=report.image.dict(),
        id=report.id,
        cvss=report.cvss,
        vulnerabilities=report.get_distribution_by_severity(),
        report_url=report_url,
        upgrade_paths=report.upgrade_paths,
        dockerfile_instructions=report.dockerfile_instructions,
        aggregate=report.is_aggregate or isinstance(report, AggregateReport),
    )
