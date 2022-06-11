import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from restapi.models import ScanReportRequest


@pytest.mark.skip(
    "Fuzzing with the current ScanReportRequest root validator always leads to exceptions. "
    "This is because we cannot express the image/aggregate constraint in the model."
)
@given(st.builds(ScanReportRequest))
def test_scanreportrequest_fuzz(request: ScanReportRequest):
    if request.aggregate:
        assert len(request.images) >= 2


def test_scanreportrequest():
    request = ScanReportRequest(
        images=["image1", "image2"],
        ignore_failed=False,
        aggregate=True,
        format="latex",
    )
    # Test that duplicates are removed
    assert request == ScanReportRequest(
        images=["image1", "image2", "image1", "image2"],
        ignore_failed=False,
        aggregate=True,
        format="latex",
    )

    # Test that aggregate with 1 image fails
    with pytest.raises(ValueError):
        ScanReportRequest(
            images=["image1"],
            aggregate=True,
            ignore_failed=False,
            format="latex",
        )

    # Test that aggregate with duplicates of 1 image fails
    with pytest.raises(ValueError):
        ScanReportRequest(
            images=["image1", "image1", "image1"],
            aggregate=True,
            ignore_failed=False,
            format="latex",
        )
