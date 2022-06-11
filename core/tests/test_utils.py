from datetime import datetime

from auspex_core.utils.time import timestamp_ms_to_datetime


def test_timestamp_ms_to_datetime():
    assert timestamp_ms_to_datetime("1588888888000") == datetime(2020, 5, 8, 0, 1, 28)
