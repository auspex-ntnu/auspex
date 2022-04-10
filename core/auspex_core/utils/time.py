from datetime import datetime
from typing import Union


def timestamp_ms_to_datetime(timestamp_ms: Union[str, int]) -> datetime:
    """Convert a timestamp in milliseconds to a datetime object"""
    ts = int(timestamp_ms) / 1000
    return datetime.fromtimestamp(ts)
