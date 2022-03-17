import os

# TODO fix this
os.environ.setdefault(
    "SERVICE_ACCOUNT_KEYFILE",
    "/Volumes/GoogleDrive/My Drive/Skole/2022V/Bachelor/repo/.keys/reporter_local.json",
)
os.environ.setdefault("LOGS_COLLECTION_NAME", "auspex-logs")
os.environ.setdefault("SCANS_BUCKET_NAME", "auspex-scans")

from typing import Any

from hypothesis import strategies as st

# Hypothesis strategies:

# Variables annotated with Any will be assigned text
st.register_type_strategy(Any, st.text())  # type: ignore
