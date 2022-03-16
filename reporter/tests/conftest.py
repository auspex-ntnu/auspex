from typing import Any

from hypothesis import strategies as st

# Hypothesis strategies:

# Variables annotated with Any will be assigned text
st.register_type_strategy(Any, st.text())  # type: ignore
