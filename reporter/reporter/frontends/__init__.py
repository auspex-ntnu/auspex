from enum import Enum
from .latex import create_document, LatexDocument


# TODO: use this enum for something
class Frontend(Enum):
    latex = "latex"


SUPPORTED_FRONTENDS = [
    "latex",
    # "html", # not supported yet
]
