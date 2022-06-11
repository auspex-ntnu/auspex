from enum import Enum

from .latex import LatexDocument, create_document


# TODO: use this enum for something
class Frontend(Enum):
    latex = "latex"


SUPPORTED_FRONTENDS = [
    "latex",
    # "html", # not supported yet
]
