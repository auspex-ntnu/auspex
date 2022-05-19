"""19/05/2022: This is not fully implemented yet.

The final structure should somewhat mirror Google API Core's exceptions.
"""

from .firestore import *
from .base import *

__all__ = [
    "DocumentNotFound",
    "InvalidDocumentId",
    "DocumentTooLarge",
    "ClientError",
    "ServerError",
    "AuspexError",
]
