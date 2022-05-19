from .base import ClientError, ServerError


class DocumentNotFound(ClientError):
    """Exception raised when a document is not found."""

    def __init__(self, document_id: str) -> None:
        super().__init__("Document with ID '{}' not found.".format(document_id))


class InvalidDocumentId(ClientError):
    """Exception raised when a document ID is invalid."""

    def __init__(self, document_id: str) -> None:
        super().__init__("Document ID '{}' is invalid.".format(document_id))


class DocumentTooLarge(ServerError):
    """Exception raised when a document is exceeds the maximum document size."""

    def __init__(self, document_id: str) -> None:
        super().__init__("Document with ID '{}' is too large.".format(document_id))
