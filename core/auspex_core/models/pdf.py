from pydantic import BaseModel


class PDFRequestBase(BaseModel):
    days: int = 7
    limit: int | None = None  # NOTE: performance implications?
    images: list[str] = []
    scan_id: str | None = None
    # summary: bool = True  # Don’t include individual reports


class PDFRequestIn(PDFRequestBase):
    pass


class PDFRequestOut(PDFRequestBase):
    reports: list[str] = []  # list of report URLs
