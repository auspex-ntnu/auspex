from pydantic import BaseModel

# FIXME: Unused. Implement or delete this before merging.


class InterfaceBase(BaseModel):
    """Base class for all models used as interfaces between services."""

    class Config:
        # All interfaces should be expandable
        extra = "allow"
