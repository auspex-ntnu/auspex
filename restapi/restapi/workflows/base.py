from abc import ABC, abstractmethod
from typing import Protocol


class WorkflowRunner(ABC):
    @abstractmethod
    async def start_scan(self) -> dict:  # ???
        pass

    @abstractmethod
    async def start_pdf(self) -> dict:
        pass
