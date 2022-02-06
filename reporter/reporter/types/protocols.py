from collections import Counter
from typing import List, Optional, Protocol, Tuple


class ScanResults(Protocol):
    def mean_cvss_score(self) -> float:
        ...

    def most_common_cve(self, max_n: Optional[int]) -> List[Tuple[str, int]]:
        ...

    def architecture(self) -> str:
        ...

    def severity_v3(self) -> Counter[str, int]:
        ...

    def severity_v2(self) -> Counter[str, int]:
        ...
