"""Base class for IOC hunting publishers."""

from abc import ABC, abstractmethod

from src.models import EnrichmentResult, HuntResult


class HuntPublisher(ABC):
    """Base class for all IOC hunting publishers.

    Hunting publishers search for IOCs in security platform log data
    (e.g. Splunk, Elastic) rather than pushing IOCs to TI platforms.
    """

    @abstractmethod
    async def hunt(self, results: list[EnrichmentResult]) -> list[HuntResult]:
        """
        Search for IOCs in the target platform's log data.

        Args:
            results: List of enrichment results to hunt for.

        Returns:
            List of HuntResult, one per IOC.
        """
        ...

    @abstractmethod
    def name(self) -> str:
        """Return the platform name (e.g. 'splunk', 'elastic')."""
        ...
