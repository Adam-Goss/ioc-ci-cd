"""Base class for TI enrichment clients."""

from abc import ABC, abstractmethod

from src.models import IOC, SourceScore


class TIEnrichmentClient(ABC):
    """Base class for all threat intelligence enrichment sources."""

    @abstractmethod
    async def enrich(self, ioc: IOC) -> SourceScore:
        """
        Query this TI source for the given IOC.

        Args:
            ioc: The IOC to enrich

        Returns:
            Normalized score (0-100) with metadata
        """
        ...

    @abstractmethod
    def supports(self, ioc: IOC) -> bool:
        """
        Check if this source can enrich this IOC type.

        Args:
            ioc: The IOC to check

        Returns:
            True if this source supports the IOC type
        """
        ...
