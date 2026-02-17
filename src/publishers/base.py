"""Base class for IOC publishers."""

from abc import ABC, abstractmethod

from src.models import EnrichmentResult


class Publisher(ABC):
    """Base class for all IOC publishers."""

    @abstractmethod
    async def publish(self, results: list[EnrichmentResult]) -> None:
        """
        Publish enrichment results to the downstream platform.

        Args:
            results: List of enrichment results to publish

        Raises:
            Exception: If publishing fails (should be fatal for deployment)
        """
        ...
