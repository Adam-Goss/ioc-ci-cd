"""Logging configuration for GitHub Actions."""

import logging
import sys


class GitHubActionsFormatter(logging.Formatter):
    """Formats log messages as GitHub Actions commands for annotations."""

    LEVEL_MAP = {
        logging.DEBUG: "::debug::",
        logging.INFO: "",
        logging.WARNING: "::warning::",
        logging.ERROR: "::error::",
        logging.CRITICAL: "::error::",
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with GitHub Actions prefix."""
        prefix = self.LEVEL_MAP.get(record.levelno, "")
        message = super().format(record)
        if prefix:
            return f"{prefix}{message}"
        return message


def setup_logging(debug: bool = False) -> logging.Logger:
    """
    Set up logging for the pipeline.

    Args:
        debug: Enable debug-level logging

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("ioc_pipeline")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        GitHubActionsFormatter(fmt="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    )

    logger.addHandler(handler)
    return logger
