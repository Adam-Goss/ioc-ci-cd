"""CLI entrypoint for the IOC pipeline."""

import argparse
import asyncio
import csv
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from src.config import load_config
from src.enrichment.aggregator import enrich_all
from src.logging_setup import setup_logging
from src.models import (
    ConfidenceLevel,
    EnrichmentResult,
    IOC,
    IOCType,
    ValidationReport,
    get_confidence_level,
)
from src.parser import parse_ioc_file
from src.publishers.misp import MISPPublisher
from src.publishers.opencti import OpenCTIPublisher
from src.reporting.pr_comment import format_report, set_github_outputs, write_report

logger = setup_logging()

MASTER_CSV_HEADER = [
    "ioc_type",
    "ioc_value",
    "confidence_score",
    "confidence_level",
    "status",
    "deployed_to",
    "added_date",
    "commit_sha",
]

CONFIDENCE_LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2}


def build_validation_report(
    valid_iocs, malformed_lines, duplicates_removed, enrichment_results, threshold, override
) -> ValidationReport:
    """Build a validation report from parsed and enriched IOCs."""
    # Mark results as above/below threshold
    for result in enrichment_results:
        result.above_threshold = result.confidence >= threshold

    return ValidationReport(
        valid_iocs=valid_iocs,
        malformed_lines=malformed_lines,
        duplicates_removed=duplicates_removed,
        enrichment_results=enrichment_results,
        threshold=threshold,
        override=override,
    )


async def validate_command(args: argparse.Namespace) -> int:
    """
    Execute the validate command.

    Returns:
        Exit code (0 = success, 1 = malformed IOCs)
    """
    logger.info(f"Validating IOCs from {args.ioc_file}")

    # Load configuration
    config = load_config()

    # Parse IOC file
    try:
        valid_iocs, malformed_lines, duplicates_removed = parse_ioc_file(args.ioc_file)
    except FileNotFoundError as e:
        logger.error(str(e))
        return 2

    logger.info(
        f"Parsed {len(valid_iocs)} valid IOCs, "
        f"{len(malformed_lines)} malformed, "
        f"{duplicates_removed} duplicates removed"
    )

    # Enrich IOCs
    if valid_iocs:
        enrichment_results = await enrich_all(valid_iocs, config)
    else:
        enrichment_results = []

    # Build report
    report = build_validation_report(
        valid_iocs,
        malformed_lines,
        duplicates_removed,
        enrichment_results,
        args.threshold,
        args.override,
    )

    # Format and write report
    markdown = format_report(report)
    report_dir = os.environ.get("GITHUB_WORKSPACE", "/tmp")
    report_path = os.path.join(report_dir, "enrichment_report.md")
    write_report(markdown, report_path)
    logger.info(f"Report written to {report_path}")

    # Set GitHub Actions outputs (workflow steps use these to fail the check)
    set_github_outputs(report)

    if malformed_lines:
        logger.warning(f"{len(malformed_lines)} malformed IOCs detected (see report)")

    logger.info("Validation complete")
    return 0


def append_to_master_inventory(
    enrichment_results: list[EnrichmentResult],
    master_csv_path: str,
    status: str = "pending",
) -> None:
    """
    Append processed IOCs to the master inventory CSV.

    All valid IOCs are appended with their confidence score and level.
    The deployed_to field is set to N/A initially; it gets updated
    when the publish command runs.

    Args:
        enrichment_results: All enrichment results (passed and failed).
        master_csv_path: Path to master-indicators.csv.
        status: Initial status for new rows ("pending" or "deployed").
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    commit_sha = os.environ.get("GITHUB_SHA", "unknown")[:8]

    # Read existing CSV to check for duplicates
    existing_iocs: set[tuple[str, str]] = set()
    csv_path = Path(master_csv_path)

    if csv_path.exists() and csv_path.stat().st_size > 0:
        with csv_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("ioc_type") and not row["ioc_type"].startswith("#"):
                    existing_iocs.add((row["ioc_type"], row["ioc_value"]))

    # Append new IOCs
    new_count = 0
    needs_header = not csv_path.exists() or csv_path.stat().st_size == 0 or not existing_iocs

    with csv_path.open("a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)

        if needs_header:
            writer.writerow(MASTER_CSV_HEADER)

        for result in enrichment_results:
            ioc = result.ioc
            ioc_key = (ioc.ioc_type.value, ioc.value)

            # Skip if already in master inventory
            if ioc_key in existing_iocs:
                logger.debug(f"Skipping duplicate in master inventory: {ioc.value}")
                continue

            conf_level = get_confidence_level(result.confidence)

            writer.writerow([
                ioc.ioc_type.value,
                ioc.value,
                f"{result.confidence:.2f}",
                conf_level.value,
                status,
                "N/A",
                timestamp,
                commit_sha,
            ])

            existing_iocs.add(ioc_key)
            new_count += 1

    logger.info(f"Appended {new_count} new IOCs to master inventory: {master_csv_path}")


def read_pending_iocs_from_csv(
    master_csv_path: str,
) -> list[tuple[EnrichmentResult, int]]:
    """
    Read IOCs with status='pending' from the master CSV.

    Returns:
        List of (EnrichmentResult, row_index) tuples. Row indices are
        1-based line numbers in the CSV file (header = line 1).
    """
    csv_path = Path(master_csv_path)
    if not csv_path.exists():
        logger.warning(f"Master CSV not found: {master_csv_path}")
        return []

    pending: list[tuple[EnrichmentResult, int]] = []

    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row_idx, row in enumerate(reader, start=2):  # header is line 1
            if not row.get("ioc_type") or row["ioc_type"].startswith("#"):
                continue

            if row.get("status") != "pending":
                continue

            try:
                ioc_type = IOCType(row["ioc_type"])
                ioc = IOC(
                    ioc_type=ioc_type,
                    value=row["ioc_value"],
                    raw_line=row["ioc_value"],
                    line_number=row_idx,
                )

                result = EnrichmentResult(
                    ioc=ioc,
                    scores=[],
                    confidence=float(row["confidence_score"]),
                    above_threshold=False,
                )

                pending.append((result, row_idx))

            except (KeyError, ValueError) as e:
                logger.warning(f"Skipping invalid CSV row {row_idx}: {e}")
                continue

    logger.info(f"Found {len(pending)} pending IOCs in master CSV")
    return pending


def update_csv_deployment_status(
    master_csv_path: str,
    updates: dict[int, str],
) -> None:
    """
    Update deployed_to and status columns for specific rows in the master CSV.

    Args:
        master_csv_path: Path to master-indicators.csv.
        updates: Mapping of row_index (1-based line number) -> deployed_to value.
                 Rows with a non-"N/A" deployed_to get status set to "deployed".
    """
    csv_path = Path(master_csv_path)
    if not csv_path.exists():
        logger.error(f"Master CSV not found: {master_csv_path}")
        return

    rows: list[dict[str, str]] = []
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        for row in reader:
            rows.append(row)

    if not fieldnames:
        logger.error("Master CSV has no header")
        return

    for row_line_num, deployed_to in updates.items():
        # row_line_num is 1-based with header on line 1, so data starts at line 2
        row_idx = row_line_num - 2
        if 0 <= row_idx < len(rows):
            rows[row_idx]["deployed_to"] = deployed_to
            rows[row_idx]["status"] = "deployed" if deployed_to != "N/A" else "pending"

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    logger.info(f"Updated deployment status for {len(updates)} IOCs in master CSV")


def filter_by_publisher_confidence(
    results: list[EnrichmentResult],
    min_level: str,
) -> list[EnrichmentResult]:
    """
    Filter enrichment results by minimum confidence level.

    Args:
        results: Enrichment results to filter.
        min_level: Minimum confidence level required ("low", "medium", "high").

    Returns:
        Results that meet or exceed the minimum level.
    """
    min_order = CONFIDENCE_LEVEL_ORDER.get(min_level.lower(), 1)

    filtered = []
    for result in results:
        result_level = get_confidence_level(result.confidence)
        if CONFIDENCE_LEVEL_ORDER[result_level.value] >= min_order:
            filtered.append(result)

    return filtered


async def inventory_command(args: argparse.Namespace) -> int:
    """
    Execute the inventory command (Phase 1 of deploy).

    Parses, enriches, and appends all valid IOCs to the master CSV
    with status=pending.

    Returns:
        Exit code (0 = success, 1 = malformed, 2 = file not found).
    """
    logger.info(f"Building inventory from {args.ioc_file}")

    # Load configuration
    config = load_config()

    # Parse IOC file
    try:
        valid_iocs, malformed_lines, duplicates_removed = parse_ioc_file(args.ioc_file)
    except FileNotFoundError as e:
        logger.error(str(e))
        return 2

    if malformed_lines:
        logger.error(f"Cannot inventory: {len(malformed_lines)} malformed IOCs")
        return 1

    logger.info(
        f"Parsed {len(valid_iocs)} valid IOCs, {duplicates_removed} duplicates removed"
    )

    if not valid_iocs:
        logger.info("No IOCs to inventory")
        return 0

    # Enrich IOCs
    enrichment_results = await enrich_all(valid_iocs, config)

    # Append ALL results to master inventory with status=pending
    master_csv = args.master_csv or "iocs/master-indicators.csv"
    append_to_master_inventory(enrichment_results, master_csv, status="pending")

    logger.info(f"Inventory complete: {len(enrichment_results)} IOCs processed")
    return 0


async def publish_command(args: argparse.Namespace) -> int:
    """
    Execute the publish command (Phase 2 of deploy).

    Reads pending IOCs from the master CSV, filters by per-publisher
    confidence levels, publishes to MISP and OpenCTI, and updates
    the CSV with deployment status.

    Returns:
        Exit code (0 = success, 3 = MISP error, 4 = OpenCTI error).
    """
    logger.info("Publishing pending IOCs from master CSV")

    # Load configuration
    config = load_config()

    # Read pending IOCs from master CSV
    master_csv = args.master_csv or "iocs/master-indicators.csv"
    pending_with_indices = read_pending_iocs_from_csv(master_csv)

    if not pending_with_indices:
        logger.info("No pending IOCs to publish")
        return 0

    pending_results = [result for result, _ in pending_with_indices]
    logger.info(f"Found {len(pending_results)} pending IOCs")

    # Track which IOCs were deployed to which platforms
    deployed_platforms: dict[str, set[str]] = {}  # ioc_value -> set of platform names

    # Publish to MISP
    misp_results = filter_by_publisher_confidence(
        pending_results, config.misp_min_confidence_level
    )
    logger.info(
        f"MISP: {len(misp_results)}/{len(pending_results)} IOCs meet "
        f"'{config.misp_min_confidence_level}' confidence level"
    )

    if misp_results:
        try:
            misp_publisher = MISPPublisher(config)
            await misp_publisher.publish(misp_results)
            logger.info(f"Successfully published {len(misp_results)} IOCs to MISP")
            for r in misp_results:
                deployed_platforms.setdefault(r.ioc.value, set()).add("MISP")
        except Exception as e:
            logger.error(f"MISP publishing failed: {e}")
            return 3

    # Publish to OpenCTI
    opencti_results = filter_by_publisher_confidence(
        pending_results, config.opencti_min_confidence_level
    )
    logger.info(
        f"OpenCTI: {len(opencti_results)}/{len(pending_results)} IOCs meet "
        f"'{config.opencti_min_confidence_level}' confidence level"
    )

    if opencti_results:
        try:
            opencti_publisher = OpenCTIPublisher(config)
            await opencti_publisher.publish(opencti_results)
            logger.info(f"Successfully published {len(opencti_results)} IOCs to OpenCTI")
            for r in opencti_results:
                deployed_platforms.setdefault(r.ioc.value, set()).add("OpenCTI")
        except Exception as e:
            logger.error(f"OpenCTI publishing failed: {e}")
            return 4

    # Build CSV status updates
    deployment_updates: dict[int, str] = {}
    for result, row_idx in pending_with_indices:
        platforms = deployed_platforms.get(result.ioc.value, set())
        deployed_to = ",".join(sorted(platforms)) if platforms else "N/A"
        deployment_updates[row_idx] = deployed_to

    # Update master CSV
    update_csv_deployment_status(master_csv, deployment_updates)

    logger.info("Publishing complete")
    return 0


def main() -> None:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(description="IOC CI/CD Pipeline")
    parser.add_argument(
        "command",
        choices=["validate", "inventory", "publish"],
        help="Command to run",
    )
    parser.add_argument(
        "ioc_file",
        nargs="?",
        default=None,
        help="Path to IOC input file (required for validate/inventory)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=70.0,
        help="Minimum confidence score (0-100) for IOCs (validate only)",
    )
    parser.add_argument(
        "--override",
        type=lambda x: x.lower() == "true",
        default=False,
        help="Set to true to allow below-threshold IOCs (validate only)",
    )
    parser.add_argument(
        "--master-csv",
        type=str,
        default="iocs/master-indicators.csv",
        help="Path to master IOC inventory CSV file",
    )

    args = parser.parse_args()

    # Treat empty string as None (Docker action passes "" when ioc_file not set)
    if args.ioc_file == "":
        args.ioc_file = None

    # Validate ioc_file is provided for commands that need it
    if args.command in ("validate", "inventory") and not args.ioc_file:
        parser.error(f"ioc_file is required for the '{args.command}' command")

    # Run the appropriate command
    if args.command == "validate":
        exit_code = asyncio.run(validate_command(args))
    elif args.command == "inventory":
        exit_code = asyncio.run(inventory_command(args))
    elif args.command == "publish":
        exit_code = asyncio.run(publish_command(args))
    else:
        parser.print_help()
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
