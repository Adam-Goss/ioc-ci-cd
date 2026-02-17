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
from src.models import EnrichmentResult, ValidationReport
from src.parser import parse_ioc_file
from src.publishers.misp import MISPPublisher
from src.publishers.opencti import OpenCTIPublisher
from src.reporting.pr_comment import format_report, set_github_outputs, write_report

logger = setup_logging()


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
    enrichment_results: list[EnrichmentResult], threshold: float, master_csv_path: str
) -> None:
    """
    Append processed IOCs to the master inventory CSV.

    Args:
        enrichment_results: All enrichment results (passed and failed)
        threshold: Confidence threshold used
        master_csv_path: Path to master-indicators.csv
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    commit_sha = os.environ.get("GITHUB_SHA", "unknown")[:8]

    # Read existing CSV to check for duplicates
    existing_iocs = set()
    csv_path = Path(master_csv_path)

    if csv_path.exists():
        with csv_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_iocs.add((row.get("ioc_type", ""), row.get("ioc_value", "")))

    # Append new IOCs
    new_count = 0
    with csv_path.open("a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)

        # Write header if file is empty/new
        if csv_path.stat().st_size == 0 or not existing_iocs:
            writer.writerow([
                "ioc_type",
                "ioc_value",
                "confidence_score",
                "deployed_to",
                "added_date",
                "commit_sha"
            ])

        for result in enrichment_results:
            ioc = result.ioc
            ioc_key = (ioc.ioc_type.value, ioc.value)

            # Skip if already in master inventory
            if ioc_key in existing_iocs:
                logger.debug(f"Skipping duplicate in master inventory: {ioc.value}")
                continue

            # Determine deployment status
            if result.confidence >= threshold:
                deployed_to = "MISP,OpenCTI"
            else:
                deployed_to = "N/A"

            writer.writerow([
                ioc.ioc_type.value,
                ioc.value,
                f"{result.confidence:.2f}",
                deployed_to,
                timestamp,
                commit_sha
            ])

            existing_iocs.add(ioc_key)
            new_count += 1

    logger.info(f"Appended {new_count} new IOCs to master inventory: {master_csv_path}")


async def publish_command(args: argparse.Namespace) -> int:
    """
    Execute the publish command.

    Returns:
        Exit code (0 = success, 3 = MISP error, 4 = OpenCTI error)
    """
    logger.info(f"Publishing IOCs from {args.ioc_file}")

    # Load configuration
    config = load_config()

    # Parse IOC file
    try:
        valid_iocs, malformed_lines, duplicates_removed = parse_ioc_file(args.ioc_file)
    except FileNotFoundError as e:
        logger.error(str(e))
        return 2

    if malformed_lines:
        logger.error(f"Cannot publish: {len(malformed_lines)} malformed IOCs")
        return 1

    logger.info(
        f"Parsed {len(valid_iocs)} valid IOCs, {duplicates_removed} duplicates removed"
    )

    # Enrich IOCs
    if not valid_iocs:
        logger.info("No IOCs to publish")
        return 0

    enrichment_results = await enrich_all(valid_iocs, config)

    # Filter to above threshold
    passed_results = [r for r in enrichment_results if r.confidence >= args.threshold]
    logger.info(
        f"{len(passed_results)}/{len(enrichment_results)} IOCs passed threshold "
        f"({args.threshold})"
    )

    # Append ALL results to master inventory (both passed and failed)
    master_csv = args.master_csv or "iocs/master-indicators.csv"
    append_to_master_inventory(enrichment_results, args.threshold, master_csv)

    if not passed_results:
        logger.warning("No IOCs passed the confidence threshold, nothing to publish")
        # Still return 0 since we recorded them in master inventory
        return 0

    # Publish to MISP
    try:
        misp_publisher = MISPPublisher(config)
        await misp_publisher.publish(passed_results)
        logger.info(f"Successfully published {len(passed_results)} IOCs to MISP")
    except Exception as e:
        logger.error(f"MISP publishing failed: {e}")
        return 3

    # Publish to OpenCTI
    try:
        opencti_publisher = OpenCTIPublisher(config)
        await opencti_publisher.publish(passed_results)
        logger.info(f"Successfully published {len(passed_results)} IOCs to OpenCTI")
    except Exception as e:
        logger.error(f"OpenCTI publishing failed: {e}")
        return 4

    logger.info("Publishing complete")
    return 0


def main() -> None:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(description="IOC CI/CD Pipeline")
    parser.add_argument("command", choices=["validate", "publish"], help="Command to run")
    parser.add_argument("ioc_file", help="Path to IOC input file")
    parser.add_argument(
        "--threshold",
        type=float,
        default=70.0,
        help="Minimum confidence score (0-100) for IOCs",
    )
    parser.add_argument(
        "--override",
        type=lambda x: x.lower() == "true",
        default=False,
        help="Set to true to allow below-threshold IOCs",
    )
    parser.add_argument(
        "--master-csv",
        type=str,
        default="iocs/master-indicators.csv",
        help="Path to master IOC inventory CSV file",
    )

    args = parser.parse_args()

    # Run the appropriate command
    if args.command == "validate":
        exit_code = asyncio.run(validate_command(args))
    elif args.command == "publish":
        exit_code = asyncio.run(publish_command(args))
    else:
        parser.print_help()
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
