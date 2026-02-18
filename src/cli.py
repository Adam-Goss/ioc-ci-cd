"""CLI entrypoint for the IOC pipeline."""

import argparse
import asyncio
import csv
import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

from src.config import load_config
from src.enrichment.aggregator import enrich_all
from src.logging_setup import setup_logging
from src.models import (
    ConfidenceLevel,
    EnrichmentResult,
    HuntResult,
    IOC,
    IOCType,
    ValidationReport,
    get_confidence_level,
)
from src.parser import parse_ioc_file
from src.publishers.elastic import ElasticHunter
from src.publishers.splunk import SplunkHunter
from src.reporting.pr_comment import format_report, set_github_outputs, write_report

logger = setup_logging()

MASTER_CSV_HEADER = [
    "ioc_type",
    "ioc_value",
    "confidence_score",
    "confidence_level",
    "added_date",
    "last_hunted_date",
    "commit_sha",
]

CONFIDENCE_LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2}

# Registry of available hunting publishers
PUBLISHER_REGISTRY = {
    "splunk": SplunkHunter,
    "elastic": ElasticHunter,
}


def build_validation_report(
    valid_iocs, malformed_lines, duplicates_removed, enrichment_results, threshold, override
) -> ValidationReport:
    """Build a validation report from parsed and enriched IOCs."""
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

    Enriches IOCs, posts a PR comment report, and writes enriched results
    to the master CSV so the deploy workflow can hunt without re-enriching.

    Returns:
        Exit code (0 = success, 2 = file not found).
    """
    logger.info(f"Validating IOCs from {args.ioc_file}")

    config = load_config()

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

    if valid_iocs:
        enrichment_results = await enrich_all(valid_iocs, config)
    else:
        enrichment_results = []

    # Write enriched results to master CSV so deploy workflow can hunt without
    # re-calling enrichment APIs. Deduplication prevents double-entries on re-runs.
    if enrichment_results:
        master_csv = getattr(args, "master_csv", None) or "iocs/master-indicators.csv"
        append_to_master_inventory(enrichment_results, master_csv)

    report = build_validation_report(
        valid_iocs,
        malformed_lines,
        duplicates_removed,
        enrichment_results,
        args.threshold,
        args.override,
    )

    markdown = format_report(report)
    report_dir = os.environ.get("GITHUB_WORKSPACE", "/tmp")
    report_path = os.path.join(report_dir, "enrichment_report.md")
    write_report(markdown, report_path)
    logger.info(f"Report written to {report_path}")

    # Set GitHub Actions outputs (workflow steps use these for warnings)
    set_github_outputs(report)

    if malformed_lines:
        logger.warning(f"{len(malformed_lines)} malformed IOCs detected (see report)")

    logger.info("Validation complete")
    return 0


def append_to_master_inventory(
    enrichment_results: list[EnrichmentResult],
    master_csv_path: str,
) -> None:
    """
    Append processed IOCs to the master inventory CSV.

    All valid IOCs are appended with their confidence score and level.
    Duplicates (same ioc_type + ioc_value) are skipped.

    Args:
        enrichment_results: All enrichment results to append.
        master_csv_path: Path to master-indicators.csv.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    commit_sha = os.environ.get("GITHUB_SHA", "unknown")[:8]

    # Read existing IOCs to check for duplicates
    existing_iocs: set[tuple[str, str]] = set()
    csv_path = Path(master_csv_path)

    if csv_path.exists() and csv_path.stat().st_size > 0:
        with csv_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("ioc_type") and not row["ioc_type"].startswith("#"):
                    existing_iocs.add((row["ioc_type"], row["ioc_value"]))

    new_count = 0
    needs_header = not csv_path.exists() or csv_path.stat().st_size == 0

    with csv_path.open("a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)

        if needs_header:
            writer.writerow(MASTER_CSV_HEADER)

        for result in enrichment_results:
            ioc = result.ioc
            ioc_key = (ioc.ioc_type.value, ioc.value)

            if ioc_key in existing_iocs:
                logger.debug(f"Skipping duplicate in master inventory: {ioc.value}")
                continue

            conf_level = get_confidence_level(result.confidence)

            writer.writerow([
                ioc.ioc_type.value,
                ioc.value,
                f"{result.confidence:.2f}",
                conf_level.value,
                timestamp,
                "",           # last_hunted_date — empty until first hunt
                commit_sha,
            ])

            existing_iocs.add(ioc_key)
            new_count += 1

    logger.info(f"Appended {new_count} new IOCs to master inventory: {master_csv_path}")


def read_iocs_by_age(
    master_csv_path: str,
    max_age_days: int = 30,
) -> list[EnrichmentResult]:
    """
    Read IOCs from master CSV that are within the age window.

    Args:
        master_csv_path: Path to master-indicators.csv.
        max_age_days: Maximum age in days. IOCs older than this are skipped.

    Returns:
        List of EnrichmentResult reconstructed from CSV rows.
    """
    csv_path = Path(master_csv_path)
    if not csv_path.exists():
        logger.warning(f"Master CSV not found: {master_csv_path}")
        return []

    cutoff = datetime.now() - timedelta(days=max_age_days)
    results: list[EnrichmentResult] = []

    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row_idx, row in enumerate(reader, start=2):
            if not row.get("ioc_type") or row["ioc_type"].startswith("#"):
                continue

            try:
                added_date = datetime.strptime(
                    row["added_date"], "%Y-%m-%d %H:%M:%S"
                )
            except (KeyError, ValueError):
                logger.warning(f"Skipping row {row_idx}: invalid added_date")
                continue

            if added_date < cutoff:
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
                results.append(result)
            except (KeyError, ValueError) as e:
                logger.warning(f"Skipping invalid CSV row {row_idx}: {e}")
                continue

    logger.info(
        f"Found {len(results)} IOCs within {max_age_days}-day window in master CSV"
    )
    return results


def update_csv_last_hunted(
    master_csv_path: str,
    hunted_ioc_values: set[str],
) -> None:
    """
    Update the last_hunted_date column for IOCs that were successfully hunted.

    Args:
        master_csv_path: Path to master-indicators.csv.
        hunted_ioc_values: Set of IOC values that were hunted.
    """
    csv_path = Path(master_csv_path)
    if not csv_path.exists():
        logger.error(f"Master CSV not found: {master_csv_path}")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows: list[dict[str, str]] = []

    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or MASTER_CSV_HEADER)
        for row in reader:
            rows.append(dict(row))

    # Ensure last_hunted_date column exists in fieldnames
    if "last_hunted_date" not in fieldnames:
        fieldnames.append("last_hunted_date")

    updated = 0
    for row in rows:
        if row.get("ioc_value") in hunted_ioc_values:
            row["last_hunted_date"] = timestamp
            updated += 1

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    logger.info(f"Updated last_hunted_date for {updated} IOCs in master CSV")


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
    min_order = CONFIDENCE_LEVEL_ORDER.get(min_level.lower(), 0)

    filtered = []
    for result in results:
        result_level = get_confidence_level(result.confidence)
        if CONFIDENCE_LEVEL_ORDER[result_level.value] >= min_order:
            filtered.append(result)

    return filtered


async def inventory_command(args: argparse.Namespace) -> int:
    """
    Execute the inventory command (Phase 1 of deploy).

    Parses IOCs and records any not already in the master CSV. IOCs enriched
    during PR validation are already present (skipped via deduplication).
    IOCs from a direct push to main (no PR) are recorded with a fallback
    confidence score of 0.0 / level "low".

    No enrichment API keys are used here.

    Returns:
        Exit code (0 = success, 2 = file not found).
    """
    logger.info(f"Building inventory from {args.ioc_file}")

    try:
        valid_iocs, malformed_lines, duplicates_removed = parse_ioc_file(args.ioc_file)
    except FileNotFoundError as e:
        logger.error(str(e))
        return 2

    if malformed_lines:
        logger.warning(
            f"Skipping {len(malformed_lines)} malformed IOCs (not added to master inventory)"
        )

    logger.info(
        f"Parsed {len(valid_iocs)} valid IOCs, "
        f"{len(malformed_lines)} malformed, "
        f"{duplicates_removed} duplicates removed"
    )

    if not valid_iocs:
        logger.info("No IOCs to inventory")
        return 0

    # Build fallback EnrichmentResults (score=0, no source data).
    # append_to_master_inventory deduplicates by (ioc_type, ioc_value) so IOCs
    # already written by the validate step (with real scores) are skipped.
    fallback_results = [
        EnrichmentResult(ioc=ioc, scores=[], confidence=0.0)
        for ioc in valid_iocs
    ]

    master_csv = args.master_csv or "iocs/master-indicators.csv"
    append_to_master_inventory(fallback_results, master_csv)

    logger.info(f"Inventory complete: {len(valid_iocs)} IOCs checked")
    return 0


async def publish_command(args: argparse.Namespace) -> int:
    """
    Execute the publish/hunt command (Phase 2 of deploy).

    Reads IOCs from the master CSV within the age window, then hunts
    for each IOC across enabled security platforms (Splunk, Elastic).

    Hunt results are logged. The last_hunted_date column is updated
    in the master CSV for successfully hunted IOCs.

    Returns:
        Exit code (0 = always succeeds, failures are non-fatal).
    """
    logger.info("Hunting for IOCs from master CSV")

    config = load_config()

    master_csv = args.master_csv or "iocs/master-indicators.csv"
    iocs_to_hunt = read_iocs_by_age(master_csv, config.max_ioc_age_days)

    if not iocs_to_hunt:
        logger.info(
            f"No IOCs within {config.max_ioc_age_days}-day window to hunt"
        )
        return 0

    logger.info(
        f"Hunting {len(iocs_to_hunt)} IOCs across "
        f"{len(config.publishers)} platform(s): {', '.join(config.publishers)}"
    )

    all_hunt_results: list[HuntResult] = []
    successfully_hunted: set[str] = set()

    for publisher_name in config.publishers:
        publisher_class = PUBLISHER_REGISTRY.get(publisher_name)
        if publisher_class is None:
            logger.warning(f"Unknown publisher: {publisher_name!r}, skipping")
            continue

        min_level = config.publisher_min_confidence.get(publisher_name, "low")
        filtered = filter_by_publisher_confidence(iocs_to_hunt, min_level)

        if not filtered:
            logger.info(
                f"{publisher_name}: no IOCs meet '{min_level}' confidence threshold"
            )
            continue

        try:
            publisher = publisher_class(config)
            results = await publisher.hunt(filtered)
            all_hunt_results.extend(results)

            hits_total = sum(r.hits_found for r in results if r.success)
            iocs_with_hits = sum(1 for r in results if r.success and r.hits_found > 0)
            logger.info(
                f"{publisher_name}: hunted {len(filtered)} IOCs — "
                f"{iocs_with_hits} had hits, {hits_total} total events"
            )

            for r in results:
                if r.success:
                    successfully_hunted.add(r.ioc.value)

            # Log individual hits
            for r in results:
                if r.success and r.hits_found > 0:
                    logger.info(
                        f"  [{publisher_name}] {r.ioc.ioc_type.value} "
                        f"{r.ioc.value}: {r.hits_found} hit(s)"
                    )

        except Exception as e:
            logger.warning(f"::warning::{publisher_name} hunting failed: {e}")

    # Update last_hunted_date for IOCs that were successfully hunted
    if successfully_hunted:
        update_csv_last_hunted(master_csv, successfully_hunted)

    total_hits = sum(r.hits_found for r in all_hunt_results if r.success)
    logger.info(
        f"Hunt complete — {total_hits} total event hits across "
        f"{len(all_hunt_results)} IOC/platform combinations"
    )

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

    if args.command in ("validate", "inventory") and not args.ioc_file:
        parser.error(f"ioc_file is required for the '{args.command}' command")

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
